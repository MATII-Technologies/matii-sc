package matii

// Wire-compatible implementation of the Secret Service's client-side
// cryptography (libsodium crypto_kx + XChaCha20-Poly1305), written from the
// MIT-licensed console source (backend/api/utils/crypto.py) and verified
// against vectors produced by that code (testdata/vectors.json).
//
// Ciphertext format: "ph:v1:<ephemeral public key hex>:<base64(ciphertext||nonce)>".

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ErrDecrypt is returned for any undecryptable or malformed ciphertext.
var ErrDecrypt = errors.New("matii: decryption failed")

// KeyPair is an X25519 key exchange keypair.
type KeyPair struct {
	Public  [32]byte
	Private [32]byte
}

// KXSeedKeyPair mirrors libsodium crypto_kx_seed_keypair:
// sk = BLAKE2b-256(seed), pk = X25519(sk, basepoint).
func KXSeedKeyPair(seed []byte) (KeyPair, error) {
	var kp KeyPair
	sk := blake2b.Sum256(seed)
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Private[:], sk[:])
	copy(kp.Public[:], pk)
	return kp, nil
}

// sessionKeys returns BLAKE2b-512(q || clientPK || serverPK), split in halves.
func sessionKeys(q, clientPK, serverPK []byte) (first, second []byte, err error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, nil, err
	}
	h.Write(q)
	h.Write(clientPK)
	h.Write(serverPK)
	sum := h.Sum(nil)
	return sum[:32], sum[32:], nil
}

func sealRaw(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(aead.Seal(nil, nonce, plaintext, nil), nonce...), nil
}

func openRaw(ct, key []byte) ([]byte, error) {
	if len(ct) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	split := len(ct) - chacha20poly1305.NonceSizeX
	out, err := aead.Open(nil, ct[split:], ct[:split], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// DecryptAsymmetric opens a "ph:v1" ciphertext addressed to kp.
func DecryptAsymmetric(ciphertext string, kp KeyPair) (string, error) {
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 4 || parts[0] != "ph" || parts[1] != "v1" {
		return "", ErrDecrypt
	}
	ephemeral, err := hex.DecodeString(parts[2])
	if err != nil || len(ephemeral) != 32 {
		return "", ErrDecrypt
	}
	raw, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", ErrDecrypt
	}
	q, err := curve25519.X25519(kp.Private[:], ephemeral)
	if err != nil {
		return "", ErrDecrypt
	}
	// We are the crypto_kx "server": rx is the second half.
	_, rx, err := sessionKeys(q, ephemeral, kp.Public[:])
	if err != nil {
		return "", ErrDecrypt
	}
	plaintext, err := openRaw(raw, rx)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptAsymmetric seals plaintext to recipientPublic with an ephemeral keypair.
func EncryptAsymmetric(plaintext string, recipientPublic [32]byte) (string, error) {
	var eph [32]byte
	if _, err := rand.Read(eph[:]); err != nil {
		return "", err
	}
	ephPub, err := curve25519.X25519(eph[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	q, err := curve25519.X25519(eph[:], recipientPublic[:])
	if err != nil {
		return "", err
	}
	// We are the crypto_kx "client": tx is the second half.
	_, tx, err := sessionKeys(q, ephPub, recipientPublic[:])
	if err != nil {
		return "", err
	}
	sealed, err := sealRaw([]byte(plaintext), tx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ph:v1:%s:%s", hex.EncodeToString(ephPub), base64.StdEncoding.EncodeToString(sealed)), nil
}

// KeyDigest mirrors blake2b_digest: keyed BLAKE2b-256 with the environment salt (as UTF-8 text).
func KeyDigest(key, salt string) (string, error) {
	h, err := blake2b.New256([]byte(salt))
	if err != nil {
		return "", err
	}
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// recoverTokenKey rebuilds a token's X25519 private key from share A (in the
// token) and share B (wrapped server-side with the token's wrap key).
func recoverTokenKey(t *Token, wrappedShareHex string) (KeyPair, error) {
	var kp KeyPair
	wrapped, err := hex.DecodeString(wrappedShareHex)
	if err != nil {
		return kp, ErrDecrypt
	}
	wrapKey, err := hex.DecodeString(t.wrapKey)
	if err != nil {
		return kp, ErrDecrypt
	}
	shareBHex, err := openRaw(wrapped, wrapKey)
	if err != nil {
		return kp, err
	}
	shareB, err := hex.DecodeString(string(shareBHex))
	if err != nil {
		return kp, ErrDecrypt
	}
	shareA, err := hex.DecodeString(t.shareA)
	if err != nil || len(shareA) != 32 || len(shareB) != 32 {
		return kp, ErrDecrypt
	}
	for i := range kp.Private {
		kp.Private[i] = shareA[i] ^ shareB[i]
	}
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return kp, ErrDecrypt
	}
	expected, err := hex.DecodeString(t.kxPublic)
	if err != nil || subtle.ConstantTimeCompare(pub, expected) != 1 {
		return kp, errors.New("matii: token key shares do not match the token's public key")
	}
	copy(kp.Public[:], pub)
	return kp, nil
}
