package matii

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	Token           string `json:"token"`
	KXPublic        string `json:"kx_public"`
	KXPrivate       string `json:"kx_private"`
	WrappedKeyShare string `json:"wrapped_key_share"`
	EnvSeed         string `json:"env_seed"`
	EnvSalt         string `json:"env_salt"`
	EnvPublic       string `json:"env_public"`
	EnvPrivate      string `json:"env_private"`
	WrappedSeed     string `json:"wrapped_seed"`
	WrappedSalt     string `json:"wrapped_salt"`
	Secrets         []struct {
		Key             string `json:"key"`
		Value           string `json:"value"`
		KeyCiphertext   string `json:"key_ciphertext"`
		ValueCiphertext string `json:"value_ciphertext"`
		KeyDigest       string `json:"key_digest"`
	} `json:"secrets"`
	KXSeedKeyPair struct {
		Seed, Public, Private string
	} `json:"kx_seed_keypair"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKXSeedKeyPairMatchesLibsodium(t *testing.T) {
	v := loadVectors(t)
	kp, err := KXSeedKeyPair(mustHex(t, v.KXSeedKeyPair.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(kp.Public[:]) != v.KXSeedKeyPair.Public || hex.EncodeToString(kp.Private[:]) != v.KXSeedKeyPair.Private {
		t.Fatal("seed keypair differs from libsodium")
	}
}

func TestFullE2EEChain(t *testing.T) {
	v := loadVectors(t)
	token, err := ParseToken(v.Token)
	if err != nil {
		t.Fatal(err)
	}
	tokenKey, err := recoverTokenKey(token, v.WrappedKeyShare)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tokenKey.Private[:]) != v.KXPrivate {
		t.Fatal("recovered token key differs")
	}
	seed, err := DecryptAsymmetric(v.WrappedSeed, tokenKey)
	if err != nil || seed != v.EnvSeed {
		t.Fatalf("seed: %v", err)
	}
	salt, err := DecryptAsymmetric(v.WrappedSalt, tokenKey)
	if err != nil || salt != v.EnvSalt {
		t.Fatalf("salt: %v", err)
	}
	envKey, err := KXSeedKeyPair(mustHex(t, seed))
	if err != nil || hex.EncodeToString(envKey.Public[:]) != v.EnvPublic {
		t.Fatal("env keypair differs")
	}
	for _, s := range v.Secrets {
		key, err := DecryptAsymmetric(s.KeyCiphertext, envKey)
		if err != nil || key != s.Key {
			t.Fatalf("key %q: %v", s.Key, err)
		}
		value, err := DecryptAsymmetric(s.ValueCiphertext, envKey)
		if err != nil || value != s.Value {
			t.Fatalf("value of %q: %v", s.Key, err)
		}
		digest, _ := KeyDigest(s.Key, salt)
		if digest != s.KeyDigest {
			t.Fatalf("digest of %q differs", s.Key)
		}
	}
}

func TestRoundTripAndTamperDetection(t *testing.T) {
	v := loadVectors(t)
	envKey, _ := KXSeedKeyPair(mustHex(t, v.EnvSeed))
	ct, err := EncryptAsymmetric("round trip ✓", envKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := DecryptAsymmetric(ct, envKey); err != nil || pt != "round trip ✓" {
		t.Fatal("round trip failed")
	}
	tampered := ct[:len(ct)-4] + "AAAA"
	if _, err := DecryptAsymmetric(tampered, envKey); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	other, _ := KXSeedKeyPair(make([]byte, 32))
	if _, err := DecryptAsymmetric(ct, other); err == nil {
		t.Fatal("wrong key decrypted")
	}
}

func TestTokenParsingAndRedaction(t *testing.T) {
	v := loadVectors(t)
	token, err := ParseToken(v.Token)
	if err != nil {
		t.Fatal(err)
	}
	if token.Kind() != "ServiceAccount" {
		t.Fatal("kind")
	}
	for _, s := range []string{token.String(), token.GoString()} {
		if s != "ServiceAccount token (redacted)" {
			t.Fatalf("token leaked in %q", s)
		}
	}
	for _, bad := range []string{"", "pss_service:v1:a:b:c:d", "nope:v2:a:b:c:d", "pss_service:v2:short:b:c:d"} {
		if _, err := ParseToken(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
