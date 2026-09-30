"""Matii Secret Service cryptography (mirrors the server and the Go SDK).

ph:v1:<ephemeral X25519 public key hex>:<base64(XChaCha20-Poly1305(ciphertext) || nonce)>
with session keys from libsodium crypto_kx; environment key pairs from
crypto_kx_seed_keypair; key digests are keyed BLAKE2b-256 with the salt.
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass

from nacl import bindings
from nacl.utils import random as _random


class DecryptError(ValueError):
    """Any undecryptable or malformed ciphertext."""


@dataclass(frozen=True)
class KeyPair:
    public: bytes
    private: bytes

    def __repr__(self):
        return f"KeyPair(public={self.public.hex()}, private=<redacted>)"


def kx_seed_keypair(seed: bytes) -> KeyPair:
    pk, sk = bindings.crypto_kx_seed_keypair(seed)
    return KeyPair(pk, sk)


def _open_raw(data: bytes, key: bytes) -> bytes:
    if len(data) < 24 + 16:
        raise DecryptError("matii: decryption failed")
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(data[:-24], None, data[-24:], key)
    except Exception:
        raise DecryptError("matii: decryption failed") from None


def _seal_raw(plaintext: bytes, key: bytes) -> bytes:
    nonce = _random(24)
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key) + nonce


def decrypt_asymmetric(ciphertext: str, keys: KeyPair) -> str:
    parts = ciphertext.split(":")
    if len(parts) != 4 or parts[0] != "ph" or parts[1] != "v1":
        raise DecryptError("matii: decryption failed")
    try:
        ephemeral = bytes.fromhex(parts[2])
        raw = base64.b64decode(parts[3], validate=True)
    except ValueError:
        raise DecryptError("matii: decryption failed") from None
    try:
        rx, _ = bindings.crypto_kx_server_session_keys(keys.public, keys.private, ephemeral)
    except Exception:
        raise DecryptError("matii: decryption failed") from None
    return _open_raw(raw, rx).decode()


def encrypt_asymmetric(plaintext: str, recipient_public: bytes) -> str:
    eph_pk, eph_sk = bindings.crypto_kx_keypair()
    _, tx = bindings.crypto_kx_client_session_keys(eph_pk, eph_sk, recipient_public)
    return f"ph:v1:{eph_pk.hex()}:{base64.b64encode(_seal_raw(plaintext.encode(), tx)).decode()}"


def key_digest(key: str, salt: str) -> str:
    return hashlib.blake2b(key.encode(), key=salt.encode(), digest_size=32).hexdigest()


@dataclass(frozen=True)
class Token:
    kind: str  # "ServiceAccount" or "User"
    value: str
    kx_public: str
    share_a: str
    wrap_key: str

    def __repr__(self):
        return f"Token(kind={self.kind}, <redacted>)"

    @property
    def authorization(self) -> str:
        return f"Bearer {self.kind} {self.value}"


def parse_token(raw: str) -> Token:
    """pss_service:v2 and pss_user:v1/v2 tokens."""
    parts = raw.strip().split(":")
    if len(parts) != 6 or not (parts[1] == "v2" or (parts[0] == "pss_user" and parts[1] == "v1")):
        raise ValueError("matii: unsupported token format")
    kind = {"pss_service": "ServiceAccount", "pss_user": "User"}.get(parts[0])
    if kind is None:
        raise ValueError("matii: unknown token type")
    if any(len(p) != 64 for p in parts[2:]):
        raise ValueError("matii: malformed token")
    return Token(kind, parts[2], parts[3], parts[4], parts[5])


def recover_token_key(token: Token, wrapped_share_hex: str) -> KeyPair:
    """The token's X25519 private key: share A (in the token) XOR share B (server-wrapped)."""
    try:
        share_b = bytes.fromhex(_open_raw(bytes.fromhex(wrapped_share_hex), bytes.fromhex(token.wrap_key)).decode())
        share_a = bytes.fromhex(token.share_a)
    except ValueError:
        raise DecryptError("matii: decryption failed") from None
    if len(share_a) != 32 or len(share_b) != 32:
        raise DecryptError("matii: decryption failed")
    private = bytes(a ^ b for a, b in zip(share_a, share_b))
    public = bindings.crypto_scalarmult_base(private)
    if not hmac.compare_digest(public.hex(), token.kx_public.lower()):
        raise DecryptError("matii: token key shares do not match the token's public key")
    return KeyPair(public, private)
