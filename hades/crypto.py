"""Cryptographic utilities"""

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hades.unicode import decode_tags, encode_tags

# --- config ---
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 131072  # 128 MB
ARGON2_PARALLELISM = 4


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derives a key from a password using Argon2id. Returns (key, salt)."""
    if salt is None:
        salt = os.urandom(SALT_LEN)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return key, salt


def encrypt_with_key(text: str, key: bytes, salt: bytes) -> str:
    """Encrypts text using a pre-derived key"""
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode()


def _decrypt(token: str, password: str) -> str:
    """Decrypts a token previously encrypted with `encrypt`"""
    blob = base64.b64decode(token)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN :]

    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def encrypt_text(text: str, key: bytes, salt: bytes) -> str:
    """Encrypt text with tag encoding using a pre-derived key"""
    encrypted = encrypt_with_key(text, key, salt)
    encoded = encode_tags(encrypted)
    return encoded


def decrypt_text(token: str, password: str) -> str:
    """Decrypt text with tag decoding"""
    decoded = decode_tags(token)
    decrypted = _decrypt(decoded, password)
    return decrypted
