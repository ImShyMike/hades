"""Cryptographic utilities"""

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- config ---
ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2HMAC"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt(text: str, password: str) -> str:
    """Encrypts text using a password"""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)

    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode()


def decrypt(token: str, password: str) -> str:
    """Decrypts a token previously encrypted with `encrypt`"""
    blob = base64.b64decode(token)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
