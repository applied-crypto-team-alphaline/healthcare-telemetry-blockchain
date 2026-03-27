import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(session_key: bytes, plaintext: str):
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce.hex(), ciphertext.hex()


def decrypt_message(session_key: bytes, nonce_hex: str, ciphertext_hex: str) -> str:
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")