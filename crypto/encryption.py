import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(session_key, plaintext):
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt_message(session_key, nonce, ciphertext):
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()