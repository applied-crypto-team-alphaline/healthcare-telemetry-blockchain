from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization


def generate_identity_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_identity_private_key(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


def serialize_identity_public_key(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()


def load_identity_private_key_from_hex(private_key_hex: str):
    private_key_bytes = bytes.fromhex(private_key_hex)
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)


def load_identity_public_key_from_hex(public_key_hex: str):
    public_key_bytes = bytes.fromhex(public_key_hex)
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)


def sign_message(private_key, message: bytes) -> str:
    return private_key.sign(message).hex()


def verify_signature(public_key, message: bytes, signature_hex: str) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), message)
        return True
    except InvalidSignature:
        return False


def generate_exchange_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_exchange_public_key(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()


def load_exchange_public_key_from_hex(public_key_hex: str):
    public_key_bytes = bytes.fromhex(public_key_hex)
    return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
