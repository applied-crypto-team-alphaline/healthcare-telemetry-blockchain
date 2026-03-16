from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)


def derive_session_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"healthcare-telemetry"
    )
    return hkdf.derive(shared_secret)