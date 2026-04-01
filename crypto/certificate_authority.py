from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


class CertificateAuthority:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign_certificate(self, device_id: str, public_key_hex: str):
        message = f"{device_id}:{public_key_hex}".encode("utf-8")
        signature = self.private_key.sign(message)

        return {
            "device_id": device_id,
            "public_key": public_key_hex,
            "signature": signature.hex()
        }

    def verify_certificate(self, certificate: dict):
        message = f"{certificate['device_id']}:{certificate['public_key']}".encode("utf-8")
        signature = bytes.fromhex(certificate["signature"])

        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False