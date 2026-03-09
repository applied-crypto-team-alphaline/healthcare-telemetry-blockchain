# Cryptographic Design

## Identity Model
Each device generates its own public and private key pair. The public key acts as the device's identity and is registered on the blockchain registry.

## Blockchain Identity Registry
The blockchain acts as a decentralized registry where device public keys are stored. This allows peers to verify device identities without relying on a centralized certificate authority.

## Cryptographic Primitives

### Public Key Signatures
Ed25519 signatures are used to verify device identity and ensure authenticity.

### Key Exchange
X25519 (Elliptic Curve Diffie-Hellman) is used to derive shared session keys between communicating peers.

### Symmetric Encryption
AES-GCM or ChaCha20-Poly1305 is used for authenticated encryption of telemetry messages.

### Hashing
SHA-256 is used for hashing operations and record verification.

## Rationale

- Elliptic curve cryptography provides strong security with low computational overhead.
- Authenticated encryption ensures both confidentiality and integrity of telemetry data.
- Blockchain provides decentralized trust for identity verification.

## Misuse Prevention

- Private keys are never stored on the blockchain.
- Replay attacks are prevented using sequence numbers.
- Revoked devices are rejected during authentication.
- Session keys are generated per communication session.

