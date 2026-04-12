# Crypto Design Decision Record (CDDR)

Version: `v0.5-spec`  
Status: Frozen for MVP implementation

## Goal

This project secures healthcare telemetry by combining:

- registry-based public-key trust
- signed challenge-response authentication
- ephemeral session-key establishment
- authenticated encryption for telemetry payloads

The design is intentionally lightweight and avoids building a full PKI or production blockchain network.

## Design Decisions

### Identity and Signatures

- Primitive: `Ed25519`
- Key size: Ed25519 standard curve keys
- Purpose:
  - device identity
  - challenge-response authentication
  - proof of private-key possession

Reason:

- fast and widely used signature scheme
- appropriate for lightweight device authentication
- avoids custom cryptographic construction

### Session Key Establishment

- Primitive: `X25519`
- Key size: X25519 standard curve keys
- Purpose:
  - ephemeral Elliptic Curve Diffie-Hellman key exchange
  - per-session shared secret derivation

Reason:

- efficient elliptic-curve key agreement
- good fit for short-lived secure sessions
- separates long-term identity keys from session keys

### KDF

- Primitive: `HKDF-SHA256`
- Output length: 32 bytes
- Purpose:
  - derive a session key from the X25519 shared secret

Reason:

- standard key derivation method
- uses SHA-256
- provides clean separation between raw shared secret and encryption key

### Telemetry Encryption

- Primitive: `AES-GCM`
- Key size: 256-bit session key output from HKDF
- Nonce size: 96 bits
- Purpose:
  - confidentiality
  - integrity
  - authenticated encryption of telemetry

Reason:

- standard AEAD scheme
- widely available in existing libraries
- appropriate for short structured telemetry payloads

## Nonce Strategy

- AES-GCM uses a fresh 96-bit random nonce per encryption
- Nonces are generated with `os.urandom(12)`
- Nonces are never reused intentionally within the prototype

Misuse prevention:

- a fresh nonce is generated for every encrypted message
- encryption occurs only after authentication and session establishment

## Replay Strategy

- each telemetry record carries a `sequence_number`
- replay detection uses `(sender, sequence_number)` tracking
- repeated sequence numbers from the same sender are rejected

Reason:

- protects against simple replay of previously accepted telemetry
- complements fresh challenge-response authentication

## Trust Model

- trusted device public keys are stored in the local ledger-style registry
- the registry acts as the prototype trust anchor
- devices must be:
  - present in the registry
  - marked `active`
  - able to produce a valid signature

This prototype does not use a traditional centralized certificate authority in the runtime trust path.

## Authentication Message Binding

The signed authentication message binds:

- `device_id`
- `challenge`
- `sender_ephemeral_pub_hex`
- `receiver_ephemeral_pub_hex`

Reason:

- proves identity
- proves freshness
- binds authentication to the exact session establishment attempt
- reduces risk of key-substitution during handshake

## Validation Discipline

Before telemetry is accepted, the system must reject:

- unregistered devices
- revoked devices
- invalid signature proofs
- spoofed sender identities
- replayed sequence numbers

The implementation follows fail-closed behavior for these checks.

## Versioning and Freeze Note

This document defines the frozen cryptographic baseline for Week 5 / `v0.5-spec`.

Frozen decisions:

- `Ed25519` for identity and authentication
- `X25519` for session establishment
- `HKDF-SHA256` for session-key derivation
- `AES-GCM` for telemetry encryption
- random 96-bit AES-GCM nonce generation
- sequence-number replay detection

Any later change to these choices should be documented as a follow-up design decision record before implementation diverges.
