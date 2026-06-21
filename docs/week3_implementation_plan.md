# Week 3 Implementation Plan

github: https://github.com/applied-crypto-team-alphaline/healthcare-telemetry-blockchain

This week, the next step is to move from the security design into the **code / prototype phase**.

The security story already defines the main implementation targets clearly: registry-based identity lookup, peer public-key verification, authenticated key exchange, encrypted telemetry, replay protection, revocation checks, and audit logging.

## Coding Scope for This Week

### 1. Blockchain Identity Registry Mock

Implement a simple registry that stores:

- `device_id`
- `public_key`
- `timestamp`
- `status` (`active` / `revoked`)

This supports identity lookup and revocation handling.

### 2. Device Registration and Identity Verification

Write code so Device A and Device B can:

- register their public keys
- query the peer's identity
- reject unknown, revoked, or malformed records
- verify that the peer public key matches the registry record

This maps to the identity and trust requirements in the design.

### 3. ECDH Session Key Establishment

Implement authenticated key exchange so each session derives a fresh session key.

### 4. Encrypted Telemetry Channel

Send telemetry off-chain over the peer-to-peer channel using authenticated encryption, and reject modified ciphertext.

### 5. Freshness and Replay Protection

Add sequence numbers or timestamps to each telemetry message, and reject stale or duplicate messages.

Also ensure a unique nonce is used for every encryption operation.

### 6. Audit Logging

Log failures for cases such as:

- unknown device
- revoked device
- malformed identity record
- public-key mismatch

## Recommended Implementation Order

1. Build the registry
2. Build device key generation and registration
3. Implement peer verification
4. Implement ECDH and session key derivation
5. Implement encrypted telemetry messages
6. Add replay checks and nonce handling
7. Add revocation and logging tests

## Weekly Summary

This week, we move from the security design into implementation by coding the core prototype: a blockchain-based identity registry, device registration and peer verification, ECDH session establishment, encrypted telemetry transfer, replay protection, revocation checks, and audit logging.
