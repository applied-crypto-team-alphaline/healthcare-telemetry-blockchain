# Key Lifecycle Plan

Version: `v1.0-implemented-prototype`  
Status: Updated to match current implementation

## 1. Key Generation

- each simulated device generates an Ed25519 identity key pair locally
- each communication session generates a fresh X25519 ephemeral key pair

Purpose:

- Ed25519 keys are used for long-term device identity and signatures
- X25519 keys are used only for session establishment

## 2. Key Storage

- identity private keys remain local to the simulated device runtime
- identity public keys are registered in the ledger-style registry
- session private keys are temporary and used only within a single handshake

Security goal:

- private keys are never written to the public registry
- long-term identity keys and session keys are separated

## 3. Key Registration

During provisioning:

1. generate device identity key pair
2. serialize the device public key
3. write the public key into the registry under the device ID
4. mark the device status as `active`
5. append a registration event to the ledger history

## 4. Key Usage

- registry public keys are used to verify signed challenge-response proofs
- ephemeral X25519 public keys are used to derive shared session secrets
- derived session keys are used for AES-GCM telemetry encryption

## 5. Rotation Plan

If a device needs key rotation:

1. generate a new Ed25519 identity key pair
2. append an explicit `rotate` event with the new public key
3. keep the device status `active`
4. require future authentication to validate only against the latest active key

Prototype note:

- the registry supports explicit `register`, `revoke`, `rotate`, and `reenroll` lifecycle events
- active device IDs cannot be silently rebound to a different key through registration

## 6. Compromise Response

If a device private key is suspected to be compromised:

1. revoke the device immediately in the registry
2. reject any future authentication from that revoked device
3. generate a fresh identity key pair for recovery
4. append an explicit `reenroll` event with a new active public key
5. treat all prior compromised key material as invalid

Security effect:

- compromised devices stop passing authentication
- replayed or reused proofs from revoked identities are rejected

## 7. Session-Key Lifetime

- session keys are derived per communication session
- session keys are not reused across sessions intentionally
- session keys are not stored in the registry

## 8. Implementation Note

This document reflects the implemented lifecycle model in `blockchain/ledger.py` and the active-binding protection in `p2p/device_identity.py`.
