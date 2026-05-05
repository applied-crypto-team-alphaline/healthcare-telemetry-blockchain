# Key Lifecycle Plan

Version: `v0.5-spec`  
Status: Frozen for MVP implementation

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
2. register the new public key in the registry
3. revoke the old device record or mark the old key inactive
4. require future authentication to validate only against the latest active key

Prototype note:

- current implementation supports registration and revocation directly
- full automated rotation logic is planned but not yet implemented as a separate workflow

## 6. Compromise Response

If a device private key is suspected to be compromised:

1. revoke the device immediately in the registry
2. reject any future authentication from that revoked device
3. generate a fresh identity key pair for recovery
4. re-register the recovered device with a new active public key
5. treat all prior compromised key material as invalid

Security effect:

- compromised devices stop passing authentication
- replayed or reused proofs from revoked identities are rejected

## 7. Session-Key Lifetime

- session keys are derived per communication session
- session keys are not reused across sessions intentionally
- session keys are not stored in the registry

## 8. Freeze Note

This document defines the Week 5 / `v0.5-spec` baseline key lifecycle assumptions.

Changes to:

- long-term identity-key handling
- session-key derivation flow
- rotation rules
- compromise procedures

should be documented before implementation changes are made.
