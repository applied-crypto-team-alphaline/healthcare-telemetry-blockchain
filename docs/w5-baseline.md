# Week 5 Baseline Freeze

Baseline name: `v0.5-spec`  
Week tag target: `w5`

## Frozen Scope

This baseline freezes the following design decisions for MVP implementation:

- Ed25519 for device identity and challenge-response authentication
- X25519 for ephemeral session establishment
- HKDF-SHA256 for session-key derivation
- AES-GCM for telemetry encryption
- ledger-style registry as the prototype trust anchor
- sequence-number replay detection
- registration and revocation as the current key lifecycle operations

## Freeze Discipline

After this baseline:

- message fields should not be changed casually
- cryptographic primitives should not be swapped without documentation
- key lifecycle assumptions should remain stable for MVP work

If a change is needed after this point, the team should document:

1. what changed
2. why it changed
3. what security or protocol impact it introduces

This keeps the implementation aligned with the approved design-review baseline.
