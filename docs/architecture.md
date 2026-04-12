# System Architecture

## Overview

The system uses a hybrid architecture:

- a permissioned blockchain-style registry for device trust metadata
- off-registry peer-to-peer telemetry transport
- end-to-end authentication and encryption before telemetry is accepted

This architecture keeps patient telemetry off-chain while making device trust decisions auditable and tamper-evident.

## Components

### Telemetry Device

The sender device:

- loads or creates its identity key pair
- generates telemetry from the dataset emulator
- signs the handshake proof
- encrypts telemetry after session establishment

### Hospital Gateway / Receiver

The receiver:

- checks registry state
- generates the challenge
- verifies the sender signature
- derives the session key
- decrypts accepted telemetry

### Ledger-Style Registry

The registry stores:

- device public keys
- trust status
- registration and revocation events
- `prev_hash` and `event_hash` values

The implementation simulates replication across three node ledgers.

### Secure Channel Layer

The secure channel is implemented in two forms:

- `p2p/secure_channel.py` for in-process simulation and testing
- `p2p/device_a.py` and `p2p/device_b.py` for real TCP socket communication

## Communication Flow

1. A device generates or loads its long-term identity key pair.
2. The device public key is registered in the ledger-style registry.
3. The receiver checks whether the sender exists and is active.
4. The receiver sends a fresh challenge and an ephemeral `X25519` public key.
5. The sender signs the bound handshake message with `Ed25519`.
6. The receiver verifies the signature against the registry public key.
7. Both peers derive a shared session key using `X25519` and `HKDF-SHA256`.
8. Telemetry is encrypted with `AES-GCM`.
9. Replay checks and trust checks determine whether telemetry is accepted or rejected.

## Data Storage

### Registry

- device ID
- public key
- status
- timestamp
- event history
- chained event hashes

### Off-chain

- telemetry payloads
- session keys
- device-local private identity keys
