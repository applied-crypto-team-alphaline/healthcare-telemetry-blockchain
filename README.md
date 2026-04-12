Team Member: Geethika Padamati, Zichen Fan

# Blockchain-Assisted Peer-to-Peer Authentication for Secure Healthcare Telemetry

![Secure Telemetry System Architecture](../Gemini_Generated_Image_q3z8lpq3z8lpq3z8.png)

System overview showing the device layer, hospital gateway, hospital processing layer, clinical access layer, and the 3-node permissioned blockchain-style trust registry.

## Overview

This project is a Python prototype for secure healthcare telemetry in a hospital-like environment. It combines a permissioned blockchain-style device registry with authenticated peer-to-peer communication so that telemetry is accepted only from trusted, active devices.

The system does not implement a public blockchain or a production PKI. Instead, it demonstrates the security workflow end to end:

- device identity generation with `Ed25519`
- signed challenge-response authentication
- ephemeral key exchange with `X25519`
- session key derivation with `HKDF-SHA256`
- encrypted telemetry with `AES-GCM`
- replay detection and revocation enforcement
- a 3-node replicated ledger-style registry
- both dashboard-based and real socket-based P2P demos

Sensitive patient telemetry remains off-registry. The registry stores only device trust metadata and trust events such as registration and revocation.

## Implemented Features

- `Signed challenge-response authentication`
  Devices prove possession of their registered private keys before telemetry is accepted.

- `Encrypted telemetry transport`
  After authentication, peers derive a shared session key and protect telemetry with `AES-GCM`.

- `Replay protection`
  Reuse of the same `(sender, sequence_number)` pair is rejected.

- `Revocation`
  A revoked device remains in the ledger history but is rejected at runtime.

- `3-node permissioned registry simulation`
  Registry events are written to a primary ledger and replicated to three hospital-controlled node files.

- `Hash-chained trust events`
  Each registration or revocation event contains `prev_hash` and `event_hash` so the chain can be verified.

- `Real socket-based P2P flow`
  `p2p/device_a.py` and `p2p/device_b.py` run an actual sender/receiver handshake over TCP sockets.

- `Interactive dashboard`
  `dashboard.py` visualizes accepted and rejected telemetry, protocol evidence, ledger events, registry node status, and the real P2P demo output.

## Project Structure

```text
healthcare-telemetry-blockchain/
├── blockchain/
│   └── ledger.py              # Ledger-style device registry with hash-chained events
├── crypto/
│   ├── encryption.py          # AES-GCM encryption/decryption
│   ├── key_exchange.py        # X25519 shared secret + HKDF session keys
│   └── key_generation.py      # Ed25519/X25519 key generation and signature helpers
├── data/
│   └── healthcare_iot.csv     # Simulated telemetry dataset
├── docs/
│   ├── architecture.md
│   ├── interface-spec.md
│   └── system-design.md
├── p2p/
│   ├── device_a.py            # Socket-based sender demo
│   ├── device_b.py            # Socket-based receiver demo
│   ├── device_emulator.py     # Dataset-driven telemetry generator
│   ├── device_identity.py     # Local device identity persistence
│   └── secure_channel.py      # In-process authenticated secure channel
├── tests/
│   ├── test_registry.py
│   ├── test_replay.py
│   └── test_secure_channel.py
└── dashboard.py               # Streamlit visualization and demo UI
```

## Security Flow

### 1. Device onboarding

1. A device generates a long-term `Ed25519` identity key pair.
2. Its public key is registered in the ledger-style device registry.
3. The registry records a `register` event and replicates it to all registry nodes.

### 2. Telemetry transmission

1. The sender starts a session with the hospital gateway.
2. The receiver checks whether the sender is registered and active.
3. The receiver creates a fresh challenge and sends its ephemeral `X25519` public key.
4. The sender signs the bound handshake message.
5. The receiver verifies the signature against the registry public key.
6. Both peers derive the same session key with `X25519 + HKDF-SHA256`.
7. Telemetry is encrypted with `AES-GCM`.
8. The receiver decrypts and accepts telemetry only if all checks succeed.

### 3. Revocation

1. A compromised device is marked `revoked`.
2. A `revoke` event is appended to the ledger.
3. Future authentication attempts from that device are rejected.

## Requirements

Use Python 3.8+.

Install the libraries used by the project:

```bash
pip install cryptography streamlit pandas altair pytest
```

## How To Run

### Run the test suite

From the project root:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

Note:
Some environments have globally installed `pytest` plugins that interfere with this repo. `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` avoids unrelated plugin conflicts.

### Run the dashboard demo

```bash
streamlit run dashboard.py
```

The dashboard supports:

- telemetry validation over the dataset
- revoking a trusted device
- replay-attack simulation
- spoofing simulation
- viewing protocol evidence
- viewing ledger events and 3-node replication state
- running the real socket-based P2P demo from the sidebar

### Run the tamper-detection demo

```bash
python tamper_demo.py
```

The demo:

- creates a fresh registry with three replicated node files
- appends `register` and `revoke` events
- verifies the chain before tampering
- manually changes a stored event without recomputing its hash
- shows that `verify_chain()` fails and replication status detects the mismatch

### Run the real socket-based P2P demo manually

Start the receiver in one terminal:

```bash
P2P_REGISTRY_FILE=/tmp/p2p_registry.json \
DEVICE_KEY_DIR=/tmp/p2p_keys \
P2P_PORT=5001 \
python p2p/device_b.py
```

Then start the sender in another terminal:

```bash
P2P_REGISTRY_FILE=/tmp/p2p_registry.json \
DEVICE_KEY_DIR=/tmp/p2p_keys \
P2P_PORT=5001 \
python p2p/device_a.py
```

Expected success path:

1. `device_b.py` starts a TCP server and waits for a connection.
2. `device_a.py` loads or creates a device identity.
3. Both peers perform signed challenge-response authentication.
4. The sender encrypts telemetry and sends it over the socket.
5. The receiver verifies, decrypts, and returns an `accepted` response.

Important runtime note:

- `device_identity.py` persists local identities under `DEVICE_KEY_DIR`
- registry state is persisted in `P2P_REGISTRY_FILE`
- using the same paths across runs keeps the demo state consistent

## Current Validation Coverage

The current test suite covers:

- device registration and lookup
- revocation and active/revoked state transitions
- replicated registry consistency
- tampered ledger chain detection
- replica mismatch detection
- authenticated handshake verification
- encrypted telemetry round-trip
- replay detection
- invalid signature rejection
- real socket-based P2P revoked-device rejection
- real socket-based P2P invalid-signature rejection

Note:
The real socket-based P2P tests may be skipped in restricted environments where local socket binding is not permitted.

## Current Threats Demonstrated

- `Spoofing`
  Rejected when the claimed sender does not match `telemetry["device_id"]`.

- `Replay`
  Rejected when a previously seen `(sender, sequence_number)` is reused.

- `Revoked device access`
  Rejected when a sender exists in the registry but is no longer active.

- `Authentication proof failure`
  Rejected when the signature does not verify against the registered public key.

## Design Notes

- This is a permissioned prototype, not a public blockchain.
- Telemetry is kept off-chain.
- The registry is blockchain-style because it keeps append-only trust events linked by hashes and replicated across multiple nodes.
- The dashboard and the real P2P scripts share the same cryptographic design, but they exercise it in different ways:
  - `SecureChannel` demonstrates the protocol in-process.
  - `device_a.py` and `device_b.py` demonstrate the protocol over real TCP sockets.

## Related Documents

- [System Design](docs/system-design.md)
- [Architecture](docs/architecture.md)
- [Interface Specification](docs/interface-spec.md)
