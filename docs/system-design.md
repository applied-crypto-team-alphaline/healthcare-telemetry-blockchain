# System Design

Version: `v1.0-implemented-prototype`

![Secure Telemetry System Architecture](../../Gemini_Generated_Image_q3z8lpq3z8lpq3z8.png)

Figure 1. End-to-end system architecture showing telemetry devices, signed and encrypted transmission, hospital gateway validation, off-chain telemetry processing, and the 3-node permissioned registry used for trust management.


## 1. System Goal

The goal of this project is to implement a realistic prototype for secure healthcare telemetry where devices must:

- authenticate before sending telemetry
- establish a secure communication session
- protect telemetry confidentiality and integrity
- support revocation of compromised devices
- reduce reliance on a single centralized trust authority

This version is no longer just a design draft. The current repository implements the full prototype flow with a replicated registry, authenticated session establishment, encrypted telemetry transport, replay protection, revocation, a dashboard demo, and a real socket-based P2P demo.

## 2. Parties Involved

### 2.1 Telemetry Device

Responsibilities:

- generate or load its own long-term identity key pair
- register its public key in the registry
- prove identity through signed challenge-response
- derive a secure session key with the receiver
- encrypt telemetry before transmission

### 2.2 Hospital Gateway / Receiver

Responsibilities:

- receive telemetry from devices
- query the registry for trusted device status and public keys
- generate a fresh challenge
- verify signed challenge-response authentication
- derive a session key
- decrypt accepted telemetry
- reject unauthorized, replayed, or revoked senders

### 2.3 Clinical Monitoring System

Responsibilities:

- display accepted telemetry
- consume only validated and decrypted telemetry
- support downstream alerting and monitoring

In this prototype, the Streamlit dashboard acts as the visualization layer for accepted and rejected events.

### 2.4 Hospital Security / Registry Administrator

Responsibilities:

- approve device onboarding
- revoke compromised devices
- supervise trust state
- inspect registry replication and ledger history

### 2.5 Permissioned Registry Nodes

Responsibilities:

- store trust events
- replicate registry state
- provide tamper-evident history through chained event hashes

## 3. Ownership Model

The trust registry is assumed to be hospital-controlled and permissioned.

This project does not assume:

- anonymous participants
- public mining
- token incentives
- a public blockchain network

Instead, it models a hospital-operated trust system where registry nodes are controlled by approved internal operators.

## 4. Registry Design

The registry is implemented as a permissioned blockchain-style event ledger.

### 4.1 Stored Trust Data

The registry stores:

- `device_id`
- `public_key`
- `status`
- `timestamp`
- `event_type`
- `prev_hash`
- `event_hash`

It does not store patient telemetry or private keys.

### 4.2 Event Model

Each trust change is recorded as an event:

- `register`
- `revoke`

Each event includes:

- the previous event hash
- its own hash
- a timestamp
- the resulting device status

This creates an append-only tamper-evident chain of trust events.

### 4.3 Replication Model

The implementation simulates three permissioned registry nodes. On each update:

1. the new event history is written to all node ledgers
2. the primary registry file is updated
3. node equality can be checked through `get_replication_status()`

This is a replication simulation, not a consensus protocol. The purpose is to demonstrate multi-node trust state replication in a small prototype.

## 5. Node Model

The deployed prototype uses a 3-node model:

### Node 1: Security Node

- manages trust updates
- acts as the primary registry reference

### Node 2: Monitoring Backend Node

- stores a synchronized replica
- supports runtime verification use cases

### Node 3: Audit / Backup Node

- stores a synchronized replica
- supports auditability and recovery scenarios

## 6. Trust Model

The trust anchor is the hospital-controlled registry, not a certificate authority.

Trust is established as follows:

1. a device generates a long-term `Ed25519` identity key pair
2. the device public key is registered in the registry
3. the receiver checks that the sender exists and is `active`
4. the receiver generates a fresh challenge
5. the sender signs a handshake message bound to:
   - `device_id`
   - `challenge`
   - sender ephemeral public key
   - receiver ephemeral public key
6. the receiver verifies the signature using the public key stored in the registry
7. only then is the session considered authenticated

This binds trust to the hospital-operated registry while proving private-key possession at runtime.

## 7. Cryptographic Design

The prototype currently uses:

- `Ed25519` for device identity and signatures
- `X25519` for ephemeral Diffie-Hellman key exchange
- `HKDF-SHA256` for session key derivation
- `AES-GCM` for authenticated encryption of telemetry

Security properties demonstrated:

- sender authentication
- telemetry confidentiality
- telemetry integrity
- replay resistance
- revocation enforcement

## 8. Data Flow

### 8.1 Device Onboarding

1. a device generates or loads an identity key pair
2. the public key is registered in the ledger-style registry
3. a `register` event is appended
4. the event history is replicated to all registry nodes

### 8.2 Authenticated Telemetry Flow

1. the sender initiates communication
2. the receiver checks sender registration and status
3. the sender and receiver generate ephemeral `X25519` keys
4. the receiver issues a challenge
5. the sender signs the handshake message
6. the receiver verifies the signature using the registry public key
7. both peers derive the same session key with `HKDF-SHA256`
8. the sender encrypts telemetry with `AES-GCM`
9. the receiver decrypts telemetry
10. telemetry is accepted only if all verification checks succeed

### 8.3 Revocation Flow

1. a device is marked compromised or no longer trusted
2. a `revoke` event is appended to the ledger
3. the new trust state is replicated to all nodes
4. future authentication attempts are rejected

### 8.4 Replay Defense

The receiver tracks previously seen `(sender, sequence_number)` pairs. If the same pair appears again, the message is rejected as a replay.

## 9. Data Classification and Storage

### 9.1 Registry Data

Registry data includes:

- device identifiers
- public keys
- trust status
- trust event history

Registry data is accessible to:

- registry nodes
- the hospital gateway
- authorized administrators
- internal trust services

### 9.2 Telemetry Data

Telemetry data includes:

- patient measurements
- timestamps
- device identifiers
- operational metadata

Telemetry is:

- encrypted in transit
- decrypted only by the authorized receiver
- intentionally stored off-registry

## 10. Implemented Components

### 10.1 In-Process Secure Channel

`p2p/secure_channel.py` provides an in-process version of the authenticated telemetry flow. It is used by the dashboard and the unit tests.

### 10.2 Real Socket-Based P2P Demo

`p2p/device_a.py` and `p2p/device_b.py` implement the same trust flow over TCP sockets:

- sender hello
- receiver challenge
- sender proof
- encrypted telemetry
- receiver acceptance or rejection

### 10.3 Dashboard Demo

`dashboard.py` exposes:

- telemetry validation against the dataset
- accepted and rejected result views
- protocol evidence for the latest run
- registry contents and ledger events
- three-node replication status
- replay and spoofing simulations
- a button that launches the real socket-based P2P demo

## 11. Security Boundaries

The prototype enforces the following runtime checks:

- sender must be registered
- receiver must be registered where applicable
- sender must be active
- telemetry sender must match the claimed sender
- signature proof must verify
- replayed sequence numbers must be rejected

This project does not yet implement:

- distributed consensus between nodes
- Byzantine fault tolerance
- network-level mutual TLS
- encrypted telemetry persistence at rest
- production device enrollment workflows

## 12. Current Prototype vs Production System

### Current Prototype

- local JSON-backed registry
- 3-node registry replication simulation
- hash-chained trust events
- device registration and revocation
- dashboard-driven demo flow
- real TCP socket demo
- unit tests for core security behavior

### Production-Inspired Future Work

- explicit consensus or quorum-based node agreement
- tamper recovery or divergence handling between replicas
- stronger operational key lifecycle controls
- persistent hospital telemetry storage pipeline
- richer audit trail and administrator tooling
