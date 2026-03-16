## Proposal v1 — Blockchain-Assisted Peer-to-Peer Authentication for Secure Healthcare Telemetry

Course: Applied Cryptography

Team:

- Geethika Padamati — Project Manager & Security Lead
- Zichen Fan — Development Lead & Test Lead

### 1) Problem Statement

    Healthcare telemetry systems transmit continuous sensor data (e.g., heart rate, SpO₂, blood pressure) from medical/IoT devices to monitoring systems. Security is critical because attackers can (i) impersonate devices, (ii) inject falsified measurements, (iii) eavesdrop on sensitive data, or (iv) replay old readings to hide anomalies.

    Traditional approaches authenticate devices using centralized Certificate Authorities (CAs). While effective, multi-vendor environments introduce operational friction: certificate issuance/rotation, revocation handling, and cross-organization trust management can become bottlenecks.

    Goal: Build a prototype that uses a tamper-evident append-only ledger (“blockchain-style registry”) as a distributed public-key registry. Devices register identity keys on the ledger; peers query the ledger to verify identities and revocation status before establishing a secure encrypted channel for telemetry transfer.

### 2) Stakeholders

    Healthcare providers: need reliable, authenticated telemetry for patient monitoring

    Device manufacturers: need device identity protection and anti-impersonation guarantees

    Patients: benefit from confidentiality and integrity of telemetry

    System administrators: need transparent registration/revocation and auditable device identity state

### 3) Why Cryptography is Required

    Authentication: public-key signatures bind messages/handshakes to device identity

    Confidentiality: encryption prevents unauthorized access to telemetry

    Integrity: authenticated encryption prevents undetected tampering

    Secure key establishment: ECDH derives session keys over untrusted networks

    Revocation: cryptographic identity lifecycle support (deny revoked devices)

### 4) Approach (High-Level Design)

    4.1 Ledger-Assisted Identity Registry
    We implement a simplified permissioned ledger (hash-chained blocks) storing device identity records: device_id → public_key, status(active/revoked), timestamp, ledger_proof

    4.2 Authenticated Session Establishment
    - Devices fetch peer public keys from the ledger and verify status = active
    - Devices perform an authenticated handshake (signed challenge/response)
    - Devices run ECDH to derive a shared session key

    4.3 Encrypted Telemetry Transmission

    Telemetry messages are sent over a peer-to-peer channel using authenticated encryption (AEAD). Each message includes {device_id, ts, seq, payload} and is protected with AEAD; seq/ts support replay detection.

### 5) Minimum Viable Product (MVP)

    MVP Components

    1. Device identity generation: each emulator generates keypairs
    2. Ledger registry service: register/lookup/revoke + hash-chained log
    3. Identity verification: peers query ledger and verify active status
    4. Secure session: authenticated handshake + ECDH session key
    5. Encrypted telemetry: AEAD-protected telemetry stream
    6. Revocation: revoked identities are rejected
    7. Telemetry emulator: “live stream” from dataset replay (no hardware)

    Measurable Success Criteria
    - A device can generate identity keys and register in the ledger
    - A peer can lookup and verify another device’s key and active status 
    - Two devices can establish a shared session key via ECDH
    - Telemetry is transmitted encrypted; tampering is detected (verification fails)
    - Replay attempts are rejected (seq/ts window)
    - Revoked device identity cannot establish a session
    - A demo shows real-time telemetry replay and security enforcement

### 6) Non-Goals and Scope Boundaries

    - No production blockchain network / consensus protocol
    - No real medical devices / hardware integration
    - No custom cryptographic primitives (use vetted libraries only)
    - No hospital EHR integration / HIPAA system deployment
    - No large-scale PKI infrastructure or enterprise identity management
    - No advanced anonymity / privacy techniques (e.g., ZK proofs)

    Scope Boundaries
    - Two to four software device emulators only
    - Permissioned ledger implemented as a single service with hash-chained integrity
    - Focus on applied crypto mechanisms: signatures, ECDH, AEAD, replay defense, revocation

### 7) Risk Register (Top-5)

    1. Ledger complexity / scope creep → Use hash-chained append-only log; no consensus
    2. Crypto implementation errors → Use established libraries (PyNaCl / cryptography)
    3. Revocation semantics unclear → Define revoke record + “latest status wins” rule
    4. Replay handling edge cases → Use per-device monotonic seq + server cache window
    5. Demo instability/perf issues → Keep protocol minimal; add deterministic test scripts

### 8) Demo Plan

    1. Device A/B generate keys and register in ledger
    2. A looks up B; verifies key + active status
    3. A↔B signed handshake + ECDH → session key
    4. A streams encrypted telemetry (dataset replay) to B
    5. Attacks: (i) unregistered device, (ii) tampered ciphertext, (iii) replay, (iv) revoked device → all rejected