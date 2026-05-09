# Project Proposal

## Project Title
Blockchain-Assisted Peer-to-Peer Authentication for Secure Healthcare Telemetry

## Team Members and Roles

Geethika Padamati — Project Manager & Security Lead  
Responsible for project coordination, threat modeling, cryptographic design, and blockchain trust architecture.

Zichen Fan — Development Lead & Test Lead  
Responsible for system implementation, peer-to-peer communication module, telemetry emulator, and performance testing.

---

# Candidate Project Ideas

## Candidate 1: Blockchain-Assisted Peer-to-Peer Authentication for Healthcare Telemetry

Healthcare telemetry devices continuously transmit sensor data to backend systems. Traditional security architectures often rely on centralized certificate authorities or manual trust provisioning for device authentication, which introduces trust bottlenecks and management overhead.

This project proposes a registry-based authentication model. Each simulated device generates its own key pair, registers its public key in a ledger-style registry, proves private-key possession through signed challenge-response, and then establishes an encrypted peer-to-peer channel for telemetry exchange.

---

## Candidate 2: Lightweight Authentication Protocol for Healthcare IoT Devices

Healthcare IoT devices often operate in resource-constrained environments where heavy cryptographic protocols may not be efficient. Designing a lightweight authentication protocol could help reduce computational overhead while maintaining strong security guarantees.

This project would design and evaluate a lightweight authentication mechanism using elliptic curve cryptography to secure communication between healthcare devices and monitoring systems. The focus would be on minimizing latency and resource usage while preventing attacks such as replay, impersonation, and man-in-the-middle attacks.

---

# Chosen Project Direction

We selected the **Ledger-Style Peer-to-Peer Authentication for Secure Healthcare Telemetry** approach because it addresses real-world challenges in identity management and trust verification for healthcare devices. Instead of relying on centralized certificate authorities during communication, devices register their public keys in a ledger-style registry where identities and revocation state can be verified transparently.

This approach reduces trust friction between vendors, enables transparent public-key verification, and supports secure peer-to-peer encrypted communication between devices. The project demonstrates the practical application of digital signatures, key agreement, authenticated encryption, and ledger-style identity management in a healthcare communication system.
