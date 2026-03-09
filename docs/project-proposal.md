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

Healthcare telemetry devices continuously transmit sensor data to backend systems. Traditional security architectures rely on centralized certificate authorities for device authentication, which introduces trust bottlenecks and management overhead. In environments where multiple vendors and devices interact, certificate management can become complex and slow.

This project proposes a decentralized authentication model using blockchain as a public key registry. Each device generates its own key pair and registers its public key on a blockchain network. Peers verify device identities using the blockchain before establishing encrypted peer-to-peer communication channels for telemetry exchange.

---

## Candidate 2: Lightweight Authentication Protocol for Healthcare IoT Devices

Healthcare IoT devices often operate in resource-constrained environments where heavy cryptographic protocols may not be efficient. Designing a lightweight authentication protocol could help reduce computational overhead while maintaining strong security guarantees.

This project would design and evaluate a lightweight authentication mechanism using elliptic curve cryptography to secure communication between healthcare devices and monitoring systems. The focus would be on minimizing latency and resource usage while preventing attacks such as replay, impersonation, and man-in-the-middle attacks.

---

# Chosen Project Direction

We selected the **Blockchain-Assisted Peer-to-Peer Authentication for Secure Healthcare Telemetry** approach because it addresses real-world challenges in identity management and trust verification for healthcare devices. Instead of relying on centralized certificate authorities, devices register their public keys on a blockchain network where identities can be verified transparently.

This approach reduces trust friction between vendors, enables decentralized identity verification, and supports secure peer-to-peer encrypted communication between devices. The project demonstrates the practical application of public key cryptography and blockchain-based identity verification in a healthcare communication system.
