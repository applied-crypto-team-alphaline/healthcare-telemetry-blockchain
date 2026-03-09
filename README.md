# Blockchain-Assisted Peer-to-Peer Authentication for Secure Healthcare Telemetry

Team Member: Geethika Padamati, Zichen Fan

# Problem Statement
Healthcare telemetry systems are widely used to monitor patient conditions in hospitals, remote care environments, and wearable health devices. These systems continuously transmit sensitive medical data from sensors to monitoring platforms.
Traditionally, device authentication in such systems relies on centralized certificate authorities (CAs) to issue and validate device certificates. While this approach provides strong identity verification, it introduces several operational challenges. Certificate issuance, verification, and revocation become complicated when multiple vendors, organizations, and device types interact within the same healthcare network.
Additionally, centralized certificate infrastructures can introduce trust bottlenecks, administrative overhead, and delays in verifying device identities. In distributed healthcare environments where devices may be deployed across multiple institutions or vendors, managing certificates through a central authority can become inefficient.
This project explores a blockchain-assisted approach to device authentication. Instead of relying on a centralized certificate authority, each device generates its own cryptographic identity and registers its public key in a distributed blockchain registry. Devices verify each other’s identity directly through this registry before establishing a secure peer-to-peer communication channel.
By combining blockchain-based identity verification with encrypted peer-to-peer communication, this system aims to reduce certificate-management friction while maintaining strong security guarantees for healthcare telemetry.

# Proposal Summary
This project proposes a blockchain-assisted peer-to-peer authentication framework for secure healthcare telemetry. Instead of relying on centralized certificate authorities, each device generates its own cryptographic identity and registers its public key in a blockchain-based identity registry. Devices verify each other’s identities through this registry before establishing encrypted peer-to-peer communication channels. Sensitive telemetry data remains off-chain and is protected using authenticated encryption, while the blockchain stores only identity metadata such as public keys, timestamps, and revocation status. This architecture reduces certificate management complexity, increases transparency in trust, and demonstrates the application of modern cryptographic mechanisms to a real-world healthcare communication problem





