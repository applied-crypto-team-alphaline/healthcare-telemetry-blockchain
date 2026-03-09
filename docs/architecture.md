# System Architecture

## Overview
The system uses a hybrid architecture combining blockchain-based identity verification with off-chain encrypted peer-to-peer communication.

## Components

### Device A
A healthcare telemetry device that generates sensor data and sends telemetry messages.

### Device B
A receiver or monitoring system that verifies the sender and receives telemetry data.

### Blockchain Registry
A decentralized registry that stores device public keys and identity metadata.

### Peer-to-Peer Secure Channel
Devices establish encrypted communication channels after verifying each other's public keys.

## Communication Flow

1. Device generates a public/private key pair.
2. Device registers its public key on the blockchain registry.
3. A peer retrieves the public key from the blockchain.
4. Devices perform a key exchange to derive a shared session key.
5. Telemetry data is encrypted and transmitted over the peer-to-peer channel.

## Data Storage

### On-chain
- Device ID
- Public key
- Registration timestamp
- Device status

### Off-chain
- Telemetry data
- Session keys
- Sensor readings
