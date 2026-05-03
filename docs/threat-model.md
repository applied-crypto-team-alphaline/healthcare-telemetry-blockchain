# Threat Model

## System Overview
Healthcare telemetry systems involve devices that continuously transmit sensor data to monitoring systems. These systems must ensure that data originates from legitimate devices and that the communication channel is secure.

## Threats Considered

### Device Spoofing
An attacker may attempt to impersonate a legitimate healthcare device and inject false telemetry data.

### Man-in-the-Middle Attacks
An attacker intercepts communication between two devices and modifies or observes transmitted data.

### Replay Attacks
An attacker replays previously captured telemetry messages to manipulate monitoring systems.

### Data Exposure
Sensitive telemetry data could be intercepted if communication is not properly encrypted.

### Compromised Device Identity
A device's private key could be compromised, allowing attackers to impersonate the device.

### Registry Key Rebinding / Ownership Takeover
An attacker may try to claim an existing trusted `device_id` with a different public key and replace the active registry binding.

## Security Goals

- Authenticate devices before communication
- Ensure confidentiality of telemetry data
- Ensure integrity of transmitted data
- Prevent replay attacks
- Allow compromised devices to be revoked
- Prevent silent replacement of active device-to-key bindings

## Final Mitigation Notes

The final design enforces these identity-binding rules:

- a new `device_id` may be registered once
- an already active `device_id` may continue only with the same public key
- a different public key for an active `device_id` is rejected
- a revoked `device_id` requires explicit admin-controlled re-enrollment
