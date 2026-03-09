# Key Lifecycle Plan

## Key Generation
Each device generates a public/private key pair locally using a secure cryptographic library.

## Key Storage
Private keys are stored securely on the device and never exposed publicly. Public keys are stored on the blockchain registry.

## Key Registration
Devices publish their public keys to the blockchain during initial registration.

## Key Usage
Public keys are used to verify device identity and establish secure communication channels.

## Key Rotation
Devices may generate new key pairs and update the blockchain registry while deactivating old keys.

Example:

Keys are rotated periodically, such as every 6 or 12 months.
Keys must also be rotated immediately after suspected compromise or device reset.

## Compromise Handling
If a device's private key is compromised, its public key is marked as revoked in the blockchain registry.
