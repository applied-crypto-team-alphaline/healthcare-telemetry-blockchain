# Attack Write-Up: Device ID Key Takeover

## Vulnerability Summary

The current onboarding helper allows an active device identity to be silently rebound to a different public key if another actor claims the same `device_id` with a different local key store.

This affects:

- `p2p/device_identity.py`
- specifically `ensure_registered_identity()`

## Impact

An attacker can impersonate a trusted telemetry device without revoking the original device first.

Meaningful security impact:

- trusted `device_id` ownership can be overwritten
- the receiver will verify signatures against the attacker-controlled replacement key
- attacker telemetry is accepted as if it came from the legitimate device

This is aligned with a realistic threat model:

- weak device onboarding policy
- writable shared registry baseline
- internal attacker or compromised client process

## Root Cause

The vulnerable logic is:

```python
if record is None:
    registry.register_device(device_id, identity["public_key"])
elif record["public_key"] != identity["public_key"] and record["status"] == "active":
    registry.register_device(device_id, identity["public_key"])
```

Technical root cause:

- device identity ownership is not immutable while active
- no authorization step is required before replacing the registry public key
- the latest registration event wins, even if it comes from a different key pair

As a result, a second actor can generate a new key pair and overwrite the trusted binding for an existing active device ID.

## Reproduction Steps

Run:

```bash
python attack_key_takeover.py
```

Expected outcome:

- the original registry key ID for `deviceA` is shown
- a different attacker-controlled key ID replaces it
- telemetry signed by the attacker is accepted as `deviceA`

## Evidence

Example evidence fields produced by the attack script:

- `original_key_id`
- `attacker_key_id`
- `registry_key_changed: true`
- `accepted_sender: "deviceA"`
- `signature_verified: true`
- `impact: "attacker telemetry accepted as trusted deviceA"`

## Regression Test

The regression test that captures the vulnerability is:

- `tests/test_attack_key_takeover.py`

It reliably reproduces the issue by:

1. registering a legitimate `deviceA`
2. generating a second identity for the same `device_id`
3. silently rebinding the active registry entry
4. successfully sending accepted telemetry as `deviceA`
