# Attack Write-Up: Device ID Key Takeover

## Vulnerability Summary

The original onboarding helper allowed an active device identity to be silently rebound to a different public key if another actor claimed the same `device_id` with a different local key store.

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

As a result, a second actor could generate a new key pair and overwrite the trusted binding for an existing active device ID.

## Reproduction Steps

Original exploit run:

```bash
python3 attack_key_takeover.py
```

Before the patch, the expected outcome was:

- the original registry key ID for `deviceA` is shown
- a different attacker-controlled key ID replaces it
- telemetry signed by the attacker is accepted as `deviceA`

## Mitigation

The mitigation changes `ensure_registered_identity()` so that:

- new device IDs can still be registered
- an already-bound active device ID remains valid only for the same key
- a different key for an active device ID is rejected
- a revoked device ID cannot self-reenroll without explicit admin action

## Post-Patch Verification

Re-run:

```bash
python3 attack_key_takeover.py
```

Expected post-patch outcome:

- `registry_key_changed` is `false`
- `attack_blocked` is `true`
- `failure_reason` indicates that the device ID is already bound to a different active key

## Evidence

Example evidence fields produced by the post-patch rerun:

- `original_key_id`
- `final_key_id`
- `registry_key_changed: false`
- `attack_blocked: true`
- `failure_reason: "deviceA is already bound to a different active key"`
- `impact: "key takeover prevented; attacker cannot replace active deviceA key"`

## Regression Test

The regression test that captures the vulnerability is:

- `tests/test_attack_key_takeover.py`

It now verifies the mitigation by:

1. registering a legitimate `deviceA`
2. generating a second identity for the same `device_id`
3. attempting to rebind the active device with a different key
4. confirming that the rebind is rejected and the original registry key remains unchanged
