# MVP Runbook

## Goal

This runbook defines the minimum steps to demonstrate the MVP security property:

- only trusted and active devices are accepted
- device identity is verified before telemetry is processed
- telemetry is encrypted in transit
- replayed or revoked senders are rejected
- registry tampering is detectable

## Environment Assumptions

- Python 3.8+ is available
- dependencies are installed:
  - `cryptography`
  - `streamlit`
  - `pandas`
  - `altair`
  - `pytest`
- the working directory is the repository root
- local socket binding is available if the real P2P demo is used

Optional environment variables:

- `DEVICE_KEY_DIR`
  directory for locally persisted device identities
- `P2P_REGISTRY_FILE`
  registry file used by the real socket-based P2P demo
- `P2P_PORT`
  TCP port used by the real socket-based P2P demo
- `AUDIT_LOG_FILE`
  JSONL audit log file for security-relevant runtime events

## Pre-Demo Validation

Run the test suite:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
```

Expected result:

- unit and integration tests pass
- real socket tests may skip in restricted environments that do not allow local socket bind

## Happy Path Demo

Recommended live demo:

```bash
python3 -m streamlit run dashboard.py
```

Suggested flow:

1. show accepted telemetry and latest protocol evidence
2. show registry contents, ledger events, and 3-node status
3. run the real P2P demo from the sidebar
4. run replay and spoofing simulations
5. run the tamper-detection demo

## Manual Real P2P Demo

Terminal 1:

```bash
DEMO_DIR=/tmp/healthcare_p2p_demo_run1
P2P_REGISTRY_FILE=$DEMO_DIR/p2p_registry.json \
DEVICE_KEY_DIR=$DEMO_DIR/p2p_keys \
AUDIT_LOG_FILE=$DEMO_DIR/security_audit.log \
P2P_PORT=5001 \
python3 p2p/device_b.py
```

Terminal 2:

```bash
DEMO_DIR=/tmp/healthcare_p2p_demo_run1
P2P_REGISTRY_FILE=$DEMO_DIR/p2p_registry.json \
DEVICE_KEY_DIR=$DEMO_DIR/p2p_keys \
AUDIT_LOG_FILE=$DEMO_DIR/security_audit.log \
P2P_PORT=5001 \
python3 p2p/device_a.py
```

Expected happy-path result:

- sender is authenticated
- telemetry is decrypted and accepted
- audit entries are written for identity load/create, authentication, and accepted telemetry

## Tamper Detection Demo

```bash
python3 tamper_demo.py
```

Expected result:

- chain verification passes before tampering
- chain verification fails after tampering
- node replication status shows mismatch

## Audit Log

The audit log is written as JSON lines.

Default file:

```text
security_audit.log
```

Example event types:

- `identity_created`
- `identity_loaded`
- `device_registered`
- `device_revoked`
- `authentication_succeeded`
- `authentication_failed`
- `replay_detected`
- `telemetry_accepted`

Logged fields may include:

- `device_id`
- `sender`
- `receiver`
- `sequence_number`
- `reason`
- `key_id`
- `key_version`

## MVP Submission Note

For the final demo, use a clean dependency environment, a fresh `DEMO_DIR`, and the same commit for the README, report, and live run.
