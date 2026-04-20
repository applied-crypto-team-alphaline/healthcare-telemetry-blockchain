import hashlib
import json
import os
import time
from pathlib import Path


DEFAULT_AUDIT_LOG_FILE = "security_audit.log"


def get_audit_log_path() -> Path:
    return Path(os.environ.get("AUDIT_LOG_FILE", DEFAULT_AUDIT_LOG_FILE))


def key_id_from_public_key(public_key_hex: str) -> str:
    return hashlib.sha256(public_key_hex.encode("utf-8")).hexdigest()[:16]


def record_security_event(event_type: str, **fields):
    log_path = get_audit_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "audit_version": "v1",
    }
    entry.update(fields)

    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
