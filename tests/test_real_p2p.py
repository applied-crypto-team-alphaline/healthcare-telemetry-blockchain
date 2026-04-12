import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from blockchain.ledger import DeviceRegistry
from p2p.device_identity import ensure_registered_identity


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_free_port():
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
    except PermissionError:
        sock.close()
        pytest.skip("Socket bind is not permitted in this environment")
    port = sock.getsockname()[1]
    sock.close()
    return port


def build_env(tmp_path, port, extra_env=None):
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(PROJECT_ROOT),
            "P2P_HOST": "127.0.0.1",
            "P2P_PORT": str(port),
            "P2P_REGISTRY_FILE": str(tmp_path / "registry.json"),
            "DEVICE_KEY_DIR": str(tmp_path / "keys"),
            "P2P_DEVICE_ID": "deviceA",
            "P2P_RECEIVER_ID": "ICU_GATEWAY_01",
        }
    )
    if extra_env:
        env.update(extra_env)
    return env


def run_p2p_pair(tmp_path, env):
    server = subprocess.Popen(
        [sys.executable, "p2p/device_b.py"],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(0.5)
        client = subprocess.run(
            [sys.executable, "p2p/device_a.py"],
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        server_stdout, server_stderr = server.communicate(timeout=5)
    finally:
        if server.poll() is None:
            server.terminate()

    return client, server.returncode, server_stdout, server_stderr


def parse_client_output(stdout):
    return json.loads(stdout) if stdout.strip() else None


def test_real_p2p_rejects_revoked_device(tmp_path):
    port = get_free_port()
    env = build_env(tmp_path, port)

    registry = DeviceRegistry(registry_file=tmp_path / "registry.json")
    ensure_registered_identity("deviceA", registry)
    ensure_registered_identity("ICU_GATEWAY_01", registry)
    registry.revoke_device("deviceA")

    client, server_returncode, _, server_stderr = run_p2p_pair(tmp_path, env)

    assert client.returncode == 0
    assert server_returncode == 0, server_stderr
    assert parse_client_output(client.stdout) == {
        "status": "rejected",
        "error": "ERR_DEVICE_REVOKED",
    }


def test_real_p2p_rejects_invalid_signature(tmp_path):
    port = get_free_port()
    env = build_env(tmp_path, port, {"P2P_TAMPER_SIGNATURE": "1"})

    registry = DeviceRegistry(registry_file=tmp_path / "registry.json")
    ensure_registered_identity("deviceA", registry)
    ensure_registered_identity("ICU_GATEWAY_01", registry)

    client, server_returncode, _, server_stderr = run_p2p_pair(tmp_path, env)

    assert client.returncode == 0
    assert server_returncode == 0, server_stderr
    assert parse_client_output(client.stdout) == {
        "status": "rejected",
        "error": "ERR_AUTH_PROOF_FAILED",
    }
