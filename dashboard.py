import streamlit as st
import pandas as pd
import altair as alt
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from blockchain.ledger import DeviceRegistry
from p2p.secure_channel import SecureChannel
from p2p.device_emulator import generate_telemetry, get_unique_devices

DEFAULT_TRUSTED_DEVICE_COUNT = 50


# -----------------------------
# Page config
# -----------------------------
st.set_page_config(
    page_title="Trusted Healthcare Telemetry Dashboard",
    page_icon="🔐",
    layout="wide",
)

# -----------------------------
# Custom styling
# -----------------------------
st.markdown(
    """
    <style>
        .main {
            background-color: #0b1220;
        }

        .hero {
            padding: 1.2rem 1.4rem;
            border-radius: 18px;
            background: linear-gradient(135deg, #111827 0%, #0f172a 60%, #111827 100%);
            border: 1px solid rgba(148, 163, 184, 0.18);
            box-shadow: 0 10px 30px rgba(0,0,0,0.25);
            margin-bottom: 1rem;
        }

        .hero-title {
            font-size: 2rem;
            font-weight: 800;
            color: #f8fafc;
            margin-bottom: 0.2rem;
        }

        .hero-subtitle {
            font-size: 0.98rem;
            color: #cbd5e1;
            margin-bottom: 0.8rem;
        }

        .badge-row {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.4rem;
        }

        .badge {
            padding: 0.35rem 0.65rem;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            border: 1px solid rgba(255,255,255,0.08);
        }

        .badge-blue { background: rgba(59,130,246,0.16); color: #bfdbfe; }
        .badge-green { background: rgba(34,197,94,0.16); color: #bbf7d0; }
        .badge-red { background: rgba(239,68,68,0.16); color: #fecaca; }
        .badge-purple { background: rgba(168,85,247,0.16); color: #e9d5ff; }

        .section-card {
            background: #111827;
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 16px;
            padding: 1rem;
            margin-bottom: 1rem;
        }

        .section-title {
            font-size: 1.1rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 0.4rem;
        }

        .pipeline {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.6rem;
            margin-top: 0.8rem;
        }

        .pipe-box {
            border-radius: 14px;
            padding: 0.8rem;
            min-height: 90px;
            border: 1px solid rgba(255,255,255,0.08);
            background: #0f172a;
        }

        .pipe-title {
            font-size: 0.9rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 0.3rem;
        }

        .pipe-text {
            font-size: 0.8rem;
            color: #cbd5e1;
            line-height: 1.35;
        }

        .metric-card {
            border-radius: 16px;
            padding: 1rem;
            color: white;
            border: 1px solid rgba(255,255,255,0.08);
            margin-bottom: 0.5rem;
        }

        .metric-blue {
            background: linear-gradient(135deg, #1d4ed8, #1e293b);
        }

        .metric-green {
            background: linear-gradient(135deg, #15803d, #1e293b);
        }

        .metric-red {
            background: linear-gradient(135deg, #b91c1c, #1e293b);
        }

        .metric-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .metric-value {
            font-size: 1.8rem;
            font-weight: 800;
            margin-top: 0.1rem;
        }

        .log-card {
            border-radius: 16px;
            padding: 0.9rem 1rem;
            margin-bottom: 0.7rem;
            border-left: 6px solid;
            background: #0f172a;
        }

        .accepted {
            border-left-color: #22c55e;
            background: rgba(34,197,94,0.08);
        }

        .rejected {
            border-left-color: #ef4444;
            background: rgba(239,68,68,0.08);
        }

        .log-title {
            font-weight: 800;
            font-size: 0.95rem;
            color: #0f172a;
        }

        .log-text {
            font-size: 0.86rem;
            color: #1e293b;
            line-height: 1.45;
        }

        .small-note {
            font-size: 0.84rem;
            color: #94a3b8;
        }

        .footer-note {
            font-size: 0.82rem;
            color: #94a3b8;
            margin-top: 0.3rem;
        }

        .accepted .log-title {
            color: #14532d;
        }

        .accepted .log-text {
            color: #166534;
        }

        .rejected .log-title {
            color: #7f1d1d;
        }

        .rejected .log-text {
            color: #991b1b;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------
# Session initialization
# -----------------------------
if "channel" not in st.session_state:
    st.session_state.channel = SecureChannel()
    st.session_state.gateway = "ICU_GATEWAY_01"
    st.session_state.trusted_devices = []
    st.session_state.results = []
    st.session_state.last_protocol = None
    st.session_state.last_p2p_demo = None
    st.session_state.last_tamper_demo = None

    if not st.session_state.channel.registry.list_devices():
        all_devices = get_unique_devices()
        trusted_devices = all_devices[:DEFAULT_TRUSTED_DEVICE_COUNT]
        gateway = st.session_state.gateway
        trusted_devices.append(gateway)
        st.session_state.trusted_devices = trusted_devices
        st.session_state.channel.register_trusted_devices(trusted_devices)
    else:
        st.session_state.trusted_devices = list(st.session_state.channel.registry.list_devices().keys())

channel = st.session_state.channel
gateway = st.session_state.gateway
trusted_devices = st.session_state.trusted_devices

# -----------------------------
# Helper
# -----------------------------
def process_rows(n: int):
    for _ in range(n):
        telemetry = generate_telemetry()
        sender = telemetry["device_id"]
        receiver = gateway

        try:
            result = channel.send_secure(sender, receiver, telemetry)
            st.session_state.last_protocol = result
            st.session_state.results.append({
                "status": "ACCEPTED",
                "device_id": sender,
                "patient_id": telemetry["patient_id"],
                "oxygen_level": telemetry["oxygen_level"],
                "heart_rate": telemetry["heart_rate"],
                "temperature": telemetry["temperature"],
                "reason": "Trusted device + signed authentication proof verified + registry approved",
                "timestamp": telemetry["timestamp"],
                "action": telemetry["action"],
            })
        except Exception as e:
            st.session_state.last_protocol = None
            st.session_state.results.append({
                "status": "REJECTED",
                "device_id": sender,
                "patient_id": telemetry["patient_id"],
                "oxygen_level": telemetry["oxygen_level"],
                "heart_rate": telemetry["heart_rate"],
                "temperature": telemetry["temperature"],
                "reason": str(e),
                "timestamp": telemetry["timestamp"],
                "action": telemetry["action"],
            })

def add_result(status, device_id, patient_id, oxygen_level, heart_rate, temperature, reason, timestamp, action):
    st.session_state.results.append({
        "status": status,
        "device_id": device_id,
        "patient_id": patient_id,
        "oxygen_level": oxygen_level,
        "heart_rate": heart_rate,
        "temperature": temperature,
        "reason": reason,
        "timestamp": timestamp,
        "action": action,
    })


def get_free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run_real_p2p_demo():
    temp_dir = tempfile.mkdtemp(prefix="p2p_demo_")
    registry_file = os.path.join(temp_dir, "registry.json")
    key_dir = os.path.join(temp_dir, "keys")
    port = get_free_port()

    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["P2P_REGISTRY_FILE"] = registry_file
    env["DEVICE_KEY_DIR"] = key_dir
    env["P2P_PORT"] = str(port)

    server = subprocess.Popen(
        [sys.executable, "p2p/device_b.py"],
        cwd=os.getcwd(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        time.sleep(1.0)
        client = subprocess.run(
            [sys.executable, "p2p/device_a.py"],
            cwd=os.getcwd(),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        server_stdout, server_stderr = server.communicate(timeout=5)
    finally:
        if server.poll() is None:
            server.terminate()

    if client.returncode != 0:
        raise RuntimeError(client.stderr.strip() or "Client demo failed")
    if server.returncode not in (0, None):
        raise RuntimeError(server_stderr.strip() or "Server demo failed")

    return {
        "client_output": json.loads(client.stdout),
        "server_output": server_stdout.strip(),
        "registry_file": registry_file,
    }


def run_tamper_demo():
    temp_dir = Path(tempfile.mkdtemp(prefix="tamper_demo_"))
    registry_file = temp_dir / "registry.json"
    node_paths = [temp_dir / "node1.json", temp_dir / "node2.json", temp_dir / "node3.json"]

    registry = DeviceRegistry(registry_file=registry_file, node_paths=node_paths)
    registry.reset_registry()

    source_events = channel.registry.list_events()
    if source_events:
        copied_registry = {"events": source_events}
        registry_file.write_text(json.dumps(copied_registry, indent=2), encoding="utf-8")
        for path in node_paths:
            path.write_text(json.dumps(copied_registry, indent=2), encoding="utf-8")
    else:
        registry.register_device("deviceA", "public-key-A")
        registry.revoke_device("deviceA")

    before_valid = registry.verify_chain()
    before_status = registry.get_replication_status()

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_event = tampered_data["events"][-1]
    original_status = tampered_event["status"]
    tampered_event["status"] = "active" if original_status != "active" else "revoked"
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    return {
        "tampered_field": {
            "node": "node1",
            "event_index": len(tampered_data["events"]) - 1,
            "field": "status",
            "from": original_status,
            "to": tampered_event["status"],
        },
        "before_valid": before_valid,
        "after_valid": registry.verify_chain(),
        "before_status": before_status,
        "after_status": registry.get_replication_status(),
        "registry_file": str(registry_file),
        "node1_file": str(node_paths[0]),
    }

# Auto-run on first load
if len(st.session_state.results) == 0:
    process_rows(10)

# -----------------------------
# Hero section
# -----------------------------
st.markdown(
    """
    <div class="hero">
        <div class="hero-title">🔐 Blockchain-Assisted Secure Healthcare Telemetry</div>
        <div class="hero-subtitle">
            Validates whether telemetry comes from trusted devices using a ledger-style registry,
            signed challenge-response authentication, secure channel establishment, replay protection,
            and revocation enforcement.
        </div>
        <div class="badge-row">
            <div class="badge badge-blue">Blockchain Registry</div>
            <div class="badge badge-purple">Signature Proof</div>
            <div class="badge badge-green">Secure Channel</div>
            <div class="badge badge-red">Threat Rejection</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.success("🟢 System Active: Secure Channel + Blockchain Trust Validation Running")

st.info(
    """
🔐 **Security Model**
- Devices must be registered in the ledger-style registry
- Devices must prove ownership of their registered private keys
- Secure channel protects telemetry in transit
- Replay protection blocks reused messages
- Revocation blocks compromised devices
"""
)

# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.header("⚙️ Control Panel")
st.sidebar.markdown("Use the controls below to simulate validation outcomes.")

num_rows = st.sidebar.slider("Rows to process", 1, 50, 10)

revocable_devices = [d for d in trusted_devices if d != gateway]
selected_revoke = st.sidebar.selectbox(
    "Trusted device to revoke",
    revocable_devices if revocable_devices else ["No trusted devices loaded"]
)

if st.sidebar.button("Run telemetry validation"):
    process_rows(num_rows)
    st.rerun()

if st.sidebar.button("Revoke selected device", disabled=not revocable_devices):
    channel.revoke_device(selected_revoke)
    st.sidebar.warning(f"{selected_revoke} has been revoked.")

if st.sidebar.button("Simulate Replay Attack"):
    try:
        telemetry = generate_telemetry()
        telemetry["device_id"] = trusted_devices[0]
        sender = telemetry["device_id"]

        channel.send_secure(sender, gateway, telemetry)
        channel.send_secure(sender, gateway, telemetry)
    except Exception as e:
        add_result(
            "REJECTED",
            sender,
            telemetry["patient_id"],
            telemetry["oxygen_level"],
            telemetry["heart_rate"],
            telemetry["temperature"],
            f"Replay blocked: {e}",
            telemetry["timestamp"],
            telemetry["action"],
        )
        st.sidebar.error(f"Replay Attack Detected: {e}")
        st.rerun()

if st.sidebar.button("Simulate Spoofing Attack"):
    telemetry = generate_telemetry()
    fake_sender = "HACKER_DEVICE"

    try:
        channel.send_secure(fake_sender, gateway, telemetry)
    except Exception as e:
        add_result(
            "REJECTED",
            fake_sender,
            telemetry["patient_id"],
            telemetry["oxygen_level"],
            telemetry["heart_rate"],
            telemetry["temperature"],
            f"Spoofing blocked: {e}",
            telemetry["timestamp"],
            telemetry["action"],
        )
        st.sidebar.error(f"Spoofing Blocked: {e}")
        st.rerun()

if st.sidebar.button("Reset demo"):
    st.session_state.channel = SecureChannel()
    st.session_state.channel.registry.reset_registry()

    all_devices = get_unique_devices()
    trusted_devices = all_devices[:DEFAULT_TRUSTED_DEVICE_COUNT]
    gateway = "ICU_GATEWAY_01"
    trusted_devices.append(gateway)

    st.session_state.gateway = gateway
    st.session_state.trusted_devices = trusted_devices
    st.session_state.channel.register_trusted_devices(trusted_devices)
    st.session_state.results = []
    st.session_state.last_protocol = None
    st.session_state.last_p2p_demo = None
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Trusted devices registered:**")
st.sidebar.write(len(trusted_devices))

if st.sidebar.button("Reset registry only"):
    st.session_state.channel.registry.reset_registry()
    st.session_state.trusted_devices = []
    st.session_state.results = []
    st.session_state.last_protocol = None
    st.session_state.last_p2p_demo = None
    st.sidebar.warning("Registry cleared. Use Reset demo to repopulate trusted devices.")
    st.rerun()

if st.sidebar.button("Run real P2P demo"):
    try:
        st.session_state.last_p2p_demo = run_real_p2p_demo()
        st.sidebar.success("Real P2P demo completed successfully.")
    except Exception as e:
        st.session_state.last_p2p_demo = {"error": str(e)}
        st.sidebar.error(f"P2P demo failed: {e}")
    st.rerun()

if st.sidebar.button("Run tamper-detection demo"):
    try:
        st.session_state.last_tamper_demo = run_tamper_demo()
        st.sidebar.success("Tamper-detection demo completed.")
    except Exception as e:
        st.session_state.last_tamper_demo = {"error": str(e)}
        st.sidebar.error(f"Tamper demo failed: {e}")
    st.rerun()

# -----------------------------
# Security pipeline
# -----------------------------
st.markdown(
    """
    <div class="section-card">
        <div class="section-title">🛡️ Security Validation Pipeline</div>
        <div class="small-note">Every telemetry row passes through this trust pipeline before acceptance.</div>
        <div class="pipeline">
            <div class="pipe-box">
                <div class="pipe-title">1. Device Identity</div>
                <div class="pipe-text">The sender device ID is extracted from the telemetry dataset row.</div>
            </div>
            <div class="pipe-box">
                <div class="pipe-title">2. Signature Proof</div>
                <div class="pipe-text">The sender signs a fresh challenge using its private key.</div>
            </div>
            <div class="pipe-box">
                <div class="pipe-title">3. Blockchain Status</div>
                <div class="pipe-text">The ledger-style registry checks whether the device is trusted and active.</div>
            </div>
            <div class="pipe-box">
                <div class="pipe-title">4. Secure Channel</div>
                <div class="pipe-text">A secure session is established before telemetry is transmitted.</div>
            </div>
            <div class="pipe-box">
                <div class="pipe-title">5. Final Decision</div>
                <div class="pipe-text">Telemetry is accepted only if trust, freshness, and security checks all pass.</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# -----------------------------
# Protocol evidence
# -----------------------------
st.markdown('<div class="section-title">🔍 Latest Protocol Evidence</div>', unsafe_allow_html=True)

protocol = st.session_state.last_protocol
if protocol is None:
    st.info("Run telemetry validation to inspect the latest authentication and encryption evidence.")
else:
    auth_col, session_col, enc_col = st.columns(3)

    with auth_col:
        st.markdown("**Authentication**")
        st.json(protocol["authentication"])

    with session_col:
        st.markdown("**Session Establishment**")
        st.json(protocol["session_establishment"])

    with enc_col:
        st.markdown("**Encryption**")
        st.json(protocol["encryption"])

st.markdown("---")

# -----------------------------
# Blockchain device registry view
# -----------------------------
st.markdown('<div class="section-title">🔗 Device Registry</div>', unsafe_allow_html=True)

registry_rows = []
for device, record in channel.registry.list_devices().items():
    registry_rows.append({
        "device_id": device,
        "registry_status": record["status"],
        "public_key": record["public_key"][:16] + "...",
        "updated_at": record["timestamp"],
    })

st.dataframe(pd.DataFrame(registry_rows), use_container_width=True)

st.markdown("---")

# -----------------------------
# Ledger events
# -----------------------------
st.markdown('<div class="section-title">📜 Ledger Events</div>', unsafe_allow_html=True)
events = channel.registry.list_events()
if events:
    st.dataframe(pd.DataFrame(events[-10:]), use_container_width=True)
else:
    st.info("No ledger events yet.")

st.markdown("---")

st.markdown('<div class="section-title">🧩 Registry Node Status</div>', unsafe_allow_html=True)
node_status = channel.registry.get_replication_status()
st.dataframe(pd.DataFrame(node_status), use_container_width=True)

st.markdown("---")

st.markdown('<div class="section-title">🌐 Real P2P Demo</div>', unsafe_allow_html=True)
p2p_demo = st.session_state.last_p2p_demo
if p2p_demo is None:
    st.info("Use the sidebar to run the real socket-based peer-to-peer demo.")
elif "error" in p2p_demo:
    st.error(p2p_demo["error"])
else:
    p2p_left, p2p_right = st.columns(2)
    with p2p_left:
        st.markdown("**Client Output**")
        st.json(p2p_demo["client_output"])
    with p2p_right:
        st.markdown("**Server Output**")
        st.code(p2p_demo["server_output"] or "[SERVER] completed", language="text")

st.markdown("---")

st.markdown('<div class="section-title">🧪 Ledger Tamper Detection</div>', unsafe_allow_html=True)
tamper_demo = st.session_state.last_tamper_demo
if tamper_demo is None:
    st.info("Use the sidebar to run a ledger tamper-detection demo without modifying the main dashboard registry.")
elif "error" in tamper_demo:
    st.error(tamper_demo["error"])
else:
    tamper_left, tamper_right = st.columns(2)
    with tamper_left:
        st.markdown("**Tamper Summary**")
        st.json(
            {
                "chain_valid_before_tampering": tamper_demo["before_valid"],
                "chain_valid_after_tampering": tamper_demo["after_valid"],
                "tampered_field": tamper_demo["tampered_field"],
            }
        )
    with tamper_right:
        st.markdown("**Replication Status**")
        st.write("Before tampering")
        st.dataframe(pd.DataFrame(tamper_demo["before_status"]), use_container_width=True)
        st.write("After tampering")
        st.dataframe(pd.DataFrame(tamper_demo["after_status"]), use_container_width=True)

    st.caption(
        f"Demo files: registry={tamper_demo['registry_file']} | tampered node copy={tamper_demo['node1_file']}"
    )

st.markdown("---")

# -----------------------------
# Results DataFrame
# -----------------------------
results = st.session_state.results
df = pd.DataFrame(results) if results else pd.DataFrame(
    columns=[
        "status", "device_id", "patient_id", "oxygen_level",
        "heart_rate", "temperature", "reason", "timestamp", "action"
    ]
)

accepted_count = len(df[df["status"] == "ACCEPTED"]) if not df.empty else 0
rejected_count = len(df[df["status"] == "REJECTED"]) if not df.empty else 0
total_count = len(df)

# -----------------------------
# Metrics
# -----------------------------
m1, m2, m3 = st.columns(3)

with m1:
    st.markdown(
        f"""
        <div class="metric-card metric-blue">
            <div class="metric-label">Total Processed</div>
            <div class="metric-value">{total_count}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with m2:
    st.markdown(
        f"""
        <div class="metric-card metric-green">
            <div class="metric-label">Accepted</div>
            <div class="metric-value">{accepted_count}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with m3:
    st.markdown(
        f"""
        <div class="metric-card metric-red">
            <div class="metric-label">Rejected</div>
            <div class="metric-value">{rejected_count}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------
# Accepted / Rejected
# -----------------------------
left, right = st.columns(2)

with left:
    st.markdown('<div class="section-title">✅ Accepted Telemetry</div>', unsafe_allow_html=True)
    accepted_df = df[df["status"] == "ACCEPTED"] if not df.empty else pd.DataFrame()

    if accepted_df.empty:
        st.info("No accepted telemetry yet.")
    else:
        for _, row in accepted_df.tail(8).iterrows():
            st.markdown(
                f"""
                <div class="log-card accepted">
                    <div class="log-title">Device {row['device_id']} · Patient {row['patient_id']}</div>
                    <div class="log-text">
                        Oxygen: <b>{row['oxygen_level']}%</b><br>
                        Heart Rate: {row['heart_rate']} bpm<br>
                        Temperature: {row['temperature']} °C<br>
                        Action: {row['action']}<br>
                        Reason: {row['reason']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if row["oxygen_level"] < 90:
                st.warning(f"⚠ Low Oxygen Alert for {row['patient_id']}: {row['oxygen_level']}%")

with right:
    st.markdown('<div class="section-title">❌ Rejected Telemetry</div>', unsafe_allow_html=True)
    rejected_df = df[df["status"] == "REJECTED"] if not df.empty else pd.DataFrame()

    if rejected_df.empty:
        st.info("No rejected telemetry yet.")
    else:
        for _, row in rejected_df.tail(8).iterrows():
            st.markdown(
                f"""
                <div class="log-card rejected">
                    <div class="log-title">Device {row['device_id']} · Patient {row['patient_id']}</div>
                    <div class="log-text">
                        Oxygen: <b>{row['oxygen_level']}%</b><br>
                        Heart Rate: {row['heart_rate']} bpm<br>
                        Temperature: {row['temperature']} °C<br>
                        Action: {row['action']}<br>
                        Reason: {row['reason']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

st.markdown("---")

# -----------------------------
# Oxygen chart
# -----------------------------
st.markdown('<div class="section-title">📈 Oxygen Trend (Accepted Telemetry Only)</div>', unsafe_allow_html=True)
st.warning("⚠ Only trusted device telemetry is used for clinical insights")

if not df.empty and accepted_count > 0:
    accepted_chart_df = accepted_df[["device_id", "oxygen_level"]].copy()
    accepted_chart_df["entry_number"] = range(1, len(accepted_chart_df) + 1)
    chart = (
        alt.Chart(accepted_chart_df)
        .mark_line(point=True, strokeWidth=3)
        .encode(
            x=alt.X("entry_number:Q", title="Accepted Reading #"),
            y=alt.Y("oxygen_level:Q", title="Oxygen Level (%)", scale=alt.Scale(domain=[85, 100])),
            color=alt.Color(
                "device_id:N",
                title="Device",
                scale=alt.Scale(
                    range=[
                        "#1d4ed8",
                        "#dc2626",
                        "#15803d",
                        "#b45309",
                        "#7c3aed",
                        "#0891b2",
                    ]
                ),
            ),
            tooltip=["device_id", "entry_number", "oxygen_level"],
        )
        .properties(height=320)
    )
    st.altair_chart(chart, use_container_width=True)
    st.caption("Accepted telemetry only. Colored lines show oxygen readings from trusted devices.")
else:
    st.info("Run telemetry validation to view oxygen trends.")

st.markdown("---")

# -----------------------------
# Full log
# -----------------------------
st.markdown('<div class="section-title">📋 Full Validation Log</div>', unsafe_allow_html=True)

if df.empty:
    st.info("No validation results yet.")
else:
    st.dataframe(df, use_container_width=True)

st.info("Only telemetry from blockchain-registered devices with valid signature proofs is accepted. All others are rejected.")
st.markdown(
    '<div class="footer-note">This dashboard visualizes trusted telemetry validation using registry-based public keys, signed challenge-response authentication, secure channel enforcement, and attack rejection.</div>',
    unsafe_allow_html=True,
)
