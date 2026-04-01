import streamlit as st
import pandas as pd

from p2p.secure_channel import SecureChannel
from p2p.device_emulator import generate_telemetry, get_unique_devices


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
            color: #f8fafc;
        }

        .log-text {
            font-size: 0.86rem;
            color: #dbe4ee;
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
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------
# Session initialization
# -----------------------------
if "channel" not in st.session_state:
    st.session_state.channel = SecureChannel()
    st.session_state.channel.registry.reset_registry()

    all_devices = get_unique_devices()
    trusted_devices = all_devices[:20]
    gateway = "ICU_GATEWAY_01"
    trusted_devices.append(gateway)

    st.session_state.gateway = gateway
    st.session_state.trusted_devices = trusted_devices
    st.session_state.channel.register_trusted_devices(trusted_devices)
    st.session_state.results = []

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
            channel.send_secure(sender, receiver, telemetry)
            st.session_state.results.append({
                "status": "ACCEPTED",
                "device_id": sender,
                "patient_id": telemetry["patient_id"],
                "oxygen_level": telemetry["oxygen_level"],
                "heart_rate": telemetry["heart_rate"],
                "temperature": telemetry["temperature"],
                "reason": "Trusted device + CA verified + blockchain approved",
                "timestamp": telemetry["timestamp"],
                "action": telemetry["action"],
            })
        except Exception as e:
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
            Validates whether telemetry comes from trusted devices using a blockchain-backed registry,
            CA-signed certificates, secure channel establishment, replay protection, and revocation enforcement.
        </div>
        <div class="badge-row">
            <div class="badge badge-blue">Blockchain Registry</div>
            <div class="badge badge-purple">CA Verification</div>
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
- Devices must be registered on the blockchain-backed registry
- Devices must have valid CA-signed certificates
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

selected_revoke = st.sidebar.selectbox(
    "Trusted device to revoke",
    [d for d in trusted_devices if d != gateway]
)

if st.sidebar.button("Run telemetry validation"):
    process_rows(num_rows)
    st.rerun()

if st.sidebar.button("Revoke selected device"):
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
    trusted_devices = all_devices[:20]
    gateway = "ICU_GATEWAY_01"
    trusted_devices.append(gateway)

    st.session_state.gateway = gateway
    st.session_state.trusted_devices = trusted_devices
    st.session_state.channel.register_trusted_devices(trusted_devices)
    st.session_state.results = []
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Trusted devices registered:**")
st.sidebar.write(len(trusted_devices))

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
                <div class="pipe-title">2. CA Certificate</div>
                <div class="pipe-text">The device certificate is verified using the Certificate Authority.</div>
            </div>
            <div class="pipe-box">
                <div class="pipe-title">3. Blockchain Status</div>
                <div class="pipe-text">The blockchain-backed registry checks whether the device is trusted and active.</div>
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
# Blockchain device registry view
# -----------------------------
st.markdown('<div class="section-title">🔗 Blockchain Device Registry</div>', unsafe_allow_html=True)

registry_rows = []
for device in get_unique_devices()[:25]:
    registry_rows.append({
        "device_id": device,
        "registry_status": "Trusted" if device in trusted_devices else "Unknown / Unregistered"
    })

st.dataframe(pd.DataFrame(registry_rows), use_container_width=True)

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

    chart_df = accepted_chart_df.pivot_table(
        index="entry_number",
        columns="device_id",
        values="oxygen_level",
        aggfunc="last"
    )

    st.line_chart(chart_df, use_container_width=True)
    st.caption("Accepted telemetry only. Each line represents oxygen readings from trusted devices.")
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

st.info("Only telemetry from blockchain-registered, CA-certified devices is accepted. All others are rejected.")
st.markdown(
    '<div class="footer-note">This dashboard visualizes trusted telemetry validation using blockchain registry checks, CA certificate verification, secure channel enforcement, and attack rejection.</div>',
    unsafe_allow_html=True,
)