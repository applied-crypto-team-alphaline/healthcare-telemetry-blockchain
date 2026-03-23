from p2p.device_emulator import generate_telemetry


def test_telemetry_generation():
    data = generate_telemetry()
    assert "heart_rate" in data
    assert "sequence_number" in data