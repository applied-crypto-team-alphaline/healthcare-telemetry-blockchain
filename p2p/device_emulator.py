import csv
from pathlib import Path

sequence_number = 0
index = 0


DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "healthcare_iot.csv"


def load_dataset():
    with open(DATASET_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


dataset = load_dataset()


def generate_telemetry():
    global index, sequence_number

    row = dataset[index % len(dataset)]
    index += 1
    sequence_number += 1

    telemetry = {
        "patient_id": row["Patient ID"],
        "device_id": row["Device ID"],
        "sequence_number": sequence_number,
        "heart_rate": int(float(row["Heart Rate (bpm)"])),
        "oxygen_level": int(float(row["oxygen_level"])),
        "temperature": float(row["Temperature (°C)"]),
        "blood_pressure": row["Blood Pressure (mmHg)"],
        "timestamp": row["Timestamp"],
        "ip_address": row["IP Address"],
        "access_type": row["Access Type"],
        "action": row["Action"],
        "target": int(row["Target"]),
    }

    return telemetry


def get_unique_devices():
    return sorted({row["Device ID"] for row in dataset})


if __name__ == "__main__":
    print("Unique devices:", len(get_unique_devices()))
    for _ in range(3):
        print(generate_telemetry())
