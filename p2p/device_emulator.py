import random
import time

sequence_number = 0


def generate_telemetry():
    global sequence_number
    sequence_number += 1
    return {
        "sequence_number": sequence_number,
        "heart_rate": random.randint(60, 100),
        "oxygen_level": random.randint(95, 100),
        "temperature": round(random.uniform(36.5, 37.5), 1),
        "timestamp": time.time()
    }


if __name__ == "__main__":
    for _ in range(3):
        print(generate_telemetry())
        time.sleep(1)
