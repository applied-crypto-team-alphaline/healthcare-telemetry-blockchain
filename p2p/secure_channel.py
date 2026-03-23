import json
from blockchain.ledger import DeviceRegistry
from crypto.key_generation import generate_key_pair, serialize_public_key
from crypto.key_exchange import generate_x25519_keypair, derive_shared_secret, derive_session_key
from crypto.encryption import encrypt_message, decrypt_message
from p2p.device_emulator import generate_telemetry


# Replay protection store
seen_sequences = set()


def verify_device(registry, device_id):
    record = registry.lookup_device(device_id)
    if not record:
        print(f"{device_id} not found")
        return False
    if record["status"] != "active":
        print(f"{device_id} is revoked")
        return False
    return True


def demo_secure_communication():
    registry = DeviceRegistry()

    # STEP 1: Generate identities
    a_priv, a_pub = generate_key_pair()
    b_priv, b_pub = generate_key_pair()

    # STEP 2: Register devices
    registry.register_device("deviceA", serialize_public_key(a_pub))
    registry.register_device("deviceB", serialize_public_key(b_pub))

    # STEP 3: Verify devices
    if not verify_device(registry, "deviceA"):
        return
    if not verify_device(registry, "deviceB"):
        return

    # STEP 4: Key exchange
    a_kx_priv, a_kx_pub = generate_x25519_keypair()
    b_kx_priv, b_kx_pub = generate_x25519_keypair()

    shared_a = derive_shared_secret(a_kx_priv, b_kx_pub)
    shared_b = derive_shared_secret(b_kx_priv, a_kx_pub)

    session_key_a = derive_session_key(shared_a)
    session_key_b = derive_session_key(shared_b)

    # STEP 5: Send telemetry
    telemetry = generate_telemetry()
    seq = telemetry["sequence_number"]

    plaintext = json.dumps(telemetry)

    nonce, ciphertext = encrypt_message(session_key_a, plaintext)

    # STEP 6: Replay protection
    if seq in seen_sequences:
        print("Replay attack detected! Message rejected.")
        return
    else:
        seen_sequences.add(seq)

    decrypted = decrypt_message(session_key_b, nonce, ciphertext)

    print("\nOriginal telemetry:")
    print(plaintext)

    print("\nDecrypted telemetry:")
    print(decrypted)

    # STEP 7: Simulate replay attack
    print("\nSimulating replay attack...")
    if seq in seen_sequences:
        print("Replay attack detected! Blocked successfully.")

    # STEP 8: Revoke device
    registry.revoke_device("deviceA")

    print("\nAfter revocation:")
    if not verify_device(registry, "deviceA"):
        print("Communication blocked due to revocation")


if __name__ == "__main__":
    demo_secure_communication()