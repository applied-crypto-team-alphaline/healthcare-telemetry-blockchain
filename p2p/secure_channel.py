import json
from blockchain.ledger import DeviceRegistry
from crypto.key_generation import generate_key_pair, serialize_public_key
from crypto.key_exchange import generate_x25519_keypair, derive_shared_secret, derive_session_key
from crypto.encryption import encrypt_message, decrypt_message
from p2p.device_emulator import generate_telemetry


def demo_secure_communication():
    registry = DeviceRegistry()

    # Step 1: create identities
    a_private_id, a_public_id = generate_key_pair()
    b_private_id, b_public_id = generate_key_pair()

    # Step 2: register devices in registry
    registry.register_device("deviceA", serialize_public_key(a_public_id))
    registry.register_device("deviceB", serialize_public_key(b_public_id))

    # Step 3: verify devices
    record_a = registry.lookup_device("deviceA")
    record_b = registry.lookup_device("deviceB")

    if not record_a or record_a["status"] != "active":
        print("deviceA is not valid")
        return

    if not record_b or record_b["status"] != "active":
        print("deviceB is not valid")
        return

    # Step 4: perform key exchange
    a_kx_priv, a_kx_pub = generate_x25519_keypair()
    b_kx_priv, b_kx_pub = generate_x25519_keypair()

    shared_a = derive_shared_secret(a_kx_priv, b_kx_pub)
    shared_b = derive_shared_secret(b_kx_priv, a_kx_pub)

    session_key_a = derive_session_key(shared_a)
    session_key_b = derive_session_key(shared_b)

    # Step 5: generate telemetry
    telemetry = generate_telemetry()
    plaintext = json.dumps(telemetry)

    # Step 6: encrypt and decrypt
    nonce, ciphertext = encrypt_message(session_key_a, plaintext)
    decrypted = decrypt_message(session_key_b, nonce, ciphertext)

    print("Original telemetry:")
    print(plaintext)
    print("\nDecrypted telemetry:")
    print(decrypted)

    # Step 7: revoke a device and test
    registry.revoke_device("deviceA")
    revoked_record = registry.lookup_device("deviceA")
    print("\nDeviceA status after revocation:", revoked_record["status"])


if __name__ == "__main__":
    demo_secure_communication()