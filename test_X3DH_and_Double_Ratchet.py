"""
Test for X3DH and Double Ratchet
"""

from X3DH import Alice, Bob
from Double_Ratchet import DoubleRatchetSession


def main() -> None:

    """Demonstrate an X3DH handshake between two parties."""

    bob = Bob()
    bundle = bob.get_prekey_bundle()

    alice = Alice()
    # Bob publishes their bundle; Alice loads and verifies it
    # Alice starts handshake
    initial_message, alice_ss, alice_ephemeral_private_key = alice.initiate_handshake(bundle)

    # Bob processes handshake and derives the same secret
    bob_ss = bob.receive_initial_message(initial_message)

    assert alice_ss == bob_ss, "Shared secrets do not match!"
    print("\nX3DH handshake successful. Shared secret:", alice_ss.hex())

    """Run a four-message Alice ↔ Bob exchange to verify ratchet behavior."""
    print("\n[Demo] Starting Double Ratchet test...\n")

    # Alice derives initial_root_key and initial_chain_key to start a Double Ratchet session with Bob
    alice_initial_root_key, alice_initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=alice_ss)

    # Bob derives initial_root_key and initial_chain_key to obtain a Double Ratchet session with Alice
    bob_initial_root_key, bob_initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=alice_ss)

    alice_session = DoubleRatchetSession(initial_dh_private_key=alice_ephemeral_private_key, root_key=alice_initial_root_key, sending_chain_key=alice_initial_chain_key,
                                  receiving_chain_key=None, initial_remote=bundle["identity_public_key"])

    bob_session = DoubleRatchetSession(initial_dh_private_key=bob.signed_prekey_private, root_key=bob_initial_root_key, sending_chain_key=None,
                                receiving_chain_key=bob_initial_chain_key, initial_remote=initial_message["alice_ephemeral_public"])

    # Initial DH exchange
    # alice.remote_public_key = bob.dh_private_key.public_key()
    # bob.remote_public_key = alice.dh_private_key.public_key()

    convo = [
        ("Alice", b"Hey Bob, this is a new session."),
        ("Bob", b"Hi Alice! Good to hear from you."),
        ("Alice", b"How's the thesis going?"),
        ("Bob", b"Slow but steady. Yours?"),
    ]

    for speaker, msg in convo:
        if speaker == "Alice":
            header_bytes, ciphertext, associated_data = alice_session.encrypt_message(msg)
            rec = bob_session.decrypt_message(header_bytes, ciphertext, associated_data)
            print(f"{speaker}->Bob   :", msg.decode())
            print("Bob  decrypted :", rec.decode(), "\n")
        else:
            header_bytes, ciphertext, associated_data = bob_session.encrypt_message(msg)
            rec = alice_session.decrypt_message(header_bytes, ciphertext, associated_data)
            print(f"{speaker}->Alice :", msg.decode())
            print("Alice decrypted :", rec.decode(), "\n")

    print("[✓] Demo complete – all messages round-tripped successfully.")


if __name__ == "__main__":
    main()
