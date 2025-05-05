"""
    Diffie–Hellman key exchange algorithm
"""
import random
import secrets
import hashlib

# Shared prime and generator (small for demo purposes; insecure in real life)
P = 23   # Prime modulus
G = 5    # Primitive root modulo P (generator)

print(f"Public parameters:\n  Prime (P): {P}\n  Generator (G): {G}")

# Alice chooses a private key and computes her public key
alice_private = random.randint(1, P-2)
alice_public = pow(G, alice_private, P)

# Bob chooses a private key and computes his public key
bob_private = random.randint(1, P-2)
bob_public = pow(G, bob_private, P)

print(f"\nAlice's Public Key: {alice_public}")
print(f"Bob's Public Key: {bob_public}")

# Alice and Bob compute the shared secret
alice_shared_secret = pow(bob_public, alice_private, P)
bob_shared_secret = pow(alice_public, bob_private, P)

print(f"\nAlice's Shared Secret: {alice_shared_secret}")
print(f"Bob's Shared Secret:   {bob_shared_secret}")

# They should be the same
assert alice_shared_secret == bob_shared_secret
print("\nShared secret matches!")


# with larger numbers -------------------------------------------------------------------------------------------------

# Large safe prime (2048-bit MODP Group from RFC 3526, shortened here for readability)
P = int('''
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
'''.replace('\n', '').replace(' ', ''), 16)

G = 2  # Common generator for DH

# Generate private keys (256-bit secure random)
alice_private = secrets.randbits(256)
bob_private = secrets.randbits(256)

# Compute public keys
alice_public = pow(G, alice_private, P)
bob_public = pow(G, bob_private, P)

# Compute shared secret
alice_shared = pow(bob_public, alice_private, P)
bob_shared = pow(alice_public, bob_private, P)

print("Shared secret matches:", alice_shared == bob_shared)

# Optional: hash it to derive symmetric key
shared_key = hashlib.sha256(str(alice_shared).encode()).hexdigest()
print("SHA-256 of shared secret (usable as symmetric key):")
print(shared_key)
