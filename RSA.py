"""
    RSA (Rivest–Shamir–Adleman) cryptosystem
    RSA can be used for authentication by signature (just encrypt the hashed message) or for encryption directly (very costly, not common)
    asymmetric encryption that uses two different but linked keys
    keys are mathematically symmetric
    when either key encrypts, the other key can decrypt
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
"""


import random
from math import gcd


# --- Helper functions ---
def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    # Miller-Rabin primality test
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= 1  # make it odd
        if is_prime(p):
            return p


def modinv(a, m):
    # Extended Euclidean Algorithm (handles negatives properly)
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


# --- RSA Key Generation ---
def generate_rsa_keys(bits=512):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    d = modinv(e, phi)

    return (e, n), (d, n)


# --- Encryption/Decryption ---
def rsa_encrypt(message: int, public_key):
    e, n = public_key
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)


# === Example Usage ===
if __name__ == "__main__":
    public, private = generate_rsa_keys(bits=128)  # small bit size for demo

    message = 42  # must be < n
    ciphertext = rsa_encrypt(message, public)
    decrypted = rsa_decrypt(ciphertext, private)

    print("\n🔐 Original Message:", message)
    print("🧾 Encrypted:", ciphertext)
    print("✅ Decrypted:", decrypted)
