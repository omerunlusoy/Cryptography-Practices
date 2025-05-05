"""
    RSA (Rivest–Shamir–Adleman) cryptosystem
    RSA can be used for authentication by signature (just encrypt the hashed message) or for encryption directly (very costly, not common)
    asymmetric encryption that uses two different but linked keys
    keys are mathematically symmetric
    when either key encrypts, the other key can decrypt
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Encrypt with public key
def rsa_encrypt(public_key, message: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(  # Use OAEP padding for modern security
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# Decrypt with private key
def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# === Example usage ===
if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()

    message = b"Hello RSA Encryption!"
    encrypted = rsa_encrypt(public_key, message)
    print("Encrypted message:", encrypted.hex())

    decrypted = rsa_decrypt(private_key, encrypted)
    print("Decrypted message:", decrypted.decode())

