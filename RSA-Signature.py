""""
    RSA Signatures
    simple Python demo that mimics how asymmetric encryption (specifically digital signatures) is used in blockchain-style transaction verification.
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# 1. Generate a key pair (like creating a wallet)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 2. Create a fake "transaction" (no encryption on transaction which would not be a real case)
transaction = b"Alice sends 1 BTC to Bob"

# 3. Sign the transaction with the private key (like submitting a signed transaction to the blockchain)
signature = private_key.sign(
    transaction,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# 4. Verify the signature with the public key (like a node verifying the sender's authenticity)
try:
    public_key.verify(
        signature,
        transaction,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Transaction signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)