"""
Educational implementation of the Signal X3DH
===============================================================================

X3DH key agreement implementation in Python using the Signal Protocol's
Extended Triple Diffie-Hellman handshake.

This script demonstrates:
1. Generation of identity and pre-keys
2. Performing four Diffie-Hellman computations
3. Deriving a shared secret via HKDF with salt
4. A simple handshake between an Initiator (Alice) and Responder (Bob)

Dependencies:
    pip install cryptography

Key Significance:
    Alice   ↔   Bob
 1.  IK_A   ↔   SPK_B   (authenticity via SPK signature)
 2.  EK_A   ↔   IK_B    (ties Alice’s fresh randomness to Bob’s identity)
 3.  EK_A   ↔   SPK_B   (strengthens binding between Alice’s ephemeral and Bob’s semi-static)
 4.  EK_A   ↔   OPK_B   (per-session one-time secrecy boost)

Note:
    Your display name and avatar live in your Signal Profile
        (stored encrypted on Signal’s servers as profile blob)
    Your first message establishes X3DH and then sends your
        symmetric profile key
"""

from typing import TypedDict, Tuple, List
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.exceptions import InvalidSignature


class PreKeyBundle(TypedDict):
    identity_public_key: X25519PublicKey
    signing_public_key: Ed25519PublicKey
    signed_prekey_public: X25519PublicKey
    signed_prekey_signature: bytes
    one_time_prekey_public: X25519PublicKey


class InitialMessage(TypedDict):
    alice_identity_public: X25519PublicKey
    alice_ephemeral_public: X25519PublicKey


def generate_identity_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a long-term X25519 identity key pair.
    Identity Key Pair (X25519) Role & significance:
        This is your long‑term Diffie–Hellman key pair. Its public half is published in your “address book” and used by anyone initiating a session.
        Provides a stable anchor for authenticity: others can trust your identity.
    Lifetime:
        Rotate very infrequently—months to years. Protect its private half rigorously (HSM or encrypted storage).
    """
    identity_private_key = X25519PrivateKey.generate()
    identity_public_key = identity_private_key.public_key()
    return identity_private_key, identity_public_key


def generate_signed_prekey(signing_key_private: Ed25519PrivateKey) -> Tuple[X25519PrivateKey, X25519PublicKey, bytes]:
    """
    Generate a semi-static X25519 pre-key and sign its public key with an Ed25519 signing key.
    Signed Pre-Key Pair (X25519) Role & significance:
        A semi‑static DH key published with an Ed25519 signature. Allows asynchronous session starts without you online.
    Lifetime:
        Rotate periodically—days to weeks. Limits the impact of compromise and balances bundle update frequency.

    Args:
        signing_key_private: The Ed25519 private key used to sign the pre-key.

    Returns:
        A tuple of (prekey_private_key, prekey_public_key, signature).
    """
    signed_prekey_private = X25519PrivateKey.generate()
    signed_prekey_public = signed_prekey_private.public_key()
    raw_public = signed_prekey_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed_prekey_signature = signing_key_private.sign(raw_public)
    return signed_prekey_private, signed_prekey_public, signed_prekey_signature


def generate_one_time_prekey() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a tuple of one-time X25519 prekeys.

    One-Time Pre-Key Pair (X25519) Role & significance:
        A single‑use DH key providing extra forward‑secrecy boost per session.
    Lifetime:
        Until used, then removed. Client replenishes automatically.

    This method creates a one-time prekey pair using the X25519 key exchange algorithm.
    The pair consists of a public key and a corresponding private key.

    Returns:
        A tuple containing two keys:
        - An X25519PublicKey object, representing a generated public key.
        - An X25519PrivateKey object, representing the corresponding private key.
    """
    one_time_prekey_private = X25519PrivateKey.generate()
    one_time_prekey_public = one_time_prekey_private.public_key()
    return one_time_prekey_private, one_time_prekey_public


def derive_shared_secret(dh_shared_materials: List[bytes], salt: bytes, info: bytes = b'X3DH') -> bytes:
    """
    Derive a final symmetric shared secret via HKDF-SHA256.

    Args:
        dh_shared_materials: A list of raw Diffie-Hellman shared secrets.
        salt: A byte string used as salt for HKDF.
        info: Optional context information for HKDF.

    Returns:
        A 32-byte shared secret.
    """
    concatenated_materials = b''.join(dh_shared_materials)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(concatenated_materials)


class Bob:
    def __init__(self) -> None:
        # Long-term DH identity key pair
        self.identity_private_key, self.identity_public_key = generate_identity_keypair()

        # Identity‑Signing Key Pair (Ed25519)
        # Role & significance: signs the Signed Pre-Key to authenticate bundles
        # Lifetime: tied to identity key, rotate months to years
        self.signing_private_key = Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_private_key.public_key()

        # Signed Pre-Key and signature
        self.signed_prekey_private, self.signed_prekey_public, self.signed_prekey_signature = \
            generate_signed_prekey(self.signing_private_key)

        # One-Time Pre-Key
        self.one_time_prekey_private, self.one_time_prekey_public = generate_one_time_prekey()

    def get_prekey_bundle(self) -> PreKeyBundle:
        """Publish the public bundle for initiators (no private material)."""
        return {
            'identity_public_key': self.identity_public_key,
            'signing_public_key': self.signing_public_key,
            'signed_prekey_public': self.signed_prekey_public,
            'signed_prekey_signature': self.signed_prekey_signature,
            'one_time_prekey_public': self.one_time_prekey_public
        }

    def receive_initial_message(self, initial_message: InitialMessage) -> bytes:
        """
        Process Alice's initial message and compute the shared secret from Bob's side.
        """
        alice_identity_public = initial_message['alice_identity_public']
        alice_ephemeral_public = initial_message['alice_ephemeral_public']

        # Derive salt from concatenated public keys to feed into HKDF
        salt = (
            alice_identity_public.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            alice_ephemeral_public.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            self.identity_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            self.signed_prekey_public.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            self.one_time_prekey_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

        # Four DH computations
        dh1 = self.signed_prekey_private.exchange(alice_identity_public)
        dh2 = self.identity_private_key.exchange(alice_ephemeral_public)
        dh3 = self.signed_prekey_private.exchange(alice_ephemeral_public)
        dh4 = self.one_time_prekey_private.exchange(alice_ephemeral_public)

        # Zeroize one-time pre-key material
        self.one_time_prekey_private = None  # type: ignore

        return derive_shared_secret([dh1, dh2, dh3, dh4], salt)


class Alice:
    def __init__(self) -> None:
        # Long-term DH identity key pair
        self.identity_private_key, self.identity_public_key = generate_identity_keypair()

    def initiate_handshake(self, bob_bundle: PreKeyBundle) -> Tuple[InitialMessage, bytes, X25519PrivateKey]:
        """
        Generate an ephemeral keypair, validate Bob's Signed Pre-Key, and compute the shared secret.
        Returns the message to send and the derived shared secret.
        """
        # Ephemeral Key Pair (X25519)
        # Role & significance: single-handshake forward secrecy
        # Lifetime: single handshake only
        ephemeral_private_key = X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Verify SPK signature
        raw_spk = bob_bundle['signed_prekey_public'].public_bytes(Encoding.Raw, PublicFormat.Raw)
        try:
            bob_bundle['signing_public_key'].verify(bob_bundle['signed_prekey_signature'], raw_spk)
        except InvalidSignature:
            raise ValueError("Signed Pre-Key signature verification failed: wrong bundle or tampering.")

        # Derive salt from concatenated public keys
        salt = (
            self.identity_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            ephemeral_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            bob_bundle['identity_public_key'].public_bytes(Encoding.Raw, PublicFormat.Raw) +
            bob_bundle['signed_prekey_public'].public_bytes(Encoding.Raw, PublicFormat.Raw) +
            bob_bundle['one_time_prekey_public'].public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

        # Four DH computations
        dh1 = self.identity_private_key.exchange(bob_bundle['signed_prekey_public'])
        dh2 = ephemeral_private_key.exchange(bob_bundle['identity_public_key'])
        dh3 = ephemeral_private_key.exchange(bob_bundle['signed_prekey_public'])
        dh4 = ephemeral_private_key.exchange(bob_bundle['one_time_prekey_public'])

        # Zeroize ephemeral private key
        # ephemeral_private_key = None

        shared_secret = derive_shared_secret([dh1, dh2, dh3, dh4], salt)

        message: InitialMessage = {
            'alice_identity_public': self.identity_public_key,
            'alice_ephemeral_public': ephemeral_public_key
        }
        return message, shared_secret, ephemeral_private_key
