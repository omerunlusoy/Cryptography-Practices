# End-to-end Encryption (E2EE) Core 
This project implements well-known ciphers and hash functions for educational purposes. Some implementations are pure while most of them are wrappers for well-known packages such as Crypto, argon2d, and cryptography.

## Asymmetric Cryptography (Public - Key Cryptography)
- Diffie – Hellman key exchange
- RSA
  - useful for signing (mathematically symmetric public - private key pair)
  - also used for encryption
  - can be used alone for handshakes without DH (historically used)
    - DH is only required for perfect forward 
    - RSA once (for authentication) + ephemeral DH (session-based)
  - can be used along with DH for authentication (hash the message to sign) (ECDHE_RSA)
    - still relies on proper public key exchange 
      - little problem for internet (website certificates)
      - but still allows rogue servers (Meta) to do MITM attack
        - solution: __audited open-source clients (Signal)__ + __Out-of-Band (OOB) Verification of safety number__ + build from the source code + uncompromised device (no Pegasus)
        - Safety number: hashed IPk_A || IPk_B
- Elliptic Cryptography (Elliptic Diffie – Hellman (ECDHE))
- X3DH (Extended Triple Diffie-Hellman)
  - Asynchronous Diffie - Hellman
- DSA (Digital Signature Algorithm)
  - Federal Information Processing Standard for digital signatures


## Symmetric Encryption (Block Ciphers)
- AES-256 (Other variants: 128, 192)


## Hashing
- SHA-2 (Variants: SHA-224, SHA-256, SHA-384, SHA-512)
  - not memory-intensive
  - susceptible to brute force attacks
- SHA-3
- scrypt
- bcrypt 
  - designed specifically for securing passwords 
  - protect against rainbow table attacks
  - intentionally slow (to make brute-force attacks more difficult)
- Argon2id
  - Slow and memory-intensive, but secure.
  - Good for password storage and verification.
  - Handles salt itself.
  - __Not deterministic__ unless you fixed the salt (loses security).
- HMAC (Stream Cipher (bit position preserving, might be used for UDP, live communication))
  - Keyed-hash message authentication code.
  - Ideal for checking if the message is tempered.
  - Fast, __deterministic__, keyed.
  - Good for hash comparison.


## HTTPS Example
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (from an actual website certificate)
  - TLS: secure communication protocol
  - ECDHE: key exchange (handshake)
  - RSA: public key authentication system
  - AES-128: cipher (message encryption after key exchange)
  - GCM: mode of operation (for cipher) (Galois/Counter Mode)
  - SHA-256: agreed hash function (e.g. for secret → key)

## Signal Protocol
- X3DH  (Extended Triple Diffie-Hellman) key agreement protocol
  - establishes a shared secret key between two parties who mutually authenticate each other based on public keys.
  - perfect forward secrecy
  - post compromised security (self-healing)
    - If the eavesdropper looks away for a second, they lose the keys
  - cryptographic deniability

- Double Ratchet
  - derive new keys for every Double Ratchet message so that earlier keys cannot be calculated from later ones.

## TO-DO
- version info for each file