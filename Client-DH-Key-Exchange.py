"""
	Simple Python script demonstrating client-server Diffie–Hellman key exchange with SHA-256 hashing.
	Client side first creates a socket and connects to the server on port 12345.
	Diffie–Hellman key exchange: 
		client decides on P and G, calculates its public key and sends them to server. 
		receives the server's public key and calculates the shared secret.
		hashes the shared secret with SHA-256 to derive the symmetric key.
	Client also times this key exchange.	
"""

import socket
import pickle

import secrets
import hashlib
import time

# Create a socket object (IPv4 + TCP)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server on localhost and port 12345
client_socket.connect(('localhost', 12345))

# ⏱️ Start DH timer before sending
start_time = time.time()

# Start DH key exchange
# Shared prime and generator
P = int('''
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
'''.replace('\n', '').replace(' ', ''), 16)

G = 2  # Common generator for DH

# Generate private keys (256-bit secure random) and compute the client public key
client_private = secrets.randbits(256)
client_public = pow(G, client_private, P)

# Prepare a tuple to send
client_public_data = (P, G, client_public)
serialized_data = pickle.dumps(client_public_data)
client_socket.sendall(serialized_data)

# Receive response (server_public_data) from server
response = client_socket.recv(1024)
server_public = pickle.loads(response)

# calculate the shared secret
client_shared_secret = pow(server_public, client_private, P)

# hash it to derive symmetric key
shared_key = hashlib.sha256(str(client_shared_secret).encode()).hexdigest()
print("🔐 SHA-256 of shared secret (usable as symmetric key):", shared_key)

# ⏱️ End DH timer after receiving
end_time = time.time()
roundtrip_time = end_time - start_time
print(f"⏱️ Roundtrip time: {roundtrip_time:.6f} seconds")

# Close the connection
client_socket.close()
