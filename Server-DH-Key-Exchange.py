"""
	Simple Python script demonstrating client-server Diffie–Hellman key exchange with SHA-256 hashing.
	The server side first creates a socket, binds the localhost, and starts listening on port 12345.
	Diffie–Hellman key exchange: 
		server receives P, G, and client public key.
		calculates its public key and sends it to the client.
		calculates the shared secret. 
		hashes the shared secret with SHA-256 to derive the symmetric key.
"""

import socket
import pickle

import secrets
import hashlib

# Create a socket object (IPv4 + TCP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind to localhost on port 12345
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server is listening on port 12345...")

# Accept a connection
conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# wait for handshake
client_public_data = conn.recv(1024)
P, G, client_public = pickle.loads(client_public_data)

# Generate private keys (256-bit secure random) and compute the server public key
server_private = secrets.randbits(256)
server_public = pow(G, server_private, P)

# Prepare a tuple to send
server_public_data = (server_public)
serialized_data = pickle.dumps(server_public_data)
conn.sendall(serialized_data)

# calculate the shared secret
server_shared_secret = pow(client_public, server_private, P)

# hash it to derive symmetric key
shared_key = hashlib.sha256(str(server_shared_secret).encode()).hexdigest()
print("SHA-256 of shared secret (usable as symmetric key):", shared_key)

# Close the connection
conn.close()
server_socket.close()
