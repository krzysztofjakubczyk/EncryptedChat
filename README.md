# EncryptedChat

This project is an encrypted chat application written in C#.
It utilizes modern cryptographic algorithms to ensure secure communication over a network.

🔒 Used Cryptographic Algorithms:
ECDH (Elliptic-Curve Diffie–Hellman) — for secure key exchange.

RSA — for encrypting the hash of messages to ensure integrity and authenticity.

AES — for symmetric encryption of messages.

SHA-256 — for hashing messages to verify integrity.

💬 How It Works:
Connection:
The client establishes a TCP connection to the server (127.0.0.1:7891).

Key Exchange:

The client generates its own Diffie-Hellman public key and derives a shared session key using the server's Diffie-Hellman public key.

The client and server exchange RSA public keys to enable secure signing of message hashes.

Message Reception (OpCode 5):

Messages are received encrypted with AES.

Along with the message, a signed hash (RSA) and an IV (for AES encryption) are received.

The client decrypts the message, then checks the hash using RSA to ensure its integrity. If the hash is valid, the message is displayed.

Sending Messages:

The message is hashed with SHA-256.

Then it is encrypted with AES using the derived session key.

The hash is encrypted with the server's RSA public key to ensure integrity.

All data is sent to the server in a custom packet format.

🔐 Security Features:
ECDH ensures a secure shared session key exchange.

RSA ensures the authenticity and integrity of messages via encrypted hashes.

AES provides fast and secure message encryption.

SHA-256 guarantees message integrity and verifies that the received message is untampered.
