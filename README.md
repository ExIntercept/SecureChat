SecureP2PChat (Prototype)

A lightweight, LAN-based P2P chat application with end-to-end encryption (E2EE) and AES encryption.

Features

✅ Peer-to-peer (P2P) communication over HTTP
✅ End-to-end encryption (AES-based)
✅ Local network (LAN) support
✅ No central server

How It Works
	1.	Multiple Local Servers – Each peer runs an independent HTTP server (server1.py, server2.py, server3.py).
	2.	Message Sending & Receiving –
	•	sender.py: Encrypts and sends messages.
	•	receiver.py: Decrypts and displays received messages.
	3.	End-to-End Encryption (E2EE) – Uses AES encryption for secure messaging.
	4.	Direct LAN Communication – Peers communicate directly over the network.

Setup & Usage
	1.	Install dependencies:

pip install cryptography flask


	2.	Start individual servers:

python server1.py  
python server2.py  
python server3.py  


	3.	Send a message:

python sender.py 
then send a message.


	4.	The receiver runs:

python receiver.py
