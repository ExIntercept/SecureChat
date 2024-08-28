from flask import Flask, request
import requests
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Configuration for this server
server_config = {
    "server_id": "server1",
    "next_node_url": "http://localhost:5002/receive",  # Forward to server2
    "key_file_path": "../server1/aes_key1.bin",  # Key for this server
    "next_node_key_path": "../server2/aes_key2.bin"  # Key for the next node
}

def load_aes_key(key_file_path):
    try:
        with open(key_file_path, 'rb') as key_file:
            return key_file.read()
    except Exception as e:
        print(f"Error loading AES key from {key_file_path}: {e}")
        raise

def decrypt_aes(data, key):
    try:
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        print(f"Error during AES decryption: {e}")
        raise


@app.route('/receive', methods=['POST'])

def receive_data():
    encrypted_data = request.data

    aes_key = load_aes_key("../server1/aes_key1.bin")  # Replace with actual key file path

    decrypted_data = decrypt_aes(encrypted_data, aes_key)


    next_node_url = 'http://localhost:5002/receive'

    # Forward the data to the next node

    response = requests.post(next_node_url, data=decrypted_data)
    print(f"Data forwarded to {next_node_url}: {response.status_code}")
    return 'Data forwarded', 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)  # Server1 on port 5001