from flask import Flask, request
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Configuration for this server
server_config = {
    "server_id": "server2",
    "next_node_url": "http://localhost:5004/receive",  # Forward to server4
    "key_file_path": "../server3/aes_key3.bin",  # Key for this server
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

    # Load the AES key
    aes_key = load_aes_key(server_config['key_file_path'])

    # Decrypt the received data
    decrypted_data = decrypt_aes(encrypted_data, aes_key)

    # Forward the data to the next node
    next_node_url = server_config['next_node_url']
    try:
        response = requests.post(next_node_url, data=decrypted_data)
        print(f"Data forwarded to {next_node_url}: {response.status_code}")
        return 'Data forwarded', 200
    except requests.exceptions.RequestException as e:
        print(f"Error forwarding data to {next_node_url}: {e}")
        return 'Failed to forward data', 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5003)  # Server2 on port 5003
