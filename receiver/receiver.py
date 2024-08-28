from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import requests
from flask import Flask, request

# Directory paths
keys_directory = "../keys"
private_key_directory = "./receiver_private_keys"

# Generate public and private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Save the public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

if not os.path.exists(keys_directory):
    os.makedirs(keys_directory)
public_key_path = os.path.join(keys_directory, "receiver_public_pem.pem")

with open(public_key_path, 'wb') as public_file:
    public_file.write(public_pem)

# Save the private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

if not os.path.exists(private_key_directory):
    os.makedirs(private_key_directory)
private_key_path = os.path.join(private_key_directory, "receiver_private_key.pem")

with open(private_key_path, 'wb') as private_file:
    private_file.write(private_pem)

def decrypt_aes(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
    return decrypted_data

def decrypt_rsa(encrypted_data):
    private_key_path = os.path.join(private_key_directory, "receiver_private_key.pem")
    with open(private_key_path, 'rb') as private_file:
        private_pem = private_file.read()
    
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None
    )
    
    # Print lengths for debugging
    print(f"Length of encrypted data: {len(encrypted_data)}")
    print(f"Key size: {private_key.key_size // 8}")
    
    try:
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    except Exception as e:
        print(f"RSA decryption error: {e}")
        raise


def handle_received_data(encrypted_data):
    # Decrypt the AES layers

    
    # Decrypt the RSA encrypted data
    decrypted_data = decrypt_rsa(encrypted_data)
    return decrypted_data

def load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key = key_file.read()
    return key

def receive_data_from_previous_server():
    # Here, we assume the receiver is listening on port 5004
    # Modify as needed to match your actual setup
    
    
    app = Flask(__name__)

    @app.route('/receive', methods=['POST'])
    def receive():
        encrypted_data = request.data
        decrypted_message = handle_received_data(encrypted_data)
        print(f"Decrypted message: {decrypted_message.decode()}")
        return "Data received and processed.", 200

    if __name__ == "__main__":
        app.run(host='0.0.0.0', port=5004)

receive_data_from_previous_server()
