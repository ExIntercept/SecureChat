from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import os
import requests

# Generate private and public keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Save private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
private_key_path = os.path.join(os.getcwd(), "private_key.pem")
with open(private_key_path, 'wb') as private_file:
    private_file.write(private_pem)

# Save public key
sender_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
directory = "../keys"
if not os.path.exists(directory):
    os.makedirs(directory)
public_key_path = os.path.join(directory, "sender_public_pem.pem")
with open(public_key_path, 'wb') as public_file:
    public_file.write(sender_public_pem)

# Load receiver public key for encryption
receiver_public_key_path = "../keys/receiver_public_pem.pem"
if not os.path.exists(receiver_public_key_path):
    raise FileNotFoundError(f"Receiver public key file not found: {receiver_public_key_path}")
with open(receiver_public_key_path, 'rb') as receiver_public_file:
    receiver_public_pem = receiver_public_file.read()
receiver_public_key = serialization.load_pem_public_key(receiver_public_pem)

# Encrypt data with receiver public key
data = b"Hi this is a message by Aryan."
try:
    encrypted_data = receiver_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
except Exception as e:
    print(f"Error encrypting data with receiver's public key: {e}")
    raise

# Triple AES encryption
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

aes_key1 = generate_aes_key()
aes_key2 = generate_aes_key()
aes_key3 = generate_aes_key()

def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    return encrypted_data

try:
    layer3_encrypted = encrypt_aes(encrypted_data, aes_key3)
    layer2_encrypted = encrypt_aes(layer3_encrypted, aes_key2)
    layer1_encrypted = encrypt_aes(layer2_encrypted, aes_key1)
except Exception as e:
    print(f"Error during AES encryption: {e}")
    raise

# Save AES keys
def save_key(key, filename):
    try:
        with open(filename, 'wb') as key_file:
            key_file.write(key)
    except Exception as e:
        print(f"Error saving AES key to {filename}: {e}")
        raise

save_key(aes_key1, "../server1/aes_key1.bin")
save_key(aes_key2, "../server2/aes_key2.bin")
save_key(aes_key3, "../server3/aes_key3.bin")

# Send data to server1
def send_data_to_server1(data):
    url = 'http://localhost:5001/receive'
    headers = {
        'Forward-To': 'http://localhost:5002/receive'  # Forward to server2
    }
    print(f"Sending data to {url} with headers {headers}")
    try:
        response = requests.post(url, data=data, headers=headers)
        print(f"Data sent to server1: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
print("Sender encrypted: ", layer1_encrypted)

send_data_to_server1(layer1_encrypted)
