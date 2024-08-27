from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
private_key = rsa.generate_private_key(             #create private and public keys
    public_exponent=65537,
    key_size = 2048,
)

public_key = private_key.public_key()


private_pem = private_key.private_bytes(            #creating pem files for keys
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption()
)

receiver_public_pem = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)

directory = "../keys"

if not os.path.exists(directory):
    os.makedirs(directory)
public_key_path = os.path.join(directory, "receiver_public_pem.pem")

with open(public_key_path, 'wb') as public_file:
    public_file.write(receiver_public_pem)

current_directory = os.getcwd()


private_key_path = os.path.join(current_directory, "private_key.pem")
with open(private_key_path, 'wb') as private_file:
    private_file.write(private_pem)