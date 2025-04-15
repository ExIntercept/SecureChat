from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import requests
from flask import Flask, request
import logging
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading

print("""
  ____  _____ ____ _____ _____     _______ ____  
 |  _ \| ____/ ___| ____|_ _\ \   / / ____|  _ \ 
 | |_) |  _|| |   |  _|  | | \ \ / /|  _| | |_) |
 |  _ <| |__| |___| |___ | |  \ V / | |___|  _ < 
 |_| \_\_____\____|_____|___|  \_/  |_____|_| \_\
                                                 
""")
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

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
    # Decrypt the RSA encrypted data
    decrypted_data = decrypt_rsa(encrypted_data)
    return decrypted_data

def load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key = key_file.read()
    return key

# Tkinter UI
class ReceiverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat - Receiver")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f2f5")

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#f0f2f5")
        style.configure("Chat.TFrame", background="white", borderwidth=2, relief="groove")

        # Chat display area
        chat_frame = ttk.Frame(self.root, style="Chat.TFrame")
        chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area = scrolledtext.ScrolledText(
            chat_frame, wrap=tk.WORD, height=15, font=("Helvetica", 11), bg="white", bd=0
        )
        self.chat_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.chat_area.configure(state='disabled')

    def display_message(self, message):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"Sender: {message}\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

def run_flask_app(app, receiver_app):
    app.run(host='0.0.0.0', port=5004, use_reloader=False)

def receive_data_from_previous_server():
    app = Flask(__name__)
    receiver_app = None

    @app.route('/receive', methods=['POST'])
    def receive():
        url = "http://localhost:5001"
        encrypted_data = request.data
        try:
            decrypted_message = handle_received_data(encrypted_data)
            message = decrypted_message.decode()
            if receiver_app:
                receiver_app.display_message(message)
        except Exception as e:
            if receiver_app:
                receiver_app.display_message(f"Error: {e}")
            return "Error processing data.", 500
        return "Data received and processed.", 200

    # Create Tkinter UI
    root = tk.Tk()
    receiver_app = ReceiverApp(root)
    
    # Run Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask_app, args=(app, receiver_app), daemon=True)
    flask_thread.start()
    
    root.mainloop()

if __name__ == "__main__":
    receive_data_from_previous_server()