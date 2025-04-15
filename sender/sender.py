from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import os
import requests
import tkinter as tk
from tkinter import scrolledtext, ttk, Toplevel

# master_script.py

print("""
  ____  _____ _   _ ____  _____ ____  
 / ___|| ____| \ | |  _ \| ____|  _ \ 
 \___ \|  _| |  \| | | | |  _| | |_) |
  ___) | |___| |\  | |_| | |___|  _ < 
 |____/|_____|_| \_|____/|_____|_| \_\
                                      
""")

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

    try:
        response = requests.post(url, data=data, headers=headers)
        print("✓")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

# Tkinter UI
class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat - Sender")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f2f5")

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#f0f2f5")
        style.configure("TButton", padding=6, relief="flat", background="#007bff", foreground="white", font=("Helvetica", 10))
        style.map("TButton", background=[("active", "#0056b3")])
        style.configure("TEntry", padding=5, fieldbackground="white", font=("Helvetica", 11))
        style.configure("Chat.TFrame", background="white", borderwidth=2, relief="groove")

        # Chat display area
        chat_frame = ttk.Frame(self.root, style="Chat.TFrame")
        chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area = scrolledtext.ScrolledText(
            chat_frame, wrap=tk.WORD, height=15, font=("Helvetica", 11), bg="white", bd=0
        )
        self.chat_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.chat_area.configure(state='disabled')

        # Input frame
        self.input_frame = ttk.Frame(self.root, style="TFrame")
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)

        # Emoji button
        self.emoji_button = ttk.Button(self.input_frame, text="😊", width=4, command=self.open_emoji_picker)
        self.emoji_button.pack(side=tk.LEFT, padx=(0, 5))

        # Message entry
        self.message_entry = ttk.Entry(self.input_frame, font=("Helvetica", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)

        # Send button
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

    def open_emoji_picker(self):
        emoji_window = Toplevel(self.root)
        emoji_window.title("Select Emoji")
        emoji_window.geometry("300x200")
        emoji_window.configure(bg="#f0f2f5")

        emojis = [
            "😊", "😂", "😍", "😢", "😎", "😡", "👍", "👎",
            "❤️", "🔥", "🎉", "🌟", "🍎", "🍕", "🚀", "🐱"
        ]

        frame = ttk.Frame(emoji_window, style="TFrame")
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for i, emoji in enumerate(emojis):
            btn = ttk.Button(
                frame, text=emoji, width=4,
                command=lambda e=emoji: self.insert_emoji(e, emoji_window)
            )
            btn.grid(row=i // 4, column=i % 4, padx=5, pady=5)

    def insert_emoji(self, emoji, window):
        self.message_entry.insert(tk.END, emoji)
        window.destroy()

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return

        # Display sent message in chat area
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"You: {message}\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

        # Clear input
        self.message_entry.delete(0, tk.END)

        # Encrypt and send message
        try:
            bdata = message.encode('utf-8')
            encrypted_data = receiver_public_key.encrypt(
                bdata,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            layer3_encrypted = encrypt_aes(encrypted_data, aes_key3)
            layer2_encrypted = encrypt_aes(layer3_encrypted, aes_key2)
            layer1_encrypted = encrypt_aes(layer2_encrypted, aes_key1)
            send_data_to_server1(layer1_encrypted)
        except Exception as e:
            self.chat_area.configure(state='normal')
            self.chat_area.insert(tk.END, f"Error: {e}\n")
            self.chat_area.configure(state='disabled')
            self.chat_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()