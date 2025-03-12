import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

# Constants
SALT_FILE = "salt.bin"
DATA_FILE = "passwords.enc"
ITERATIONS = 100000

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.master_password = None
        self.encryption_key = None
        
        self.load_or_create_salt()
        self.create_login_screen()
    
    def load_or_create_salt(self):
        if not os.path.exists(SALT_FILE):
            salt = os.urandom(16)
            with open(SALT_FILE, "wb") as f:
                f.write(salt)
        else:
            with open(SALT_FILE, "rb") as f:
                salt = f.read()
        self.salt = salt
    
    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=ITERATIONS,
        )
        return kdf.derive(password.encode())
    
    def create_login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Enter Master Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()
        tk.Button(self.root, text="Unlock", command=self.verify_master_password).pack()
    
    def verify_master_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return
        
        self.master_password = password
        self.encryption_key = self.derive_key(password)
        self.load_passwords()
        self.create_main_screen()
    
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def encrypt_data(self, plaintext):
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
    
    def decrypt_data(self, encrypted_data):
        try:
            encrypted_data = base64.b64decode(encrypted_data)
            iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            messagebox.showerror("Error", "Failed to decrypt data. Incorrect master password?")
            return "{}"
    
    def load_passwords(self):
        if not os.path.exists(DATA_FILE):
            self.passwords = {}
        else:
            with open(DATA_FILE, "r") as f:
                encrypted_data = f.read()
                decrypted_json = self.decrypt_data(encrypted_data)
                self.passwords = json.loads(decrypted_json)
    
    def save_passwords(self):
        encrypted_data = self.encrypt_data(json.dumps(self.passwords))
        with open(DATA_FILE, "w") as f:
            f.write(encrypted_data)
    
    def create_main_screen(self):
        self.clear_screen()
        tk.Button(self.root, text="Add Password", command=self.add_password).pack()
        tk.Button(self.root, text="Show Passwords", command=self.show_passwords).pack()
    
    def add_password(self):
        site = simpledialog.askstring("New Entry", "Website:")
        username = simpledialog.askstring("New Entry", "Username:")
        password = simpledialog.askstring("New Entry", "Password:")
        if site and username and password:
            self.passwords[site] = {"username": username, "password": password}
            self.save_passwords()
            messagebox.showinfo("Success", "Password saved successfully.")
    
    def show_passwords(self):
        self.clear_screen()
        for site, creds in self.passwords.items():
            frame = tk.Frame(self.root)
            frame.pack()
            tk.Label(frame, text=f"{site}: {creds['username']}" ).pack(side=tk.LEFT)
            tk.Button(frame, text="Copy Password", command=lambda p=creds['password']: self.copy_to_clipboard(p)).pack(side=tk.RIGHT)
        tk.Button(self.root, text="Back", command=self.create_main_screen).pack()
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
