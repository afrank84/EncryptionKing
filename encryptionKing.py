import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
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
        self.root.geometry("400x500")
        self.root.configure(bg="#1e1e1e")  # Dark background
        self.master_password = None
        self.encryption_key = None
        
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 12), padding=5, background="#3a3a3a", foreground="white")
        self.style.configure("TLabel", font=("Arial", 12), background="#1e1e1e", foreground="white")
        self.style.configure("TEntry", font=("Arial", 12), padding=5)
        
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
        frame = ttk.Frame(self.root, padding=20, style="TFrame")
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Enter Master Password:").pack(pady=10)
        self.password_entry = ttk.Entry(frame, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)
        
        show_password_btn = ttk.Button(frame, text="Show", command=self.toggle_password)
        show_password_btn.pack(pady=5)
        
        ttk.Button(frame, text="Unlock", command=self.verify_master_password).pack(pady=10)
    
    def toggle_password(self):
        if self.password_entry["show"] == "*":
            self.password_entry["show"] = ""
        else:
            self.password_entry["show"] = "*"
    
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
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        ttk.Button(frame, text="Add Password", command=self.add_password).pack(pady=10)
        ttk.Button(frame, text="Show Passwords", command=self.show_passwords).pack(pady=10)
    
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
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        for site, creds in self.passwords.items():
            sub_frame = ttk.Frame(frame)
            sub_frame.pack(pady=5, fill=tk.X)
            ttk.Label(sub_frame, text=f"{site}: {creds['username']}").pack(side=tk.LEFT)
            ttk.Button(sub_frame, text="Copy Password", command=lambda p=creds['password']: self.copy_to_clipboard(p)).pack(side=tk.RIGHT)
        
        ttk.Button(frame, text="Back", command=self.create_main_screen).pack(pady=10)
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
