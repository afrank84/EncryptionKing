import tkinter as tk
from tkinter import ttk, simpledialog
import json
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
from tkinter import PhotoImage

# Constants
SALT_FILE = "salt.bin"
DATA_FILE = "passwords.enc"
ITERATIONS = 100000

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("600x700")
        self.root.configure(bg="#1e1e1e")  # Dark background
        self.master_password = None
        self.encryption_key = None
        
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 12), padding=5, background="#3a3a3a", foreground="white")
        self.style.configure("TLabel", font=("Arial", 12), background="#1e1e1e", foreground="white")
        self.style.configure("TEntry", font=("Arial", 12), padding=5)
        
        self.load_or_create_salt()
        self.create_ui()
    
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

    def create_ui(self):
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(expand=True, fill=tk.BOTH)

        # Load and display the logo
        try:
            self.logo_image = PhotoImage(file="ek_logo.png").subsample(2, 2)  # Shrink by a factor of 2
            self.logo_label = ttk.Label(self.main_frame, image=self.logo_image)
            self.logo_label.pack(pady=10)
        except Exception as e:
            print("Error loading logo:", e)

        self.password_label = ttk.Label(self.main_frame, text="Enter Master Password:")
        self.password_label.pack(pady=10)

        self.password_entry = ttk.Entry(self.main_frame, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)

        self.unlock_button = ttk.Button(self.main_frame, text="Unlock", command=self.verify_master_password)
        self.unlock_button.pack(pady=10)

    
    def verify_master_password(self):
        password = self.password_entry.get()
        if not password:
            return
        
        self.master_password = password
        self.encryption_key = self.derive_key(password)
        self.load_passwords()
        self.show_main_menu()
    
    def show_main_menu(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        ttk.Button(self.main_frame, text="Add Password", command=self.add_password).pack(pady=10)
        ttk.Button(self.main_frame, text="Show Passwords", command=self.show_passwords).pack(pady=10)
    
    def add_password(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.main_frame, text="Website:").pack(pady=5)
        site_entry = ttk.Entry(self.main_frame)
        site_entry.pack(pady=5, fill=tk.X)

        ttk.Label(self.main_frame, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(self.main_frame)
        username_entry.pack(pady=5, fill=tk.X)

        ttk.Label(self.main_frame, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(self.main_frame, show="*")
        password_entry.pack(pady=5, fill=tk.X)

        def save_password():
            site = site_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if site and username and password:
                self.passwords[site] = {"username": username, "password": password}
                self.save_passwords()
                self.show_main_menu()  # Return to main menu after saving

        ttk.Button(self.main_frame, text="Save", command=save_password).pack(pady=10)
        ttk.Button(self.main_frame, text="Back", command=self.show_main_menu).pack(pady=10)

    
    def show_passwords(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # Create Treeview (Table)
        tree = ttk.Treeview(self.main_frame, columns=("Website", "Username", "Actions"), show="headings")
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Actions", text="Actions")
        
        tree.column("Website", width=150)
        tree.column("Username", width=100)
        tree.column("Actions", width=50)

        # Insert data
        for site, creds in self.passwords.items():
            tree.insert("", "end", values=(site, creds["username"], "Copy"))

        tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Bind click event to copy password
        def on_item_click(event):
            selected_item = tree.selection()
            if selected_item:
                site = tree.item(selected_item, "values")[0]  # Get website name
                self.copy_to_clipboard(self.passwords[site]["password"])

        tree.bind("<Double-1>", on_item_click)  # Double-click to copy password

        ttk.Button(self.main_frame, text="Back", command=self.show_main_menu).pack(pady=10)

    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
    
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
            return "{}"

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
