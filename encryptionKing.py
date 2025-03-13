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

        # Load icons (Resized properly)
        try:
            self.edit_icon = PhotoImage(file="icons/edit.png").subsample(5, 5)  # Shrink images
            self.copy_icon = PhotoImage(file="icons/copy.png").subsample(5, 5)
            self.delete_icon = PhotoImage(file="icons/delete.png").subsample(5, 5)
        except Exception as e:
            print("Error loading icons:", e)
            return

        # Create a frame for the table
        table_frame = ttk.Frame(self.main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create Treeview (without actions column)
        tree = ttk.Treeview(table_frame, columns=("Website", "Username"), show="headings", height=10)
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")

        tree.column("Website", width=200)
        tree.column("Username", width=150)

        tree.grid(row=0, column=0, sticky="nsew")

        # Create a canvas for icons next to each row
        canvas = tk.Canvas(table_frame, width=120, height=300, bg="#1e1e1e", highlightthickness=0)
        canvas.grid(row=0, column=1, sticky="ns")

        # Scrollbars
        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scrollbar_y.grid(row=0, column=2, sticky="ns")

        tree.configure(yscrollcommand=scrollbar_y.set)

        # Insert rows into Treeview & create icons next to each row
        button_refs = {}  # Store references to avoid garbage collection
        for i, (site, creds) in enumerate(self.passwords.items()):
            item_id = tree.insert("", "end", values=(site, creds["username"]))

            # Place icons in the canvas, aligned with the rows
            y_position = 30 + (i * 30)

            edit_button = ttk.Button(table_frame, image=self.edit_icon, command=lambda s=site: self.edit_password(s))
            copy_button = ttk.Button(table_frame, image=self.copy_icon, command=lambda p=creds["password"]: self.copy_to_clipboard(p))
            delete_button = ttk.Button(table_frame, image=self.delete_icon, command=lambda s=site: self.delete_password(s))

            # Place buttons on the canvas
            canvas.create_window(10, y_position, anchor="w", window=edit_button)
            canvas.create_window(50, y_position, anchor="w", window=copy_button)
            canvas.create_window(90, y_position, anchor="w", window=delete_button)

            # Store references to avoid garbage collection
            button_refs[item_id] = (edit_button, copy_button, delete_button)

        # Back button
        ttk.Button(self.main_frame, text="Back", command=self.show_main_menu).pack(pady=10)



    def edit_password(self, site):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.main_frame, text="Edit Password Entry").pack(pady=10)

        ttk.Label(self.main_frame, text="Website:").pack(pady=5)
        site_entry = ttk.Entry(self.main_frame)
        site_entry.insert(0, site)
        site_entry.pack(pady=5, fill=tk.X)

        ttk.Label(self.main_frame, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(self.main_frame)
        username_entry.insert(0, self.passwords[site]["username"])
        username_entry.pack(pady=5, fill=tk.X)

        ttk.Label(self.main_frame, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(self.main_frame, show="*")
        password_entry.insert(0, self.passwords[site]["password"])
        password_entry.pack(pady=5, fill=tk.X)

        def save_changes():
            new_site = site_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()

            if new_site and new_username and new_password:
                # Remove old entry if site name changed
                if new_site != site:
                    del self.passwords[site]

                self.passwords[new_site] = {"username": new_username, "password": new_password}
                self.save_passwords()
                self.show_passwords()  # Return to list after saving

        ttk.Button(self.main_frame, text="Save Changes", command=save_changes).pack(pady=10)
        ttk.Button(self.main_frame, text="Back", command=self.show_passwords).pack(pady=10)

    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        
    def delete_password(self, site):
        del self.passwords[site]
        self.save_passwords()
        self.show_passwords()  # Refresh the list

    
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
