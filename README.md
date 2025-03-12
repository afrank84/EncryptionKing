# EncryptionKing
Portable local storage of password, never saves master pass, of you forget you're screwed!

## Features

- **Master Password Protection:** Never stored, only used to unlock the encrypted file.
- **AES-GCM Encryption:** Ensures secure encryption of stored passwords.
- **Secure File Storage:** Passwords are always encrypted when saved to disk.
- **Tkinter GUI:** For a simple user interface to add, retrieve, and manage passwords.
- **Clipboard Copying:** Securely copies passwords without displaying them in plaintext.
- **PBKDF2 Key Derivation:** Prevents brute-force attacks by using a strong key derivation function.


### 🔹 **How It Works**
1. **Login Screen:**  
   - User enters a master password (never stored).  
   - If correct, the encrypted password storage is unlocked.

2. **Password Management:**  
   - Add new passwords securely.  
   - View stored passwords without displaying them in plaintext.  
   - Copy passwords to clipboard securely.  

3. **Encryption:**  
   - **AES-GCM with PBKDF2-HMAC SHA256** for key derivation.  
   - **Unique salt for each installation** (stored in `salt.bin`).  
   - **Passwords stay encrypted** at all times.  
