import os
import getpass
import hashlib
from cryptography.fernet import Fernet
import base64

def generate_key_from_password(password):
    """Generate a 32-byte key using the SHA256 hash of a password."""
    password_hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(password_hash[:32])

def create_password_and_key():
    """Prompt user to create a password and save it encrypted in secret.key."""
    password = getpass.getpass("Set a new password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match. Try again.")
        return None

    key = generate_key_from_password(password)
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Password saved and encrypted in 'secret.key'.")
    return key

def load_key_from_password(password):
    """Load the key from the user's password."""
    if not os.path.exists("secret.key"):
        print("No key file found. Please create a password first.")
        return None
    stored_key = open("secret.key", "rb").read()
    generated_key = generate_key_from_password(password)

    if stored_key != generated_key:
        print("Incorrect password.")
        return None
    return generated_key

def encrypt_file(file_path, fernet):
    """Encrypt a file."""
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    print(f"Encrypted: {file_path}")

def decrypt_file(file_path, fernet):
    """Decrypt a file."""
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as f:
        f.write(decrypted_data)
    print(f"Decrypted: {file_path}")

def protect_folder(folder_path, password):
    """Encrypt all files in a folder."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, fernet)
    print(f"Folder '{folder_path}' is now locked.")

def unlock_folder(folder_path, password):
    """Decrypt all files in a folder."""
    key = load_key_from_password(password)
    if key is None:
        return
    fernet = Fernet(key)

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, fernet)
    print(f"Folder '{folder_path}' is now unlocked.")

def main():
    print("Folder Lock/Unlock System")
    print("1. Lock a folder")
    print("2. Unlock a folder")
    choice = input("Enter your choice (1/2): ").strip()

    folder_path = input("Enter the path of the folder: ").strip()

    if choice == "1":
        if not os.path.exists("secret.key"):
            password = getpass.getpass("Set a new password: ")
            create_password_and_key()
        else:
            print("Password already exists. Locking will use the existing password.")
            password = getpass.getpass("Enter your password: ")

        protect_folder(folder_path, password)

    elif choice == "2":
        password = getpass.getpass("Enter your password: ")
        unlock_folder(folder_path, password)

    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
