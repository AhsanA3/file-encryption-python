import os
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class User:
    def __init__(self, username, password, private_key=None, public_key=None):
        # User class to represent a user with username, password, private key, and public key.
        self.username = username
        self.password = password
        # Generate a private key if not provided, and derive public key from it.
        self.private_key = private_key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = public_key or self.private_key.public_key()

    def to_dict(self):
        # Convert user information to a dictionary for easy serialization.
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "username": self.username,
            "password": self.password,
            "private_key": base64.b64encode(private_key_pem).decode("utf-8"),
            "public_key": base64.b64encode(public_key_pem).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, user_dict):
        # Create a User object from a dictionary.
        private_key = serialization.load_pem_private_key(
            base64.b64decode(user_dict["private_key"]),
            password=None,
            backend=default_backend(),
        )
        public_key = serialization.load_pem_public_key(
            base64.b64decode(user_dict["public_key"]), backend=default_backend()
        )

        return cls(
            user_dict["username"], user_dict["password"], private_key, public_key
        )

class SecureStorage:
    def __init__(self):
        # Initialize the SecureStorage class with a dictionary to store users and load existing users.
        self.users = {}
        self.current_user = None
        self.load_users()

    def load_users(self):
        # Load user information from a JSON file if it exists.
        if os.path.exists("users.json"):
            try:
                with open("users.json", "r") as file:
                    user_data = json.load(file)
                    for username, data in user_data.items():
                        self.users[username] = User.from_dict(data)
            except json.decoder.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")
                print("Content of the 'users.json' file:")
                with open("users.json", "r") as file:
                    print(file.read())

    def save_users(self):
        # Save user information to a JSON file.
        user_data = {user.username: user.to_dict() for user in self.users.values()}
        with open("users.json", "w") as file:
            json.dump(user_data, file)

    def register_user(self, username, password):
        # Register a new user and save the updated user information.
        if username in self.users:
            raise ValueError("Username already exists.")
        user = User(username, password)
        self.users[username] = user
        self.save_users()
        return user

    def login(self, username, password):
        # Log in a user and set it as the current user.
        user = self.users.get(username)
        if user is not None and user.password == password:
            self.current_user = user
            print(f"Logged in as {username}")
        else:
            print("Login failed. Invalid username or password.")

    def logout(self):
        # Log out the current user.
        self.current_user = None
        print("Logged out.")

    def encrypt_file(self, input_file_path):
        # Encrypt a file using the current user's public key.
        if self.current_user is None:
            print("Please log in first.")
            return

        with open(input_file_path, "rb") as file:
            plaintext = file.read()

        # Encrypt using user's public key
        ciphertext = self.current_user.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Set up paths and save the encrypted file.
        original_filename, original_extension = os.path.splitext(
            os.path.basename(input_file_path)
        )
        encrypted_folder = "encrypted"
        if not os.path.exists(encrypted_folder):
            os.makedirs(encrypted_folder)

        output_file_path = os.path.join(
            encrypted_folder, f"{original_filename}_encrypted{original_extension}"
        )

        with open(output_file_path, "wb") as file:
            file.write(ciphertext)

        print(f"File '{input_file_path}' encrypted and saved to '{output_file_path}'.")

    def decrypt_file(self, input_file_path):
        # Decrypt a file using the current user's private key.
        if self.current_user is None:
            print("Please log in first.")
            return

        with open(input_file_path, "rb") as file:
            ciphertext = file.read()

        # Decrypt using user's private key
        plaintext = self.current_user.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Set up paths and save the decrypted file.
        original_filename, original_extension = os.path.splitext(
            os.path.basename(input_file_path)
        )
        decrypted_filename = original_filename.replace("_encrypted", "_decrypted")

        decrypted_folder = "decrypted"
        if not os.path.exists(decrypted_folder):
            os.makedirs(decrypted_folder)

        output_file_path = os.path.join(
            decrypted_folder, f"{decrypted_filename}{original_extension}"
        )

        with open(output_file_path, "wb") as file:
            file.write(plaintext)

        print(f"File '{input_file_path}' decrypted and saved to '{output_file_path}'.")

if __name__ == "__main__":
    # Main program to create a SecureStorage instance and interact with the user.
    secure_storage = SecureStorage()

    while True:
        print("\nMain Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Logout")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            secure_storage.register_user(username, password)

        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            secure_storage.login(username, password)

        elif choice == "3":
            if secure_storage.current_user is None:
                print("Please log in first.")
            else:
                input_file = input("Enter the path of the file to encrypt: ")
                secure_storage.encrypt_file(input_file)

        elif choice == "4":
            if secure_storage.current_user is None:
                print("Please log in first.")
            else:
                input_file = input("Enter the path of the file to decrypt: ")
                secure_storage.decrypt_file(input_file)

        elif choice == "5":
            secure_storage.logout()

        elif choice == "6":
            secure_storage.save_users()  # Save user information before exiting
            break

        else:
            print("Invalid choice. Please enter a valid option.")
