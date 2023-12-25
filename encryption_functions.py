# encryption_functions.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from constants import AES

class EncryptionApp:
    def __init__(self):
        self.key = None

    def generate_key(self):
        # Generate a random key
        self.key = os.urandom(32)

    def enter_key_manually(self):
        # Allow the user to enter a key manually
        key_str = input("Enter a 32-byte key in hexadecimal format (e.g., 00112233445566778899aabbccddeeff): ")
        try:
            self.key = bytes.fromhex(key_str)
            if len(self.key) != 32:
                raise ValueError("Key must be 32 bytes long.")
        except ValueError as e:
            print(f"Error: {e}")
            print("Key not set. Please generate a key or enter a valid key manually.")

    def _check_key(self):
        if not self.key:
            raise ValueError("Key not generated or entered manually. Please generate a key or enter a valid key manually.")

    def encrypt_text(self, text):
        self._check_key()

        # Generate a random initialization vector (iv)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
        return iv + encrypted_text  # Prepend the iv to the encrypted text

    def decrypt_text(self, encrypted_text):
        self._check_key()

        # Extract the iv from the first 16 bytes
        iv = encrypted_text[:16]
        ciphertext = encrypted_text[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text.decode()
