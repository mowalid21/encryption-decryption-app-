# encryption_interface.py
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from PIL import ImageTk ,Image

from encryption_functions import EncryptionApp

class EncryptionInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptini by Walid")
        self.root.geometry("600x800")
        self.root.iconbitmap("téléchargement.ico")


        self.root.configure(bg="cyan")
        self.encryption_app = EncryptionApp()
        

        # Create UI elements
        self.label = tk.Label(root, text="© mohamed walid sammari ", font=("Arial", 16), fg="black", bg="cyan")
        self.label.pack(pady=10)

        # Entry for manual key entry
        self.manual_key_entry_label = tk.Label(root, text="Enter Key Manually:", font=("Arial", 12), fg="black", bg="cyan")
        self.manual_key_entry_label.pack(pady=5)
        self.manual_key_entry = tk.Entry(root, font=("Arial", 12))
        self.manual_key_entry.pack(pady=5)

        # Entry for encryption
        self.encrypt_text_label = tk.Label(root, text="Encrypt Text:", font=("Arial", 12), fg="black", bg="cyan")
        self.encrypt_text_label.pack(pady=5)
        self.encrypt_text_entry = tk.Entry(root, font=("Arial", 12))
        self.encrypt_text_entry.pack(pady=5)

        # Entry for decryption
        self.decrypt_text_label = tk.Label(root, text="Decrypt Text:", font=("Arial", 12), fg="black", bg="cyan")
        self.decrypt_text_label.pack(pady=5)
        self.decrypt_text_entry = tk.Entry(root, font=("Arial", 12))
        self.decrypt_text_entry.pack(pady=5)

        # Buttons
        self.generate_key_button = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.generate_key_button.pack(pady=5)

        self.enter_key_button = tk.Button(root, text="Enter Key Manually", command=self.enter_key_manually)
        self.enter_key_button.pack(pady=5)

        self.encrypt_text_button = tk.Button(root, text="Encrypt Text", command=self.encrypt_text)
        self.encrypt_text_button.pack(pady=5)

        self.decrypt_text_button = tk.Button(root, text="Decrypt Text", command=self.decrypt_text)
        self.decrypt_text_button.pack(pady=5)

        self.encrypt_file_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.pack(pady=5)

        self.decrypt_file_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.pack(pady=5)

        self.exit_button = tk.Button(root, text="Exit", command=root.destroy)
        self.exit_button.pack(pady=5)

        # Text box for displaying results
        self.result_textbox = tk.Text(root, height=10, width=50, font=("Arial", 12), wrap=tk.WORD)
        self.result_textbox.pack(pady=10)

    def generate_key(self):
        self.encryption_app.generate_key()
        messagebox.showinfo("Key Generated", "Key generated successfully.")

    def enter_key_manually(self):
        key_str = self.manual_key_entry.get()
        try:
            self.encryption_app.key = bytes.fromhex(key_str)
            if len(self.encryption_app.key) != 32:
                raise ValueError("Key must be 32 bytes long.")
            messagebox.showinfo("Key Entered", "Key entered successfully.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def encrypt_text(self):
        try:
            self.encryption_app._check_key()
            text = self.encrypt_text_entry.get()
            if text:
                encrypted_text = self.encryption_app.encrypt_text(text)
                self.result_textbox.insert(tk.END, f"Encrypted Text:\n{encrypted_text.hex()}\n\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        try:
            self.encryption_app._check_key()
            encrypted_text = self.decrypt_text_entry.get()
            if encrypted_text:
                encrypted_bytes = bytes.fromhex(encrypted_text)
                decrypted_text = self.encryption_app.decrypt_text(encrypted_bytes)
                self.result_textbox.insert(tk.END, f"Decrypted Text:\n{decrypted_text}\n\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file(self):
        try:
            self.encryption_app._check_key()
            file_path = filedialog.askopenfilename(title="Select File to Encrypt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'r') as file:
                    text = file.read()
                    encrypted_text = self.encryption_app.encrypt_text(text)
                    encrypted_file_path = filedialog.asksaveasfilename(
                        title="Save Encrypted File As",
                        filetypes=[("Text files", "*.txt")],
                        defaultextension=".txt"
                    )
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(encrypted_text)
                    self.result_textbox.insert(tk.END, f"File encrypted successfully.\n"
                                                       f"Encrypted file saved as '{encrypted_file_path}'.\n\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        try:
            self.encryption_app._check_key()
            file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'rb') as file:
                    encrypted_text = file.read()
                    decrypted_text = self.encryption_app.decrypt_text(encrypted_text)
                    decrypted_file_path = filedialog.asksaveasfilename(
                        title="Save Decrypted File As",
                        filetypes=[("Text files", "*.txt")],
                        defaultextension=".txt"
                    )
                    with open(decrypted_file_path, 'w') as decrypted_file:
                        decrypted_file.write(decrypted_text)
                    self.result_textbox.insert(tk.END, f"File decrypted successfully.\n"
                                                       f"Decrypted file saved as '{decrypted_file_path}'.\n\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    interface = EncryptionInterface(root)
    root.mainloop()
