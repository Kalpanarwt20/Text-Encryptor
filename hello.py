import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, Button
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import pyperclip

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Text Encryption Project")

        self.text_box = scrolledtext.ScrolledText(master, width=60, height=10)
        self.text_box.pack(pady=10)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.show_encrypt_options)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.show_decrypt_options)
        self.decrypt_button.pack()

        self.about_button = tk.Button(master, text="About", command=self.about)
        self.about_button.pack()

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack()

    def show_encrypt_options(self):
        self.clear_text_box()
        self.sub_menu = tk.Toplevel(self.master)
        self.sub_menu.title("Encryption Options")

        encrypt_aes_button = tk.Button(self.sub_menu, text="AES Encryption", command=self.encrypt_aes)
        encrypt_aes_button.pack()

        encrypt_des_button = tk.Button(self.sub_menu, text="DES Encryption", command=self.encrypt_des)
        encrypt_des_button.pack()

        encrypt_rsa_button = tk.Button(self.sub_menu, text="RSA Encryption", command=self.encrypt_rsa)
        encrypt_rsa_button.pack()

        back_button = tk.Button(self.sub_menu, text="Back", command=self.sub_menu.destroy)
        back_button.pack()

    def show_decrypt_options(self):
        self.clear_text_box()
        self.sub_menu = tk.Toplevel(self.master)
        self.sub_menu.title("Decryption Options")

        decrypt_aes_button = tk.Button(self.sub_menu, text="AES Decryption", command=self.decrypt_aes)
        decrypt_aes_button.pack()

        decrypt_des_button = tk.Button(self.sub_menu, text="DES Decryption", command=self.decrypt_des)
        decrypt_des_button.pack()

        decrypt_rsa_button = tk.Button(self.sub_menu, text="RSA Decryption", command=self.decrypt_rsa)
        decrypt_rsa_button.pack()

        back_button = tk.Button(self.sub_menu, text="Back", command=self.sub_menu.destroy)
        back_button.pack()

    def clear_text_box(self):
        self.text_box.delete("1.0", tk.END)

    def generate_aes_key(self):
        """Generates a random key for AES encryption"""
        key = Fernet.generate_key()
        return key

    def generate_rsa_keypair(self, key_size=2048):
        """Generates a key pair (public & private) for RSA encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_des_key(self):
        """Generates a random key for DES encryption"""
        key = os.urandom(8)  # 8 bytes key for DES
        return key

    def encrypt_aes(self):
        text = self.text_box.get("1.0", tk.END)
        key = self.generate_aes_key()
        ciphertext = self.encrypt_text(text, key)
        self.show_encrypted_text(ciphertext, key)

    def decrypt_aes(self):
        ciphertext_hex = simpledialog.askstring("Input", "Enter ciphertext (in hex format):")
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex format")
            return

        key = simpledialog.askstring("Input", "Enter AES key:")
        try:
            decrypted_text = self.decrypt_text(ciphertext, key)
            self.show_decrypted_text(decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_des(self):
        text = self.text_box.get("1.0", tk.END)
        key = self.generate_des_key()
        ciphertext = self.encrypt_text(text, key)
        self.show_encrypted_text(ciphertext, key)

    def decrypt_des(self):
        ciphertext_hex = simpledialog.askstring("Input", "Enter ciphertext (in hex format):")
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex format")
            return

        key = simpledialog.askstring("Input", "Enter DES key:")
        try:
            decrypted_text = self.decrypt_text(ciphertext, key)
            self.show_decrypted_text(decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_rsa(self):
        text = self.text_box.get("1.0", tk.END)
        private_key, public_key = self.generate_rsa_keypair()
        ciphertext = public_key.encrypt(
            text.encode(),
            rsa.OAEP(
                mgf=rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.show_encrypted_text(ciphertext, private_key)

    def decrypt_rsa(self):
        ciphertext_hex = simpledialog.askstring("Input", "Enter ciphertext (in hex format):")
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex format")
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        decrypted_text = private_key.decrypt(
            ciphertext,
            rsa.OAEP(
                mgf=rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.show_decrypted_text(decrypted_text.decode())

    def encrypt_text(self, text, key):
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(text.encode())
        return ciphertext.hex()

    def decrypt_text(self, ciphertext_hex, key):
        fernet = Fernet(key)
        plaintext = fernet.decrypt(ciphertext_hex).decode()
        return plaintext

    def show_encrypted_text(self, ciphertext, key):
        messagebox.showinfo("Encrypted Text", ciphertext)
        copy_button_encryption = Button(self.sub_menu, text="Copy Encryption Key", command=lambda: pyperclip.copy(key))
        copy_button_encryption.pack()
        copy_button_decryption = Button(self.sub_menu, text="Copy Decryption Key", command=lambda: pyperclip.copy(key))
        copy_button_decryption.pack()
        copy_button_ciphertext = Button(self.sub_menu, text="Copy Ciphertext", command=lambda: pyperclip.copy(ciphertext))
        copy_button_ciphertext.pack()

    def show_decrypted_text(self, plaintext):
        messagebox.showinfo("Decrypted Text", plaintext)
        copy_button = Button(self.sub_menu, text="Copy Plaintext", command=lambda: pyperclip.copy(plaintext))
        copy_button.pack()

    def about(self):
        messagebox.showinfo("About", "This is a simple text encryption project. It allows you to encrypt and decrypt text using various algorithms. DES encryption is included for educational purposes only.")

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()