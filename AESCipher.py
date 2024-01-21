import base64
import hashlib
from aes import run, Direction

class AESCipher(object):

    def __init__(self, key, cipher_file_path):
        self.bs = 16  # Adjusted block size to match the AES block size used in aes.py
        # self.key = hashlib.sha256(key.encode()).digest()[:128]
        self.key = key[:128]
        self.cipher_file_path = cipher_file_path

    def encrypt(self, raw):
        raw = self._pad(raw)
        # Use the run function from aes.py for encryption
        encrypted_data = run(Direction.ENCRYPT, raw, self.key, self.cipher_file_path)
        return encrypted_data

    def decrypt(self, enc):
        # Use the run function from aes.py for decryption
        decrypted_data = run(Direction.DECRYPT, enc, self.key, self.cipher_file_path)
        return decrypted_data

    def _pad(self, s):
        pad_len = self.bs - len(s) % self.bs
        return s + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(s):
        pad_len = s[-1]
        return s[:-pad_len]

# # Example usage:
# key = "your_secret_key"  # Replace with your secret key
# aes_cipher = AESCipher(key)

# text_to_encrypt = "Hello, this is a test!"
# encrypted_text = aes_cipher.encrypt(text_to_encrypt)
# print(f"Encrypted: {encrypted_text}")

# decrypted_text = aes_cipher.decrypt(encrypted_text)
# print(f"Decrypted: {decrypted_text}")
