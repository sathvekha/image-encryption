# image-encryption
The images must be encrypted in such a way that even with arbitrary access to them via the internet, the image must not be decryptable without a secure key. This project would help you delve into the basics of cybersecurity and develop your cryptography skills.

pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def encrypt_image(input_image_path, output_encrypted_path, key):
    # Read the image file
    with open(input_image_path, 'rb') as file:
        image_data = file.read()
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the image data
    encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))
    
    # Save the IV + encrypted data
    with open(output_encrypted_path, 'wb') as enc_file:
        enc_file.write(iv + encrypted_data)
    
    print("Image encrypted successfully!")

# Generate a 16-byte key (AES-128) or use a 32-byte key for AES-256
key = b'ThisIsASecretKey'  # 16 bytes key (must be kept safe)

# Encrypt the image
encrypt_image("input.jpg", "encrypted_image.enc", key)
from Crypto.Util.Padding import unpad

def decrypt_image(input_encrypted_path, output_decrypted_path, key):
    # Read the encrypted file
    with open(input_encrypted_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    # Create AES cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and remove padding
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    # Save the decrypted image
    with open(output_decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    
    print("Image decrypted successfully!")

# Decrypt the image
decrypt_image("encrypted_image.enc", "decrypted.jpg", key)
