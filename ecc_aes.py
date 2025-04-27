from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Function to perform ECC key exchange and derive a shared AES key
def ecc_key_exchange(curve):
    # Generate ECC key pairs
    alice_private_key = ec.generate_private_key(curve())
    bob_private_key = ec.generate_private_key(curve())

    # Exchange public keys
    alice_public_key = alice_private_key.public_key()
    bob_public_key = bob_private_key.public_key()

    # Perform ECDH key exchange
    alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

    # Verify both derived the same secret
    assert alice_shared_secret == bob_shared_secret, "Key exchange failed!"

    # Derive a symmetric key using HKDF (Hash-based Key Derivation Function)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b"ECC AES Key",
    ).derive(alice_shared_secret)

    return aes_key

# Function to encrypt message using AES-GCM
def encrypt_message(aes_key, plaintext):
    iv = os.urandom(12)  # Generate a random IV (12 bytes for AES-GCM)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag  # Return IV, ciphertext, and authentication tag

# Function to decrypt message using AES-GCM
def decrypt_message(aes_key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Message to encrypt
message = "Hell0 SRM AP"

# Test with SECP256R1 curve
print("Using SECP256R1 curve:")
aes_key1 = ecc_key_exchange(ec.SECP256R1)
iv1, ciphertext1, tag1 = encrypt_message(aes_key1, message)
decrypted_message1 = decrypt_message(aes_key1, iv1, ciphertext1, tag1)
print("Ciphertext:", ciphertext1.hex())
print("Decrypted message:", decrypted_message1, "\n")

# Test with SECP384R1 curve
print("Using SECP384R1 curve:")
aes_key2 = ecc_key_exchange(ec.SECP384R1)
iv2, ciphertext2, tag2 = encrypt_message(aes_key2, message)
decrypted_message2 = decrypt_message(aes_key2, iv2, ciphertext2, tag2)
print("Ciphertext:", ciphertext2.hex())
print("Decrypted message:", decrypted_message2, "\n")