from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate Alice's ECC key pair
alice_private_key = ec.generate_private_key(ec.SECP256R1())  # You can use other curves like SECP384R1
alice_public_key = alice_private_key.public_key()

# Generate Bob's ECC key pair
bob_private_key = ec.generate_private_key(ec.SECP256R1())
bob_public_key = bob_private_key.public_key()

# Serialize and exchange public keys (simulated)
alice_public_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

bob_public_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Deserialize received public keys (simulated exchange)
alice_received_public_key = serialization.load_pem_public_key(alice_public_bytes)
bob_received_public_key = serialization.load_pem_public_key(bob_public_bytes)

# Perform key exchange (derive shared secret)
alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_received_public_key)
bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_received_public_key)

# Verify that both shared secrets are the same
assert alice_shared_secret == bob_shared_secret
print("Key exchange successful! \nShared secret:", alice_shared_secret.hex())