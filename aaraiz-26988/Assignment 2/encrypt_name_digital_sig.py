from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Step 1: Generate RSA Key Pair (Private and Public)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Public key for encryption
public_key = private_key.public_key()

# Your name to encrypt and sign
name = "AARAIZ MASOOD"

# Step 2: Encrypt the name using the public key
encrypted_name = public_key.encrypt(
    name.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 3: Sign the name using the private key with SHA-256 and PKCS#1 v1.5
signature = private_key.sign(
    name.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Print the encrypted name (hex encoded for readability)
print("Encrypted Name (Hex):")
print(encrypted_name.hex())

# Print the digital signature (hex encoded for readability)
print("\nDigital Signature (PKCS#1 v1.5, SHA-256):")
print(signature.hex())

# Serialize the private key to PEM format and save it to a file
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Save the private key to a PEM file
with open("private_key.pem", "wb") as private_key_file:
    private_key_file.write(pem_private_key)

# Serialize the public key to PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print the public key in PEM format
print("\nPublic Key (PEM):")
print(pem_public_key.decode('utf-8'))

# Optionally, save the public key to a file (if needed)
with open("public_key.pem", "wb") as public_key_file:
    public_key_file.write(pem_public_key)
