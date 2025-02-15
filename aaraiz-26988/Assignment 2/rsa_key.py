from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate the private key
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Common choice for public exponent
    key_size=2048
)

# Serialize the private key to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Print the private key to the console
print(pem.decode('utf-8'))