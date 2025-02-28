import hashlib
import binascii
import base58

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes

#RSA key pair 
rsa_private_key  = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = rsa_private_key.public_key()


rsa_private_pem  = rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
rsa_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
ecdsa_public_key = ecdsa_private_key.public_key()


# Serialize ECDSA Public Key in Compressed Format
ecdsa_public_bytes = ecdsa_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)

name = "Hammadullah Muazam"

#SHA256
sha256_digest = hashlib.sha256(name.encode()).hexdigest()

#RIPEMD160
ripemd160 = hashlib.new('ripemd160', name.encode())
ripemd160_digest = ripemd160.hexdigest()

# SHA3-256
sha3_256_digest = hashlib.sha3_256(name.encode()).hexdigest()

#encrypting name
ciphertext = public_key.encrypt(
    name.encode(),
    padding.PKCS1v15()
)

#signing name
signature = rsa_private_key.sign(
    name.encode(),
    padding.PKCS1v15(),
    hashes.SHA256()
)

#bitcoin wallet address
sha256_pub = hashlib.sha256(ecdsa_public_bytes).digest()
ripemd160_pub = hashlib.new('ripemd160', sha256_pub).digest()

version = b'\x00'
payload = version + ripemd160_pub

checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

address_bytes = payload + checksum
bitcoin_address = base58.b58encode(address_bytes).decode('utf-8')


#output
print("RSA Private Key:\n", rsa_private_pem.decode())
print("\nRSA Public Key:\n", rsa_public_pem.decode())
print("\nSHA-256 Digest:", sha256_digest)
print("RIPEMD-160 Digest:", ripemd160_digest)
print("SHA3-256 Digest:", sha3_256_digest)
print("\nEncrypted Name (Hex):", ciphertext.hex())
print("\nSignature (Hex):", signature.hex())
print("\nBitcoin Address:", bitcoin_address)
