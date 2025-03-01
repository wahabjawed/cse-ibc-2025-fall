import hashlib
import base64
import base58
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Step 1: Generate RSA Key Pair (Private & Public Keys)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save keys to files (optional)
with open("private_key.pem", "wb") as priv_file:
    priv_file.write(private_key)

with open("public_key.pem", "wb") as pub_file:
    pub_file.write(public_key)

print("\n✅ RSA Key Pair Generated Successfully!")
print("Public Key:\n", public_key.decode())

# Step 2: Hash Your Name
name = "Abaan"  # Replace with your own name

sha256_hash = hashlib.sha256(name.encode()).hexdigest()
ripemd160 = hashlib.new("ripemd160", name.encode()).hexdigest()
sha3_hash = hashlib.sha3_256(name.encode()).hexdigest()

print("\n✅ Hashed Values:")
print("SHA-256:", sha256_hash)
print("RIPEMD-160:", ripemd160)
print("SHA-3:", sha3_hash)

# Step 3: Encrypt Name Using Base64 (Simulated Encryption)
encrypted_name = base64.b64encode(name.encode()).decode()
print("\n✅ Encrypted Name (Base64 Encoded):", encrypted_name)

# Step 4: Generate a Digital Signature (Using RSA)
name_hash = SHA256.new(name.encode())
signature = pkcs1_15.new(key).sign(name_hash)
print("\n✅ Digital Signature Generated Successfully!")
print("Digital Signature (Base64 Encoded):", base64.b64encode(signature).decode())

# Step 5: Generate Bitcoin Wallet Address
sha256_pubkey = hashlib.sha256(public_key).digest()
ripemd160_pubkey = hashlib.new("ripemd160", sha256_pubkey).digest()
versioned_payload = b"\x00" + ripemd160_pubkey
checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
bitcoin_address = base58.b58encode(versioned_payload + checksum).decode()

print("\n✅ Bitcoin Wallet Address:", bitcoin_address)