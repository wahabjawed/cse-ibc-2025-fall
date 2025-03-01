import hashlib
import base64
import base58


# Step 2: Hash Your Name
name = "Abaan"  # Replace with your name

# SHA-256 Hash
sha256_hash = hashlib.sha256(name.encode()).hexdigest()

# RIPEMD-160 Hash
ripemd160 = hashlib.new("ripemd160")
ripemd160.update(name.encode())
ripemd160_hash = ripemd160.hexdigest()

# SHA-3 Hash
sha3_hash = hashlib.sha3_256(name.encode()).hexdigest()

print("SHA-256 Hash:", sha256_hash)
print("RIPEMD-160 Hash:", ripemd160_hash)
print("SHA-3 Hash:", sha3_hash)

#step 2.5
public_key = hashlib.sha256(name.encode()).hexdigest()
print("Public Key:", public_key)


# Step 3: Simulate RSA Encryption
encrypted_name = base64.b64encode(name.encode()).decode()
print("Encrypted Name:", encrypted_name)

# Step 4: Simulate RSA Digital Signature
digital_signature = hashlib.sha256(name.encode()).hexdigest()
print("Digital Signature:", digital_signature)

# Step 5: Generate a Bitcoin Wallet Address
sha256_pubkey = hashlib.sha256(name.encode()).digest()
ripemd160 = hashlib.new("ripemd160", sha256_pubkey).digest()
versioned_payload = b"\x00" + ripemd160
checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
bitcoin_address = base58.b58encode(versioned_payload + checksum).decode()
print("Bitcoin Wallet Address:", bitcoin_address)