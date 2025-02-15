import hashlib
from ecdsa import SECP256k1, keys
import base58

# Step 1: Generate a secp256k1 private key (Bitcoin private key)
private_key = keys.SigningKey.generate(curve=SECP256k1)

# Step 2: Derive the public key from the private key
public_key = private_key.get_verifying_key()

# Step 3: Perform SHA-256 and RIPEMD-160 hashing on the public key
public_key_bytes = public_key.to_string()
sha256_hash = hashlib.sha256(public_key_bytes).digest()
ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

# Step 4: Add version byte (0x00 for main network) to the hash
versioned_payload = b'\x00' + ripemd160_hash

# Step 5: Perform double SHA-256 hashing to get the checksum
checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

# Step 6: Concatenate versioned payload and checksum
address_payload = versioned_payload + checksum

# Step 7: Convert the result into a Base58 Bitcoin address
bitcoin_address = base58.b58encode(address_payload)

# Step 8: Print the Bitcoin address
print("Bitcoin Address:", bitcoin_address.decode('utf-8'))
