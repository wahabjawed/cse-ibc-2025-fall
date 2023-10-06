from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

# Generate a random Bitcoin private key (256-bit)
private_key = SigningKey.generate(curve=SECP256k1)

# Get the corresponding public key in bytes
public_key_bytes = private_key.get_verifying_key().to_string()

# Compute the Bitcoin address
# Step 1: Hash the public key using SHA-256
sha256_hash = hashlib.sha256(public_key_bytes).digest()

# Step 2: Hash the SHA-256 result using RIPEMD-160
ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()

# Step 3: Add a network byte (0x00 for mainnet)
network_byte = b"\x00"  # Mainnet

# Step 4: Append the network byte to the RIPEMD-160 hash
extended_hash = network_byte + ripemd160_hash

# Step 5: Compute the double SHA-256 hash of the extended hash
double_sha256_hash = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()

# Step 6: Take the first 4 bytes of the double SHA-256 hash as the checksum
checksum = double_sha256_hash[:4]

# Step 7: Append the checksum to the extended hash to create the address
address_bytes = extended_hash + checksum

# Step 8: Encode the address in Base58
bitcoin_address = base58.b58encode(address_bytes)

print("Bitcoin Private Key (Hex):", private_key.to_string().hex())
print("Bitcoin Public Key (Hex):", public_key_bytes.hex())
print("Bitcoin Address:", bitcoin_address.decode("utf-8"))
