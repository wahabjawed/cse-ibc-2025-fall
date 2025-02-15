import os
import ecdsa
import hashlib
import base58

# Generating private key
private_key = os.urandom(32)

# Generating public key
sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
public_key = b'\x04' + vk.to_string()  # Prefix 0x04 for uncompressed public key

# Generating the Bitcoin address from below

# Performing SHA-256 hash on the public key
sha256_hash = hashlib.sha256(public_key).digest()

# Performing RIPEMD160 hash on the SHA-256 hash
ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

# Adding version byte (0x00 for Bitcoin mainnet)
versioned_data = b'\x00' + ripemd160_hash

# Performing double SHA-256 to generate a checksum
checksum = hashlib.sha256(hashlib.sha256(versioned_data).digest()).digest()[:4]

# Concatenating the versioned payload with the checksum
address_with_checksum = versioned_data + checksum

# Encoding in Base58Check
bitcoin_address = base58.b58encode(address_with_checksum).decode('utf-8')

print("Private Key (Hex):", private_key.hex())
print("Public Key (Hex):", public_key.hex())
print("Bitcoin Address:", bitcoin_address)
