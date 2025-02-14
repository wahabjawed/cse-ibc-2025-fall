import hashlib

# Your name
name = "AARAIZ MASOOD"

# Create a hash object using SHA-256
hash_object = hashlib.sha3_256()

# Update the hash object with the bytes of your name
hash_object.update(name.encode('utf-8'))

# Get the hexadecimal digest of the hash
hex_digest = hash_object.hexdigest()

# Print the hex-encoded hash
print(hex_digest)