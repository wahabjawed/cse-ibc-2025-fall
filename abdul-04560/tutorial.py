import hashlib
import ecdsa
from ecdsa import SECP256k1
from Crypto.Hash import RIPEMD

# Step 2: Generate ECDSA keypair
private_key = ecdsa.SigningKey.generate(curve=SECP256k1)
public_key = private_key.get_verifying_key()
private_key_hex = private_key.to_string().hex()
public_key_hex = public_key.to_string().hex()
print("Private key:", private_key_hex)
print("Public key:", public_key_hex)

# Helper method to compress the public key
def compress_pub_key(pub_key):
    x_hex = pub_key.to_string("compressed").hex()
    y_prefix = "03" if int(x_hex, 16) % 2 == 1 else "02"
    return y_prefix + x_hex[2:]

compressed_public_key = compress_pub_key(public_key)
print("Compressed Public key:", compressed_public_key)

# Step 3: Generate SHA-256 hash
sha256 = hashlib.sha256()
sha256.update(bytes.fromhex(compressed_public_key))
s1 = sha256.digest()
print("SHA256:", s1.hex())

# Calculate RIPEMD-160 hash using pycryptodome's RIPEMD
ripemd160_hash = RIPEMD.new()
ripemd160_hash.update(s1)
r1 = ripemd160_hash.digest()
print("RIPEMD160:", r1.hex())

#Private key: c41bf3513c87d097899df187a3cdfd1b16537de9e390d016d3c0fc358c460ad6
#Public key: ad2c67bde346eb5ec836e43aaddeff3b55e9b26a6896359090f1eb797b15358fbe96a92f7b6dd38c1dc1f143dc224fb9027aae4003a18f63791329c903f9a334
#Compressed Public key: 03ad2c67bde346eb5ec836e43aaddeff3b55e9b26a6896359090f1eb797b15358f
#SHA256: d4c9b9c24ff7b994e38179eb3a2760ca5c4cd7ca8d5dd34d2e28a3aa7267eadb
#RIPEMD160: 8e74e2bde93c1274e14bc5a4672874347df9cd7e
