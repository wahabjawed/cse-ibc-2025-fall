# This code contains all the code for all the fields, including 
# RSA key pair, 
# Hashing the name
# encrypting the name
# signing the name using RSA and SHA256

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256, RIPEMD160
import hashlib 
import binascii

# RSA KEY PAIR QUESTION
key = RSA.generate(2048)
private_key = key.export_key();
public_key = key.publickey().export_key()
print("Private key: ", private_key.decode())
print("Public key: ", public_key.decode())


# HASHING THE NAME
name = b"ISHT DEV"
hash_sha256 = SHA256.new(name)
hash_ripemd160 = RIPEMD160.new(name)
hash_sha3 = hashlib.sha3_256(name).hexdigest()

print("hash sha256: ", hash_sha256.hexdigest())
print("hash ripemd160: ", hash_ripemd160.hexdigest())
print("hash sha3: ", hash_sha3)


# ENCRYPTING THE NAME
RSA_Cipher = PKCS1_OAEP.new(key.publickey())
encrypted_name = RSA_Cipher.encrypt(name)
print("Encrypted Message: ", binascii.hexlify(encrypted_name).decode())

# Signing the name
sign = PKCS1_v1_5.new(key).sign(hash_sha256)
print("Sign:", binascii.hexlify(sign).decode())


#NOTES: hexdigest gives answer in hexadecimal format
# Dependencies: pycryptodome library, use command "pip install pycryptodome" to install the library


