# hasaan_ahmed_saeed_22955

import hashlib
import base58
import base64

def generate_bitcoin_address(private_key_str, public_key_str):
    # Decode from Base64
    private_key_bytes = base64.b64decode(private_key_str)
    public_key_bytes = base64.b64decode(public_key_str)

    # Convert to hexadecimal format
    private_key_hex = private_key_bytes.hex()
    public_key_hex = public_key_bytes.hex()

    # Perform SHA-256 on the public key
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()

    # Perform RIPEMD-160 hashing
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    # Add the version byte (0x00 for Mainnet)
    address_bytes = b'\x00' + ripemd160_hash

    # Perform double SHA-256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]

    # Concatenate the address bytes and checksum
    address_bytes += checksum

    # Encode the result in Base58
    wallet_address = base58.b58encode(address_bytes).decode()

    return wallet_address

# Replace with your actual keys in Base64 format
private_key_str = "MIICXAIBAAKBgQCvvRnFHjRU+Z1L/QOavKAm0RNUsvQhqZgrefZrEtI4+Gh+XuItZkLH5Tk54l5OVYDDjU6V8hRYjewSC3hZDzx7cNYGAi8XmZIbx7DXXGxMbBYp91WbfnEket/fhqK76Vt8kvDiRBeMKVVXh3vd0z6jU+R1NtDp9EqogEyuUEwhEwIDAQABAoGAHpXcvE/Lb9aZp7X7QJz/ioHsyVrz3j/z+e0aE/yMldm15fiBiME5cizUztw06ZE7/czEFpixLdBVe7Z/VZCvR8q+QGwz2I7yZ491PDpxoLIvoF1IqLn6aZkpeB3XQkWyFUNV9ifPlZkS2dwT6WBDAXwjhaOon2SMw27IqqAyPUECQQDXsw702kGUA1rENZ3sruDhQnHrWKsG1EKorNrS3fX8oxa6N2wwwZNntejz0coLBhzq6056+/FWIkTaE+57kBIxAkEA0JK2LYKx9VTKk/XHBcLTdrWtEtVB7QQXNAhYb19Sfpm3pZGcjNrx9qBPC0w6M/HrvjG3SyfP4KJlonLktclygwJAVpb+KRM5Ajc6h8vSYwJtKmCnJMhKmAo73ETP75jFOC8sX4MCPqxnBVpEcyTDzBsfHrtpnPtpDZ/iLf2UXiwe8QJAazjw1Kaai69iUPwJq2mDwkQVTFg7gvgWYZZkuCR9yT2GzmPz4elweEPjPsCaLzgP4/+05br6v9VcgE2mS9natwJBAIjO4n8t+dkuoBycCNFHn5idpDv8t+XpMfBGeToLl6La8iXu+stIQVDvFcl9lcDlMLncMQCdnCRFETkj1rfTrqc="
public_key_str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvvRnFHjRU+Z1L/QOavKAm0RNUsvQhqZgrefZrEtI4+Gh+XuItZkLH5Tk54l5OVYDDjU6V8hRYjewSC3hZDzx7cNYGAi8XmZIbx7DXXGxMbBYp91WbfnEket/fhqK76Vt8kvDiRBeMKVVXh3vd0z6jU+R1NtDp9EqogEyuUEwhEwIDAQAB"

wallet_address = generate_bitcoin_address(private_key_str, public_key_str)

print(f"Bitcoin Wallet Address: {wallet_address}")
