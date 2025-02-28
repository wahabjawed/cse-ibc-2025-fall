import rsa
import hashlib
import base58
import ecdsa
from Cryptodome.Hash import RIPEMD160
import base64

# 1. Generate RSA keys with PEM formatting
def generate_rsa_keys():
    pub_key, priv_key = rsa.newkeys(2048)
    return {
        "rsa_private": priv_key.save_pkcs1().decode('utf-8'),
        "rsa_public": pub_key.save_pkcs1().decode('utf-8')
    }

# 2. Hash generation with multiple algorithms
def generate_hashes(name):
    data = name.encode()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
        "ripemd160": RIPEMD160.new(data).hexdigest()
    }

# 3. RSA signing with formatted output
def rsa_signature(name, private_key):
    signature = rsa.sign(name.encode(), private_key, "SHA-256")
    return {
        "message": name,
        "signature_b64": base64.b64encode(signature).decode(),
        "signature_hex": signature.hex()
    }

# 4. Bitcoin address generation with proper key formatting
def generate_bitcoin_wallet():
    # Generate ECDSA keys
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    
    # Format private key (WIF format)
    wif_private = base58.b58encode_check(b'\x80' + private_key.to_string())
    
    # Generate address
    sha256 = hashlib.sha256(public_key.to_string()).digest()
    ripemd160 = RIPEMD160.new(sha256).digest()
    address = base58.b58encode_check(b'\x00' + ripemd160)
    
    return {
        "btc_private_wif": wif_private.decode(),
        "btc_public_hex": public_key.to_string().hex(),
        "btc_address": address.decode()
    }

# Main execution
if __name__ == "__main__":
    # Generate and display all components
    rsa_keys = generate_rsa_keys()
    hashes = generate_hashes("Muhammad Musab Suhail")
    signature = rsa_signature("Muhammad Musab Suhail", rsa.PrivateKey.load_pkcs1(rsa_keys["rsa_private"].encode()))
    bitcoin_wallet = generate_bitcoin_wallet()
    
    # Display formatted output
    print("=== RSA Keys ===")
    print(f"Private Key (PEM):\n{rsa_keys['rsa_private']}\n")
    print(f"Public Key (PEM):\n{rsa_keys['rsa_public']}\n")
    
    print("=== Hashes ===")
    print(f"SHA-256: {hashes['sha256']}")
    print(f"SHA3-256: {hashes['sha3_256']}")
    print(f"RIPEMD-160: {hashes['ripemd160']}\n")
    
    print("=== RSA Signature ===")
    print(f"Message: {signature['message']}")
    print(f"Base64 Signature: {signature['signature_b64']}")
    print(f"Hexadecimal Signature: {signature['signature_hex']}\n")
    
    print("=== Bitcoin Wallet ===")
    print(f"Private Key (WIF): {bitcoin_wallet['btc_private_wif']}")
    print(f"Public Key (hex): {bitcoin_wallet['btc_public_hex']}")
    print(f"Address: {bitcoin_wallet['btc_address']}")


