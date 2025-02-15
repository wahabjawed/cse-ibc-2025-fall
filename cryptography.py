from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA3_256, RIPEMD160
from Crypto.Util.Padding import unpad
import base58
from ecdsa import SigningKey, SECP256k1
import textwrap
import hashlib
import base64

def generate():
    print("\n--- GENERATE ---")
    name = input("Enter your name: ").encode()

    # 1. Generate RSA Key Pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print("\n[+] RSA Key Pair Generated.")
    print("Private Key (Keep this safe):\n", private_key.decode())
    print("Public Key (Share this for verification):\n", public_key.decode())

    # 2. Hash the name using different algorithms
    sha256_hash = hashlib.sha256(name).hexdigest()
    ripemd160 = RIPEMD160.new(name)
    ripemd160_hash = ripemd160.hexdigest()
    sha3_hash = hashlib.sha3_256(name).hexdigest()
    print("\n[+] Hashes Generated:")
    print("SHA-256:", sha256_hash)
    print("RIPEMD-160:", ripemd160_hash)
    print("SHA-3:", sha3_hash)

    # 3. Encrypt the name
    cipher = PKCS1_v1_5.new(key.publickey())
    encrypted_name = cipher.encrypt(name)
    print("\n[+] Encrypted Name (Base64 Encoded):", base64.b64encode(encrypted_name).decode())

    # 4. Sign the name
    hasher = SHA256.new(name)
    signature = pkcs1_15.new(key).sign(hasher)
    print("\n[+] Digital Signature (Base64 Encoded):", base64.b64encode(signature).decode())


def verify():
    print("\n--- VERIFY ---")
    # Input Public Key
    public_key_input = input("Enter the sender's RSA Public Key:\n")

    public_key_input = fix_public_key_format(public_key_input)
    public_key = RSA.import_key(public_key_input)
    
    # Input Received Data
    received_name = input("\nEnter the received name: ").encode()
    received_sha256 = input("Enter the received SHA-256 hash: ")
    received_ripemd160 = input("Enter the received RIPEMD-160 hash: ")
    received_sha3 = input("Enter the received SHA-3 hash: ")
    received_signature_b64 = input("Enter the received digital signature (Base64 Encoded): ")
    received_signature = base64.b64decode(received_signature_b64)
    
    # Verify Hashes
    sha256_hash = hashlib.sha256(received_name).hexdigest()
    ripemd160 = RIPEMD160.new(received_name).hexdigest()
    sha3_hash = hashlib.sha3_256(received_name).hexdigest()

    print("\n[+] Hash Verification:")
    print("SHA-256 Match:", sha256_hash == received_sha256)
    print("RIPEMD-160 Match:", ripemd160 == received_ripemd160)
    print("SHA-3 Match:", sha3_hash == received_sha3)

    # Verify Digital Signature
    try:
        hasher = SHA256.new(received_name)
        pkcs1_15.new(public_key).verify(hasher, received_signature)
        print("\n[+] Digital Signature Verification: Valid")
    except (ValueError, TypeError):
        print("\n[-] Digital Signature Verification: Invalid")

def fix_public_key_format(key_input):
    # Remove header, footer, and any surrounding whitespace
    key_body = key_input.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
    # Add line breaks every 64 characters
    key_body = "\n".join(textwrap.wrap(key_body, 64))
    # Re-add the headers and footers
    fixed_key = f"-----BEGIN PUBLIC KEY-----\n{key_body}\n-----END PUBLIC KEY-----"
    return fixed_key

def fix_private_key_format(key_input):
    # Remove header, footer, and any surrounding whitespace
    key_body = key_input.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").strip()
    # Add line breaks every 64 characters
    key_body = "\n".join(textwrap.wrap(key_body, 64))
    # Re-add the headers and footers
    fixed_key = f"-----BEGIN RSA PRIVATE KEY-----\n{key_body}\n-----END RSA PRIVATE KEY-----"
    return fixed_key

def send_message():
    print("\n--- SEND MESSAGE ---")
    recipient_public_key_input = input("Enter the recipient's RSA Public Key:\n")

    recipient_public_key_input = fix_public_key_format(recipient_public_key_input)
    recipient_public_key = RSA.import_key(recipient_public_key_input)

    message = input("Enter the message to encrypt: ").encode()
    
    cipher = PKCS1_v1_5.new(recipient_public_key)
    encrypted_message = cipher.encrypt(message)
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
    
    print("\n[+] Encrypted Message (Base64 Encoded):", encrypted_message_b64)
    print("\n[!] Send this to the recipient!")

def decrypt_message():
    print("\n--- DECRYPT MESSAGE ---")
    private_key_input = input("Enter your RSA Private Key:\n")

    private_key_input = fix_private_key_format(private_key_input)
    private_key = RSA.import_key(private_key_input)

    encrypted_message_b64 = input("Enter the received encrypted message (Base64 Encoded): ")
    encrypted_message = base64.b64decode(encrypted_message_b64)
    
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message, sentinel=None)
    
    print("\n[+] Decrypted Message:", decrypted_message.decode())

def bitcoin_address_generator():
    # Step 1: Generate Private Key
    private_key = SigningKey.generate(curve=SECP256k1)
    private_key_bytes = private_key.to_string()
    private_key_hex = private_key_bytes.hex()
    print("\n[INFO] Private Key (Hex):", private_key_hex)

    # Step 2: Generate Public Key
    public_key = private_key.get_verifying_key()
    public_key_bytes = b'\x04' + public_key.to_string()  # Add 0x04 prefix for uncompressed key
    public_key_hex = public_key_bytes.hex()
    print("\n[INFO] Public Key (Hex):", public_key_hex)

    # Step 3: Create Bitcoin Address
    # 3.1: SHA-256 and then RIPEMD-160
    sha256_pubkey = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pubkey)
    public_key_hash = ripemd160.digest()

    # 3.2: Add version byte (0x00 for Mainnet)
    versioned_payload = b'\x00' + public_key_hash

    # 3.3: Double SHA-256 to get checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

    # 3.4: Append checksum to versioned payload
    binary_address = versioned_payload + checksum

    # 3.5: Base58Check encode the result
    bitcoin_address = base58.b58encode(binary_address).decode()
    print("\n[INFO] Bitcoin Address:", bitcoin_address)

def main():
    while True:
        print("\n=== CRYPTOGRAPHY TUTORIAL ===")
        print("1. Generate (Keys, Hashes, Signature)")
        print("2. Verify (Hashes and Digital Signature)")
        print("3. Send Message (Encrypt)")
        print("4. Decrypt Message")
        print("5. Bitcoin Address Generator")
        print("6. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            generate()
        elif choice == '2':
            verify()
        elif choice == '3':
            send_message()
        elif choice == '4':
            decrypt_message()
        elif choice == '5':
            bitcoin_address_generator()
        elif choice == '6':
            print("\n[!] Exiting...")
            break
        else:
            print("\n[-] Invalid option. Try again.")

if __name__ == "__main__":
    main()
