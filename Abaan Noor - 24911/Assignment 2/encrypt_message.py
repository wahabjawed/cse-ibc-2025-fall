import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ✅ Correctly formatted partner's public key
partner_public_key_pem = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxgHa8QDwzqhwu8lDboX+
hiZ+SRYyn1PF0Gu+hrWiywQ4FZKozbc0wPibZ3JhXznI0qh589fYs1KaH59m7hwf
2kX7foR0/M1HDQEsp5jZBkWPnGE3ykklGT/VVySPHOQdrBpacGxf9yqQkS/OvUgp
GyJ/5NQQoE45g4hvps0uyKG/g+FTDELl+s924VEqESnxTBfaRGhQXed3BA/UCP41
29iAd0mlQa+5i5Nmppto/KMFbwumq9NvJduLe+BS5oBVFPa3hdFW1L/spPbwBkSF
lAa3FoKA9+jyqEZNm8YKa0++TkBmdtczxWCzo4zhteudh2iM01yNJETtgO7A5PCz
dwIDAQAB"""

# ✅ Convert Public Key from String to RSA Format
partner_public_key = RSA.import_key(partner_public_key_pem)

# ✅ Create RSA Cipher Object
cipher = PKCS1_OAEP.new(partner_public_key)

# ✅ Message to Encrypt
message = "shapatar"

# ✅ Encrypt the Message
encrypted_message = cipher.encrypt(message.encode())

# ✅ Encode to Base64 (So It Can Be Sent Easily)
encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

print("\n✅ Encrypted Message (Base64 Encoded):")
print(encrypted_message_b64)
