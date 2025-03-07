import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ✅ Load Private Key
private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAoldLeUnD8U7fw/Tp6RBhUBvCglwiOCrVt7J8xMYMg6n/aAVh
EMtKSaWrRm45FvjwkxsWvX8jeR31GQSqJ8WWFgSRdeZ0DQ5LpM2C8YRW972cEDkl
0eNfTOaWITpLLdKH4iltKId9HftkThnzcq36anu+G806p0Q6TPBu+AOcUmS7LSz/
gUFdKuaKdbfr/pD5bojmnPMg74dl4f+pmhnhlh7MeeOH92YtrKizh6XtXRCpSraH
+SuECP8y6NrpYFgc/nLBCEY/1mp1TXr5as6rL1euSwnCLhgGQrQJVvoKgqivUwC+
n5izE9OXPRIZ8UgjxktRBmszUjkVw1aVEUciDQIDAQABAoIBAAKIPozihewoaQyf
MBvazc3IVREf+0epgWJnZhNSrITMPMfkV5aBuUOrUh/b3ceaM/RzdngXuNetjDJq
9HWA2z22LgerA9HlUHA+ZWW7hPjBzCKjpY+fzo9+REa56EzLbSOttj5s2JqEXpTq
SjYWeSK6keVQnvLXeVpUYMK9Ga3eToFBxcSXBFy0qFyOIG/8OWWqRs67cdd4fWJg
ZxWec4bugaQqoSrsKFk1SK3PHzV+M9PsakpsTHtOGhAXMHl+zteEmkkOK9MQ45bB
+b2hw6jVI5UNcsggjIXNpM+lUZr8I+cPwFf15iY+a2FJDiGWXyn5F+CMvLGQLDwI
oUsv+TkCgYEAxbfETX8XrPqWdjfql8XwFggMsOkdiKuIqmmYHvpMVnrW4SSKdJ4O
O9GVFYQUe4NzXUheUF28IdHxcMpm5S0KGKxIcXj2RkcgDOwvE66Be5jXzd40seXC
FFcwOQEF2NhWr7sHsbDDNHfgoCWN4oVQYw/vlin8S980KkMAaBbAY5kCgYEA0jHp
aLroRqPhX4EbhuejG+ZJAQw8IGT38ci4UHT4hI/ozQ0IGokoC47p0vTHuHElQvZT
Z8reaONTyTU92FRKXSQpu+SYEMpGjMfUoaej0te5TwDz6GIMB/6hhgLnjA5uExOV
R1rVN3Os8IeJXwQqJqznIXAoOPN1qcZdezhwupUCgYBi1hdKSiMStH2sgQ1Da441
5TY65X1/CYia74g8zBCHFob+Kx8PZsdkvcMR62G10KNF2VxUPldCbMmOAY/oNlia
ttzL5JTv0rRB4XszEoPlviT6435iA6G+O0t+43UBzjufQxZ4jA042EgwpjVELDJg
IuI4papaXyybh7zXS7BG2QKBgBV05uC8A64CWKVJJqg0yR+1+EnVF+YuqGjUFoyQ
BDZ0Ak28QNGEosPbSN8yAZlAY49cWdNEkEOgwRLPDosgv56WbHQzt5ovK9h/JaOC
22RQhSgdbsiQCa5fPdnSPhS7/FySKTDpgs5wTn0XONysLilYiReOvWxi3eYAy9Yi
Qs+pAoGATnp8J+/aQ0JZ3ASohdijK5gb4PzjjeKInllLodZybl1enUISHbovkYoM
uGSL+Jl6pKjPQr7WJgZjFlcA9nOKGglluLdRY7moNAOEPHnNYKoQZH055LGWzVEU
CZ9YyMzmz/GRZ+u8JazN/4JEwSUinQoSRNggllM797u8Na7zROc=
-----END RSA PRIVATE KEY-----"""

# ✅ Load Private Key
private_key = RSA.import_key(private_key_pem)
cipher = PKCS1_OAEP.new(private_key)

# ✅ Encrypted Message (Ensure this is in bytes, not altered)
encrypted_message = b'\x78\xb8:\x04\x18\x82Q\x08\x93\xadz\x9a#$|2z\x94\x15r/w\xe7\xb0K\x9e\xc0b\xf9\xc03\xbb5\xff{\xd3\xfe\xa7\x95}M\x1c\xd0\xba\xdd\xf2\x8a\x08O\xf3\x16\xb2*;\xca\x83|\xdcw\xb2Z\x00\x83\x0e\x15\xfe\x9d\x1c\x0c|\x161\xfc\x1f\x14\xc6\x06_\x9bN>h\xc3k{\xa1\xc2\xda:qp\xe5\x83\xeez3\xfc49\xe1\xf1\xd8\xd0\xdf7\x06\xd2\x96\x81\xd2F~%\xf1\x89"\n\x15\\\xda8\x9c\x0e\x07\x8b\x8f\xc0\x82C\x8c\xcb\x03\xb2\xadN\xc1l~npX@\xda\xf7\x1e\xd4\x17\x9d\xf9\xfaYY\xc0\x0eO\xfe\x81\x1d\x0c%7\xfa\xe1f\x9ec\xe1\xe6\xb8\\y,rZ4\x9d\x9c\xc8\xd5(\xb5\x0c\xa4`\xe2\xf8w?P\xd2\xec\x1dc\x8c\x8fSP\xa6\xf8\xf3xl\x93\xefoK(RZD\t\x9bB_\xe4\xc3\x80F\xbc\xcf$C\x05!\r\xa3\xb7\x8e+\xd2\xac\x0f\xe0\xc5\x81W\x91\xe4\x94\x8f9q`\xba\x93MA[\x8d\xd4\xc1\x83Z\xf8aA'

try:
    # ✅ Attempt Decryption
    decrypted_message = cipher.decrypt(encrypted_message)
    print("\n🔓 Decrypted Message:", decrypted_message.decode())
except ValueError as e:
    print("\n❌ Decryption failed:", str(e))
