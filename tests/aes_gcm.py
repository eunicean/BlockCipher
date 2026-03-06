from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)   # AES-256
nonce = get_random_bytes(16)

# Cifrar
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(b"Mensaje secreto")

# Descifrar y verificar integridad
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
print(plaintext)  # b"Mensaje secreto"