import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

module_dir = os.path.join(os.getcwd(), 'src')
sys.path.append(module_dir)

from generacion_llaves import generate_aes_key, generate_iv

key = generate_aes_key(key_size=128)
message = b"ATAQUE  ATAQUE  ATAQUE ATAQUE  ATAQUE  ATAQUE"  # 3 bloques de 8 bytes idénticos (ajustado a 16 con espacios)

# ECB
cipher_ecb = AES.new(key, AES.MODE_ECB)
ct_ecb = cipher_ecb.encrypt(pad(message, 16))

# CBC
iv = generate_iv(block_size=16)
cipher_cbc = AES.new(key, AES.MODE_CBC, iv)
ct_cbc = cipher_cbc.encrypt(pad(message, 16))

print("ECB (hex):")
for i in range(0, len(ct_ecb), 16):
    print(f"  Bloque {i//16}: {ct_ecb[i:i+16].hex()}")

print("\nCBC (hex):")
for i in range(0, len(ct_cbc), 16):
    print(f"  Bloque {i//16}: {ct_cbc[i:i+16].hex()}")