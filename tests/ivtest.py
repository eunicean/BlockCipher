from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys
import os
module_dir = os.path.join(os.getcwd(), 'src')
sys.path.append(module_dir)

from generacion_llaves import generate_aes_key, generate_iv

key = generate_aes_key(key_size=128)
message = b"Mensaje secreto!"

# Caso 1: mismo IV
iv_fijo = b'\x00' * 16
cipher1 = AES.new(key, AES.MODE_CBC, iv_fijo)
cipher2 = AES.new(key, AES.MODE_CBC, iv_fijo)
ct1 = cipher1.encrypt(pad(message, 16))
ct2 = cipher2.encrypt(pad(message, 16))
print("Mismo IV:")
print(f"  CT1: {ct1.hex()}")
print(f"  CT2: {ct2.hex()}")
print(f"  Iguales: {ct1 == ct2}")   # True ← peligroso

# Caso 2: IVs distintos
iv1 = generate_iv(block_size=16)
iv2 = generate_iv(block_size=16)
cipher3 = AES.new(key, AES.MODE_CBC, iv1)
cipher4 = AES.new(key, AES.MODE_CBC, iv2)
ct3 = cipher3.encrypt(pad(message, 16))
ct4 = cipher4.encrypt(pad(message, 16))
print("\nIVs diferentes:")
print(f"  CT3: {ct3.hex()}")
print(f"  CT4: {ct4.hex()}")
print(f"  Iguales: {ct3 == ct4}")