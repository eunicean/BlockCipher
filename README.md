# Laboratorio 3: Block Cipher

## **Instalación y uso**
```bash
pip install -r requirements.txt
```

## **Ejemplo de ejecución**
Test prehechos
```
python src\aes_cipher.py
python src\des_cipher.py
python src\tripledes_cipher.py
```
Resultados de Cifrado de imagen AES en el folder [Imagenes](images)

Encriptado ecb
![ecb](images\encrypted_ecb_pad.bmp)

Encriptado cbc
![cbc](images\encrypted_cbc_pad.bmp)

Archivo de Test


## **Análisis**

### **2.1 Análisis de Tamaños de Clave**
#### Tamaños utilizados

| Algoritmo | Bits | Bytes | Función de generación |
|-----------|------|-------|----------------------|
| DES       | 64 (56 efectivos) | 8 | `secrets.token_bytes(8)` |
| 3DES      | 128 o 192 | 16 o 24 | `secrets.token_bytes(16)` / `secrets.token_bytes(24)` |
| AES       | 128, 192 o 256 | 16, 24 o 32 | `secrets.token_bytes(key_size // 8)` |

#### Snippets de generación de claves

```python
# DES — 8 bytes (64 bits, 56 efectivos)
from generacion_llaves import generate_des_key
key_des = generate_des_key()
print(f"DES key: {key_des.hex()} — {len(key_des)} bytes = {len(key_des)*8} bits")

# 3DES — 16 o 24 bytes
from generacion_llaves import generate_3des_key
key_3des = generate_3des_key(key_option=2)   # opción 2: 16 bytes
print(f"3DES key: {key_3des.hex()} — {len(key_3des)} bytes = {len(key_3des)*8} bits")

# AES — 16, 24 o 32 bytes
from generacion_llaves import generate_aes_key
key_aes = generate_aes_key(key_size=128)
print(f"AES key: {key_aes.hex()} — {len(key_aes)} bytes = {len(key_aes)*8} bits")
```

#### ¿Por qué DES es inseguro hoy?
DES usa una clave efectiva de solo 56 bits, lo que da un espacio de claves de 2⁵⁶ ≈ 72 billones de combinaciones. Con hardware moderno esto es bastante fácil de forzar. Y esto fue principalmente porque fue diseñando cuando no existían GPUS, las computadoras no eran de tan fácil acceso y el harware era lento.

### **2.2 Comparación de Modos de Operación**
#### Modos implementados

| Algoritmo | Modo |
|-----------|------|
| DES       | ECB  |
| 3DES      | CBC  |
| AES       | ECB y CBC |

#### Diferencias fundamentales entre ECB y CBC

**ECB**
- Cada bloque se cifra de forma independiente con la misma clave.
- Bloques de texto plano idénticos -> bloques cifrados idénticos.
- No usa IV.
- filtra patrones del mensaje original.

Encriptado ecb
![ecb](images\encrypted_ecb_pad.bmp)

**CBC**
- Cada bloque de texto plano se XORea con el bloque cifrado anterior antes de cifrarse.
- El primer bloque usa el IV en lugar del bloque anterior.
- Bloques de texto plano idénticos -> bloques cifrados completamente distintos.
- Seguro contra ataques de análisis de patrones.

Encriptado cbc
![cbc](images\encrypted_cbc_pad.bmp)

**Snippet para generar las imagenes**
```python
from Crypto.Cipher import AES
from generacion_llaves import generate_aes_key, generate_iv
from Crypto.Util.Padding import pad as crypto_pad
from pathlib import Path

BLOCK_SIZE = 16

def encrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(crypto_pad(data, BLOCK_SIZE))

def encrypt_aes_cbc(data: bytes, key: bytes) -> bytes:
    iv = generate_iv(block_size=16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(crypto_pad(data, BLOCK_SIZE))

def encrypt_image(input_file, output_file, encrypt_fn, key):
    with open(input_file, "rb") as f:
        data = f.read()
    header, body = data[:54], data[54:]   # BMP: header fijo de 54 bytes
    with open(output_file, "wb") as f:
        f.write(header + encrypt_fn(body, key))

key = generate_aes_key(key_size=128)
encrypt_image("images/original.bmp", "images/encrypted_ecb.bmp", encrypt_aes_ecb, key)
encrypt_image("images/original.bmp", "images/encrypted_cbc.bmp", encrypt_aes_cbc, key)
```

### **2.3 Vulnerabilidad de ECB**
**¿Por qué no usar ECB con datos sensibles?**

ECB cifra cada bloque de manera independiente, por lo que dos bloques de texto plano iguales siempre producen el mismo bloque cifrado. Esto permite que un atacante pueda identificar patrones repetidos en el mensaje sin descifrarlo, deducir la estructura o contenido del mensaje (ej: el mismo campo en distintos registros) y realizar ataques de reordenamiento o sustitución de bloques.

**Demostración con texto repetido**
[archivo](tests\ecbexample.py)
``` python
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

module_dir = os.path.join(os.getcwd(), 'src')
sys.path.append(module_dir)

from generacion_llaves import generate_aes_key, generate_iv

key = generate_aes_key(key_size=128)
message = b"ATAQUE  ATAQUE  ATAQUE  "  # 3 bloques de 8 bytes idénticos (ajustado a 16 con espacios)

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
```

![ecb exmaple](images\ssresults\ecb.png)

El encriptado de ECB tiene partes identicas es su inicio y se parecen en cierta medida. Si se cifran registros de base de datos con ECB como contraseñas, NIT, salarios, alguien que observe el ciphertext puede detectar qué usuarios tienen la misma contraseña o el mismo valor en un campo, sin necesidad de descifrar nada. 

Esto pidría romper la seguridad de sistemas de votación electrónica y bases de datos médicas en la práctica.

### **2.4 Vector de Inicialización**

**¿Qué es el IV y para qué sirve?**

El IV (vector de inicialización) es un valor aleatorio que se XORea con el primer bloque de texto plano antes de cifrarlo en CBC. Su propósito es asegurar que el mismo mensaje cifrado dos veces produzca ciphertexts distintos, incluso con la misma clave. ECB no usa IV porque cifra cada bloque de forma independiente pero eso tambien es su vulnerabilidad.

**Experimento de mismo mensaje, IVs distintos**
[archivo](tests\ivtest.py)
```python
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
print(f"  Iguales: {ct1 == ct2}")   # Es TRUE, es peligroso

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
print(f"  Iguales: {ct3 == ct4}") # Es FALSE, es correcto
```
![iv test](images\ssresults\ivtest.png)

### ¿Qué pasa si un atacante ve mensajes con el mismo IV?

Si se reutiliza el IV con la misma clave, alguien puede realizar un ataque de análisis diferencial comparando dos ciphertexts del mismo mensaje puede detectar en qué bloque difieren, filtrando información sobre el cambio en el plaintext. En el caso extremo si IV=0 es siempre fijo, CBC se degrada a algo similar a ECB para mensajes con prefijos comunes. En la implementación del proyecto el IV se genera con secrets.token_bytes(16) por cada cifrado y se concatena al inicio del ciphertext (iv + ciphertext) para que el receptor pueda extraerlo al descifrar.

### **2.5 Padding**
**¿Qué es el padding y por qué es necesario?**

Los cifrados de bloque operan sobre bloques de tamaño fijo (8 bytes en DES/3DES, 16 bytes en AES). Si el mensaje no es múltiplo exacto del tamaño de bloque, se necesita **completar el último bloque** con bytes extra. PKCS#7 define que el valor de cada byte de padding es igual a la cantidad de bytes agregados.

**Demostración con pkcs7_pad**
```python
from manual_padding import pkcs7_pad, pkcs7_unpad

# Mensaje de 5 bytes -> bloque de 8 -> faltan 3 bytes -> padding: 0x03 0x03 0x03
m1 = b"HOLA!"
print(pkcs7_pad(m1, 8).hex())
# 484f4c4121 03 03 03
#  H O L A !  padding: 3 bytes con valor 3

# Mensaje de 8 bytes (exactamente un bloque) -> se agrega un bloque completo de 0x08
m2 = b"12345678"
print(pkcs7_pad(m2, 8).hex())
# 3132333435363738 0808080808080808
#     12345678      8 bytes con valor 8

# Mensaje de 10 bytes -> bloque de 16 (AES) -> faltan 6 bytes -> padding: 0x06 x6
m3 = b"HolaMundo!"
print(pkcs7_pad(m3, 16).hex())
# 486f6c614d756e646f21 06060606 0606
#       HolaMundo!       6 bytes con valor 6
```

**Verificación de unpad**

```python
for m, bs in [(b"HOLA!", 8), (b"12345678", 8), (b"HolaMundo!", 16)]:
    padded = pkcs7_pad(m, bs)
    recovered = pkcs7_unpad(padded)
    assert recovered == m
    print(f"✔ '{m}' → padded → unpadded = '{recovered}'")
```


### **2.6 Recomendaciones de Uso**
**Tabla comparativa de modos**
| Modo | Requiere IV | Paralelizable (cifrado) | Paralelizable (descifrado) | Autenticación | Casos de uso recomendados | Desventajas |
|------|------------|------------------------|--------------------------|---------------|--------------------------|-------------|
| **ECB** | No | Sí | Sí | No | No recomendado en producción | Filtra patrones, no semántico seguro |
| **CBC** | Sí | No | Sí | No | Cifrado de archivos, disco | Secuencial al cifrar, vulnerable a padding oracle si no hay MAC |
| **CTR** | Sí (nonce) | Sí | Sí | No | Streams, comunicación en tiempo real | Reutilizar nonce compromete todo |
| **GCM** | Sí (nonce) | Sí | Sí | Sí (AEAD) | TLS, APIs, almacenamiento seguro | Nonce no debe repetirse jamás |

**Recomendado**
GCM Galois/Counter Mode

Es actualmente el estándar recomendado porque combina cifrado y autenticación en una sola operación, protegiéndose contra manipulación del ciphertext com ataques de padding oracle, bit-flipping, entre otros.

[Código de python](tests\aes_gcm.py):
```python
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
```

Código en node.js
```javascript
const crypto = require('crypto');

const key = crypto.randomBytes(32);    // AES-256
const iv  = crypto.randomBytes(16);

// Cifrar
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let ct = cipher.update('Mensaje secreto', 'utf8', 'hex');
ct += cipher.final('hex');
const tag = cipher.getAuthTag();

// Descifrar
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(tag);
let pt = decipher.update(ct, 'hex', 'utf8');
pt += decipher.final('utf8');
console.log(pt);  // "Mensaje secreto"
```

