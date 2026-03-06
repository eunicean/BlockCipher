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


### **2.4 Vector de Inicialización**


### **2.5 Padding**


### **2.6 Recomendaciones de Uso**


## **Documentación**
## **Comparación visual de ECB vs CBC**