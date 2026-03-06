# ultima modificación: 26/02/2026 18:26
# TODO: para el lab3 cambiar la función de pading a la que se tiene ya hecha

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from generacion_llaves import generate_3des_key, generate_iv
from manual_padding import pkcs7_pad,pkcs7_unpad
BLOCK_SIZE = 8

# uso de chat principalmente para saber como usar las librerías y completar verificar cosas que faltan
# https://chatgpt.com/share/6997a74a-85d4-800f-89fe-34498341a13b (mismo chat para el lab3)
def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """

    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")

    if len(iv) != 8:
        raise ValueError("El IV debe ser de 8 bytes")

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pkcs7_pad(plaintext, BLOCK_SIZE))

    return ciphertext


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    # TODO: Implementar
    # 1. Validar longitud de clave y IV
    # 2. Crear cipher: DES3.new(key, DES3.MODE_CBC, iv=iv)
    # 3. Descifrar
    # 4. Eliminar padding usando unpad() de Crypto.Util.Padding
    # 5. Retornar
    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")

    if len(iv) != 8:
        raise ValueError("El IV debe ser de 8 bytes")

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    decrypted_padded = cipher.decrypt(ciphertext)

    decrypted = pkcs7_unpad(decrypted_padded)

    return decrypted

if __name__ == "__main__":
    key = DES3.adjust_key_parity(generate_3des_key())
    print(f"Esta es la llave:       {key}")
    iv = generate_iv()  # debe generar 8 bytes
    print(f"Esta es el iv:          {iv}")

    message = b"Hola mundo con 3DES CBC"
    print(f"Mensaje original:       {message}")

    ciphertext = encrypt_3des_cbc(message, key, iv)
    print("Ciphertext:", ciphertext.hex())

    decrypted = decrypt_3des_cbc(ciphertext, key, iv)
    print("Decrypted:", decrypted)

    assert decrypted == message
    print("✔ El mensaje original fue recuperado correctamente")