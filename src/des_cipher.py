# LAST MODIFIED: 24/02/2026 19:28

from Crypto.Cipher import DES
from generacion_llaves import generate_des_key
from manual_padding import pkcs7_pad, pkcs7_unpad


BLOCK_SIZE = 8


def des_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando DES en modo ECB.
    """

    if len(key) != 8:
        raise ValueError("La clave DES debe ser de 8 bytes")

    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_data)

    return ciphertext


def des_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando DES en modo ECB.
    """

    if len(key) != 8:
        raise ValueError("La clave DES debe ser de 8 bytes")

    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext

if __name__ == "__main__":

    message = b"Hola mundo criptografia"
    print("Mensaje", message)

    # Generar clave segura
    key = generate_des_key()

    print("Clave:", key.hex())

    # Cifrar
    ciphertext = des_encrypt_ecb(message, key)
    print("Ciphertext:", ciphertext.hex())

    # Descifrar
    decrypted = des_decrypt_ecb(ciphertext, key)
    print("Descifrado:", decrypted)

    # Validación
    assert decrypted == message
    print("✔ El mensaje original fue recuperado correctamente")