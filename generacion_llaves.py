"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """
    des_key = secrets.token_bytes(8) # recomendación de gemini en busqueda de google
    return des_key

# https://chatgpt.com/share/6997a74a-85d4-800f-89fe-34498341a13b
def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.   

    """
    if key_option == 2:
        return secrets.token_bytes(16) 
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option debe ser 2 o 3")
    return True


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
   
    """
    # TODO: Implementar
    # Convertir bits a bytes: key_size // 8
    pass


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """
    # TODO: Implementar
    pass

