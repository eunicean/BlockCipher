from generacion_llaves import generate_aes_key, generate_iv
from manual_padding import pkcs7_pad # notita: en las instrucciones dice "Usar pad de la biblioteca para el padding" pero no estoy segura a que pad se refiere :p
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pathlib import Path

BLOCK_SIZE = 16

# como siempre:
# https://chatgpt.com/share/69aa54af-3d1c-800f-b81f-640f72b294cc
# adaptando lo que me da a mis funciones ya hechas
def encrypt_aes_ecb(data: bytes, key: bytes, use_manual_pad  = True) -> bytes:

    cipher = AES.new(key, AES.MODE_ECB)

    if use_manual_pad:
        padded = pkcs7_pad(data, BLOCK_SIZE)
    else:
        padded = pad(data, BLOCK_SIZE)

    ciphertext = cipher.encrypt(padded)

    return ciphertext

def encrypt_aes_cbc(data: bytes, key: bytes, use_manual_pad=True):

    iv = generate_iv(block_size=16)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    if use_manual_pad:
        padded = pkcs7_pad(data, BLOCK_SIZE)
    else:
        padded = pad(data, BLOCK_SIZE)

    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext

def encrypt_image(input_file, output_file, encrypt_function, key, pad_opt = True):
    input_path = Path(input_file)
    
    with open(input_path, "rb") as f:
        data = f.read()

    if input_path.suffix.lower() == ".bmp":
        header = data[:54]
        body = data[54:]
        encrypted_body = encrypt_function(body, key,pad_opt)
        result = header + encrypted_body
    else:
        result = encrypt_function(data, key, pad_opt)

    with open(output_file, "wb") as f:
        f.write(result)

def main():

    current_file = Path(__file__)
    project_root = current_file.parent.parent

    images_folder = project_root / "images"

    input_image = images_folder / "original.bmp"

    output_ecb1 = images_folder / "encrypted_ecb_pad.bmp"
    output_cbc1 = images_folder / "encrypted_cbc_pad.bmp"
    output_ecb2 = images_folder / "encrypted_ecb_pkcs7.bmp"
    output_cbc2 = images_folder / "encrypted_cbc_pkcs7.bmp"

    key = generate_aes_key(key_size=128)

    encrypt_image(input_image, output_ecb1, encrypt_aes_ecb, key)          
    encrypt_image(input_image, output_cbc1, encrypt_aes_cbc, key)
    encrypt_image(input_image, output_ecb2, encrypt_aes_ecb, key, False)    
    encrypt_image(input_image, output_cbc2, encrypt_aes_cbc, key, False)

    print("Imagen original:", input_image)
    print("ECB guardado en:", output_ecb1)
    print("CBC guardado en:", output_cbc1)
    print("ECB con pad personalizado guardado en:", output_ecb2)
    print("CBC con pad personalizado guardado en:", output_cbc2)

if __name__ == "__main__":
    main()