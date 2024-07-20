from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import getpass
import string
import random
import hmac

MAX_INTENTOS_FALLIDOS = 3
BLOQUEO_TEMPORAL = 60  # Bloqueo temporal en segundos

intentos_fallidos = 0

def generar_clave_pbkdf2(password, salt, length=32, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def calcular_mac(clave, datos):
    mac = hmac.new(clave, datos, 'sha256')
    return mac.digest()

def cifrar_texto(clave, texto):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    texto_cifrado = encryptor.update(texto.encode()) + encryptor.finalize()
    
    # Calcular el MAC sobre los datos cifrados
    mac = calcular_mac(clave, texto_cifrado)
    
    return base64.b64encode(iv + encryptor.tag + texto_cifrado + mac)

def descifrar_texto(clave, texto_cifrado):
    texto_cifrado = base64.b64decode(texto_cifrado)
    iv = texto_cifrado[:16]
    tag = texto_cifrado[16:32]
    texto_cifrado = texto_cifrado[32:-32]  # Excluir el MAC del texto cifrado
    mac = texto_cifrado[-32:]  # Extraer el MAC del texto cifrado
    texto_cifrado = texto_cifrado[:-32]  # Excluir el MAC del texto cifrado
    
    # Verificar el MAC
    mac_calculado = calcular_mac(clave, texto_cifrado)
    if mac != mac_calculado:
        raise ValueError("Error: El MAC no coincide. Posible manipulación de datos.")
    
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    texto_descifrado = decryptor.update(texto_cifrado) + decryptor.finalize()
    return texto_descifrado.decode().strip()

def obtener_opcion_valida():
    while True:
        opcion = input("> ")
        if opcion in {"1", "2"}:
            return opcion
        else:
            print("Opción no válida. Por favor, elige 1 o 2.")

def obtener_password():
    global intentos_fallidos
    while intentos_fallidos < MAX_INTENTOS_FALLIDOS:
        password = getpass.getpass("Introduce tu contraseña: ")
        confirmacion = getpass.getpass("Confirma tu contraseña: ")
        if password == confirmacion:
            if validar_contraseña(password):
                intentos_fallidos = 0
                return password
            else:
                print("La contraseña no cumple con los criterios de seguridad mínimos.")
        else:
            print("Las contraseñas no coinciden. Por favor, inténtalo de nuevo.")
        intentos_fallidos += 1
    print("Demasiados intentos fallidos. Bloqueando temporalmente...")
    time.sleep(BLOQUEO_TEMPORAL)
    intentos_fallidos = 0
    return None

def validar_contraseña(password):
    # Longitud mínima de 8 caracteres
    if len(password) < 8:
        return False
    # Contiene al menos una letra mayúscula
    if not any(char.isupper() for char in password):
        return False
    # Contiene al menos una letra minúscula
    if not any(char.islower() for char in password):
        return False
    # Contiene al menos un dígito
    if not any(char.isdigit() for char in password):
        return False
    # Contiene al menos un carácter especial
    if not any(char in string.punctuation for char in password):
        return False
    return True

def generar_salt():
    # Generar una sal de 16 bytes
    return os.urandom(16)

def limpiar_memoria(dato):
    # Sobrescribe el dato con caracteres nulos
    dato = b'\x00' * len(dato)

def main():
    print("Bienvenido al programa ReadyCript de cifrado y descifrado AES-256.")
    print("Por favor, elige una opción:")
    print("1. Cifrar texto")
    print("2. Descifrar texto")
    opcion = obtener_opcion_valida()

    if opcion == "1":
        texto = input("Introduce el texto a cifrar: ")
        password = obtener_password()
        if password:
            salt = generar_salt()
            clave = generar_clave_pbkdf2(password, salt)
            texto_cifrado = cifrar_texto(clave, texto)
            # Almacenar la sal junto con el texto cifrado
            texto_cifrado = base64.b64encode(salt + texto_cifrado)
            print("Texto cifrado:")
            print(texto_cifrado.decode())
            # Limpiar la contraseña y la sal de la memoria
            limpiar_memoria(password.encode())
            limpiar_memoria(salt)

    elif opcion == "2":
        texto_cifrado_base64 = input("Introduce el texto cifrado: ")
        password = obtener_password()
        if password:
            texto_cifrado = base64.b64decode(texto_cifrado_base64)
            # Extraer la sal del texto cifrado
            salt = texto_cifrado[:16]
            texto_cifrado = texto_cifrado[16:]
            clave = generar_clave_pbkdf2(password, salt)
            try:
                texto_original = descifrar_texto(clave, texto_cifrado)
                print("Texto descifrado:")
                print(texto_original)
            except ValueError:
                print("Error: La clave proporcionada no es válida.")
            # Limpiar la contraseña y la sal de la memoria
            limpiar_memoria(password.encode())
            limpiar_memoria(salt)

if __name__ == "__main__":
    main()
