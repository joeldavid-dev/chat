import socket
import hashlib
import time
import threading
import base64
import json
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2  # Importamos PBKDF2 para la clave simetrica

def generate_symmetric_key(password, salt=b'salt', iterations=100000):
    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, prf=lambda p, s: hashlib.sha256(p + s).digest())
    print("\nClave simétrica generada:", key)
    return key

# Función para cifrar un mensaje simétricamente
def symmetric_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

# Función para descifrar un mensaje simétricamente
def symmetric_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Función para generar un par de claves RSA (privada y pública)
def generate_asymetric_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print('\nMi llave privada:',private_key.decode(),'\nMi llave publica:',public_key.decode())
    return private_key, public_key

# Función para cifrar un mensaje asimétricamente utilizando la clave pública
# El mensaje debe ser bytes, no string
def asymmetric_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(message)
    return cipher_text

# Función para descifrar un mensaje asimétricamente utilizando la clave privada
# El texto cifrado debe ser bytes, no string
def asymmetric_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Función para generar el hash de un mensaje
def generate_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()



cadena = "chanchito feliz"
cadena_hash = generate_hash(cadena)
print ('Resultado: ',cadena_hash)