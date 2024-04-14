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


canal = None
conexion = None
PORT = 65432        # Puerto arbitrario no utilizado

# ========================================================================================
# Funciones criptográficas
# ========================================================================================
# Función para generar una clave simétrica a partir de una contraseña
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

# ========================================================================================
# Funciones de UI
# ========================================================================================
# Función que inserta un mensaje de sistema
def system_msg(mensaje):
    msj = '[Sistema] '+mensaje+'\n'
    system_messages_text.insert(tk.END, msj)

# Función que solicita un texto al usuario y verifica que no sea una cadena vacía
def solicitud(titulo, mensaje):
    while True:
        texto_ingresado = simpledialog.askstring(titulo, mensaje)
        if texto_ingresado:
            break
    return texto_ingresado

def my_msg(mensaje):
    msj = '[Yo] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

def new_msg(mensaje):
    msj = '[Interlocutor] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

# ========================================================================================
# Funciones de conexión
# ========================================================================================
def obtenerIP():
    # Obtener el nombre de host de la máquina local
    hostname = socket.gethostname()
    # Obtener la dirección IP correspondiente al nombre de host
    direccion_ip = socket.gethostbyname(hostname)
    return direccion_ip


def recibir_msg():
    global conexion, llave_privada, clave_simetrica
    while True:
        try:
            if conexion:
                # Recibir paquete
                #paquete = conexion.recv(1024)
                #received_data = json.loads(paquete)
                # Desempaquetar datos
                crypt_msg_asym = conexion.recv(1024)
                conexion.sendall(b"ok")
                print('\nC asimétrico recibido: ',crypt_msg_asym)
                
                nonce = conexion.recv(1024)
                conexion.sendall(b"ok")
                print('\nNonce recibido: ',nonce)

                tag = conexion.recv(1024)
                conexion.sendall(b"ok")
                print('\nTag recibido: ',tag)

                firma = conexion.recv(1024)
                conexion.sendall(b"ok")
                print('\nFirma recibida: ',firma)

                system_msg('Mensaje recibido')

                # Desencriptado y verificación de firma
                crypt_msg_sym = asymmetric_decrypt(crypt_msg_asym, llave_privada)
                system_msg('Mensaje descifrado con método asimétrico')
                plaintext = symmetric_decrypt(crypt_msg_sym, nonce, tag, clave_simetrica)
                system_msg('Mensaje descifrado con método simétrico')
                new_msg(plaintext)        
            else:
                print('conexion terminada')
                break
        except Exception as e:
            messagebox.showerror("Error", f"Conexión perdida: {e}")  
            break 

def enviar_msg():
    # Descifrado y creación de firma
    global conexion, clave_simetrica, llaveP_interloc
    mensaje = message_entry.get()
    my_msg(mensaje)
    crypt_msg_sym, nonce, tag = symmetric_encrypt(mensaje, clave_simetrica)
    system_msg('Mensaje cifrado con método simétrico')
    crypt_msg_asym = asymmetric_encrypt(crypt_msg_sym, llaveP_interloc)
    system_msg('Mensaje cifrado con método asimétrico')

    firma = b"firma"

    # Empaquetar datos con el formato json
    #paquete = json.dumps({
    #        'cripto': crypt_msg_asym.decode(),
    #        'nonce': nonce.decode(),
    #        'tag': tag.decode(),
    #        'firma': firma.decode()
    #    })

    # Enviando el paquete
    conexion.sendall(crypt_msg_asym)
    confirm = conexion.recv(1024)
    conexion.sendall(nonce)
    confirm = conexion.recv(1024)
    conexion.sendall(tag)
    confirm = conexion.recv(1024)
    conexion.sendall(firma)
    confirm = conexion.recv(1024)
    
    system_msg('Mensaje enviado')

    # Impresiones para debug
    print('\nC asimétrico: ',crypt_msg_asym)
    print('\nNonce: ',nonce)
    print('\nTag: ',tag)
    print('\nFirma: ',firma)

    

# Función que contiene las ejecuciones iniciales para establecer la conexión
# desde el punto de vista del host.
def host_communication(HOST, PORT):
    global conexion, canal, llave_publica, llaveP_interloc, clave_simetrica
    # Crear un objeto socket TCP/IP
    canal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Vincular el socket al host y al puerto
    canal.bind((HOST, PORT))    
    # Escuchar conexiones entrantes
    canal.listen()
    system_msg('Conversación iniciada. Esperando interlocutor...')
    # Aceptar conexiones entrantes
    conexion, addr = canal.accept()
    system_msg('Conexión establecida con: '+ addr[0])

    # Enviar mi llave pública
    conexion.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')
    # Recibir llave pública
    llaveP_interloc = conexion.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')
    # Cifra la clave simetrica (asimetrico) con la llave publica del receptor
    secreto = asymmetric_encrypt(clave_simetrica, llaveP_interloc)
    # Envio del secreto al guest
    print('\nSecreto enviado:', secreto)
    system_msg('Llave simétrica cifrada con la llave pública del interlocutor (secreto)')
    conexion.sendall(secreto)
    system_msg('Secreto compartido con el interlocutor')

    # Confirmación de conexión verificada
    confirm = conexion.recv(1024)
    if confirm == b"confirmado":
        # Inicio de la comunicación
        system_msg('Conexión verificada. Iniciando hilo de recepción de datos...')
        send_message_button.config(state=tk.NORMAL)
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        system_msg('Conexión no verificada. Cancelando comunicación')
        conexion.close()

# Función que contiene las ejecuciones iniciales para establecer la conexión
# desde el punto de vista del invitado.
def guest_communication(HOST, PORT):
    global conexion, llave_publica, llaveP_interloc, clave_simetrica, temp_password
    # Crear un objeto socket TCP/IP
    conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conectar al servidor
    conexion.connect((HOST, PORT))
    system_msg('Conexión establecida con: '+ HOST)

    # Recibir llave publica del interlocutor
    llaveP_interloc = conexion.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')
    # Enviar mi llave pública
    conexion.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')
    # Recibir secreto
    secreto = conexion.recv(1024)
    print('\nSecreto recibido:', secreto)
    system_msg('Secreto recibido')
    # Descifrar secreto con mi llave privada
    clave_simetrica = asymmetric_decrypt(secreto, llave_privada)
    print('\n Clave simetrica obtenida:',clave_simetrica)

    # Verificar la conexión. La clave simetrica que se genera debe coincidir con
    # con la obtenida del secreto recibido.
    system_msg('Clave simetrica obtenida. Verificando conexión...')
    temp_simetrica = generate_symmetric_key(temp_password)
    if temp_simetrica == clave_simetrica:
        # Enviar la confirmación
        conexion.sendall("confirmado".encode())
        # Iniciar conversación
        send_message_button.config(state=tk.NORMAL)
        system_msg('Conexión confirmada. Iniciando hilo de recepción de datos...')
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        system_msg('Conexión no verificada. Cancelando comunicación')
        conexion.close()

def iniciarComunicacion():
    global escuchando
    while True:
        if escuchando:
            msj = escucharMensaje()
        else:
            msj = input('>>> ')
            enviarMensaje(msj)
            
        if msj == '*cambio':
            escuchando = not escuchando
        elif msj == '*fin':
            break

# Función para desconectarse del servidor
def cerrar_conexion():
    global conexion
    if conexion:
        conexion.close()

# ========================================================================================
# Ejecución principal
# ========================================================================================
password = ''
temp_password = ''
clave_simetrica = b''
llave_privada = b''
llave_publica = b''
llaveP_interloc= b'' # Llave publica del interlocutor
mi_IP = obtenerIP()

ventana = tk.Tk()
ventana.title("Cliente de Mensajería Segura")
ventana.resizable(0,0)

# Crear etiquetas para los archivos de claves
private_key_label = ttk.Label(ventana, text="Mi dirección IP es: "+mi_IP, font=("Arial",12))
private_key_label.grid(row=0, column=0, columnspan=3)

# Entrada de mensaje
ttk.Label(ventana, text="Mensaje:").grid(row=1, column=0, sticky=tk.W)
message_entry = ttk.Entry(ventana)
message_entry.grid(row=1, column=1)

# Botón para enviar mensaje
send_message_button = ttk.Button(ventana,text="Enviar Mensaje", state=tk.DISABLED, command=enviar_msg)
send_message_button.grid(row=1, column=2)

# Texto para mensajes recibidos
received_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=15)
received_messages_text.grid(row=2, column=0, columnspan=3)

# Entrada de mensajes de sistemas
ttk.Label(ventana, text="Mensajes del sistema:").grid(row=3, column=0, sticky=tk.W)

# Texto para mensajes del sistema
system_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=10)
system_messages_text.grid(row=4, column=0, columnspan=3)


# Creando la conexión y generar las llaves dependiendo del modo de ejecución.
isHost = messagebox.askyesno("Modo de ejecución", "¿Deseas crear una nueva conversación?")
if isHost:
    password = solicitud('Ingresar contraseña', "Por favor, ingresa una contraseña para la conversación")
    clave_simetrica = generate_symmetric_key(password)
    system_msg('Clave simetrica generada')
    llave_privada, llave_publica = generate_asymetric_keys()
    system_msg('Llaves asimetricas generadas')
    HOST = mi_IP        # localhost
    host_thread = threading.Thread(target=host_communication, args=(HOST, PORT))
    host_thread.start()
else:
    HOST = solicitud('Ingresar IP', "Por favor, ingresa la IP de la conversación a la que deseas unirte")
    temp_password = solicitud("Ingresa la contraseña", "Por favor, ingresa la contraseña de la conversación")
    llave_privada, llave_publica = generate_asymetric_keys()
    system_msg('Llaves asimetricas generadas')
    invitado_thread = threading.Thread(target=guest_communication, args=(HOST, PORT))
    invitado_thread.start()


# Ejecutar el bucle de eventos
ventana.mainloop()