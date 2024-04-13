import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import multiprocessing

main_frame = None
canal = None
conexion = None
escuchando = False

def crearCanal(HOST, PORT):
    global conexion, canal

    # Crear un objeto socket TCP/IP
    canal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Vincular el socket al host y al puerto
    canal.bind((HOST, PORT))    
    # Escuchar conexiones entrantes
    canal.listen()
    print('Conexión TCP iniciada...')
    # Aceptar conexiones entrantes
    conexion, addr = canal.accept()
    print('Conexión establecida con:', addr)
                
def unirCanal(HOST, PORT):
    global conexion
    # Crear un objeto socket TCP/IP
    conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conectar al servidor
    conexion.connect((HOST, PORT))

def enviarMensaje(mensaje):
    global conexion
    conexion.sendall(mensaje.encode('utf-8'))

def escucharMensaje():
    global conexion
    mensaje = conexion.recv(1024)
    print(mensaje.decode())
    return mensaje.decode()

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

# =======================================================================
# Modo de conexion y ejecuciones iniciales
# =======================================================================
# Obtener el nombre de host de la máquina local
hostname = socket.gethostname()

# Obtener la dirección IP correspondiente al nombre de host
direccion_ip = socket.gethostbyname(hostname)

print("Mi dirección IP es:", direccion_ip)
# Crear una cola para la comunicación entre procesos

modoConexion = input('Deseas iniciar una conexión (i) o unirte a una conexión (u)?:')
if modoConexion == 'i':
    # Definir el host y el puerto en el que se escuchará
    HOST = direccion_ip # localhost
    PORT = 65432        # Puerto arbitrario no utilizado (enviar)
    crearCanal(HOST, PORT)
    conexion.sendall("Hola, soy el host".encode('utf-8'))
    conexion.sendall("Clave: 2345432".encode('utf-8'))
    escuchando = True
    iniciarComunicacion()
    canal.close()

elif modoConexion == 'u':
    # Definir el host y el puerto del servidor
    ip_host = input("Ingresa el IP de la persona que quieres conectar:")
    HOST = ip_host
    PORT = 65432        # Puerto utilizado por el host
    unirCanal(HOST, PORT)
    escucharMensaje()
    escucharMensaje()
    escuchando = False
    iniciarComunicacion()

else:
    print('Opción no valida. Ejecución terminada.')