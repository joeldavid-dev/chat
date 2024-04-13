import socket

# Definir el host y el puerto del servidor
ip_recibo = input("Ingresa el IP de la persona que quieres conectar:")
HOST = ip_recibo  # localhost
PORT = 65432        # Puerto utilizado por el servidor

# Crear un objeto socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
    # Conectar al servidor
    cliente.connect((HOST, PORT))
    # Enviar datos al servidor
    mensaje = b'Hola, servidor!'
    cliente.sendall(mensaje)
    # Recibir respuesta del servidor
    respuesta = cliente.recv(1024)
    print('Respuesta del servidor:', respuesta.decode())