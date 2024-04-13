import multiprocessing

# Función para el proceso 1
def proceso1(queue):
    for i in range(5):
        queue.put(f"Mensaje {i} desde Proceso 1")
    queue.put(None)  # Señal de finalización

# Función para el proceso 2
def proceso2(queue):
    while True:
        mensaje = queue.get()
        if mensaje is None:
            break  # Salir del bucle cuando se recibe la señal de finalización
        print("Proceso 2 recibió:", mensaje)

if __name__ == '__main__':
    # Crear una cola para la comunicación entre procesos
    cola = multiprocessing.Queue()

    # Crear y arrancar los procesos
    p1 = multiprocessing.Process(target=proceso1, args=(cola,))
    p2 = multiprocessing.Process(target=proceso2, args=(cola,))
    p1.start()
    p2.start()

    # Esperar a que los procesos terminen
    p1.join()
    p2.join()