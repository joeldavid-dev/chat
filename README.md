# Crypto-chat 📨
Crypto-chat es un programa de mensajería creado en Python para enviar y recibir mensajes entre computadoras conectadas a la misma red, utilizando múltiples métodos de cifrado simétrico y 
asimétrico, así como métodos estándar de firmas para maximizar la seguridad de la comunicación. Puedes utilizar este código como ejemplo para implementar más seguridad en tus proyectos :)

<hr>
<p align="center"> <a href="#screenshots">Screenshots</a> &bull; <a href="#como-funciona">¿Como funciona?</a> &bull; <a href="#ejecutar-en-windows">Ejecutar en Windows</a> &bull; <a href="#ejecutar-en-linux">Ejecutar en Linux</a> </p>
<hr>

> [!NOTE] 
> Es recomendable ejecutar este Script dentro de un entorno virtual, esto para evitar conflictos entre paquetes de Python instalados globalmente en tu computadora!

## Screenshots
<img src="https://github.com/user-attachments/assets/2b94d7d6-a704-4987-9197-7ffa3018f7f1" height=300> <img src="https://github.com/user-attachments/assets/aae6c0dc-f2a6-4ab6-98c5-bc21db2382e1" height=300>

## Como funciona
El mensaje es cifrado simétricamente con AES y asimétricamente con RSA. Se crea una llave del mensaje original con SHA-256 y se envían ambos. El receptor obtiene el mensaje cifrado, descifra con RSA y después con AES. Obtiene la llave con SHA-256 del mensaje recibido y la compara con la llave recibida. Si coinciden, el mensaje es auténtico.

Para obtener mas detalles leer los archivos [HOST.txt](./HOST.txt) y [GUEST.txt](./GUEST.txt)

## Ejecutar en Windows
Obtener el código:
```
git clone https://github.com/joeldavid-dev/crypto-chat.git
```

Crear un entorno virtual, en donde se instalarán los paquetes de Python necesarios:
```
cd .\crypto-chat\
python -m venv entorno
```

Activar el entorno virtual:
```
.\entorno\Scripts\activate
```

Instalar Cryptodome, una dependencia necesaria:
```
pip install pycryptodome
```

Ejecutar el Script:
```
python .\crypto-chat.py
```

Desactivar el entorno virtual al terminar la ejecución del Script:
```
deactivate
```

> [!IMPORTANT]
> Si tienes instalado VirtualBox, es posible que su adaptador de red no permita obtener la dirección IP correcta, puedes consultarla en configuración de Windows o desactivar temporalmente el adaptador de red de VirtualBox en Administrador de dispositivos → Adaptadores de red → VirtualBox Host-Only Ethernet Adapter → Deshabilitar dispositivo.
> 
> ![Captura de pantalla 2025-03-05 003506](https://github.com/user-attachments/assets/ad725971-baff-4221-8c44-71ff81ee19fb)

## Ejecutar en Linux
Obtener el código:
```
git clone https://github.com/joeldavid-dev/crypto-chat.git
```

Crear un entorno virtual, en donde se instalarán los paquetes de Python necesarios:
```
cd crypto-chat
python -m venv entorno
```

Activar el entorno virtual:
```
source entorno/bin/activate
```

Instalar Cryptodome, una dependencia necesaria:
```
pip install pycryptodome
```

Ejecutar el Script:
```
python crypto-chat.py
```

Desactivar el entorno virtual al terminar la ejecución del Script:
```
deactivate
```

> [!NOTE] 
> Es necesario tener instalado TKinter, en la mayoría de los casos ya está instalado, pero si no, puedes instalarlos con los siguientes comandos.
>
> Para instalarlo en Debian, Ubuntu o derivados:
> - sudo apt install python3-tk
> 
> Para instalarno en Arch o derivados:
> - sudo pacman -S tk
