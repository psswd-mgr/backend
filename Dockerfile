#Imagen base de python 3.12 en su versión slim
FROM python:3.12-slim

WORKDIR /app
#Copia de dependencias
COPY requirements.txt .
#Instalación de dependencias
RUN pip install --no-cache-dir -r requirements.txt
#Copia del código fuente
COPY . .
#Exposición del puerto 8765 para el servidor WebSocket
EXPOSE 8765
#Comando para ejecutar el servidor
CMD ["python", "server.py"]