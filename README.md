# Authenticated-Secure-Key-Recovery-System

`server.py`
```python
import socket

HOST = '0.0.0.0'  # รับการเชื่อมต่อจากทุก IP
PORT = 5000        # พอร์ตที่ต้องการรับข้อมูล

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode()}")
            conn.sendall(b"Message received")
```
---
`client.py`
```python
import socket
import os

SERVER = 'server'  # ชื่อ container ของ server
PORT = 5000        # พอร์ตที่ต้องการเชื่อมต่อ

message = os.getenv("MESSAGE", "Default Message")  # อ่านข้อความจาก environment variable

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER, PORT))
    print(f"Sending message: {message}")
    s.sendall(message.encode())
    data = s.recv(1024)
    print(f"Received from server: {data.decode()}")
```
---
`Dockerfile`
```Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY . /app

CMD ["python", "server.py"]  # หรือ client.py
```
---
`docker-compose.yml`
```yaml
version: '3.8'
services:
  server:
    build:
      context: .
    container_name: server
    networks:
      - my_network
    ports:
      - "5000:5000"
    command: python server.py

  client:
    build:
      context: .
    container_name: client
    networks:
      - my_network
    depends_on:
      - server
    environment:
      - MESSAGE=Hello from Client!
    command: python client.py

networks:
  my_network:
    external: true
```
---