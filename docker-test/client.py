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
