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
