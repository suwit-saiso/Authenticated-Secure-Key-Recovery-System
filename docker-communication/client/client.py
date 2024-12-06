# client.py
import requests

server_url = "http://server:5000/data"

data = {
    "name": "Docker",
    "message": "Hello from Client!"
}

response = requests.post(server_url, json=data)
print(f"Server response: {response.json()}")
