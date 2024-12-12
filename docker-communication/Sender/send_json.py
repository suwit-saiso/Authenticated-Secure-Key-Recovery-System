import requests

# ตั้งค่าพารามิเตอร์
url = "http://192.168.1.3:5000/endpoint"  # URL ของเซิร์ฟเวอร์
json_file = "data.json"  # ไฟล์ JSON ที่จะส่ง

# อ่านข้อมูล JSON จากไฟล์
with open(json_file, 'r') as file:
    data = file.read()

# ส่งข้อมูลไปยังเซิร์ฟเวอร์
response = requests.post(url, data=data, headers={"Content-Type": "application/json"})

# แสดงผลลัพธ์
if response.status_code == 200:
    print("Response from server:", response.json())
else:
    print(f"Failed to send JSON. Status code: {response.status_code}")
