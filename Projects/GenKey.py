from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# ฟังก์ชันสร้าง RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# ฟังก์ชันบันทึก Private Key
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# ฟังก์ชันบันทึก Public Key
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# ฟังก์ชันสร้างโฟลเดอร์หากยังไม่มี
def ensure_folder_exists(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)

# โฟลเดอร์เก็บ Key
BASE_FOLDER = "./shared/keys"
ensure_folder_exists(BASE_FOLDER)

# ฝ่ายทั้งหมด
entities = ["sender", "receiver", "krc", "kra1", "kra2", "kra3", "kra4", "kra5"]

# สร้าง Key สำหรับแต่ละฝ่าย
for entity in entities:
    entity_folder = os.path.join(BASE_FOLDER, entity)
    ensure_folder_exists(entity_folder)
    
    private_key, public_key = generate_rsa_key_pair()
    save_private_key(private_key, os.path.join(entity_folder, f"{entity}_private_key.pem"))
    save_public_key(public_key, os.path.join(entity_folder, f"{entity}_public_key.pem"))

print("Keys generated and stored in 'shared/keys' directory.")
