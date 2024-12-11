from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import time
import json
import hashlib
import requests

# Initialize Flask app
app = Flask(__name__)

# Load keys
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

#========================= Setup =========================
# Load Receiver's private key and public key
receiver_private_key = load_private_key("receiver_private_key.pem")
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load Sender's public key
sender_public_key = load_public_key("sender_public_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

# Dictionary to store session IDs and corresponding session keys
sessions = {}


#========================= Encryption/Decryption Functions =========================
def decrypt_session_key(encrypted_session_key):
    # Decrypt the session key using receiver's private key
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return session_key

def encrypt_plaintext(plaintext, session_key):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    
    # Pad the plaintext before encryption (if needed)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt the padded plaintext
    encrypted_message = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv, encrypted_message

# Decrypt the ciphertext using the session key (AES)
def decrypt_plaintext(encrypted_message, session_key, iv):
    # Create an AES cipher object for decryption
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Remove padding from the plaintext
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

# Encrypt challenge code with KRC's public key
def encrypt_challenge_code(challenge_code, krc_public_key):
    # Encrypt the challenge code with KRC's public key
    encrypted_challenge_code = krc_public_key.encrypt(
        challenge_code, # No need to encode since already in bytes format
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return encrypted_challenge_code

def recover_session_key(krf,session_id):
    # Generate PKCE-like challenge
    challenge_code, challenge_verifier = generate_pkce_challenge()
    
    # Add current timestamp
    timestamp = time.time()  
    
    # Prepare key recovery request to KRC
    recovery_request = {
        'krf': krf,
        'challenge_verifier': challenge_verifier,
        'session_id':session_id,
        'timestamp': timestamp
        # Include any other necessary information
    }
    
    # Encrypt the recovery request with KRC's public key
    encrypted_request = krc_public_key.encrypt(
        str(recovery_request).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send the encrypted request to the KRC (implementation of send_to_krc needed)
    send_to_krc(encrypted_request)

    # Simulate receiving response from KRC
    response = receive_response_from_krc()
    if response == "Request accepted, please verify yourself":
        # Encrypt the challenge code to verify identity with KRC
        encrypted_challenge_code = encrypt_challenge_code(challenge_code, krc_public_key)
        send_to_krc(encrypted_challenge_code)
        
        # Receive the response from KRC
        auth_response = receive_response_from_krc()
        if auth_response == "Authenticate successfully":
            encrypted_session_key = receive_from_krc()  # Receive the session key from KRC
            # Decrypt the session key using receiver's private key
            session_key = receiver_private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            sessions[session_id]['session_key'] = session_key
            return session_key
        else:
            return "Authentication failed"
    else:
        return "Request denied"

# Send encrypted data to KRC (Placeholder function)
def send_to_krc(data):
    print(f"Sending to KRC: {data}")
    # Actual sending code would be implemented here (e.g., using HTTP POST)

# Receive response from KRC (Placeholder function)
def receive_response_from_krc():
    # In a real system, this would receive a response from KRC
    return "Request accepted, please verify yourself"  # Simulated response for testing

# Receive session key from KRC (Placeholder function)
def receive_from_krc():
    # In a real system, this would receive the session key from KRC
    return os.urandom(32)  # Simulated 256-bit AES key for session key

# ฟังก์ชั่นสำหรับสร้าง session ใหม่
def establish_session(session_id, session_key):
    sessions[session_id] = {'session_key': session_key}

# ฟังก์ชั่นตรวจสอบความถูกต้องของ session_key
def is_valid_session_key(session_key):
    # ตรวจสอบว่า session_key อยู่ในรูปแบบที่ถูกต้องหรือไม่
    # ตัวอย่างการตรวจสอบว่า session_key เป็น byte string และมีความยาว 32 bytes
    return isinstance(session_key, bytes) and len(session_key) == 32

# Function to receive data from sender
def receiver_from_sender(session_id, iv, encrypted_session_key, encrypted_message, encrypted_krf=None):
    # Step 1: ตรวจสอบว่า session_id มีอยู่ใน sessions หรือไม่
    if session_id not in sessions:
        # สร้าง session ใหม่หากไม่มี session_id
        session_key = decrypt_session_key(encrypted_session_key)  # ถอดรหัส session_key
        establish_session(session_id, session_key)

    # Step 2: หาก session_id มีอยู่แล้ว ให้ดึง session_key มาใช้งาน
    session_key = sessions.get(session_id)['session_key']
    
    # Step 3: ตรวจสอบว่า session_key มีรูปแบบที่ถูกต้องหรือไม่
    if not is_valid_session_key(session_key):
        # หาก session_key ไม่ถูกต้อง ให้ทำการขอกู้คืนกุญแจจาก KRC
        return jsonify({"message": "session key is lost, attempting key recovery."}), 400
    
    # Step 4: If session_key exists, decrypt with it
    if session_key:
        iv = iv
        decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)
        return jsonify({
            "message": decrypted_message,
            "session_key_used": "from sender"
        })

    # Step 5: If session_key doesn't exist, attempt key recovery
    if encrypted_krf:
        # Decrypt the KRF using receiver's private key
        krf = receiver_private_key.decrypt(
            encrypted_krf,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        session_key = recover_session_key(krf, session_id)
        
        if session_key == "Authentication failed" or session_key == "Request denied":
            return jsonify({"error": session_key}), 403

        # Decrypt again using the new session key from KRC
        decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)
        return jsonify({
            "message": decrypted_message,
            "session_key_used": "from KRC"
        })

    return jsonify({"error": "No encrypted message or KRF found"}), 400

# Endpoint for receiving recovery request
# ฟังก์ชั่นสำหรับรับข้อมูลจาก sender
@app.route('/receive', methods=['POST'])
def receive_from_sender_endpoint():
    data = request.json
    session_id = data.get('session_id')
    encrypted_session_key = data.get('encrypted_session_key', None)
    encrypted_message = data.get('encrypted_message')
    iv = data.get('iv')
    encrypted_krf = data.get('krf', None)

    return receiver_from_sender(session_id, iv, encrypted_session_key, encrypted_message, encrypted_krf)

# Endpoint to trigger session key recovery from Postman
# ฟังก์ชั่นสำหรับเริ่มการทดสอบการกู้คืนกุญแจ
@app.route('/start_testing', methods=['POST'])
def start_testing():
    data = request.json
    if data.get('message') == "start test":
        session_id = data.get('session_id')
        if session_id in sessions:
            # ลบหรือเปลี่ยนแปลง session_key ใน sessions
            sessions[session_id]['session_key'] = None
            # Trigger the recovery process for testing
            result = receiver_from_sender(session_id, None, encrypted_krf="test")  # Simulate KRF testing
            return jsonify({"message": result})
            return jsonify({"message": "session key is now lost, attempting key recovery."})
        else:
            return jsonify({"message": "session_id not found."}), 400

        

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
