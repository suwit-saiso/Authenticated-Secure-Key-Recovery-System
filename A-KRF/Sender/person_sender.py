from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from LoadKey import load_private_key, load_public_key
import uuid
import time
import os

#========================= Setup =========================
# Load KRC and KRA public keys (here we assume they are already available)
# Load Sender private and public key
sender_private_key = load_private_key("sender_private_key.pem")
sender_public_key = load_public_key("sender_public_key.pem")

# Load Receiver's public key
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

# Load KRAs' public keys
kra_public_keys = [
    load_public_key(f"kra_public_key_{i}.pem") for i in range(1, 4)
]

# Proceed with the Sender's operations using these keys

# Generate session key (AES key)
def generate_session_key():
    return os.urandom(32)  # AES 256-bit key

# Encrypt message with session key
def encrypt_plaintext(plaintext, session_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, encrypted_message

# Encrypt session key and message for first establishment
def first_establishment(session_key, plaintext, receiver_public_key):
    session_id = str(uuid.uuid4())  # Generate a unique session ID for this communication
    
    # Encrypt the session key with the receiver's public key
    encrypted_session_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Encrypt the plaintext message with the session key
    iv, encrypted_message = encrypt_plaintext(plaintext, session_key)
    
    # Package the session_id, encrypted session key, IV, and encrypted message
    return session_id, encrypted_session_key, iv, encrypted_message

# Send the message in an ongoing session
def send_message_in_session(session_id, session_key, plaintext):
    iv, encrypted_message = encrypt_plaintext(plaintext, session_key)
    
    # Include the session ID and encrypted message in the package
    return session_id, iv, encrypted_message

# Helper functions for KRF 
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

def split_session_key_xor(session_key, num_parts):
    parts = [os.urandom(len(session_key)) for _ in range(num_parts - 1)]
    last_part = session_key
    for part in parts:
        last_part = xor(last_part, part)
    parts.append(last_part)
    return parts

# Function to generate Key Recovery Field (KRF) with session_id and timestamp
def generate_krf(session_key, krc_public_key, kra_public_keys, session_id):
    krf = {}
    sgn = os.urandom(16)  # Shared Group Number
    num_kras = len(kra_public_keys)
    key_shares = split_session_key_xor(session_key, num_kras)  # Split session key
    timestamp = time.time()  # Add current timestamp

    # Include session_id and timestamp outside of KRF_i
    session_info = {
        "session_id": session_id,
        "timestamp": timestamp
    }

    # Encrypt session_id and timestamp with KRC's public key
    encrypted_session_info = krc_public_key.encrypt(
        str(session_info).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Add encrypted session info to the KRF
    krf["session_info"] = encrypted_session_info

    # Generate KRF_i for each KRA
    for i, kra_public_key in enumerate(kra_public_keys):
        si = key_shares[i]  # Get the key share for this KRA
        tti = xor(si, sgn)  # TTi = Si XOR SGN
        krf_i = {
            "Si": si,
            "SGN": sgn,
            "TTi": tti
        }

        # Encrypt KRF_i with the KRA's public key
        krf_i_encrypted = kra_public_key.encrypt(
            str(krf_i).encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Encrypt the KRF_i with the KRC's public key and add to the KRF
        krf[f"KRF-{i}"] = krc_public_key.encrypt(
            krf_i_encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    return krf

#==================Process==========================
# Usage example
plaintext = "Sensitive information"
session_key = generate_session_key()

# First establishment of secure communication
session_id,encrypted_session_key, iv, encrypted_message = first_establishment(session_key, plaintext, receiver_public_key)

# Send encrypted_session_key, iv, and encrypted_message to the receiver

encrypted_message = encrypt_plaintext(plaintext, session_key)

krf = generate_krf(session_key, krc_public_key, kra_public_keys)
#krf need to be encrypted with receiver public key


#new part
# Sender process !!!need to be adjust later!!! sending session key and so on
def sender_process(message):
    session_key = generate_session_key()
    iv, encrypted_message = encrypt_plaintext(message, session_key)
    
    krc_public_key = load_krc_public_key()
    krf = generate_krf(session_key, krc_public_key)
    
    return iv, encrypted_message, krf

# Example usage
iv, encrypted_message, krf = sender_process(plaintext)
