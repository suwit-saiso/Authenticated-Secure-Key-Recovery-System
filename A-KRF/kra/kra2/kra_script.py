from LoadKey import load_private_key, load_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
import json

#========================= Setup =========================
# Load KRA1's private key
kra1_private_key = load_private_key("kra1_private_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

#====================== Functions ======================

# Function to receive and process information from KRC !!!change later!!!
def receive_from_krc(encrypted_message, message_type):
    """
    Receive data from KRC and process it based on the message type.
    :param encrypted_message: Encrypted data sent by KRC
    :param message_type: Type of message ('challenge_code' or 'krf_i')
    """
    if message_type == 'challenge_code':
        process_challenge_code(encrypted_message)
    elif message_type == 'krf_i':
        process_krf_i(encrypted_message)
    else:
        raise ValueError("Unknown message type received from KRC")

# Function to receive, decrypt challenge code, and respond with verifier
def process_challenge_code(encrypted_challenge_code):
    # Decrypt the challenge code using KRA's private key
    challenge_code = kra1_private_key.decrypt(
        encrypted_challenge_code,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Hash the decrypted challenge code to generate the verifier
    challenge_verifier = hashlib.sha256(challenge_code).digest()

    # Encrypt the verifier with the KRC's public key
    encrypted_challenge_verifier = krc_public_key.encrypt(
        challenge_verifier,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Send the encrypted challenge verifier back as a response (placeholder function for sending)
    send_to_krc(encrypted_challenge_verifier)

# Function to receive KRF-i, decrypt, and re-encrypt with KRC's public key
def process_krf_i(encrypted_krf_i):
    # Decrypt KRF-i using KRA's private key
    krf_i = kra1_private_key.decrypt(
        encrypted_krf_i,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Encrypt KRF-i with the KRC's public key
    encrypted_krf_i_for_krc = krc_public_key.encrypt(
        krf_i,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Send the encrypted KRF-i back to KRC as the response (placeholder function for sending)
    send_to_krc(encrypted_krf_i_for_krc)

# Placeholder function for sending data to KRC
def send_to_krc(data):
    # Implement the actual communication with KRC
    pass

