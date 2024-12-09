from LoadKey import load_private_key, load_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
import hashlib
import time
import os


#========================= Setup =========================
# Load Receiver's private key
receiver_private_key = load_private_key("receiver_private_key.pem")
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load Sender's public key
sender_public_key = load_public_key("sender_public_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

# Dictionary to store session IDs and corresponding session keys
sessions = {}

# Encrypt the plaintext message using the session key (AES) not in use yet!
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

# Decrypt the initial package from the sender and establish a session
def establish_session(receiver_private_key, session_id, encrypted_session_key, iv, encrypted_message):
    # Decrypt the session key using the receiver's private key
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Decrypt the message using the session key and IV
    plaintext = decrypt_plaintext(encrypted_message, session_key, iv)
    
    # Store the session_id and session_key in the session dictionary
    sessions[session_id] = session_key
    
    return plaintext

def receive_message_with_krf(session_id, iv, encrypted_message, encrypted_krf, receiver_private_key):
    # Retrieve the session key from the session dictionary using session_id
    session_key = sessions.get(session_id) #later might check id first if there was any if not make establishment
    
    # Decrypt the KRF using receiver's private key
    krf = receiver_private_key.decrypt(
        encrypted_krf,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # If the session key is None, raise an error and initiate key recovery
    if session_key is None:
        print(f"Session ID {session_id} not found. Initiating key recovery.")
        session_key = recover_session_key(krf, receiver_private_key,session_id,krc_public_key)
        # After recovery, store the session key in the sessions dictionary
        sessions[session_id] = session_key
    else:
        print(f"Session key for session ID {session_id} retrieved successfully.")
    
    # Decrypt the message using the session key and IV
    plaintext = decrypt_plaintext(encrypted_message, session_key, iv)
    
    return plaintext

def encrypt_challenge_code(challenge_code, krc_public_key):
    # Encrypt the challenge code with KRC's public key
    encrypted_challenge_code = krc_public_key.encrypt(
        challenge_code, # No need to encode since already in bytes format
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return encrypted_challenge_code

def recover_session_key(krf, receiver_private_key,session_id,krc_public_key):
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

    # Simulate receiving response from KRC (need actual receive implementation)
    response_to_request = receive_response_from_krc()
    # Receive first response from KRC to verify identity
    encrypted_challenge_code = encrypt_challenge_code(challenge_code, krc_public_key)
    # Send the en. challegen code

    # Receive response from KRC
    encrypted_session_key = receive_from_krc()
    
    # Decrypt the session key using receiver's private key
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return session_key

def send_to_krc(encrypted_request):
    # Implementation depends on your communication setup
    pass

def receive_response_from_krc():
    # Implementation depends on your communication setup
    pass

def receive_from_krc():
    # Implementation depends on your communication setup
    # Should return the encrypted session key
    pass


#new part 2
# Example usage
session_key = os.urandom(32)  # 256-bit AES key
plaintext = "This is a secret message"

# Encrypt the message
iv, encrypted_message = encrypt_plaintext(plaintext, session_key)

# Decrypt the message
decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)

print(f"Original message: {plaintext}")
print(f"Decrypted message: {decrypted_message}")
