from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    return private_key, public_key

# Save private key to PEM format
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # Use PKCS#8 format for PKI
        encryption_algorithm=serialization.NoEncryption()  # Optionally, add encryption here
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Save public key to PEM format
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo # PKI-compliant format
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Example usage to generate keys for Sender, Receiver, KRC, and KRAs
# Generate and save keys for Sender
sender_private_key, sender_public_key = generate_rsa_key_pair()
save_private_key(sender_private_key, "sender_private_key.pem")
save_public_key(sender_public_key, "sender_public_key.pem")

# Generate and save keys for Receiver
receiver_private_key, receiver_public_key = generate_rsa_key_pair()
save_private_key(receiver_private_key, "receiver_private_key.pem")
save_public_key(receiver_public_key, "receiver_public_key.pem")

# Generate and save keys for KRC
krc_private_key, krc_public_key = generate_rsa_key_pair()
save_private_key(krc_private_key, "krc_private_key.pem")
save_public_key(krc_public_key, "krc_public_key.pem")

# Generate and save keys for KRAs
kra1_private_key, kra1_public_key = generate_rsa_key_pair()
save_private_key(kra1_private_key, "kra1_private_key.pem")
save_public_key(kra1_public_key, "kra1_public_key.pem")

kra2_private_key, kra2_public_key = generate_rsa_key_pair()
save_private_key(kra2_private_key, "kra2_private_key.pem")
save_public_key(kra2_public_key, "kra2_public_key.pem")

kra3_private_key, kra3_public_key = generate_rsa_key_pair()
save_private_key(kra3_private_key, "kra3_private_key.pem")
save_public_key(kra3_public_key, "kra3_public_key.pem")

kra4_private_key, kra4_public_key = generate_rsa_key_pair()
save_private_key(kra4_private_key, "kra4_private_key.pem")
save_public_key(kra4_public_key, "kra4_public_key.pem")

kra5_private_key, kra5_public_key = generate_rsa_key_pair()
save_private_key(kra5_private_key, "kra5_private_key.pem")
save_public_key(kra5_public_key, "kra5_public_key.pem")