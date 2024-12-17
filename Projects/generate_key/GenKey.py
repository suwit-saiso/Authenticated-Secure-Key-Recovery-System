from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Base folders
SHARED_KEYS_FOLDER = "./Projects/Shared/keys"
CONTAINERS_FOLDER = "./Projects/"

# List of entities to generate keys for
ENTITIES = ["sender", "receiver", "krc", "kra1", "kra2", "kra3", "kra4", "kra5"]

# Function to generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Function to save a private key to a file
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Function to save a public key to a file
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Ensure a folder exists
def ensure_folder_exists(folder):
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
    except Exception as e:
        print(f"Error creating folder {folder}: {e}")

# Main script logic
def main():
    # Ensure shared keys folder exists
    ensure_folder_exists(SHARED_KEYS_FOLDER)
    
    for entity in ENTITIES:
        # Define paths for entity-specific folders
        entity_folder = os.path.join(CONTAINERS_FOLDER, entity, "keys")
        shared_public_key_path = os.path.join(SHARED_KEYS_FOLDER, f"{entity}_public.pem")
        entity_private_key_path = os.path.join(entity_folder, f"{entity}_private.pem")
        entity_public_key_path = os.path.join(entity_folder, f"{entity}_public.pem")
        
        # Ensure entity folder exists
        ensure_folder_exists(entity_folder)
        
        # Generate key pair
        private_key, public_key = generate_rsa_key_pair()
        
        try:
            # Save private key to the container's folder
            save_private_key(private_key, entity_private_key_path)
            
            # Save public key to both the container's folder and shared folder
            save_public_key(public_key, entity_public_key_path)
            save_public_key(public_key, shared_public_key_path)
            
            print(f"Keys for {entity} saved successfully:")
            print(f"  Private key -> {entity_private_key_path}")
            print(f"  Public key -> {entity_public_key_path}")
            print(f"  Public key (shared) -> {shared_public_key_path}")
        except Exception as e:
            print(f"Error saving keys for {entity}: {e}")

if __name__ == "__main__":
    main()
