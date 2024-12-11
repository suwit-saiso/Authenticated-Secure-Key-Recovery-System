#======Utilitie file======
# Load private key
def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

# Load public key
def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Example to load KRC public key
# krc_public_key = load_public_key("krc_public_key.pem")
