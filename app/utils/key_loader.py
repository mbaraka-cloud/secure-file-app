from Crypto.PublicKey import RSA

def load_private_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def load_public_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())