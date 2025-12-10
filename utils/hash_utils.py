import hashlib

def sha256_bytes(data):
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()
