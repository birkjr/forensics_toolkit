"""
Hash Verifier
Generates SHA-256 hashes and compares file versions.
"""

import hashlib
import os

def sha256_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha.update(block)
    return sha.hexdigest()

def compare_files(file1, file2):
    h1 = sha256_file(file1)
    h2 = sha256_file(file2)

    print(f"{file1}: {h1}")
    print(f"{file2}: {h2}")

    if h1 == h2:
        print("Files are identical.")
    else:
        print("Files differ.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 hash_verifier.py <file1> <file2>")
    else:
        compare_files(sys.argv[1], sys.argv[2])
