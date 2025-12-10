"""
File Signature Analyzer
Identifies real file types based on magic numbers (file headers).
"""

import os

MAGIC_NUMBERS = {
    "jpg": [b"\xFF\xD8\xFF"],
    "png": [b"\x89PNG"],
    "gif": [b"GIF87a", b"GIF89a"],
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04"],
    "exe": [b"MZ"],
    "elf": [b"\x7FELF"],
}

def detect_file_type(filepath):
    with open(filepath, "rb") as f:
        header = f.read(16)

    matches = []
    for filetype, signatures in MAGIC_NUMBERS.items():
        for sig in signatures:
            if header.startswith(sig):
                matches.append(filetype)

    return header, matches

def analyze_file(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    header, matches = detect_file_type(filepath)

    print(f"Analyzing: {filepath}")
    print(f"Header bytes: {header.hex().upper()}")

    if matches:
        print(f"Detected file types: {', '.join(matches)}")
    else:
        print("No known file signature detected — file may be obfuscated or custom.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 signature_checker.py <file>")
    else:
        analyze_file(sys.argv[1])
