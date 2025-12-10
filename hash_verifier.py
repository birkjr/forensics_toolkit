"""
Advanced Hash Verifier
Performs cryptographic hashing, integrity checks, and byte-level comparison.
Generates a structured forensic report.
"""

import hashlib
import json
import os

# -----------------------------------------
# Hashing utilities
# -----------------------------------------

def compute_hashes(path):
    """Returns MD5, SHA1, and SHA256 of a file."""
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            for h in hashes.values():
                h.update(block)

    return {name: h.hexdigest() for name, h in hashes.items()}


# -----------------------------------------
# Byte-level difference checker
# -----------------------------------------

def compare_bytes(path1, path2, limit=50):
    """
    Identifies differing byte positions between two files.
    Returns at most `limit` differences to avoid huge outputs.
    """
    diffs = []
    i = 0

    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        while True:
            b1 = f1.read(1)
            b2 = f2.read(1)

            if not b1 and not b2:
                break

            if b1 != b2:
                diffs.append({
                    "offset": i,
                    "file1_byte": b1.hex() if b1 else None,
                    "file2_byte": b2.hex() if b2 else None,
                })

            i += 1

            if len(diffs) >= limit:
                break

    return diffs


# -----------------------------------------
# Main comparison logic
# -----------------------------------------

def compare_files(path1, path2):
    if not os.path.isfile(path1):
        raise FileNotFoundError(path1)
    if not os.path.isfile(path2):
        raise FileNotFoundError(path2)

    hashes1 = compute_hashes(path1)
    hashes2 = compute_hashes(path2)

    identical = (hashes1["sha256"] == hashes2["sha256"])

    differences = []
    if not identical:
        differences = compare_bytes(path1, path2)

    report = {
        "file1": path1,
        "file2": path2,
        "hashes_file1": hashes1,
        "hashes_file2": hashes2,
        "identical": identical,
        "differences_found": len(differences),
        "difference_preview": differences,
    }

    print(json.dumps(report, indent=4))
    return report


# -----------------------------------------
# CLI
# -----------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 hash_verifier.py <file1> <file2>")
    else:
        compare_files(sys.argv[1], sys.argv[2])
