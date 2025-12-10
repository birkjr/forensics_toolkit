"""
Advanced File Signature Analyzer (PRO Version)
Features:
- Detects real file types using magic numbers
- Detects embedded files deep inside binary content
- Computes entropy to detect obfuscated / encrypted payloads
- Flags suspicious files based on mismatch or hidden signatures
- Outputs structured forensic JSON reports
"""

import os
import json
import math

# -------------------------------------------------------------------
# Magic numbers database (extendable)
# -------------------------------------------------------------------

MAGIC_NUMBERS = {
    "jpg": [b"\xFF\xD8\xFF"],
    "png": [b"\x89PNG"],
    "gif": [b"GIF87a", b"GIF89a"],
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04"],
    "exe": [b"MZ"],
    "elf": [b"\x7FELF"],
    "mp4": [b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x20ftyp"],
    "gz": [b"\x1F\x8B\x08"],
}


# -------------------------------------------------------------------
# Entropy calculation
# -------------------------------------------------------------------

def calculate_entropy(data):
    """Shannon entropy for detecting encrypted or packed data."""
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy


# -------------------------------------------------------------------
# Detect header file type
# -------------------------------------------------------------------

def detect_file_type(header):
    matches = []
    for ftype, sigs in MAGIC_NUMBERS.items():
        for sig in sigs:
            if header.startswith(sig):
                matches.append(ftype)
    return matches


# -------------------------------------------------------------------
# Search entire file for embedded signatures
# -------------------------------------------------------------------

def detect_embedded_signatures(data):
    """Scan full file for embedded signatures after the header."""
    findings = []

    for ftype, sigs in MAGIC_NUMBERS.items():
        for sig in sigs:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break

                findings.append({
                    "type": ftype,
                    "offset": idx,
                })

                start = idx + 1

    return findings


# -------------------------------------------------------------------
# Pretty print header bytes
# -------------------------------------------------------------------

def header_hexdump(header):
    hexbytes = header.hex().upper()
    grouped = " ".join(hexbytes[i:i+2] for i in range(0, len(hexbytes), 2))
    return grouped


# -------------------------------------------------------------------
# Master analyze function
# -------------------------------------------------------------------

def analyze_file(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    header = data[:64]
    detected = detect_file_type(header)
    embedded = detect_embedded_signatures(data)
    entropy = calculate_entropy(data)

    file_extension = os.path.splitext(filepath)[1].lower().replace(".", "")
    ext_display = file_extension if file_extension else "(none)"

    suspicious = False
    reasons = []

    # Rule 1: Extension mismatch
    if detected and file_extension not in detected:
        suspicious = True
        reasons.append(
            f"Extension '{ext_display}' does not match detected type(s): {detected}"
        )

    # Rule 2: No header match at all
    if not detected:
        suspicious = True
        reasons.append("No known file signature detected — possible obfuscation.")

    # Rule 3: Embedded files found after offset 0
    for emb in embedded:
        if emb["offset"] > 0:
            suspicious = True
            reasons.append(f"Embedded file detected: {emb['type']} at offset {emb['offset']}")

    # Rule 4: High entropy (may indicate encryption or packing)
    if entropy > 7.0:
        suspicious = True
        reasons.append(f"High entropy ({entropy:.2f}) — likely encrypted or packed.")

    report = {
        "file": filepath,
        "extension": ext_display,
        "header_hex": header_hexdump(header),
        "detected_signature": detected,
        "embedded_signatures": embedded,
        "entropy": entropy,
        "suspicious": suspicious,
        "reasons": reasons,
    }

    print(json.dumps(report, indent=4))
    return report


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 signature_checker.py <file>")
    else:
        analyze_file(sys.argv[1])
