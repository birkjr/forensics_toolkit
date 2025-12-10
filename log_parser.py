"""
Advanced Log Parser
Extracts:
- IP addresses
- Timestamps
- URLs
- Hashes (MD5 / SHA256)
- Email addresses
- Suspicious events (scored)
Generates structured JSON reports for timeline building.
"""

import re
import json
import os

# ---------------- REGEX DEFINITIONS ---------------- #

REGEX_PATTERNS = {
    "timestamp": r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
    "ip": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "url": r"https?://[^\s]+",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
}

# Suspicious keywords commonly found in attacks
SUSPICIOUS_KEYWORDS = [
    "failed login",
    "unauthorized",
    "forbidden",
    "attack",
    "exploit",
    "sql injection",
    "shell",
    "root access",
    "malware",
    "ransom",
    "error",
    "denied",
]

# ---------------- SCORING ENGINE ---------------- #

def score_line(line):
    score = 0
    reasons = []

    # IP + URL detection often signals network activity → small score
    if re.search(REGEX_PATTERNS["ip"], line):
        score += 1
        reasons.append("Contains IP address")

    if re.search(REGEX_PATTERNS["url"], line):
        score += 1
        reasons.append("Contains URL")

    # Hash detection → file movement, malware, integrity issues
    if re.search(REGEX_PATTERNS["sha256"], line):
        score += 2
        reasons.append("Contains SHA256 hash")

    if re.search(REGEX_PATTERNS["md5"], line):
        score += 2
        reasons.append("Contains MD5 hash")

    # Suspicious keywords → high score
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in line.lower():
            score += 3
            reasons.append(f"Suspicious keyword: '{keyword}'")

    return score, reasons


# ---------------- MAIN PARSER ---------------- #

def parse_log(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    events = []
    with open(path, "r", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()

            extracted = {}
            for name, pattern in REGEX_PATTERNS.items():
                matches = re.findall(pattern, line)
                if matches:
                    extracted[name] = matches

            score, reasons = score_line(line)

            if extracted or score > 0:
                event = {
                    "line_number": lineno,
                    "raw": line,
                    "matches": extracted,
                    "score": score,
                    "reason": reasons,
                }
                events.append(event)

    print(json.dumps(events, indent=4))
    return events


# ---------------- CLI ---------------- #

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 log_parser.py <logfile>")
    else:
        parse_log(sys.argv[1])
