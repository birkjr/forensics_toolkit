"""
Log Parser
Regex-based log scanning for timestamps, IPs, errors, and suspicious events.
"""

import re

TIMESTAMP_REGEX = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
IP_REGEX = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

def parse_log(path):
    with open(path, "r") as f:
        lines = f.readlines()

    print("Log analysis results:")

    for line in lines:
        timestamp = re.search(TIMESTAMP_REGEX, line)
        ip = re.search(IP_REGEX, line)

        if timestamp or ip:
            print(line.strip())

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 log_parser.py <logfile>")
    else:
        parse_log(sys.argv[1])
