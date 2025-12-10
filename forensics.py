"""
Forensics Toolkit - Unified CLI Interface
Provides a single command-line entry point for:
- File signature analysis
- Hash comparison
- Metadata extraction
- Log parsing
- Timeline building

Usage:
    python3 forensics.py analyze <file>
    python3 forensics.py compare <file1> <file2>
    python3 forensics.py metadata <file>
    python3 forensics.py logs <logfile>
    python3 forensics.py timeline <folder>
"""

import sys
import os
import json

# Import project modules
from signature_checker import analyze_file as analyze_signature
from hash_verifier import compare_files as compare_hashes
from metadata_extractor import analyze_metadata
from log_parser import parse_log
from timeline_builder import load_events, print_timeline


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 forensics.py analyze <file>")
        print("  python3 forensics.py compare <file1> <file2>")
        print("  python3 forensics.py metadata <file>")
        print("  python3 forensics.py logs <logfile>")
        print("  python3 forensics.py timeline <folder>")
        sys.exit(1)

    command = sys.argv[1]

    # ---------------------------
    # analyze (signature checker)
    # ---------------------------
    if command == "analyze":
        filepath = sys.argv[2]
        analyze_signature(filepath)

    # ---------------------------
    # compare (hash verifier)
    # ---------------------------
    elif command == "compare":
        if len(sys.argv) != 4:
            print("Usage: python3 forensics.py compare <file1> <file2>")
            sys.exit(1)
        compare_hashes(sys.argv[2], sys.argv[3])

    # ---------------------------
    # metadata extraction
    # ---------------------------
    elif command == "metadata":
        filepath = sys.argv[2]
        analyze_metadata(filepath)

    # ---------------------------
    # log parsing
    # ---------------------------
    elif command == "logs":
        logfile = sys.argv[2]
        parse_log(logfile)

    # ---------------------------
    # timeline builder
    # ---------------------------
    elif command == "timeline":
        folder = sys.argv[2]
        events = load_events(folder)
        print_timeline(events)

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
