"""
Metadata Extractor
Extracts EXIF and document metadata.
"""

from PIL import Image
from PIL.ExifTags import TAGS
import os

def extract_exif(path):
    img = Image.open(path)
    exif_data = img._getexif()

    if not exif_data:
        print("No EXIF metadata found.")
        return

    print("EXIF Metadata:")
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        print(f"{tag}: {value}")

def analyze_metadata(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    print(f"Analyzing metadata: {path}")

    if path.lower().endswith((".jpg", ".jpeg", ".png")):
        extract_exif(path)
    else:
        print("Metadata extraction for this file type is not implemented yet.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 metadata_extractor.py <file>")
    else:
        analyze_metadata(sys.argv[1])
