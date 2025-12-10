"""
Advanced Metadata Extractor
Extracts:
- EXIF metadata (JPG/PNG)
- GPS coordinates (converted)
- PDF metadata
- DOCX metadata
Produces structured forensic reports and suspicious indicators.
"""

import os
import json
from PIL import Image  # pyright: ignore[reportMissingImports]
from PIL.ExifTags import TAGS, GPSTAGS  # pyright: ignore[reportMissingImports]
from docx import Document  # pyright: ignore[reportMissingImports]
from PyPDF2 import PdfReader  # pyright: ignore[reportMissingImports]


# -------------------------------------------------------------
# Utility: Convert EXIF GPS to decimal coordinates
# -------------------------------------------------------------

def convert_gps(exif_gps):
    """Convert EXIF GPS format to decimal degrees."""
    def to_deg(value):
        d = value[0][0] / value[0][1]
        m = value[1][0] / value[1][1]
        s = value[2][0] / value[2][1]
        return d + (m / 60.0) + (s / 3600.0)

    lat = to_deg(exif_gps["GPSLatitude"])
    lon = to_deg(exif_gps["GPSLongitude"])

    if exif_gps.get("GPSLatitudeRef") == "S":
        lat = -lat
    if exif_gps.get("GPSLongitudeRef") == "W":
        lon = -lon

    return {"latitude": lat, "longitude": lon}


# -------------------------------------------------------------
# EXIF extraction
# -------------------------------------------------------------

def extract_exif(path):
    img = Image.open(path)
    exif_data_raw = img._getexif()

    if not exif_data_raw:
        return {}, None

    exif = {}
    gps = {}

    for tag_id, value in exif_data_raw.items():
        tag_name = TAGS.get(tag_id, tag_id)

        if tag_name == "GPSInfo":
            for key in value:
                gps_name = GPSTAGS.get(key, key)
                gps[gps_name] = value[key]
        else:
            exif[tag_name] = value

    gps_coords = None
    if gps and "GPSLatitude" in gps and "GPSLongitude" in gps:
        gps_coords = convert_gps(gps)

    return exif, gps_coords


# -------------------------------------------------------------
# PDF metadata
# -------------------------------------------------------------

def extract_pdf_metadata(path):
    reader = PdfReader(path)
    meta = reader.metadata
    return {k[1:]: str(v) for k, v in meta.items()}


# -------------------------------------------------------------
# DOCX metadata
# -------------------------------------------------------------

def extract_docx_metadata(path):
    doc = Document(path)
    props = doc.core_properties

    return {
        "title": props.title,
        "author": props.author,
        "created": str(props.created),
        "modified": str(props.modified),
        "last_modified_by": props.last_modified_by,
        "revision": props.revision,
    }


# -------------------------------------------------------------
# Filetype detection (simple magic number)
# -------------------------------------------------------------

def detect_type(path):
    with open(path, "rb") as f:
        header = f.read(8)

    if header.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if header.startswith(b"\x89PNG"):
        return "png"
    if header.startswith(b"%PDF"):
        return "pdf"
    if header.startswith(b"PK"):
        return "docx"  # simplistic but works for DOCX

    return "unknown"


# -------------------------------------------------------------
# Master analyzer
# -------------------------------------------------------------

def analyze_metadata(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    ftype = detect_type(path)
    report = {
        "file": path,
        "type": ftype,
        "exif": None,
        "gps_coordinates": None,
        "document_metadata": None,
        "suspicious": False,
        "reason": []
    }

    # Image EXIF
    if ftype in ("jpg", "png"):
        exif, gps = extract_exif(path)
        report["exif"] = exif
        report["gps_coordinates"] = gps

        if not exif:
            report["suspicious"] = True
            report["reason"].append("Image contains no EXIF metadata (may be stripped).")

    # PDF
    elif ftype == "pdf":
        pdf_meta = extract_pdf_metadata(path)
        report["document_metadata"] = pdf_meta

        if not pdf_meta:
            report["suspicious"] = True
            report["reason"].append("PDF has no readable metadata.")

    # DOCX
    elif ftype == "docx":
        docx_meta = extract_docx_metadata(path)
        report["document_metadata"] = docx_meta

        if not docx_meta:
            report["suspicious"] = True
            report["reason"].append("DOCX has no metadata (may be sanitized).")

    else:
        report["suspicious"] = True
        report["reason"].append("Unknown or unsupported file type.")

    print(json.dumps(report, indent=4))
    return report


# -------------------------------------------------------------
# CLI
# -------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 metadata_extractor.py <file>")
    else:
        analyze_metadata(sys.argv[1])
