"""
Extract provenance metadata embedded in files.

For images: looks for C2PA Content Credentials, then falls back to EXIF.
For documents: checks for digital signatures and authoring metadata.

Returns a structured report scoring how much provenance information was found.
"""
import struct
from pathlib import Path


# Common file signatures (magic bytes) for type sniffing
MAGIC_BYTES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"%PDF-": "application/pdf",
    b"PK\x03\x04": "application/zip-or-office",
    b"MZ": "application/x-executable",
    b"\x7fELF": "application/x-elf",
}


def detect_mime_type(file_path: str) -> str:
    """Detect file type from magic bytes (first 16 bytes)."""
    with open(file_path, "rb") as f:
        head = f.read(16)
    for magic, mime in MAGIC_BYTES.items():
        if head.startswith(magic):
            return mime
    return "application/octet-stream"


def _scan_for_c2pa_marker(file_path: str) -> bool:
    """
    Scan file for the C2PA JUMBF marker. C2PA embeds content credentials
    using the 'jumb' box format. We do a simple byte scan for the marker.
    Real C2PA validation would use the c2pa-python library, but for the
    prototype demo a marker scan is enough to differentiate signed vs unsigned.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read(min(2 * 1024 * 1024, Path(file_path).stat().st_size))
        # JUMBF box type for C2PA assertion store
        return b"c2pa" in data or b"jumb" in data or b"jumd" in data
    except Exception:
        return False


def _extract_exif_basics(file_path: str) -> dict:
    """
    Minimal EXIF extraction without external libs.
    Looks for the 'Exif' marker in JPEGs and reports presence of common tags.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read(min(128 * 1024, Path(file_path).stat().st_size))

        has_exif = b"Exif\x00\x00" in data
        has_software_tag = b"Photoshop" in data or b"GIMP" in data or b"Lightroom" in data
        has_camera_make = any(brand in data for brand in [b"Canon", b"NIKON", b"SONY", b"Apple", b"samsung"])

        return {
            "exif_present": has_exif,
            "editor_software_detected": has_software_tag,
            "camera_make_detected": has_camera_make
        }
    except Exception:
        return {"exif_present": False, "editor_software_detected": False, "camera_make_detected": False}


def extract_provenance(file_path: str, mime_type: str) -> dict:
    """
    Run all provenance extraction checks.
    Returns a dict with:
      - signals_found: list of provenance signals detected
      - score: 0-100 (higher = stronger provenance)
      - explanation: human-readable summary
    """
    signals = []
    explanations = []

    if mime_type.startswith("image/"):
        if _scan_for_c2pa_marker(file_path):
            signals.append("c2pa_credentials")
            explanations.append("C2PA Content Credentials detected — file has verifiable provenance metadata.")

        exif = _extract_exif_basics(file_path)
        if exif["exif_present"]:
            signals.append("exif_metadata")
            explanations.append("EXIF metadata present.")
        if exif["camera_make_detected"]:
            signals.append("camera_origin")
            explanations.append("Camera manufacturer signature found in metadata.")
        if exif["editor_software_detected"]:
            signals.append("editor_trace")
            explanations.append("Image was processed by editing software (provenance partially modified).")

    elif mime_type == "application/pdf":
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if b"/Sig " in data or b"/ByteRange" in data:
                signals.append("pdf_digital_signature")
                explanations.append("PDF contains a digital signature.")
            if b"/Author" in data:
                signals.append("pdf_author_metadata")
                explanations.append("PDF author metadata present.")
        except Exception:
            pass

    # Score the signals
    score = 0
    if "c2pa_credentials" in signals:
        score += 60
    if "pdf_digital_signature" in signals:
        score += 60
    if "exif_metadata" in signals:
        score += 15
    if "camera_origin" in signals:
        score += 15
    if "pdf_author_metadata" in signals:
        score += 15
    if "editor_trace" in signals:
        score -= 5  # editor presence slightly weakens trust unless paired with C2PA

    score = max(0, min(100, score))

    if not signals:
        explanations.append("No provenance signals found. File origin cannot be verified.")

    return {
        "signals_found": signals,
        "score": score,
        "explanation": " ".join(explanations) if explanations else "No provenance metadata."
    }
