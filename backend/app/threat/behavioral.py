"""
Behavioral / heuristic analysis.

Even when threat intelligence has never seen a file, structural features can
reveal malicious intent. This module computes:
  - Shannon entropy: high entropy suggests packing/encryption (common in malware)
  - Header anomalies: file extension claims one thing, magic bytes say another
  - Suspicious patterns: known indicators like embedded executables in PDFs,
    macro-enabled Office docs, oversized headers, etc.

This is the 'preemptive' layer — catching threats before they are known.
"""
import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of byte data. Range: 0.0 (uniform) to 8.0 (random).
    > 7.5 typically means encrypted or compressed content (or packed malware).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _check_extension_mismatch(file_path: str, detected_mime: str) -> bool:
    """Flag if claimed extension doesn't match detected file type."""
    ext = Path(file_path).suffix.lower()
    expected = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".pdf": "application/pdf",
        ".docx": "application/zip-or-office",
        ".xlsx": "application/zip-or-office",
        ".zip": "application/zip-or-office",
        ".exe": "application/x-executable",
        ".dll": "application/x-executable",
    }
    if ext in expected:
        return expected[ext] != detected_mime
    return False


def _scan_suspicious_patterns(file_path: str, mime_type: str) -> list[str]:
    """Look for known red-flag patterns in file content."""
    flags = []
    try:
        size = Path(file_path).stat().st_size
        with open(file_path, "rb") as f:
            head = f.read(min(512 * 1024, size))

        # Embedded executable inside non-executable
        if mime_type != "application/x-executable" and b"MZ\x90\x00" in head[:size]:
            flags.append("embedded_pe_header")

        # PDF with JavaScript or embedded files
        if mime_type == "application/pdf":
            if b"/JS" in head or b"/JavaScript" in head:
                flags.append("pdf_javascript")
            if b"/Launch" in head:
                flags.append("pdf_launch_action")
            if b"/EmbeddedFile" in head:
                flags.append("pdf_embedded_file")

        # Office docs with macros (vbaProject.bin inside the zip)
        if mime_type == "application/zip-or-office":
            if b"vbaProject" in head:
                flags.append("office_macros")

        # EICAR test string (industry-standard safe malware test)
        if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" in head:
            flags.append("eicar_test_signature")

    except Exception:
        pass

    return flags


def analyze_behavior(file_path: str, mime_type: str) -> dict:
    """
    Run all behavioral checks. Return a score and explanation.

    Score logic (0-100, higher = safer):
      - Start at 100
      - Subtract for each red flag
      - Heavy penalty for extension mismatch and embedded executables
      - Entropy alone is not enough to flag — many legitimate files (jpg, zip)
        have high entropy. We weight it as a secondary signal.
    """
    try:
        size = Path(file_path).stat().st_size
        with open(file_path, "rb") as f:
            sample = f.read(min(1024 * 1024, size))  # first 1 MB for entropy
    except Exception:
        return {
            "score": 50,
            "entropy": 0.0,
            "flags": ["read_error"],
            "explanation": "Could not read file for behavioral analysis."
        }

    entropy = shannon_entropy(sample)
    extension_mismatch = _check_extension_mismatch(file_path, mime_type)
    suspicious_flags = _scan_suspicious_patterns(file_path, mime_type)

    score = 100
    explanations = []

    if "eicar_test_signature" in suspicious_flags:
        score = 0
        explanations.append("EICAR test signature detected — this is a known test malware string.")

    if "embedded_pe_header" in suspicious_flags:
        score -= 60
        explanations.append("Embedded Windows executable header found inside non-executable file.")

    if extension_mismatch:
        score -= 30
        explanations.append("File extension does not match detected file type (possible disguise).")

    if "pdf_javascript" in suspicious_flags:
        score -= 20
        explanations.append("PDF contains JavaScript code (common attack vector).")

    if "pdf_launch_action" in suspicious_flags:
        score -= 30
        explanations.append("PDF contains launch action (can execute external programs).")

    if "pdf_embedded_file" in suspicious_flags:
        score -= 15
        explanations.append("PDF contains embedded files.")

    if "office_macros" in suspicious_flags:
        score -= 25
        explanations.append("Office document contains macros (common malware delivery method).")

    # Entropy: only penalise high entropy on file types that should be low-entropy
    low_entropy_types = ("application/pdf",)
    if mime_type in low_entropy_types and entropy > 7.5:
        score -= 10
        explanations.append(f"Unusually high entropy ({entropy:.2f}) for this file type.")

    score = max(0, min(100, score))

    if not explanations:
        explanations.append("No suspicious behavioral patterns detected.")

    return {
        "score": score,
        "entropy": round(entropy, 3),
        "flags": suspicious_flags + (["extension_mismatch"] if extension_mismatch else []),
        "explanation": " ".join(explanations)
    }
