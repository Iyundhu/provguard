"""
Generate the demo files used during the presentation.

After running, you'll have in scripts/demo_files/:
  - clean_document.pdf          : a normal PDF (should verify TRUSTED or near-trusted)
  - eicar_test.txt              : the EICAR antivirus test signature (should verify MALICIOUS)
  - disguised.pdf               : a fake PDF that's actually an executable header (SUSPICIOUS/MALICIOUS)
  - high_entropy.bin            : random bytes, demonstrates entropy detection

These give you four visibly distinct demo outcomes.
"""
import os
from pathlib import Path

OUT = Path(__file__).resolve().parent / "demo_files"
OUT.mkdir(exist_ok=True)


def make_clean_pdf():
    """Minimal valid PDF that should pass most checks."""
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length 44 >>\nstream\n"
        b"BT /F1 24 Tf 100 700 Td (ProvGuard demo) Tj ET\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"/Author (ProvGuard Demo)\n"
        b"xref\n0 6\n0000000000 65535 f\n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
    )
    (OUT / "clean_document.pdf").write_bytes(pdf)
    print("✓ clean_document.pdf")


def make_eicar():
    """
    EICAR test signature. This is the official, industry-standard
    safe malware test string used by every antivirus vendor since 1991.
    It is detected as malware by all engines but is completely harmless.
    Reference: https://www.eicar.org/download-anti-malware-testfile/
    """
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    (OUT / "eicar_test.txt").write_bytes(eicar)
    print("✓ eicar_test.txt (industry-standard safe malware test string)")


def make_disguised():
    """A file with .pdf extension but Windows PE header inside."""
    fake = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 200
    (OUT / "disguised.pdf").write_bytes(fake)
    print("✓ disguised.pdf (PE header disguised as PDF)")


def make_high_entropy():
    """Random bytes -> high entropy (mimics packed/encrypted content)."""
    (OUT / "high_entropy.bin").write_bytes(os.urandom(64 * 1024))
    print("✓ high_entropy.bin")


if __name__ == "__main__":
    make_clean_pdf()
    make_eicar()
    make_disguised()
    make_high_entropy()
    print(f"\nDemo files saved to: {OUT}")
    print("\nDemo flow:")
    print("  1. Upload clean_document.pdf      -> TRUSTED-ish (good provenance)")
    print("  2. Upload eicar_test.txt          -> MALICIOUS (VT + behavioral hit)")
    print("  3. Upload disguised.pdf           -> MALICIOUS (extension mismatch + PE header)")
    print("  4. Upload high_entropy.bin        -> SUSPICIOUS (no provenance, high entropy)")
    print("  5. Visit /chain and click Verify chain")
    print("  6. Tamper with DB: sqlite3 data/provguard.db \"UPDATE provenance_chain SET payload='hacked' WHERE id=2\"")
    print("  7. Re-verify chain -> integrity violation detected")
