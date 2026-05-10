"""
Cryptographic hashing for file fingerprinting.
SHA-256 produces a unique 64-character hex string for any file.
Same file => same hash. One bit different => completely different hash.
This is how we prove integrity.
"""
import hashlib


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Compute SHA-256 hash of a file, reading in chunks to handle large files."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()
