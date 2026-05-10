"""
Digital signatures using RSA-2048.

The system holds a private key (kept secret) and exposes a public key.
Each provenance block is signed with the private key.
Anyone can verify a block's authenticity using the public key.

This is the same cryptographic foundation behind SSL/TLS, signed software updates,
and the C2PA standard for media provenance.
"""
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from app.config import settings


PRIVATE_KEY_PATH = settings.KEYS_DIR / "system_private.pem"
PUBLIC_KEY_PATH = settings.KEYS_DIR / "system_public.pem"


def generate_keypair():
    """Generate a fresh RSA-2048 keypair and save to disk. Run once on first boot."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def ensure_keys_exist():
    """Create keys if they don't exist yet."""
    if not PRIVATE_KEY_PATH.exists() or not PUBLIC_KEY_PATH.exists():
        generate_keypair()


def load_private_key():
    ensure_keys_exist()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key():
    ensure_keys_exist()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign(message: str) -> str:
    """Sign a message with the system private key. Returns hex-encoded signature."""
    private_key = load_private_key()
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()


def verify(message: str, signature_hex: str) -> bool:
    """Verify a signature against the system public key."""
    public_key = load_public_key()
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
