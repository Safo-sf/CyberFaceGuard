from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"

KEYS_DIR.mkdir(exist_ok=True)


private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()


private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

(KEYS_DIR / "private_key.pem").write_bytes(private_bytes)


public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

(KEYS_DIR / "public_key.pem").write_bytes(public_bytes)


print("=" * 60)
print("CyberFaceGuard License Keys Generated")
print("=" * 60)
print()
print("PRIVATE KEY:")
print(KEYS_DIR / "private_key.pem")
print()
print("PUBLIC KEY:")
print(KEYS_DIR / "public_key.pem")
print()
print("IMPORTANT: Keep private_key.pem SECRET.")