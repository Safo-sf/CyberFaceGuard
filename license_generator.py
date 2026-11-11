from pathlib import Path
import base64
import json
import secrets

from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent

PRIVATE_KEY_FILE = BASE_DIR / "keys" / "private_key.pem"


def load_private_key():

    if not PRIVATE_KEY_FILE.exists():
        raise FileNotFoundError(
            "private_key.pem not found."
        )

    private_key_data = PRIVATE_KEY_FILE.read_bytes()

    return serialization.load_pem_private_key(
        private_key_data,
        password=None,
    )


def generate_license(customer_name):

    private_key = load_private_key()

    license_id = secrets.token_hex(8).upper()

    data = {
        "product": "CyberFaceGuard",
        "license_id": license_id,
        "customer": customer_name,
    }

    payload = json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    signature = private_key.sign(payload)

    payload_encoded = base64.urlsafe_b64encode(
        payload
    ).decode("ascii").rstrip("=")

    signature_encoded = base64.urlsafe_b64encode(
        signature
    ).decode("ascii").rstrip("=")

    license_key = (
        f"CFG-{payload_encoded}.{signature_encoded}"
    )

    return license_key, license_id


if __name__ == "__main__":

    print("=" * 60)
    print("CyberFaceGuard License Generator")
    print("=" * 60)

    customer = input(
        "Customer name: "
    ).strip()

    if not customer:
        print("Customer name cannot be empty.")
        raise SystemExit(1)

    license_key, license_id = generate_license(
        customer
    )

    print()
    print("=" * 60)
    print("LICENSE CREATED")
    print("=" * 60)

    print()
    print("License ID:")
    print(license_id)

    print()
    print("License Key:")
    print(license_key)

    print()
    print("Keep this license key safe.")