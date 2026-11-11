import os
import json
import hashlib
import hmac
import secrets
from pathlib import Path

APP_NAME = "CyberFaceGuard"

LOCAL_APPDATA = os.getenv("LOCALAPPDATA")
if not LOCAL_APPDATA:
    LOCAL_APPDATA = os.path.expanduser("~")

APP_DATA_DIR = Path(LOCAL_APPDATA) / APP_NAME
AUTH_DIR = APP_DATA_DIR / "auth"
PASSWORD_FILE = AUTH_DIR / "app_password.dat"

SALT_SIZE = 32
HASH_SIZE = 32
ITERATIONS = 600_000


def password_requirements(password):
    if not isinstance(password, str):
        return False, "Invalid password."

    if len(password) < 12:
        return False, "Password must contain at least 12 characters."

    if " " in password:
        return False, "Password cannot contain spaces."

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."

    special = "!@#$%^&*()-_=+[]{};:,.?/\\|<>`~"

    if not any(c in special for c in password):
        return False, "Password must contain at least one special character."

    return True, "Password is strong."


def password_exists():
    try:
        if not PASSWORD_FILE.exists():
            return False

        if not PASSWORD_FILE.is_file():
            return False

        if PASSWORD_FILE.stat().st_size == 0:
            return False

        data = json.loads(
            PASSWORD_FILE.read_text(encoding="utf-8")
        )

        return (
            isinstance(data, dict)
            and "salt" in data
            and "password_hash" in data
        )

    except Exception:
        return False


def create_password(password):
    valid, message = password_requirements(password)

    if not valid:
        return False, message

    if PASSWORD_FILE.exists():
        return False, "App password is already configured."

    try:
        AUTH_DIR.mkdir(parents=True, exist_ok=True)

        salt = secrets.token_bytes(SALT_SIZE)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            ITERATIONS,
            dklen=HASH_SIZE
        )

        data = {
            "version": 1,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": ITERATIONS,
            "salt": salt.hex(),
            "password_hash": password_hash.hex()
        }

        PASSWORD_FILE.write_text(
            json.dumps(data, indent=4),
            encoding="utf-8"
        )

        return True, "App password created successfully."

    except Exception as error:
        return False, f"Failed to create app password:\n{error}"


def verify_password(password):
    if not PASSWORD_FILE.exists():
        return False, "App password has not been configured."

    try:
        data = json.loads(
            PASSWORD_FILE.read_text(encoding="utf-8")
        )

        salt = bytes.fromhex(data["salt"])
        stored_hash = bytes.fromhex(data["password_hash"])

        iterations = int(
            data.get("iterations", ITERATIONS)
        )

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=HASH_SIZE
        )

        if hmac.compare_digest(
            calculated_hash,
            stored_hash
        ):
            return True, "Password is correct."

        return False, "Incorrect password."

    except Exception as error:
        return False, f"Password verification failed:\n{error}"


def get_password_file():
    return PASSWORD_FILE