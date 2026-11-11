import os
import json
import hashlib
import hmac
import secrets
from pathlib import Path


# ============================================================
# CyberFaceGuard - Password Manager
# ============================================================

APP_NAME = "CyberFaceGuard"

# ------------------------------------------------------------
# Windows Local AppData
# ------------------------------------------------------------

LOCAL_APPDATA = os.getenv("LOCALAPPDATA")

if not LOCAL_APPDATA:
    LOCAL_APPDATA = os.path.expanduser("~")


# ------------------------------------------------------------
# Application storage
# ------------------------------------------------------------

APP_DATA_DIR = Path(LOCAL_APPDATA) / APP_NAME
VAULT_DIR = APP_DATA_DIR / "vault"

PASSWORD_FILE = VAULT_DIR / "vault_password.dat"


# ------------------------------------------------------------
# Password hashing configuration
# ------------------------------------------------------------

SALT_SIZE = 32
HASH_SIZE = 32
ITERATIONS = 600_000


# ============================================================
# Password requirements
# ============================================================

def password_requirements(password):
    """
    Check whether the password satisfies the
    CyberFaceGuard password policy.
    """

    if not isinstance(password, str):
        return False, "Invalid password."

    if len(password) < 12:
        return False, "Password must contain at least 12 characters."

    if " " in password:
        return False, "Password cannot contain spaces."

    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."

    special_characters = "!@#$%^&*()-_=+[]{};:,.?/\\|<>`~"

    if not any(char in special_characters for char in password):
        return False, "Password must contain at least one special character."

    return True, "Password is strong."


# ============================================================
# Create password
# ============================================================

def create_password(password):
    """
    Create and securely store a password verifier.

    The original password is NEVER stored.
    Only a salt and PBKDF2-derived hash are stored.
    """

    # Validate password
    valid, message = password_requirements(password)

    if not valid:
        return False, message

    # If password already exists, do not overwrite it
    if PASSWORD_FILE.exists():
        return False, "Vault password is already configured."

    try:
        # Create storage directory
        VAULT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        # Generate random salt
        salt = secrets.token_bytes(SALT_SIZE)

        # Derive password hash
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            ITERATIONS,
            dklen=HASH_SIZE
        )

        # Data stored on disk
        data = {
            "version": 1,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": ITERATIONS,
            "salt": salt.hex(),
            "password_hash": password_hash.hex()
        }

        # Convert to JSON
        json_data = json.dumps(
            data,
            indent=4
        )

        # Write password database
        PASSWORD_FILE.write_text(
            json_data,
            encoding="utf-8"
        )

        # Verify that the file was actually created
        if not PASSWORD_FILE.exists():
            return False, "Password file was not created."

        # Verify that the file contains valid JSON
        test_data = json.loads(
            PASSWORD_FILE.read_text(
                encoding="utf-8"
            )
        )

        if "salt" not in test_data:
            return False, "Password file is invalid."

        if "password_hash" not in test_data:
            return False, "Password file is invalid."

        return True, "Vault password created successfully."

    except Exception as error:
        return False, f"Failed to create password:\n{error}"


# ============================================================
# Check whether password exists
# ============================================================

def password_exists():
    """
    Return True if a valid Vault password database exists.
    """

    try:
        if not PASSWORD_FILE.exists():
            return False

        if not PASSWORD_FILE.is_file():
            return False

        # Make sure the file is not empty
        if PASSWORD_FILE.stat().st_size == 0:
            return False

        # Validate JSON structure
        data = json.loads(
            PASSWORD_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, dict):
            return False

        if "salt" not in data:
            return False

        if "password_hash" not in data:
            return False

        return True

    except Exception:
        return False


# ============================================================
# Verify password
# ============================================================

def verify_password(password):
    """
    Verify the supplied password against the stored verifier.
    """

    if not PASSWORD_FILE.exists():
        return False, "Vault password has not been configured."

    try:
        # Read password database
        raw_data = PASSWORD_FILE.read_text(
            encoding="utf-8"
        )

        data = json.loads(raw_data)

        # Read salt
        salt = bytes.fromhex(
            data["salt"]
        )

        # Read stored hash
        stored_hash = bytes.fromhex(
            data["password_hash"]
        )

        # Read iteration count
        iterations = int(
            data.get(
                "iterations",
                ITERATIONS
            )
        )

        # Calculate hash from entered password
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=HASH_SIZE
        )

        # Constant-time comparison
        if hmac.compare_digest(
            calculated_hash,
            stored_hash
        ):
            return True, "Password is correct."

        return False, "Incorrect password."

    except KeyError:
        return False, "Password database is corrupted."

    except ValueError:
        return False, "Password database contains invalid data."

    except json.JSONDecodeError:
        return False, "Password database is corrupted."

    except Exception as error:
        return False, f"Password verification failed:\n{error}"


# ============================================================
# Delete password database
# ============================================================

def delete_password():
    """
    Delete the stored password verifier.

    WARNING:
    This does NOT decrypt or delete Vault files.
    It only removes the password verifier.
    """

    try:
        if PASSWORD_FILE.exists():
            PASSWORD_FILE.unlink()

        return True, "Vault password database deleted."

    except Exception as error:
        return False, f"Failed to delete password database:\n{error}"


# ============================================================
# Get password file path
# ============================================================

def get_password_file():
    """
    Return the current password database path.
    """

    return PASSWORD_FILE


# ============================================================
# Debug information
# ============================================================

def get_password_status():
    """
    Return useful status information for debugging.
    """

    return {
        "app_data_dir": str(APP_DATA_DIR),
        "vault_dir": str(VAULT_DIR),
        "password_file": str(PASSWORD_FILE),
        "password_exists": password_exists(),
        "file_exists": PASSWORD_FILE.exists(),
    }