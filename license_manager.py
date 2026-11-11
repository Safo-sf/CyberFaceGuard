import os
import json
import base64
import hashlib
import platform
import uuid

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
)

from PySide6.QtCore import Qt


APP_NAME = "CyberFaceGuard"

LOCAL_APPDATA = os.getenv("LOCALAPPDATA")

if not LOCAL_APPDATA:
    LOCAL_APPDATA = os.path.expanduser("~")


APP_DATA_DIR = Path(LOCAL_APPDATA) / APP_NAME
LICENSE_DIR = APP_DATA_DIR / "license"

LICENSE_FILE = LICENSE_DIR / "activation.json"

PUBLIC_KEY_FILE = (
    Path(__file__).resolve().parent
    / "keys"
    / "public_key.pem"
)

LICENSE_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# DEVICE ID
# ============================================================

def get_device_id():

    raw = "|".join([
        platform.node(),
        platform.system(),
        platform.machine(),
        str(uuid.getnode()),
    ])

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# PUBLIC KEY
# ============================================================

def load_public_key():

    if not PUBLIC_KEY_FILE.exists():

        raise FileNotFoundError(
            "public_key.pem not found:\n"
            f"{PUBLIC_KEY_FILE}"
        )

    public_key_data = PUBLIC_KEY_FILE.read_bytes()

    return serialization.load_pem_public_key(
        public_key_data
    )


# ============================================================
# LICENSE PARSER
# ============================================================

def parse_license_key(key):

    key = key.strip()

    if not key.startswith("CFG-"):
        return None

    try:

        content = key[4:]

        payload_encoded, signature_encoded = (
            content.split(".", 1)
        )

        # Restore Base64 padding
        payload_encoded += "=" * (
            -len(payload_encoded) % 4
        )

        signature_encoded += "=" * (
            -len(signature_encoded) % 4
        )

        payload = base64.urlsafe_b64decode(
            payload_encoded
        )

        signature = base64.urlsafe_b64decode(
            signature_encoded
        )

        return payload, signature

    except Exception:

        return None


# ============================================================
# VERIFY LICENSE
# ============================================================

def verify_license(key):

    parsed = parse_license_key(key)

    if parsed is None:

        return False, None, "Invalid license format."

    payload, signature = parsed

    try:

        public_key = load_public_key()

        public_key.verify(
            signature,
            payload
        )

    except InvalidSignature:

        return False, None, "Invalid license signature."

    except Exception as error:

        return (
            False,
            None,
            f"License verification failed:\n{error}"
        )

    try:

        data = json.loads(
            payload.decode("utf-8")
        )

    except Exception:

        return False, None, "Invalid license data."

    if data.get("product") != APP_NAME:

        return False, None, "License is not for CyberFaceGuard."

    if not data.get("license_id"):

        return False, None, "License ID missing."

    if not data.get("customer"):

        return False, None, "Customer information missing."

    return True, data, "License signature valid."


# ============================================================
# CHECK LOCAL ACTIVATION
# ============================================================

def is_activated():

    if not LICENSE_FILE.exists():

        return False

    try:

        data = json.loads(
            LICENSE_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not data.get("activated"):
            return False

        if data.get("device_id") != get_device_id():
            return False

        license_key = data.get("license_key")

        if not license_key:
            return False

        valid, license_data, message = verify_license(
            license_key
        )

        if not valid:
            return False

        return True

    except Exception:

        return False


# ============================================================
# ACTIVATE LICENSE
# ============================================================

def activate_license(key):

    key = key.strip()

    if not key:

        return False, "Please enter a license key."

    valid, license_data, message = verify_license(
        key
    )

    if not valid:

        return False, message

    if is_activated():

        return False, "CyberFaceGuard is already activated."

    activation_data = {

        "activated": True,

        "license_key": key,

        "license_id": license_data["license_id"],

        "customer": license_data["customer"],

        "device_id": get_device_id(),
    }

    try:

        LICENSE_FILE.write_text(
            json.dumps(
                activation_data,
                indent=4
            ),
            encoding="utf-8"
        )

        return (
            True,
            "License activated successfully."
        )

    except Exception as error:

        return (
            False,
            f"Activation failed:\n{error}"
        )


# ============================================================
# LICENSE WINDOW
# ============================================================

class LicenseDialog(QDialog):

    def __init__(self, parent=None):

        super().__init__(parent)

        self.setWindowTitle(
            "CyberFaceGuard - License Activation"
        )

        self.setFixedSize(
            500,
            300
        )

        self.setStyleSheet("""
            QDialog {
                background-color: #050505;
                color: #eeeeee;
            }

            QLabel {
                color: #eeeeee;
                font-family: Consolas;
            }

            QLineEdit {
                background-color: #101010;
                color: #00ff66;
                border: 1px solid #1d5c35;
                padding: 12px;
                font-family: Consolas;
                font-size: 15px;
            }

            QPushButton {
                background-color: #0a0a0a;
                color: #00ff66;
                border: 1px solid #1d5c35;
                padding: 12px;
                font-family: Consolas;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #12351f;
                border: 1px solid #00ff66;
            }
        """)

        layout = QVBoxLayout()

        title = QLabel(
            "> CYBERFACEGUARD LICENSE"
        )

        title.setStyleSheet("""
            color: #00ff66;
            font-size: 22px;
            font-weight: bold;
        """)

        title.setAlignment(
            Qt.AlignCenter
        )

        layout.addWidget(title)

        info = QLabel(
            "Enter your CyberFaceGuard license key."
        )

        info.setAlignment(
            Qt.AlignCenter
        )

        info.setWordWrap(True)

        layout.addWidget(info)

        self.key_input = QLineEdit()

        self.key_input.setPlaceholderText(
            "CFG-..."
        )

        self.key_input.setAlignment(
            Qt.AlignCenter
        )

        self.key_input.setMaxLength(1000)

        layout.addWidget(
            self.key_input
        )

        self.activate_button = QPushButton(
            "🔐 ACTIVATE LICENSE"
        )

        self.activate_button.clicked.connect(
            self.activate
        )

        layout.addWidget(
            self.activate_button
        )

        self.status = QLabel(
            "STATUS: NOT ACTIVATED"
        )

        self.status.setAlignment(
            Qt.AlignCenter
        )

        self.status.setStyleSheet(
            "color: #888888;"
        )

        layout.addWidget(
            self.status
        )

        layout.addStretch()

        self.setLayout(layout)

    def activate(self):

        key = self.key_input.text()

        success, message = activate_license(
            key
        )

        if success:

            self.status.setText(
                "STATUS: ACTIVATED ✓"
            )

            self.status.setStyleSheet(
                "color: #00ff66; font-weight: bold;"
            )

            QMessageBox.information(
                self,
                "Activation Successful",
                "CyberFaceGuard has been activated successfully."
            )

            self.accept()

        else:

            self.status.setText(
                "STATUS: INVALID LICENSE"
            )

            self.status.setStyleSheet(
                "color: #ff3b3b; font-weight: bold;"
            )

            QMessageBox.warning(
                self,
                "License Error",
                message
            )


# ============================================================
# REQUIRE LICENSE
# ============================================================

def require_license(parent=None):

    if is_activated():

        return True

    dialog = LicenseDialog(parent)

    result = dialog.exec()

    return result == QDialog.Accepted