# ============================================================
# IMPORTS
# ============================================================

import sys
import os
import re
import json
import hashlib
import hmac
import secrets
import time
import subprocess

from datetime import datetime

import cv2

# ============================================================
# HIDDEN WINDOWS COMMAND
# ============================================================


def run_hidden_command(command, timeout=60):
    """Run a command without opening a visible console window."""

    startupinfo = None
    creationflags = 0

    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    return subprocess.run(
        command,
        shell=False,
        capture_output=True,
        text=True,
        startupinfo=startupinfo,
        creationflags=creationflags,
        timeout=timeout,
        check=False,
    )


# ============================================================
# PYSide6
# ============================================================

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QFrame,
    QStackedWidget,
    QScrollArea,
    QListWidget,
    QListWidgetItem,
    QLineEdit,
    QTextEdit,
    QInputDialog,
    QMessageBox,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
    QTabWidget,
    QSizePolicy,
)

from PySide6.QtCore import Qt, QTimer, QRectF

from PySide6.QtGui import (
    QImage,
    QPixmap,
    QIcon,
    QColor,
    QBrush,
    QPainter,
    QPen,
    QFont,
    QPdfWriter,
)

# ============================================================
# PROJECT MODULES
# ============================================================

from file_integrity import FileIntegrity
from network_audit import NetworkAudit


def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


from verify_engine import FaceRecognitionEngine
from liveness import LivenessDetector
from enrollment import UserEnrollment
from security_logger import log_event
from lock_screen import LockScreen
from vault_manager import VaultManager
from security_audit import SecurityAudit


# ============================================================
# Vault Password (built-in)
# ============================================================


def _password_dir():
    base = os.getenv("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "CyberFaceGuard")
    os.makedirs(path, exist_ok=True)
    return path


def _password_file():
    return os.path.join(_password_dir(), "vault_password.json")


def password_requirements(password):
    """Return the list of requirements NOT met (empty list = OK)."""
    failed = []
    if len(password) < 8:
        failed.append("At least 8 characters")
    if not re.search(r"[A-Z]", password):
        failed.append("One uppercase letter")
    if not re.search(r"[a-z]", password):
        failed.append("One lowercase letter")
    if not re.search(r"[0-9]", password):
        failed.append("One number")
    if not re.search(r"[^A-Za-z0-9]", password):
        failed.append("One symbol")
    return failed


def password_exists():
    return os.path.exists(_password_file())


def create_password(password):
    failed = password_requirements(password)
    if failed:
        raise ValueError("Password requirements not met: " + ", ".join(failed))
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    with open(_password_file(), "w", encoding="utf-8") as f:
        json.dump({"salt": salt.hex(), "hash": digest.hex()}, f)


def verify_password(password):
    if not password_exists():
        return False
    with open(_password_file(), "r", encoding="utf-8") as f:
        data = json.load(f)
    salt = bytes.fromhex(data["salt"])
    expected = bytes.fromhex(data["hash"])
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(digest, expected)


# ============================================================
# CONSTANTS
# ============================================================

APP_NAME = "CyberFaceGuard"

GREEN = "#00FF88"
DARK_GREEN = "#00B86B"

BLACK = "#02070B"
DARK = "#030B11"
PANEL = "#07131D"
PANEL_LIGHT = "#0A1A24"
PANEL_ACTIVE = "#0B2A22"

BORDER = "#123746"
BORDER_GREEN = "#00A866"

RED = "#FF3B4A"
YELLOW = "#FFC107"
BLUE = "#2196F3"
CYAN = "#20E0E8"

WHITE = "#F2F8FA"
GRAY = "#78909C"
TEXT_SECONDARY = "#A7BDC5"

THRESHOLD = 0.363


# ============================================================
# GLOBAL APPLICATION STYLE
# ============================================================

GLOBAL_STYLE = f"""
QMainWindow {{ background-color: {BLACK}; color: {WHITE}; }}
QDialog {{ background-color: {BLACK}; color: {WHITE}; }}

QWidget {{
    background-color: {BLACK};
    color: {WHITE};
    font-family: "Segoe UI";
    font-size: 12px;
}}

QLabel {{ background-color: transparent; color: {WHITE}; }}

QFrame#panel {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}

QFrame#card {{
    background-color: {PANEL_LIGHT};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}

QFrame#card:hover {{ border: 1px solid {GREEN}; }}

QPushButton {{
    background-color: #07151C;
    color: {GREEN};
    border: 1px solid #146044;
    border-radius: 8px;
    padding: 9px 16px;
    min-height: 18px;
    font-family: "Segoe UI";
    font-size: 11px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: #0A2922;
    color: #00FFAA;
    border: 1px solid {GREEN};
}}
QPushButton:pressed {{ background-color: #063C2B; }}
QPushButton:disabled {{
    background-color: #071016;
    color: #53636B;
    border: 1px solid #17262D;
}}

QLineEdit {{
    background-color: #050F16;
    color: {WHITE};
    border: 1px solid #194353;
    border-radius: 8px;
    padding: 9px 12px;
    selection-background-color: #00AA66;
    selection-color: {WHITE};
}}
QLineEdit:focus {{ border: 1px solid {GREEN}; }}

QComboBox {{
    background-color: #050F16;
    color: {WHITE};
    border: 1px solid #194353;
    border-radius: 8px;
    padding: 8px 10px;
}}
QComboBox:hover {{ border: 1px solid {GREEN}; }}
QComboBox:focus {{ border: 1px solid {GREEN}; }}
QComboBox QAbstractItemView {{
    background-color: {PANEL};
    color: {WHITE};
    border: 1px solid {BORDER};
    selection-background-color: #063C2B;
    selection-color: {GREEN};
}}

QListWidget {{
    background-color: #050F16;
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 6px;
}}
QListWidget::item {{ padding: 11px; margin: 2px; border-radius: 7px; }}
QListWidget::item:hover {{ background-color: #0B242A; color: {WHITE}; }}
QListWidget::item:selected {{
    background-color: #063C2B;
    color: {GREEN};
    border: 1px solid {BORDER_GREEN};
}}

QTextEdit {{
    background-color: #030B11;
    color: {GREEN};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 10px;
    font-family: Consolas;
    font-size: 10px;
}}
QTextEdit:focus {{ border: 1px solid {GREEN}; }}

QTableWidget {{
    background-color: #040D14;
    color: {WHITE};
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: #102A35;
    selection-background-color: #063C2B;
    selection-color: {GREEN};
}}
QTableWidget::item {{ padding: 7px; }}
QTableWidget::item:hover {{ background-color: #0B242A; }}
QTableWidget::item:selected {{ background-color: #063C2B; color: {GREEN}; }}

QHeaderView::section {{
    background-color: #0A1822;
    color: {CYAN};
    border: none;
    border-bottom: 1px solid #174352;
    padding: 9px;
    font-family: "Segoe UI";
    font-size: 10px;
    font-weight: 700;
}}

QTabWidget::pane {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
    top: -1px;
}}
QTabBar::tab {{
    background-color: #050F16;
    color: #6B8994;
    padding: 10px 18px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {GREEN}; }}
QTabBar::tab:selected {{
    color: {GREEN};
    background-color: #071A20;
    border-bottom: 2px solid {GREEN};
}}

QProgressBar {{
    background-color: #050F16;
    border: 1px solid {BORDER};
    border-radius: 7px;
    text-align: center;
    color: {WHITE};
    min-height: 12px;
}}
QProgressBar::chunk {{ background-color: {GREEN}; border-radius: 6px; }}

QCheckBox {{ color: {TEXT_SECONDARY}; spacing: 8px; }}
QCheckBox:hover {{ color: {WHITE}; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    background-color: #050F16;
    border: 1px solid {BORDER};
    border-radius: 4px;
}}
QCheckBox::indicator:hover {{ border: 1px solid {GREEN}; }}
QCheckBox::indicator:checked {{ background-color: {GREEN}; border: 1px solid {GREEN}; }}

QRadioButton {{ color: {TEXT_SECONDARY}; spacing: 8px; }}
QRadioButton::indicator {{
    width: 15px; height: 15px;
    background-color: #050F16;
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QRadioButton::indicator:checked {{ background-color: {GREEN}; border: 1px solid {GREEN}; }}

QSpinBox, QDoubleSpinBox {{
    background-color: #050F16;
    color: {WHITE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 7px;
}}
QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {GREEN}; }}

QScrollBar:vertical {{ background-color: #030A10; width: 8px; border: none; margin: 0; }}
QScrollBar::handle:vertical {{ background-color: #155344; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background-color: #00AA66; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background-color: #030A10; height: 8px; border: none; }}
QScrollBar::handle:horizontal {{ background-color: #155344; border-radius: 4px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background-color: #00AA66; }}

QToolTip {{
    background-color: {PANEL};
    color: {WHITE};
    border: 1px solid {GREEN};
    padding: 6px;
    font-size: 10px;
}}

QMenu {{
    background-color: {PANEL};
    color: {WHITE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 5px;
}}
QMenu::item {{ padding: 8px 22px; border-radius: 5px; }}
QMenu::item:selected {{ background-color: #063C2B; color: {GREEN}; }}

QMessageBox {{ background-color: {BLACK}; color: {WHITE}; }}
QMessageBox QLabel {{ color: {WHITE}; }}
QMessageBox QPushButton {{ min-width: 90px; }}

QToolButton {{
    background-color: transparent;
    color: {TEXT_SECONDARY};
    border: none;
    border-radius: 7px;
    padding: 7px;
}}
QToolButton:hover {{ background-color: #0B242A; color: {GREEN}; }}
QToolButton:pressed {{ background-color: #063C2B; }}
"""


TABLE_STYLE = f"""
QTableWidget {{
    background-color: #040D14;
    color: {WHITE};
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: #102A35;
    selection-background-color: #063C2B;
    selection-color: {GREEN};
}}
QHeaderView::section {{
    background-color: #0A1822;
    color: {CYAN};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 9px;
    font-weight: bold;
}}
QTableWidget::item {{ padding: 7px; }}
QTableWidget::item:selected {{ background-color: #063C2B; color: {GREEN}; }}
"""


ACTION_BUTTON_STYLE = f"""
QPushButton {{
    background-color: #071A12;
    color: {GREEN};
    border: 1px solid {GREEN};
    border-radius: 8px;
    padding: 9px 16px;
    font-family: "Segoe UI";
    font-size: 11px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: #0D2B20;
    border: 1px solid #00FFAA;
    color: #00FFAA;
}}
QPushButton:pressed {{ background-color: #063C2B; }}
QPushButton:disabled {{
    background-color: #071016;
    color: {GRAY};
    border: 1px solid #53636B;
}}
"""


def page_title(text, size=22):
    label = QLabel(text)
    label.setStyleSheet(
        f"""
        QLabel {{
            background: transparent;
            color: {WHITE};
            font-family: "Segoe UI";
            font-size: {size}px;
            font-weight: 700;
        }}
        """
    )
    return label


def panel_frame(background=None):
    if background is None:
        background = PANEL

    frame = QFrame()
    frame.setObjectName("panel")
    frame.setStyleSheet(
        f"""
        QFrame#panel {{
            background-color: {background};
            border: 1px solid {BORDER};
            border-radius: 12px;
        }}
        """
    )
    return frame


# ============================================================
# Helper - Camera Frame
# ============================================================


def frame_to_pixmap(frame):
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    height, width, channels = rgb.shape
    bytes_per_line = channels * width
    image = QImage(rgb.data, width, height, bytes_per_line, QImage.Format_RGB888)
    # .copy() so the QImage owns its data
    return QPixmap.fromImage(image.copy())


# ============================================================
# Dashboard Card
# ============================================================


class StatCard(QFrame):

    def __init__(self, title, value="0"):
        super().__init__()
        self.setObjectName("statCard")
        self.setStyleSheet(f"""
            QFrame#statCard {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
            }}
        """)
        layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {GRAY}; font-size: 12px;")
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(
            f"color: {GREEN}; font-size: 28px; font-weight: bold;"
        )
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        self.setLayout(layout)

    def set_value(self, value):
        self.value_label.setText(str(value))


# ============================================================
# PROFESSIONAL SOC DASHBOARD
# ============================================================


class DashboardPage(QWidget):
    """Responsive SOC-style dashboard. Network figures remain unknown until a real audit runs."""

    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.monitor_text = ""
        self.network_audit_result = None
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.setStyleSheet(f"""
            QFrame#socPanel {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                    stop:0 #06131a, stop:1 #02090d);
                border: 1px solid #14513d;
                border-radius: 10px;
            }}
            QFrame#metricCard {{
                background-color: #06120f;
                border: 1px solid #14513d;
                border-radius: 10px;
            }}
            QFrame#metricCard:hover {{ border: 1px solid {GREEN}; }}
            QFrame#moduleRow {{ background:#030b0e; border-radius:4px; }}
            QLabel#muted {{ color: #8aa9a0; font-size: 10px; }}
            QLabel#sectionTitle {{ color: {GREEN}; font-size: 12px; font-weight: bold; }}
            QLabel#metricTitle {{ color: #9ab8b0; font-size: 9px; font-weight: bold; }}
            QLabel#metricValue {{ color: {GREEN}; font-size: 21px; font-weight: bold; }}
        """)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        scroll = QScrollArea(self)
        scroll.setObjectName("dashboardScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea#dashboardScroll { background:#02070B; border:0; }")
        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(10)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        # Header
        header = QFrame()
        header.setObjectName("socPanel")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 10, 16, 10)
        brand = QVBoxLayout()
        title = QLabel("CYBERFACEGUARD")
        title.setStyleSheet(f"color:{GREEN};font-size:22px;font-weight:800;")
        subtitle = QLabel("SECURITY OPERATIONS CENTER  /  LOCAL MODE")
        subtitle.setObjectName("muted")
        brand.addWidget(title)
        brand.addWidget(subtitle)
        hl.addLayout(brand)
        hl.addStretch()
        self.header_status = QLabel("●  SYSTEM ONLINE")
        self.header_status.setStyleSheet(f"color:{GREEN};font-size:11px;font-weight:bold;")
        hl.addWidget(self.header_status, alignment=Qt.AlignRight)
        root.addWidget(header)

        welcome = QFrame()
        welcome.setObjectName("socPanel")
        wl = QHBoxLayout(welcome)
        wl.setContentsMargins(16, 8, 16, 8)
        self.welcome_label = QLabel("WELCOME, OPERATOR")
        self.welcome_label.setStyleSheet("font-size:16px;font-weight:700;color:#eaf7f5;")
        self.welcome_info = QLabel("Your local security environment is ready.")
        self.welcome_info.setObjectName("muted")
        wl.addWidget(self.welcome_label)
        wl.addSpacing(10)
        wl.addWidget(self.welcome_info)
        wl.addStretch()
        safe = QLabel("LOCAL CONTROL  •  PRIVACY FIRST")
        safe.setStyleSheet(f"color:{CYAN};font-size:9px;font-weight:bold;")
        wl.addWidget(safe)
        root.addWidget(welcome)

        # Status cards
        metrics = QHBoxLayout()
        metrics.setSpacing(8)
        self.security_card = self.create_metric_card("⬡", "SECURITY STATUS", "READY")
        self.face_card = self.create_metric_card("◎", "FACE AUTHENTICATION", "READY")
        self.vault_card = self.create_metric_card("▣", "SECURE VAULT", "LOCKED")
        self.threat_card = self.create_metric_card("△", "THREAT LEVEL", "UNKNOWN")
        for card in (self.security_card, self.face_card, self.vault_card, self.threat_card):
            metrics.addWidget(card, 1)
        root.addLayout(metrics)

        # Middle row
        middle = QHBoxLayout()
        middle.setSpacing(8)

        network_panel = QFrame()
        network_panel.setObjectName("socPanel")
        nl = QVBoxLayout(network_panel)
        nl.setContentsMargins(12, 10, 12, 10)
        nl.setSpacing(7)
        nl.addWidget(self.section_label("◈  NETWORK SECURITY"))
        score_row = QHBoxLayout()
        self.network_score_label = QLabel("--")
        self.network_score_label.setAlignment(Qt.AlignCenter)
        self.network_score_label.setMinimumWidth(90)
        self.network_score_label.setStyleSheet(
            f"color:{CYAN};font-size:30px;font-weight:800;border:2px solid #087d66;"
            "border-radius:48px;padding:16px;"
        )
        score_row.addWidget(self.network_score_label, 1)
        network_info = QVBoxLayout()
        network_info.addWidget(QLabel("NETWORK POSTURE"))
        self.network_posture_label = QLabel("NOT AUDITED")
        self.network_posture_label.setStyleSheet(f"color:{YELLOW};font-size:14px;font-weight:bold;")
        network_info.addWidget(self.network_posture_label)
        network_info.addSpacing(5)
        network_info.addWidget(QLabel("RISK LEVEL"))
        self.network_risk_label = QLabel("UNKNOWN")
        self.network_risk_label.setStyleSheet(f"color:{GRAY};font-size:13px;font-weight:bold;")
        network_info.addWidget(self.network_risk_label)
        network_info.addStretch()
        score_row.addLayout(network_info, 2)
        nl.addLayout(score_row)
        self.network_counts = QLabel("Connections: —     Listening ports: —")
        self.network_counts.setObjectName("muted")
        nl.addWidget(self.network_counts)
        network_button = QPushButton("▶  OPEN NETWORK AUDIT")
        network_button.setMinimumHeight(32)
        network_button.setStyleSheet(ACTION_BUTTON_STYLE)
        network_button.clicked.connect(lambda: self.main_window.change_page(8))
        nl.addWidget(network_button)
        middle.addWidget(network_panel, 5)

        system_panel = QFrame()
        system_panel.setObjectName("socPanel")
        sl = QVBoxLayout(system_panel)
        sl.setContentsMargins(14, 12, 14, 12)
        sl.setSpacing(9)
        system_panel.setMinimumHeight(285)
        sl.addWidget(self.section_label("◈  SYSTEM OVERVIEW"))
        self.system_state = QLabel("●  SYSTEM ONLINE")
        self.system_state.setStyleSheet(f"color:{GREEN};font-size:15px;font-weight:bold;")
        sl.addWidget(self.system_state)
        self.system_message = QLabel("Run Security Audit to check system protections.")
        self.system_message.setWordWrap(True)
        self.system_message.setObjectName("muted")
        sl.addWidget(self.system_message)
        sl.addSpacing(5)
        sl.addWidget(self.section_label("◈  SECURITY MODULES"))
        self.module_labels = []
        for name, state in (
            ("Face Authentication", "READY"),
            ("Liveness Detection", "READY"),
            ("File Integrity", "READY"),
            ("Secure Vault", "LOCKED"),
            ("Local License", "LOCAL"),
        ):
            row = QFrame()
            row.setObjectName("moduleRow")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 7, 8, 7)
            name_label = QLabel(name)
            name_label.setStyleSheet("font-size:11px;color:#c6dad6;")
            state_label = QLabel(state)
            state_label.setStyleSheet(
                f"font-size:10px;font-weight:bold;color:{GREEN if state != 'LOCKED' else BLUE};"
            )
            rl.addWidget(name_label)
            rl.addStretch()
            rl.addWidget(state_label)
            sl.addWidget(row)
            self.module_labels.append((name, state_label))
        sl.addStretch()
        middle.addWidget(system_panel, 4)
        root.addLayout(middle, 3)

        # Bottom row
        bottom = QHBoxLayout()
        bottom.setSpacing(8)

        activity = QFrame()
        activity.setObjectName("socPanel")
        al = QVBoxLayout(activity)
        al.setContentsMargins(12, 10, 12, 10)
        al.addWidget(self.section_label("◈  SECURITY ACTIVITY"))
        self.activity_label = QLabel(
            "› Dashboard initialized\n› Face authentication ready\n"
            "› Secure Vault available\n› Waiting for security events"
        )
        self.activity_label.setStyleSheet("color:#a5d9c2;font-family:Consolas;font-size:10px;")
        self.activity_label.setWordWrap(True)
        al.addWidget(self.activity_label)
        al.addStretch()
        bottom.addWidget(activity, 3)

        feed = QFrame()
        feed.setObjectName("socPanel")
        fl = QVBoxLayout(feed)
        fl.setContentsMargins(12, 10, 12, 10)
        fl.addWidget(self.section_label("◈  LIVE SECURITY FEED"))
        self.feed_label = QLabel(
            "[INFO] CyberFaceGuard initialized\n[INFO] Local security mode active\n[READY] Waiting for events..."
        )
        self.feed_label.setStyleSheet(f"color:{GREEN};font-family:Consolas;font-size:9px;")
        self.feed_label.setWordWrap(True)
        fl.addWidget(self.feed_label)
        fl.addStretch()
        bottom.addWidget(feed, 3)

        actions = QFrame()
        actions.setObjectName("socPanel")
        ql = QVBoxLayout(actions)
        ql.setContentsMargins(12, 10, 12, 10)
        ql.setSpacing(6)
        ql.addWidget(self.section_label("◈  QUICK ACTIONS"))
        for text, index in (
            ("◎  FACE AUTHENTICATION", 1),
            ("▣  OPEN SECURE VAULT", 2),
            ("▤  VIEW SECURITY LOGS", 4),
            ("⬡  RUN SECURITY AUDIT", 6),
        ):
            button = QPushButton(text)
            button.setMinimumHeight(29)
            button.clicked.connect(lambda checked=False, page=index: self.main_window.change_page(page))
            ql.addWidget(button)
        ql.addStretch()
        bottom.addWidget(actions, 2)
        root.addLayout(bottom, 2)

        footer = QLabel("CYBERFACEGUARD  •  ADVANCED LOCAL SECURITY  •  LOCAL CONTROL  •  TOTAL PRIVACY")
        footer.setAlignment(Qt.AlignCenter)
        footer.setStyleSheet("color:#477e68;font-size:8px;padding:2px;")
        root.addWidget(footer)
        self.refresh()

    @staticmethod
    def section_label(text):
        label = QLabel(text)
        label.setObjectName("sectionTitle")
        return label

    def create_metric_card(self, icon, title, value):
        card = QFrame()
        card.setObjectName("metricCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(11, 8, 11, 8)
        top = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"color:{CYAN};font-size:20px;font-weight:bold;")
        top.addWidget(icon_label)
        top.addStretch()
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{GREEN};font-size:10px;")
        top.addWidget(dot)
        layout.addLayout(top)
        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")
        layout.addWidget(title_label)
        value_label = QLabel(value)
        value_label.setObjectName("metricValue")
        layout.addWidget(value_label)
        card.value_label = value_label
        return card

    def set_monitor(self, text):
        self.monitor_text = str(text)
        self.refresh()

    def update_network_status(self, result):
        """Update network cards only from a completed local audit result."""
        self.network_audit_result = result or {}
        summary = self.network_audit_result.get("summary", {})
        risk = self.network_audit_result.get("risk", {})
        score = risk.get("score")
        level = str(risk.get("level", "UNKNOWN")).upper()
        network = self.network_audit_result.get("network", {})
        connections = summary.get("active_connections", "—")
        ports = summary.get("listening_ports", "—")
        if score is not None:
            self.network_score_label.setText(f"{score}/100")
        else:
            self.network_score_label.setText("--")
        self.network_posture_label.setText(
            "PROTECTED" if level == "LOW"
            else "ATTENTION" if level == "MEDIUM"
            else "REVIEW REQUIRED" if level == "HIGH"
            else "AUDITED"
        )
        self.network_risk_label.setText(level)
        self.network_counts.setText(f"Connections: {connections}     Listening ports: {ports}")
        color = GREEN if level == "LOW" else YELLOW if level == "MEDIUM" else RED if level == "HIGH" else GRAY
        self.network_score_label.setStyleSheet(
            f"color:{color};font-size:24px;font-weight:800;border:2px solid {color};border-radius:48px;padding:16px;"
        )
        self.network_posture_label.setStyleSheet(f"color:{color};font-size:14px;font-weight:bold;")
        self.network_risk_label.setStyleSheet(f"color:{color};font-size:13px;font-weight:bold;")
        self.welcome_info.setText(f"Last local network audit completed • {network.get('local_ip', 'local network')}")
        self.monitor_text = f"Network audit completed — risk {level}, score {score if score is not None else 'n/a'}/100"
        self.refresh()

    def refresh(self):
        try:
            users = self.main_window.enrollment.get_users()
        except Exception:
            users = []
        authorized = int(getattr(self.main_window, "authorized_count", 0))
        unknown = int(getattr(self.main_window, "unknown_count", 0))
        threats = int(getattr(self.main_window, "threat_count", 0))
        username = str(users[0].get("username", "OPERATOR")) if users else "OPERATOR"
        self.welcome_label.setText(f"WELCOME, {username.upper()}")

        self.security_card.value_label.setText("MONITORING")
        self.face_card.value_label.setText(f"{authorized} VERIFIED" if authorized else "READY")

        try:
            unlocked = bool(self.main_window.vault.vault.is_unlocked())
        except Exception:
            unlocked = False
        self.vault_card.value_label.setText("UNLOCKED" if unlocked else "LOCKED")
        for name, label in self.module_labels:
            if name == "Secure Vault":
                label.setText("UNLOCKED" if unlocked else "LOCKED")
                label.setStyleSheet(f"font-size:10px;font-weight:bold;color:{GREEN if unlocked else BLUE};")

        total = unknown + threats
        level = "LOW" if total == 0 else "MEDIUM" if total < 5 else "HIGH"
        color = GREEN if level == "LOW" else YELLOW if level == "MEDIUM" else RED
        self.threat_card.value_label.setText(level)
        self.threat_card.value_label.setStyleSheet(f"color:{color};font-size:21px;font-weight:bold;")
        self.system_state.setText("●  SYSTEM ONLINE")
        self.system_state.setStyleSheet(f"color:{GREEN};font-size:15px;font-weight:bold;")
        self.system_message.setText("Local modules initialized. Run Security Audit for a detailed system assessment.")
        self.activity_label.setText(
            f"› Enrolled users       : {len(users)}\n"
            f"› Authorized events    : {authorized}\n"
            f"› Unknown face events  : {unknown}\n"
            f"› Threat events        : {threats}\n"
            f"› Secure Vault         : {'UNLOCKED' if unlocked else 'LOCKED'}"
        )
        feed = (
            "[INFO] CyberFaceGuard operational\n"
            f"[AUTH] Authorized events : {authorized}\n"
            f"[AUTH] Unknown events    : {unknown}\n"
            f"[THREAT] Threat events   : {threats}\n"
            f"[VAULT] Status           : {'UNLOCKED' if unlocked else 'LOCKED'}\n"
        )
        if self.monitor_text:
            feed += f"[EVENT] {self.monitor_text}\n"
        if self.network_audit_result is None:
            feed += "[NETWORK] Run Network Audit for live local results."
        else:
            feed += "[NETWORK] Latest audit result shown above."
        self.feed_label.setText(feed)


# ============================================================
# Face Authentication Page
# ============================================================


class FaceAuthPage(QWidget):

    NO_FACE_RESET_FRAMES = 30

    def __init__(self, main_window):
        super().__init__()

        self.main_window = main_window
        self.camera = None

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_camera)

        self.engine = None
        self.liveness = LivenessDetector()
        self.running = False
        self.user_features = []
        self.last_status = ""
        self.no_face_frames = 0

        main_layout = QVBoxLayout()
        main_layout.addWidget(page_title("> FACE AUTHENTICATION"))

        self.camera_label = QLabel("CAMERA OFFLINE")
        self.camera_label.setAlignment(Qt.AlignCenter)
        self.camera_label.setMinimumSize(720, 480)
        self.camera_label.setStyleSheet(
            f"background-color: #020202; color: {GREEN}; "
            f"border: 1px solid {BORDER}; font-size: 18px;"
        )
        main_layout.addWidget(self.camera_label)

        self.status_label = QLabel("STATUS: IDLE")
        self.set_status("STATUS: IDLE", GREEN)
        main_layout.addWidget(self.status_label)

        self.similarity_label = QLabel("SIMILARITY: --")
        self.similarity_label.setStyleSheet(f"color: {GRAY};")
        main_layout.addWidget(self.similarity_label)

        buttons = QHBoxLayout()
        self.start_button = QPushButton("▶ START VERIFICATION")
        self.start_button.clicked.connect(self.start_camera)
        self.stop_button = QPushButton("■ STOP")
        self.stop_button.clicked.connect(self.stop_camera)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        main_layout.addLayout(buttons)

        self.setLayout(main_layout)

    def set_status(self, text, color):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(
            f"color: {color}; font-size: 18px; font-weight: bold;"
        )

    def load_user_features(self):
        self.user_features = []
        users = self.main_window.enrollment.get_users()

        for user in users:
            face_path = user.get("face_path")
            username = user.get("username")

            if not face_path or not os.path.exists(face_path):
                continue

            image = cv2.imread(face_path)
            if image is None:
                continue

            try:
                feature = self.engine._create_feature(image)
                self.user_features.append({"username": username, "feature": feature})
                print(f"[AUTH] Loaded user: {username}")
            except Exception as error:
                print(f"[AUTH] Failed loading {username}: {error}")

        print(f"[AUTH] Loaded {len(self.user_features)} users.")

    def start_camera(self):

        if self.running:
            return

        try:
            if self.engine is None:
                self.engine = FaceRecognitionEngine()

            self.load_user_features()

            if len(self.user_features) == 0:
                QMessageBox.warning(
                    self,
                    "No Users",
                    "No enrolled users found.\n\n"
                    "Go to USER PROFILES and enroll a user first."
                )
                return

            self.camera = cv2.VideoCapture(0)

            if not self.camera.isOpened():
                QMessageBox.critical(self, "Camera Error", "Unable to open camera.")
                self.camera = None
                return

            self.running = True
            self.liveness.reset()
            self.last_status = ""
            self.no_face_frames = 0

            self.set_status("STATUS: CAMERA ACTIVE", GREEN)
            self.timer.start(30)
            print("[CAMERA] Started.")

        except Exception as error:
            QMessageBox.critical(self, "Engine Error", str(error))
            print(f"[CAMERA ERROR] {error}")

    def stop_camera(self):

        self.timer.stop()

        if self.camera is not None:
            self.camera.release()
            self.camera = None

        self.running = False
        self.last_status = ""
        self.no_face_frames = 0
        self.liveness.reset()

        self.camera_label.clear()
        self.camera_label.setText("CAMERA OFFLINE")
        self.set_status("STATUS: IDLE", GREEN)
        self.similarity_label.setText("SIMILARITY: --")

        print("[CAMERA] Stopped.")

    def match_users(self, frame, face):

        if not self.user_features:
            return None, 0.0

        try:
            aligned = self.engine.recognizer.alignCrop(frame, face)
            feature = self.engine.recognizer.feature(aligned)

            best_user = None
            best_similarity = 0.0

            for user in self.user_features:
                similarity = float(
                    self.engine.recognizer.match(
                        user["feature"],
                        feature,
                        cv2.FaceRecognizerSF_FR_COSINE
                    )
                )

                if similarity > best_similarity:
                    best_similarity = similarity
                    best_user = user["username"]

            if best_user is not None and best_similarity >= THRESHOLD:
                return best_user, best_similarity

            return None, best_similarity

        except Exception as error:
            print(f"[MATCH ERROR] {error}")
            return None, 0.0

    def show_frame(self, frame):
        self.camera_label.setPixmap(
            frame_to_pixmap(frame).scaled(
                self.camera_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
        )

    def update_camera(self):

        if self.camera is None:
            return

        success, frame = self.camera.read()
        if not success:
            return

        frame = cv2.flip(frame, 1)

        face = self.engine.detect_face(frame)

        # ---------------- NO FACE ----------------
        if face is None:

            self.set_status("STATUS: NO FACE DETECTED", GRAY)
            self.similarity_label.setText("SIMILARITY: --")

            self.no_face_frames += 1
            if self.no_face_frames >= self.NO_FACE_RESET_FRAMES:
                self.last_status = ""

            self.show_frame(frame)
            return

        self.no_face_frames = 0

        x, y, w, h = face[:4].astype(int)

        cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 100), 2)

        # ---------------- LIVENESS ----------------
        live = self.liveness.check(face)

        if not live:

            self.set_status("STATUS: LIVENESS CHECK", GREEN)

            cv2.putText(
                frame, "LIVENESS CHECK",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 100), 2
            )

        else:

            username, similarity = self.match_users(frame, face)

            self.similarity_label.setText(f"SIMILARITY: {similarity:.3f}")

            # ------------ AUTHORIZED ------------
            if username is not None:

                status_text = f"AUTHORIZED: {username}"
                self.set_status(f"STATUS: {status_text}", GREEN)

                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 100), 3)
                cv2.putText(
                    frame, status_text,
                    (x, max(y - 10, 20)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 100), 2
                )

                if self.last_status != username:
                    log_event("AUTHORIZED", similarity)
                    self.main_window.authorized_count += 1
                    self.main_window.dashboard.set_monitor(
                        f"AUTHORIZED USER: {username}"
                    )
                    self.last_status = username

            # ------------ UNKNOWN ------------
            else:

                status_text = "UNKNOWN USER"
                self.set_status("STATUS: UNKNOWN USER", RED)

                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 3)
                cv2.putText(
                    frame, status_text,
                    (x, max(y - 10, 20)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2
                )

                if self.last_status != "UNKNOWN":
                    log_event("UNKNOWN", similarity)
                    self.main_window.unknown_count += 1
                    self.main_window.threat_count += 1
                    self.main_window.dashboard.set_monitor(
                        "WARNING: UNKNOWN FACE DETECTED"
                    )
                    self.last_status = "UNKNOWN"

        self.show_frame(frame)

    def hideEvent(self, event):
        self.stop_camera()
        super().hideEvent(event)


# ============================================================
# User Profiles Page
# ============================================================


class UsersPage(QWidget):

    def __init__(self, main_window):
        super().__init__()

        self.main_window = main_window

        layout = QVBoxLayout()
        layout.addWidget(page_title("> USER PROFILES"))

        info = QLabel("Locally enrolled users")
        info.setStyleSheet(f"color: {GRAY};")
        layout.addWidget(info)

        self.user_list = QListWidget()
        layout.addWidget(self.user_list)

        buttons = QHBoxLayout()

        enroll_button = QPushButton("+ ENROLL USER")
        enroll_button.clicked.connect(self.enroll_user)

        remove_button = QPushButton("- REMOVE USER")
        remove_button.clicked.connect(self.remove_user)

        refresh_button = QPushButton("↻ REFRESH")
        refresh_button.clicked.connect(self.refresh_users)

        buttons.addWidget(enroll_button)
        buttons.addWidget(remove_button)
        buttons.addWidget(refresh_button)
        layout.addLayout(buttons)

        self.setLayout(layout)

        self.refresh_users()

    def refresh_users(self):

        self.user_list.clear()

        users = self.main_window.enrollment.get_users()

        for user in users:
            username = user.get("username", "Unknown")
            status = user.get("status", "ACTIVE")

            item = QListWidgetItem(f"[{status}]  {username}")
            item.setData(Qt.UserRole, username)
            self.user_list.addItem(item)

        # dashboard may not exist yet during MainWindow construction
        dashboard = getattr(self.main_window, "dashboard", None)
        if dashboard is not None:
            dashboard.refresh()

    def enroll_user(self):

        username, ok = QInputDialog.getText(self, "Enroll User", "Enter username:")

        if not ok:
            return

        username = username.strip()

        valid, error = self.main_window.enrollment.validate_username(username)

        if not valid:
            QMessageBox.warning(self, "Invalid Username", error)
            return

        if self.main_window.enrollment.user_exists(username):
            QMessageBox.warning(self, "User Exists", f"User '{username}' already exists.")
            return

        dialog = EnrollmentCamera(self, self.main_window, username)
        result = dialog.exec()

        if result:
            self.refresh_users()
            QMessageBox.information(
                self,
                "Enrollment Complete",
                f"User '{username}' was enrolled successfully."
            )

    def remove_user(self):

        item = self.user_list.currentItem()

        if item is None:
            QMessageBox.warning(self, "Select User", "Please select a user first.")
            return

        username = item.data(Qt.UserRole)

        answer = QMessageBox.question(self, "Remove User", f"Remove user '{username}'?")

        if answer != QMessageBox.Yes:
            return

        success = self.main_window.enrollment.remove_user(username)

        if success:
            self.refresh_users()
            QMessageBox.information(self, "Removed", f"User '{username}' removed.")
        else:
            QMessageBox.warning(self, "Error", "Unable to remove user.")


# ============================================================
# Enrollment Camera
# ============================================================


class EnrollmentCamera(QDialog):

    def __init__(self, parent, main_window, username):
        super().__init__(parent)

        self.main_window = main_window
        self.username = username

        self.camera = None
        self.engine = None
        self.current_frame = None
        self.face_detected = False
        self.captured = False

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_camera)

        self.setWindowTitle(f"Enroll User - {username}")
        self.setMinimumSize(700, 640)
        self.setModal(True)
        self.setStyleSheet(GLOBAL_STYLE)

        layout = QVBoxLayout(self)

        layout.addWidget(page_title(f"> ENROLLING USER: {username}", 20))

        self.camera_label = QLabel("STARTING CAMERA...")
        self.camera_label.setAlignment(Qt.AlignCenter)
        self.camera_label.setMinimumSize(640, 480)
        self.camera_label.setStyleSheet(
            f"background-color: #020202; border: 1px solid {BORDER}; color: {GREEN};"
        )
        layout.addWidget(self.camera_label)

        self.status = QLabel("STATUS: INITIALIZING")
        self.status.setStyleSheet(f"color: {GREEN};")
        layout.addWidget(self.status)

        buttons = QHBoxLayout()

        self.capture_button = QPushButton("📸 CAPTURE FACE")
        self.capture_button.clicked.connect(self.capture_face)

        cancel_button = QPushButton("CANCEL")
        cancel_button.clicked.connect(self.reject)

        buttons.addWidget(self.capture_button)
        buttons.addWidget(cancel_button)
        layout.addLayout(buttons)

        self.start_camera()

    def start_camera(self):

        try:
            self.engine = FaceRecognitionEngine()
            self.camera = cv2.VideoCapture(0)

            if not self.camera.isOpened():
                self.camera = None
                self.status.setText("STATUS: CAMERA ERROR")
                QMessageBox.critical(self, "Camera Error", "Unable to open camera.")
                return

            self.timer.start(30)
            self.status.setText("STATUS: SHOW ONE FACE TO CAMERA")

        except Exception as error:
            self.status.setText(f"ERROR: {error}")

    def update_camera(self):

        if self.camera is None:
            return

        success, frame = self.camera.read()
        if not success:
            return

        frame = cv2.flip(frame, 1)
        self.current_frame = frame.copy()

        face = self.engine.detect_face(frame)
        self.face_detected = False

        if face is None:
            self.status.setText("STATUS: NO FACE DETECTED")
        else:
            self.face_detected = True
            x, y, w, h = face[:4].astype(int)

            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 100), 3)
            cv2.putText(
                frame, "FACE DETECTED",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 100), 2
            )
            self.status.setText("STATUS: FACE DETECTED - READY")

        self.camera_label.setPixmap(
            frame_to_pixmap(frame).scaled(
                self.camera_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
        )

    def capture_face(self):

        if self.current_frame is None:
            QMessageBox.warning(self, "No Camera Frame", "Camera frame is not available.")
            return

        if not self.face_detected:
            QMessageBox.warning(
                self,
                "No Face",
                "No face detected.\n\n"
                "Please position one face clearly in front of the camera."
            )
            return

        frame = self.current_frame.copy()
        face = self.engine.detect_face(frame)

        if face is None:
            QMessageBox.warning(self, "Face Error", "Face could not be detected.")
            return

        try:
            self.main_window.enrollment.save_user(self.username, frame)

            self.captured = True
            self.status.setText("STATUS: ENROLLMENT SUCCESS")

            self.stop_camera()
            self.accept()

        except Exception as error:
            QMessageBox.critical(self, "Enrollment Error", str(error))

    def stop_camera(self):
        self.timer.stop()
        if self.camera is not None:
            self.camera.release()
            self.camera = None

    def reject(self):
        # covers CANCEL button, Esc key and window close
        self.stop_camera()
        super().reject()

    def closeEvent(self, event):
        self.stop_camera()
        event.accept()


# ============================================================
# Logs Page
# ============================================================


class LogsPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        layout.addWidget(page_title("> SECURITY LOGS"))

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        layout.addWidget(self.logs)

        refresh_button = QPushButton("↻ REFRESH LOGS")
        refresh_button.clicked.connect(self.load_logs)
        layout.addWidget(refresh_button)

        self.setLayout(layout)

        self.load_logs()

    def load_logs(self):

        log_file = os.path.join("logs", "security.log")

        if not os.path.exists(log_file):
            self.logs.setPlainText("> No security logs available.")
            return

        try:
            with open(log_file, "r", encoding="utf-8") as file:
                content = file.read()
            self.logs.setPlainText(content)
            bar = self.logs.verticalScrollBar()
            bar.setValue(bar.maximum())

        except Exception as error:
            self.logs.setPlainText(f"> LOG ERROR: {error}")


# ============================================================
# Settings Page
# ============================================================


class SettingsPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        layout.addWidget(page_title("> SYSTEM SETTINGS"))

        settings = [
            "FACE DETECTOR    : YuNet",
            "FACE RECOGNIZER  : SFace",
            "LIVENESS         : Movement Prototype",
            "LOGGING          : ENABLED",
            "STORAGE          : LOCAL",
            "MODE             : OFFLINE",
        ]

        for item in settings:
            label = QLabel(f"[+] {item}")
            label.setStyleSheet(f"color: {GREEN};")
            layout.addWidget(label)

        warning = QLabel(
            "\nNOTE:\n"
            "The current liveness system is a prototype "
            "based on face movement. It is not a complete "
            "anti-spoofing solution."
        )
        warning.setStyleSheet(f"color: {GRAY};")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        layout.addStretch()
        self.setLayout(layout)


# ============================================================
# Vault Password Dialog
# ============================================================


class VaultPasswordDialog(QDialog):

    def __init__(self, mode="unlock", parent=None):
        super().__init__(parent)

        self.mode = mode
        self.setWindowTitle(
            "Create Vault Password" if mode == "create" else "Unlock Secure Vault"
        )
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        title = QLabel(
            "Create a password for Secure Vault" if mode == "create"
            else "Enter your Secure Vault password"
        )
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        info = QLabel(
            "This password is required before accessing the Vault."
            if mode == "create"
            else "Enter your password to unlock the Vault."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password")
        layout.addWidget(self.password_input)

        # FIX: confirm field only exists in "create" mode
        self.confirm_input = None
        if mode == "create":
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Confirm password")
            layout.addWidget(self.confirm_input)

        self.strength_label = QLabel("")
        self.strength_label.setWordWrap(True)
        layout.addWidget(self.strength_label)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #ff5555;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        self.action_button = QPushButton(
            "Create Password" if mode == "create" else "Unlock"
        )
        self.action_button.setDefault(True)
        layout.addWidget(self.action_button)

        self.cancel_button = QPushButton("Cancel")
        layout.addWidget(self.cancel_button)

        self.password_input.textChanged.connect(self.update_strength)
        self.password_input.returnPressed.connect(self.handle_action)
        if self.confirm_input is not None:
            self.confirm_input.returnPressed.connect(self.handle_action)
        self.action_button.clicked.connect(self.handle_action)
        self.cancel_button.clicked.connect(self.reject)

    def update_strength(self):

        if self.mode != "create":
            return

        password = self.password_input.text()

        if not password:
            self.strength_label.setText("")
            return

        failed = password_requirements(password)

        if failed:
            self.strength_label.setText("Missing: " + ", ".join(failed))
            self.strength_label.setStyleSheet("color: #ffbf3f;")
        else:
            self.strength_label.setText("Password strength: OK")
            self.strength_label.setStyleSheet(f"color: {GREEN};")

    def handle_action(self):

        password = self.password_input.text()
        self.error_label.setText("")

        if not password:
            self.error_label.setText("Please enter your password.")
            return

        if self.mode == "create":

            confirm = self.confirm_input.text()

            if password != confirm:
                self.error_label.setText("Passwords do not match.")
                return

            failed = password_requirements(password)
            if failed:
                self.error_label.setText(
                    "Password requirements not met:\n" + ", ".join(failed)
                )
                return

            try:
                create_password(password)
                QMessageBox.information(
                    self, "Password Created", "Vault password created successfully."
                )
                self.accept()

            except Exception as error:
                self.error_label.setText(f"Unable to create password:\n{error}")

        else:

            try:
                if verify_password(password):
                    self.accept()
                else:
                    self.error_label.setText("Incorrect password.")

            except Exception as error:
                self.error_label.setText(f"Unable to verify password:\n{error}")


# ============================================================
# Secure Vault Page - V1.1
# ============================================================


class VaultPage(QWidget):

    def __init__(self, main_window):
        super().__init__()

        self.main_window = main_window
        self.vault = VaultManager()

        layout = QVBoxLayout()

        layout.addWidget(page_title("SECURE VAULT"))

        subtitle = QLabel("AES-256-GCM isolated encrypted storage")
        subtitle.setStyleSheet(f"color: {GRAY};")
        layout.addWidget(subtitle)

        # ---------------- STATUS ----------------
        status_frame = panel_frame(PANEL)
        status_layout = QVBoxLayout()

        status_title = QLabel("VAULT STATUS")
        status_title.setStyleSheet(f"color: {GRAY}; font-weight: bold;")
        status_layout.addWidget(status_title)

        self.status_label = QLabel("🔒 LOCKED")
        self.status_label.setStyleSheet(
            f"color: {RED}; font-size: 24px; font-weight: bold;"
        )
        status_layout.addWidget(self.status_label)

        self.stats_label = QLabel("Files: 0    |    Folders: 0    |    Total: 0")
        self.stats_label.setStyleSheet(f"color: {GRAY};")
        status_layout.addWidget(self.stats_label)

        status_frame.setLayout(status_layout)
        layout.addWidget(status_frame)

        # ---------------- SEARCH ----------------
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search files and folders...")
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: #080808;
                color: {GREEN};
                border: 1px solid {BORDER};
                padding: 10px;
                font-family: Consolas;
            }}
            QLineEdit:focus {{ border: 1px solid {GREEN}; }}
        """)
        self.search_input.textChanged.connect(lambda _text: self.refresh())
        layout.addWidget(self.search_input)

        # ---------------- BUTTONS 1 ----------------
        buttons_1 = QHBoxLayout()

        self.unlock_button = QPushButton("🔓 UNLOCK")
        self.unlock_button.clicked.connect(self.unlock_vault)

        self.lock_button = QPushButton("🔒 LOCK")
        self.lock_button.clicked.connect(self.lock_vault)

        self.add_file_button = QPushButton("📄 ADD FILE")
        self.add_file_button.clicked.connect(self.add_file)

        self.add_folder_button = QPushButton("📁 ADD FOLDER")
        self.add_folder_button.clicked.connect(self.add_folder)

        buttons_1.addWidget(self.unlock_button)
        buttons_1.addWidget(self.lock_button)
        buttons_1.addWidget(self.add_file_button)
        buttons_1.addWidget(self.add_folder_button)
        layout.addLayout(buttons_1)

        # ---------------- BUTTONS 2 ----------------
        buttons_2 = QHBoxLayout()
        self.new_folder_button = QPushButton("📂 NEW VAULT FOLDER")
        self.new_folder_button.clicked.connect(self.create_folder)
        buttons_2.addWidget(self.new_folder_button)
        layout.addLayout(buttons_2)

        # ---------------- ITEMS ----------------
        items_title = QLabel("> PROTECTED ITEMS")
        items_title.setStyleSheet(f"color: {GREEN}; font-weight: bold;")
        layout.addWidget(items_title)

        self.item_list = QListWidget()
        self.item_list.setStyleSheet(f"""
            QListWidget {{
                background-color: #050505;
                color: #dddddd;
                border: 1px solid {BORDER};
                font-family: Consolas;
                font-size: 13px;
            }}
            QListWidget::item {{ padding: 8px; }}
            QListWidget::item:selected {{
                background-color: #12351f;
                color: {GREEN};
            }}
        """)
        layout.addWidget(self.item_list)

        # ---------------- ACTIONS ----------------
        actions = QHBoxLayout()

        self.export_button = QPushButton("📤 EXPORT SELECTED")
        self.export_button.clicked.connect(self.export_selected)

        self.remove_button = QPushButton("🗑 DELETE SELECTED")
        self.remove_button.clicked.connect(self.remove_item)

        actions.addWidget(self.export_button)
        actions.addWidget(self.remove_button)
        layout.addLayout(actions)

        layout.addStretch()
        self.setLayout(layout)

        self.refresh()

    def _notify_dashboard(self, text):
        try:
            self.main_window.dashboard.set_monitor(text)
        except Exception:
            pass

    def unlock_vault(self):

        if self.vault.is_unlocked():
            QMessageBox.information(self, "Vault", "Vault is already unlocked.")
            return

        mode = "unlock" if password_exists() else "create"
        dialog = VaultPasswordDialog(mode=mode, parent=self)

        if dialog.exec() != QDialog.Accepted:
            return

        try:
            self.vault.unlock()

            log_event("VAULT_UNLOCKED")
            self._notify_dashboard("SECURE VAULT UNLOCKED")

            self.refresh()

            QMessageBox.information(
                self,
                "Vault Unlocked",
                "Secure Vault unlocked successfully.\n\n"
                "Encrypted files remain inside the protected vault."
            )

        except Exception as error:
            QMessageBox.critical(
                self, "Vault Error", f"Unable to unlock Secure Vault:\n\n{error}"
            )

    def lock_vault(self):

        if not self.vault.is_unlocked():
            QMessageBox.information(self, "Vault", "Vault is already locked.")
            return

        try:
            self.vault.lock()

            log_event("VAULT_LOCKED")
            self._notify_dashboard("SECURE VAULT LOCKED")

            self.refresh()

            QMessageBox.information(
                self, "Vault Locked", "Secure Vault locked successfully."
            )

        except Exception as error:
            QMessageBox.critical(self, "Vault Error", str(error))

    def add_file(self):

        if not self.vault.is_unlocked():
            QMessageBox.warning(self, "Vault Locked", "Unlock the vault first.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Protect")

        if not file_path:
            return

        answer = QMessageBox.question(
            self,
            "Protect File",
            "The selected file will be encrypted "
            "and moved into the Secure Vault.\n\n"
            "The original file will be deleted "
            "after successful verification.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if answer != QMessageBox.Yes:
            return

        try:
            original_name = os.path.basename(file_path)

            self.vault.protect_file(file_path, move_to_vault=True)

            log_event("FILE_MOVED_TO_VAULT")
            self.refresh()

            QMessageBox.information(
                self,
                "File Protected",
                f"File successfully protected:\n\n{original_name}\n\n"
                "The encrypted file is now stored inside the Secure Vault."
            )

        except Exception as error:
            QMessageBox.critical(self, "Vault Error", str(error))

    def add_folder(self):

        if not self.vault.is_unlocked():
            QMessageBox.warning(self, "Vault Locked", "Unlock the vault first.")
            return

        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Protect")

        if not folder_path:
            return

        answer = QMessageBox.question(
            self,
            "Protect Folder",
            "The selected folder and its files "
            "will be encrypted and moved into "
            "the Secure Vault.\n\n"
            "Original files will be deleted only "
            "after successful encryption.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if answer != QMessageBox.Yes:
            return

        try:
            self.vault.protect_folder(folder_path, move_to_vault=True)

            log_event("FOLDER_MOVED_TO_VAULT")
            self.refresh()

            QMessageBox.information(
                self,
                "Folder Protected",
                "Folder successfully protected "
                "and moved into the Secure Vault."
            )

        except Exception as error:
            QMessageBox.critical(self, "Vault Error", str(error))

    def create_folder(self):

        if not self.vault.is_unlocked():
            QMessageBox.warning(self, "Vault Locked", "Unlock the vault first.")
            return

        name, ok = QInputDialog.getText(self, "New Vault Folder", "Folder name:")

        if not ok:
            return

        name = name.strip()

        if not name:
            QMessageBox.warning(self, "Invalid Folder", "Folder name cannot be empty.")
            return

        try:
            self.vault.create_folder(name)

            log_event("VAULT_FOLDER_CREATED")
            self.refresh()

            QMessageBox.information(
                self, "Folder Created", f"Vault folder '{name}' created successfully."
            )

        except Exception as error:
            QMessageBox.warning(self, "Vault Error", str(error))

    def _selected_item(self):
        """Return (item_id, item) of selected row, or (None, None)."""

        selected = self.item_list.currentItem()

        if selected is None:
            QMessageBox.warning(self, "Select Item", "Select an item first.")
            return None, None

        item_id = selected.data(Qt.UserRole)

        if not item_id:
            return None, None

        item = self.vault.get_item(item_id)

        if not item:
            QMessageBox.warning(self, "Vault Error", "Selected item could not be found.")
            return None, None

        return item_id, item

    def export_selected(self):

        if not self.vault.is_unlocked():
            QMessageBox.warning(self, "Vault Locked", "Unlock the vault first.")
            return

        item_id, item = self._selected_item()

        if item is None:
            return

        item_type = item.get("type", "file")
        name = item.get("original_name", "exported_file")

        try:
            if item_type == "folder":
                destination = QFileDialog.getExistingDirectory(
                    self, "Select Export Destination"
                )
            else:
                destination, _ = QFileDialog.getSaveFileName(self, "Export File", name)

            if not destination:
                return

            result = self.vault.export_item(item_id, destination)

            log_event("VAULT_ITEM_EXPORTED")

            QMessageBox.information(
                self, "Export Complete", f"Item exported successfully.\n\n{result}"
            )

        except Exception as error:
            QMessageBox.critical(self, "Export Error", str(error))

    def remove_item(self):

        if not self.vault.is_unlocked():
            QMessageBox.warning(self, "Vault Locked", "Unlock the vault first.")
            return

        item_id, item = self._selected_item()

        if item is None:
            return

        item_type = item.get("type", "file")
        name = item.get("original_name", "Unknown")

        if item_type == "folder":
            message = (
                f"Delete vault folder '{name}'?\n\n"
                "Encrypted items inside this folder "
                "will also be removed.\n\n"
                "This action cannot be undone."
            )
        else:
            message = (
                f"Delete '{name}' from the Secure Vault?\n\n"
                "The encrypted item will be permanently removed.\n\n"
                "This action cannot be undone."
            )

        answer = QMessageBox.question(
            self, "Delete Item", message,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if answer != QMessageBox.Yes:
            return

        try:
            success = self.vault.remove_item(item_id)

            if success:
                log_event("VAULT_ITEM_DELETED")
                self.refresh()
                QMessageBox.information(self, "Deleted", "Item deleted successfully.")
            else:
                QMessageBox.warning(self, "Vault Error", "Unable to delete the item.")

        except Exception as error:
            QMessageBox.critical(self, "Vault Error", str(error))

    def _set_controls(self, unlocked):
        self.item_list.setEnabled(unlocked)
        self.export_button.setEnabled(unlocked)
        self.remove_button.setEnabled(unlocked)
        self.add_file_button.setEnabled(unlocked)
        self.add_folder_button.setEnabled(unlocked)
        self.new_folder_button.setEnabled(unlocked)
        self.search_input.setEnabled(unlocked)
        self.unlock_button.setEnabled(not unlocked)
        self.lock_button.setEnabled(unlocked)

    def refresh(self):

        try:
            stats = self.vault.get_stats()
        except Exception as error:
            self.status_label.setText("⚠ VAULT ERROR")
            self.stats_label.setText(str(error))
            return

        self.item_list.clear()

        # ---------------- LOCKED ----------------
        if stats["status"] == "LOCKED":

            self.status_label.setText("🔒 LOCKED")
            self.status_label.setStyleSheet(
                f"color: {RED}; font-size: 24px; font-weight: bold;"
            )
            self.stats_label.setText("Files: 0    |    Folders: 0    |    Total: 0")
            self._set_controls(False)
            return

        # ---------------- UNLOCKED ----------------
        self.status_label.setText("🔓 UNLOCKED")
        self.status_label.setStyleSheet(
            f"color: {GREEN}; font-size: 24px; font-weight: bold;"
        )
        self.stats_label.setText(
            f"Files: {stats['files']}    |    "
            f"Folders: {stats['folders']}    |    "
            f"Total: {stats['total']}"
        )
        self._set_controls(True)

        search_text = self.search_input.text().strip().lower()

        try:
            items = self.vault.get_items()
        except Exception:
            items = []

        if search_text:
            items = [
                item for item in items
                if search_text in str(item.get("original_name", "")).lower()
                or search_text in str(item.get("virtual_path", "")).lower()
            ]

        for item in items:

            item_type = item.get("type", "file")
            name = item.get("original_name", "Unknown")
            virtual_path = item.get("virtual_path", "")

            if item_type == "folder":
                icon, item_label = "📁", "FOLDER"
            else:
                icon, item_label = "🔐", "FILE"

            display_name = virtual_path if virtual_path else name

            list_item = QListWidgetItem(f"{icon} [{item_label}]  {display_name}")
            list_item.setData(Qt.UserRole, item["id"])
            self.item_list.addItem(list_item)


# ============================================================
# SECURITY SCORE WIDGET
# ============================================================


class SecurityScoreWidget(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)

        self.score = 0
        self.status = "NOT RUN"

        self.setMinimumSize(220, 110)
        self.setMaximumHeight(125)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )

    def set_score(self, score):
        self.score = max(0, min(100, int(score)))

        if self.score >= 80:
            self.status = "EXCELLENT"
        elif self.score >= 60:
            self.status = "GOOD"
        elif self.score >= 40:
            self.status = "ATTENTION"
        else:
            self.status = "CRITICAL"

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(4, 4, -4, -4)

 
        # Score number
        painter.setPen(QColor(WHITE))
        painter.setFont(
            QFont("Segoe UI", 28, QFont.Weight.Bold)
        )

        score_text = str(self.score)

        score_x = rect.left()
        score_y = rect.top() + 5

        painter.drawText(
            int(score_x),
            int(score_y + 35),
            score_text
        )

        # /100 - immediately after the score
        score_width = painter.fontMetrics().horizontalAdvance(
            score_text
        )

        painter.setPen(QColor(CYAN))
        painter.setFont(
            QFont("Segoe UI", 11, QFont.Weight.Bold)
        )

        painter.drawText(
            int(score_x + score_width + 8),
            int(score_y + 27),
            "/100"
        )


        # Horizontal progress bar
        bar_rect = QRectF(
            rect.left(),
            rect.top() + 58,
            rect.width(),
            8
        )

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#19333B"))
        painter.drawRoundedRect(bar_rect, 4, 4)

        progress_rect = QRectF(
            bar_rect.left(),
            bar_rect.top(),
            bar_rect.width() * self.score / 100,
            bar_rect.height()
        )

        if self.score >= 80:
            score_color = QColor(GREEN)
        elif self.score >= 40:
            score_color = QColor(YELLOW)
        else:
            score_color = QColor(RED)

        painter.setBrush(score_color)
        painter.drawRoundedRect(progress_rect, 4, 4)

        # Status
        painter.setPen(score_color)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))

        painter.drawText(
            QRectF(
                rect.left(),
                rect.top() + 73,
                rect.width(),
                20
            ),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self.status
        )

# ============================================================
# SECURITY AUDIT PAGE
# ============================================================


class SecurityAuditPage(QWidget):

    RUN_TEXT = "▶  RUN SECURITY AUDIT"

    def __init__(self, main_window=None):

        super().__init__()

        self.main_window = main_window
        self.audit = SecurityAudit()

        self.last_results = {}

        self.audit_start_time = None
        self.last_audit_time = "--:--:--"

        self.status_cards = {}

        self.build_ui()

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def _label(text, style, wrap=False):
        label = QLabel(text)
        label.setStyleSheet(style)
        if wrap:
            label.setWordWrap(True)
        return label

    def _set_audit_status(self, text, fg, bg, border):
        self.audit_status.setText(text)
        self.audit_status.setStyleSheet(
            f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 6px 12px;
                font-weight: 700;
                font-size: 10px;
            }}
            """
        )

    # ========================================================
    # BUILD UI
    # ========================================================

    def build_ui(self):

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(10)

        # ---------------- HEADER ----------------
        header = QHBoxLayout()

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title_box.addWidget(self._label(
            "> SECURITY AUDIT",
            f"color: {WHITE}; font-size: 23px; font-weight: 800;"
        ))
        title_box.addWidget(self._label(
            "WINDOWS SECURITY POSTURE  //  LOCAL READ-ONLY ASSESSMENT",
            f"color: {CYAN}; font-size: 9px;"
        ))

        header.addLayout(title_box)
        header.addStretch()

        self.audit_status = QLabel()
        self.audit_status.setAlignment(Qt.AlignCenter)
        self.audit_status.setMinimumSize(118, 34)
        self._set_audit_status("● AUDIT READY", GREEN, "#061C18", "#087A55")
        header.addWidget(self.audit_status)

        main_layout.addLayout(header)

        # ---------------- TOP AREA ----------------
        top_frame = QFrame()
        top_frame.setObjectName("panel")

        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 10, 10, 10)
        top_layout.setSpacing(10)


        # Score
        score_panel = QFrame()
        score_panel.setObjectName("card")

        score_layout = QVBoxLayout(score_panel)
        score_layout.setContentsMargins(8, 8, 8, 10)
        score_layout.setSpacing(4)

        score_title = self._label(
            "SECURITY SCORE",
            f"color: {CYAN}; font-size: 9px; font-weight: 700;"
        )
        score_title.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(score_title)

        
        self.score_widget = SecurityScoreWidget()
        score_layout.addWidget(self.score_widget)

        # Audit Coverage
        self.audit_coverage = 0

        self.coverage_label = self._label(
            "AUDIT COVERAGE: --%",
            f"color: {CYAN}; font-size: 9px; font-weight: 700;"
        )
        self.coverage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.coverage_label.setMinimumHeight(22)

        score_layout.addSpacing(6)
        score_layout.addWidget(self.coverage_label)

        top_layout.addWidget(score_panel, 1)



        # Posture
        posture_panel = QFrame()
        posture_panel.setObjectName("card")
        posture_layout = QVBoxLayout(posture_panel)
        posture_layout.setContentsMargins(15, 12, 15, 12)

        posture_layout.addWidget(self._label(
            "SECURITY POSTURE",
            f"color: {CYAN}; font-size: 10px; font-weight: 700;"
        ))

        self.posture_value = self._label(
            "READY", f"color: {GREEN}; font-size: 22px; font-weight: 800;"
        )
        posture_layout.addWidget(self.posture_value)

        self.posture_message = self._label(
            "Run a complete security audit.",
            f"color: {TEXT_SECONDARY}; font-size: 10px;",
            wrap=True
        )
        posture_layout.addWidget(self.posture_message)
        posture_layout.addStretch()

        counter_layout = QHBoxLayout()

        self.pass_count = self._label(
            "● 0 PASS", f"color: {GREEN}; font-size: 9px; font-weight: 700;"
        )
        self.warning_count = self._label(
            "● 0 WARNING", f"color: {YELLOW}; font-size: 9px; font-weight: 700;"
        )
        self.error_count = self._label(
            "● 0 ERROR", f"color: {RED}; font-size: 9px; font-weight: 700;"
        )
        self.info_count = self._label(
            "● 0 INFO", f"color: {BLUE}; font-size: 9px; font-weight: 700;"
        )

        for widget in (self.pass_count, self.warning_count,
                       self.error_count, self.info_count):
            counter_layout.addWidget(widget)

        posture_layout.addLayout(counter_layout)

        top_layout.addWidget(posture_panel, 2)

        # Last audit
        last_panel = QFrame()
        last_panel.setObjectName("card")
        last_layout = QVBoxLayout(last_panel)
        last_layout.setContentsMargins(15, 12, 15, 12)

        last_layout.addWidget(self._label(
            "LAST AUDIT", f"color: {CYAN}; font-size: 10px; font-weight: 700;"
        ))

        self.last_audit_label = self._label(
            "--", f"color: {WHITE}; font-size: 15px; font-weight: 700;"
        )
        last_layout.addWidget(self.last_audit_label)
        last_layout.addSpacing(8)

        last_layout.addWidget(self._label(
            "DURATION", f"color: {CYAN}; font-size: 10px; font-weight: 700;"
        ))

        self.duration_label = self._label(
            "--", f"color: {TEXT_SECONDARY}; font-size: 11px;"
        )
        last_layout.addWidget(self.duration_label)
        last_layout.addStretch()

        top_layout.addWidget(last_panel, 1)

        main_layout.addWidget(top_frame)

        # ---------------- BUTTONS ----------------
        button_row = QHBoxLayout()
        button_row.addStretch()

        self.run_button = QPushButton(self.RUN_TEXT)
        self.run_button.setMinimumSize(250, 38)
        self.run_button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: #06261D;
                color: {GREEN};
                border: 1px solid {GREEN};
                border-radius: 8px;
                padding: 8px 20px;
                font-size: 10px;
                font-weight: 800;
            }}
            QPushButton:hover {{
                background-color: #0A3A2A;
                border: 1px solid #00FFAA;
            }}
            QPushButton:pressed {{ background-color: #0D513A; }}
            """
        )
        self.run_button.clicked.connect(self.run_audit)
        button_row.addWidget(self.run_button)

        self.export_pdf_button = QPushButton("EXPORT SECURITY AUDIT REPORT PDF")
        self.export_pdf_button.setMinimumSize(220, 38)
        self.export_pdf_button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: #101F35;
                color: {CYAN};
                border: 1px solid {CYAN};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 10px;
                font-weight: 800;
            }}
            QPushButton:hover {{ background-color: #183451; }}
            QPushButton:pressed {{ background-color: #0A1728; }}
            """
        )
        self.export_pdf_button.clicked.connect(self.export_security_report_pdf)
        button_row.addWidget(self.export_pdf_button)

        button_row.addStretch()
        main_layout.addLayout(button_row)

        # ---------------- SECURITY CONTROLS ----------------
        main_layout.addWidget(self._label(
            "◆  SECURITY CONTROLS",
            f"color: {CYAN}; font-size: 11px; font-weight: 800;"
        ))

        controls_grid = QGridLayout()
        controls_grid.setSpacing(8)

        controls = [
            ("DEFENDER", "defender"),
            ("FIREWALL", "firewall"),
            ("WINDOWS UPDATE", "windows_update"),
            ("SECURE BOOT", "secure_boot"),
            ("BITLOCKER", "bitlocker"),
            ("ACCOUNT SECURITY", "account_security"),
            ("STARTUP APPS", "startup_apps"),
            ("LISTENING PORTS", "listening_ports"),
        ]

        for index, (name, key) in enumerate(controls):
            controls_grid.addWidget(
                self.create_control_card(name, key), index // 4, index % 4
            )

        main_layout.addLayout(controls_grid)

        # ---------------- BOTTOM AREA ----------------
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(10)

        # Activity
        activity_panel = QFrame()
        activity_panel.setObjectName("panel")
        activity_layout = QVBoxLayout(activity_panel)
        activity_layout.setContentsMargins(10, 8, 10, 8)

        activity_layout.addWidget(self._label(
            "◆  SECURITY ACTIVITY",
            f"color: {CYAN}; font-size: 10px; font-weight: 800;"
        ))

        self.activity_list = QListWidget()
        self.activity_list.setMinimumHeight(145)
        self.activity_list.setMaximumHeight(165)
        self.activity_list.setStyleSheet(
            f"""
            QListWidget {{
                background-color: #030D14;
                border: 1px solid {BORDER};
                border-radius: 7px;
                padding: 4px;
            }}
            QListWidget::item {{
                color: {TEXT_SECONDARY};
                padding: 5px;
                border-bottom: 1px solid #102832;
            }}
            QListWidget::item:hover {{
                background-color: #08231E;
                color: {WHITE};
            }}
            """
        )
        activity_layout.addWidget(self.activity_list)

        bottom_layout.addWidget(activity_panel, 1)

        # Detailed analysis
        detail_panel = QFrame()
        detail_panel.setObjectName("panel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(8, 8, 8, 8)

        detail_layout.addWidget(self._label(
            "◆  DETAILED ANALYSIS",
            f"color: {CYAN}; font-size: 10px; font-weight: 800;"
        ))

        self.tabs = QTabWidget()

        self.ports_table = self.create_table(
            ["ADDRESS", "PORT", "PID", "PROCESS", "PROCESS PATH", "ANALYSIS", "REASON"]
        )
        for column, width in enumerate((120, 70, 70, 140, 280, 110, 320)):
            self.ports_table.setColumnWidth(column, width)

        self.startup_table = self.create_table(["NAME", "COMMAND", "LOCATION"])
        self.users_table = self.create_table(["USERNAME", "ENABLED"])
        self.system_table = self.create_table(["PROPERTY", "VALUE"])

        self.tabs.addTab(self.ports_table, "LISTENING PORTS")
        self.tabs.addTab(self.startup_table, "STARTUP APPS")
        self.tabs.addTab(self.users_table, "LOCAL USERS")
        self.tabs.addTab(self.system_table, "SYSTEM")

        detail_layout.addWidget(self.tabs)

        bottom_layout.addWidget(detail_panel, 1)

        main_layout.addLayout(bottom_layout, 1)

    # ========================================================
    # CONTROL CARD
    # ========================================================

    def create_control_card(self, title, key):

        frame = QFrame()
        frame.setObjectName("card")
        frame.setMinimumHeight(82)
        frame.setMaximumHeight(88)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(2)

        header = QHBoxLayout()

        name = self._label(
            title, f"color: {CYAN}; font-size: 9px; font-weight: 800;"
        )
        header.addWidget(name)
        header.addStretch()

        dot = self._label("●", f"color: {GRAY}; font-size: 10px;")
        header.addWidget(dot)

        layout.addLayout(header)

        status = self._label(
            "NOT CHECKED", f"color: {GRAY}; font-size: 13px; font-weight: 800;"
        )
        layout.addWidget(status)

        message = self._label(
            "Awaiting audit.",
            f"color: {TEXT_SECONDARY}; font-size: 8px;",
            wrap=True
        )
        layout.addWidget(message)

        self.status_cards[key] = {
            "frame": frame,
            "status": status,
            "message": message,
            "dot": dot,
        }

        return frame

    # ========================================================
    # TABLE
    # ========================================================

    def create_table(self, headers):

        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setStyleSheet(TABLE_STYLE)
        table.setMinimumHeight(145)

        return table

    # ========================================================
    # EXPORT PDF
    # ========================================================

    def export_security_report_pdf(self):
        """Export the latest security audit results to a formatted PDF."""
        import textwrap

        results = getattr(self, "last_results", None)

        if not isinstance(results, dict) or not results:
            QMessageBox.warning(
                self,
                "No Audit Results",
                "Run a full security audit before exporting the PDF report."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Security Report",
            "CyberFaceGuard_Security_Report.pdf",
            "PDF Files (*.pdf)"
        )

        if not file_path:
            return

        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"

        writer = QPdfWriter(file_path)
        writer.setResolution(96)

        painter = QPainter()

        if not painter.begin(writer):
            QMessageBox.critical(
                self,
                "PDF Export Error",
                "Could not create the PDF file. Check the save location."
            )
            return

        try:
            page_width = writer.width()
            page_height = writer.height()

            margin = 55
            line_height = 19
            y = margin
            page_number = 1

            def draw_page_header():
                painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
                painter.setPen(QColor("#007F91"))
                painter.drawText(margin, margin - 20, "CYBERFACEGUARD | SECURITY REPORT")

                painter.setPen(QColor("#A0A0A0"))
                painter.drawLine(margin, margin - 10, page_width - margin, margin - 10)

            def draw_page_footer():
                painter.setFont(QFont("Consolas", 8))
                painter.setPen(QColor("#606060"))
                painter.drawLine(
                    margin, page_height - margin + 8,
                    page_width - margin, page_height - margin + 8
                )
                painter.drawText(
                    page_width - margin - 100,
                    page_height - margin + 25,
                    f"Page {page_number}"
                )

            def new_page():
                nonlocal y, page_number

                draw_page_footer()
                writer.newPage()
                page_number += 1
                y = margin + 10
                draw_page_header()

            draw_page_header()
            y = margin + 15

            def draw_line(text, bold=False, color=None, indent=0):
                nonlocal y

                font = QFont("Consolas", 9)
                font.setBold(bold)
                painter.setFont(font)
                painter.setPen(color or QColor("#202020"))

                available_width = max(20, int((page_width - 2 * margin - indent) / 9))

                wrapped = textwrap.wrap(
                    str(text),
                    width=available_width,
                    break_long_words=True,
                    break_on_hyphens=False
                ) or [""]

                for part in wrapped:
                    if y + line_height > page_height - margin - 15:
                        new_page()

                    painter.drawText(margin + indent, y, part)
                    y += line_height

            draw_line("SECURITY AUDIT REPORT", bold=True)
            draw_line("=" * 35)
            draw_line("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            last_audit = getattr(self, "last_audit_time", None)
            if last_audit:
                draw_line(f"Last audit: {last_audit}")

            draw_line("")
            draw_line("AUDIT RESULTS", bold=True, color=QColor("#007F91"))
            draw_line("-" * 35)

            def write_value(value, prefix=""):
                if isinstance(value, dict):
                    if not value:
                        draw_line(f"{prefix}: No details available", indent=12)
                        return

                    for key, item in value.items():
                        label = f"{prefix}.{key}" if prefix else str(key)

                        if isinstance(item, (dict, list, tuple)):
                            draw_line(label, bold=True, color=QColor("#005B73"))
                            write_value(item, label)
                        else:
                            if key == "full_scan_age" and item == 4294967295:
                                display_value = "Not reported (special Windows value)"
                            else:
                                display_value = str(item)

                            status_color = None
                            if key == "status":
                                if display_value == "PASS":
                                    status_color = QColor("#167447")
                                elif display_value in ("WARNING", "FAIL"):
                                    status_color = QColor("#A15C00")
                                elif display_value == "ERROR":
                                    status_color = QColor("#B42318")

                            draw_line(
                                f"{label}: {display_value}",
                                color=status_color,
                                indent=12
                            )

                elif isinstance(value, (list, tuple)):
                    if not value:
                        draw_line(f"{prefix}: No entries", indent=12)
                        return

                    for index, item in enumerate(value, start=1):
                        label = f"{prefix}[{index}]"

                        if isinstance(item, (dict, list, tuple)):
                            draw_line(label, bold=True)
                            write_value(item, label)
                        else:
                            draw_line(f"{label}: {item}", indent=12)
                else:
                    draw_line(f"{prefix}: {value}", indent=12)

            write_value(results)

            draw_line("")
            draw_line("-" * 35)
            draw_line("End of report. Results reflect the latest completed audit.")

            draw_page_footer()

        except Exception as exc:
            QMessageBox.critical(
                self, "PDF Export Error", f"Could not generate the report:\n{exc}"
            )
            return

        finally:
            painter.end()

        QMessageBox.information(
            self, "PDF Exported", f"Security report saved successfully:\n{file_path}"
        )

    # ========================================================
    # RUN AUDIT
    # ========================================================

    def run_audit(self):

        self.run_button.setEnabled(False)
        self.run_button.setText("⟳  RUNNING SECURITY AUDIT...")

        self._set_audit_status("● AUDIT RUNNING", YELLOW, "#241D06", "#8A6A00")

        QApplication.processEvents()

        self.audit_start_time = time.perf_counter()

        try:

            self.last_results = self.audit.run_audit()

            duration = time.perf_counter() - self.audit_start_time

            self.update_cards(self.last_results)
            self.update_tables(self.last_results)

            score = self.calculate_score(self.last_results)

            self.update_score(score)
            self.update_posture(self.last_results)
            self.update_activity(self.last_results)

            self.duration_label.setText(f"{duration:.2f} seconds")

            self.last_audit_time = datetime.now().strftime("%H:%M:%S")
            self.last_audit_label.setText(self.last_audit_time)

            self._set_audit_status("● AUDIT COMPLETE", GREEN, "#061C18", "#087A55")

            try:
                log_event(f"SECURITY_AUDIT_COMPLETED_SCORE_{score}")
            except Exception:
                pass

            try:
                if self.main_window and hasattr(self.main_window, "dashboard"):
                    self.main_window.dashboard.set_monitor(
                        f"Security audit completed - Score {score}/100"
                    )
            except Exception:
                pass

        except Exception as error:

            QMessageBox.critical(
                self, "Security Audit Error", f"Security audit failed:\n\n{error}"
            )

            self._set_audit_status("● AUDIT ERROR", RED, "#26090D", RED)

        finally:

            self.run_button.setEnabled(True)
            self.run_button.setText(self.RUN_TEXT)

    
    # ========================================================
    # SCORE + AUDIT COVERAGE
    # ========================================================

    def calculate_score(self, results):

        weights = {
            "defender": 25,
            "firewall": 20,
            "windows_update": 15,
            "bitlocker": 15,
            "secure_boot": 10,
            "account_security": 15,
        }

        earned = 0
        assessed_weight = 0
        total_weight = sum(weights.values())

        for key, weight in weights.items():

            item = results.get(key)

            # Missing or malformed results are not assessed.
            if not isinstance(item, dict):
                continue

            status = str(
                item.get("status", "INFO")
            ).strip().upper()

            if status == "PASS":
                earned += weight
                assessed_weight += weight

            elif status == "WARNING":
                earned += weight * 0.5
                assessed_weight += weight

            elif status == "FAIL":
                assessed_weight += weight

            # INFO or unknown statuses remain unassessed.

        if assessed_weight == 0:
            score = 0
        else:
            score = round(
                (earned / assessed_weight) * 100
            )

        if total_weight == 0:
            coverage = 0
        else:
            coverage = round(
                (assessed_weight / total_weight) * 100
            )

        self.audit_coverage = coverage

        return score

    def update_score(self, score):
        self.score_widget.set_score(score)

        # Show coverage if this label exists in the UI.
        if hasattr(self, "coverage_label"):
            self.coverage_label.setText(
                f"Audit Coverage: {self.audit_coverage}%"
            )


    # ========================================================
    # POSTURE
    # ========================================================

    def update_posture(self, results):

        keys = [
            "defender", "firewall", "windows_update", "secure_boot",
            "bitlocker", "account_security", "startup_apps", "listening_ports",
        ]

        statuses = [
            str(results.get(key, {}).get("status", "INFO")).upper()
            for key in keys
        ]

        errors = statuses.count("ERROR")
        warnings = statuses.count("WARNING")
        passes = statuses.count("PASS")
        infos = statuses.count("INFO")

        self.pass_count.setText(f"● {passes} PASS")
        self.warning_count.setText(f"● {warnings} WARNING")
        self.error_count.setText(f"● {errors} ERROR")
        self.info_count.setText(f"● {infos} INFO")

        if errors > 0:
            posture, color = "HIGH RISK", RED
            message = "Critical security issues require attention."
        elif warnings > 0:
            posture, color = "ATTENTION REQUIRED", YELLOW
            message = "Some security controls need attention."
        else:
            posture, color = "PROTECTED", GREEN
            message = "No critical security issues found."

        self.posture_value.setText(posture)
        self.posture_value.setStyleSheet(
            f"color: {color}; font-size: 22px; font-weight: 800;"
        )
        self.posture_message.setText(message)

    # ========================================================
    # CARDS
    # ========================================================

    def update_cards(self, results):

        for key, card in self.status_cards.items():

            data = results.get(key, {})

            status = str(data.get("status", "INFO")).upper()
            message = str(data.get("message", "No information available."))

            card["status"].setText(status)
            card["message"].setText(message)

            if status == "PASS":
                color = GREEN
            elif status == "WARNING":
                color = YELLOW
            elif status == "ERROR":
                color = RED
            else:
                color = BLUE

            card["status"].setStyleSheet(
                f"color: {color}; font-size: 13px; font-weight: 800;"
            )
            card["dot"].setStyleSheet(f"color: {color}; font-size: 10px;")

            # FIX: scope to #card, otherwise every child QLabel
            # (a QFrame subclass) also received a border/background.
            card["frame"].setStyleSheet(
                f"""
                QFrame#card {{
                    background-color: {PANEL_LIGHT};
                    border: 1px solid {BORDER};
                    border-radius: 9px;
                }}
                """
            )

    # ========================================================
    # ACTIVITY
    # ========================================================

    def update_activity(self, results):

        self.activity_list.clear()

        activity_map = [
            ("defender", "Defender protection verified"),
            ("firewall", "Firewall profiles verified"),
            ("windows_update", "Windows Update checked"),
            ("secure_boot", "Secure Boot checked"),
            ("bitlocker", "BitLocker status checked"),
            ("account_security", "Account security verified"),
            ("startup_apps", "Startup applications inspected"),
            ("listening_ports", "Listening ports inspected"),
        ]

        now = datetime.now().strftime("%H:%M:%S")

        for key, text in activity_map:

            status = str(results.get(key, {}).get("status", "INFO")).upper()

            if status == "PASS":
                prefix, color = "[OK]", GREEN
            elif status == "WARNING":
                prefix, color = "[!]", YELLOW
            elif status == "ERROR":
                prefix, color = "[X]", RED
            else:
                prefix, color = "[i]", BLUE

            item = QListWidgetItem(f"{now}   {prefix}   {text}")
            item.setForeground(QColor(color))
            self.activity_list.addItem(item)

    # ========================================================
    # TABLES
    # ========================================================

    @staticmethod
    def _fill(table, rows):
        table.setRowCount(0)
        for values in rows:
            row = table.rowCount()
            table.insertRow(row)
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(str(value)))

    def update_tables(self, results):

        # Listening ports
        listening_data = results.get("listening_ports", {})

        if isinstance(listening_data, dict):
            ports = listening_data.get("ports", [])
        else:
            ports = listening_data or []

        self._fill(self.ports_table, [
            [
                port.get("address", ""),
                port.get("port", ""),
                port.get("pid", ""),
                port.get("process", port.get("process_name", "Unknown")),
                port.get("process_path", "Unavailable"),
                port.get("analysis", "INFO"),
                port.get("reason", ""),
            ]
            for port in ports
        ])

        # Startup apps
        apps = (results.get("startup_apps", {}) or {}).get("apps", [])

        self._fill(self.startup_table, [
            [app.get("name", ""), app.get("command", ""), app.get("location", "")]
            for app in apps
        ])

        # Local users
        users = (results.get("local_users", {}) or {}).get("users", [])

        self._fill(self.users_table, [
            [user.get("name", ""), "YES" if user.get("enabled", False) else "NO"]
            for user in users
        ])

        # System
        system = results.get("system", {}) or {}

        self._fill(self.system_table, [[key, value] for key, value in system.items()])

    def refresh(self):
        # refresh does NOT automatically run the security audit.
        pass


# ============================================================
# FILE INTEGRITY PAGE
# ============================================================


class FileIntegrityPage(QWidget):

    def __init__(self, main_window=None):
        super().__init__()

        self.main_window = main_window
        self.integrity = FileIntegrity()
        self.selected_folder = None

        self.build_ui()

    def build_ui(self):

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(25, 20, 25, 20)
        main_layout.setSpacing(15)

        subtitle = QLabel("SHA-256 FILE INTEGRITY MONITORING  //  LOCAL MODE")
        subtitle.setStyleSheet(f"color: {GRAY}; font-size: 11px;")

        main_layout.addWidget(page_title("> FILE INTEGRITY", 24))
        main_layout.addWidget(subtitle)

        # Selected folder
        folder_frame = panel_frame()
        folder_layout = QHBoxLayout()

        folder_label = QLabel("MONITORED FOLDER")
        folder_label.setStyleSheet(f"color: {GRAY}; font-size: 11px; font-weight: bold;")

        self.folder_value = QLabel("NO FOLDER SELECTED")
        self.folder_value.setStyleSheet(f"color: {GREEN}; font-size: 11px;")

        folder_layout.addWidget(folder_label)
        folder_layout.addStretch()
        folder_layout.addWidget(self.folder_value)
        folder_frame.setLayout(folder_layout)
        main_layout.addWidget(folder_frame)

        # Buttons
        buttons_layout = QHBoxLayout()

        self.select_button = QPushButton("📁 SELECT FOLDER")
        self.baseline_button = QPushButton("🧱 CREATE BASELINE")
        self.scan_button = QPushButton("🔍 SCAN & COMPARE")
        self.clear_button = QPushButton("🗑 CLEAR BASELINE")

        for button in (self.select_button, self.baseline_button,
                       self.scan_button, self.clear_button):
            button.setMinimumHeight(40)
            button.setStyleSheet(ACTION_BUTTON_STYLE)
            buttons_layout.addWidget(button)

        main_layout.addLayout(buttons_layout)

        # Counters
        status_frame = panel_frame()
        status_layout = QHBoxLayout()

        self.total_label = QLabel("TOTAL: 0")
        self.unchanged_label = QLabel("UNCHANGED: 0")
        self.modified_label = QLabel("MODIFIED: 0")
        self.new_label = QLabel("NEW: 0")
        self.deleted_label = QLabel("DELETED: 0")

        for label in (self.total_label, self.unchanged_label,
                      self.modified_label, self.new_label, self.deleted_label):
            label.setStyleSheet(f"color: {GREEN}; font-size: 11px; font-weight: bold;")
            status_layout.addWidget(label)

        status_frame.setLayout(status_layout)
        main_layout.addWidget(status_frame)

        # Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(
            ["FILE", "STATUS", "OLD SHA-256", "NEW SHA-256"]
        )
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setStyleSheet(TABLE_STYLE)
        main_layout.addWidget(self.results_table)

        self.setLayout(main_layout)

        self.select_button.clicked.connect(self.select_folder)
        self.baseline_button.clicked.connect(self.create_baseline)
        self.scan_button.clicked.connect(self.scan_compare)
        self.clear_button.clicked.connect(self.clear_baseline)

        self.update_buttons()

    def select_folder(self):

        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")

        if not folder:
            return

        self.selected_folder = folder
        self.folder_value.setText(folder)
        self.update_buttons()

    def create_baseline(self):

        if not self.selected_folder:
            QMessageBox.warning(self, "File Integrity", "Please select a folder first.")
            return

        reply = QMessageBox.question(
            self,
            "Create Baseline",
            f"Create SHA-256 baseline for this folder?\n\n{self.selected_folder}",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        self.baseline_button.setEnabled(False)
        QApplication.processEvents()

        try:
            baseline = self.integrity.create_baseline(self.selected_folder)
            count = len(baseline.get("files", {}))

            self.results_table.setRowCount(0)
            self.update_counts(count, count, 0, 0, 0)

            try:
                log_event(f"FILE_INTEGRITY_BASELINE_CREATED_{count}")
            except Exception:
                pass

            QMessageBox.information(
                self,
                "Baseline Created",
                f"Baseline created successfully.\n\nFiles recorded: {count}"
            )

        except Exception as error:
            QMessageBox.critical(self, "File Integrity Error", str(error))

        finally:
            self.baseline_button.setEnabled(True)
            self.update_buttons()

    def scan_compare(self):

        if not self.selected_folder:
            QMessageBox.warning(self, "File Integrity", "Please select a folder first.")
            return

        if not self.integrity.baseline_exists():
            QMessageBox.warning(
                self, "File Integrity", "No baseline exists.\n\nCreate a baseline first."
            )
            return

        self.scan_button.setEnabled(False)
        QApplication.processEvents()

        try:
            results = self.integrity.compare_folder(self.selected_folder)
            self.populate_results(results)

            try:
                log_event("FILE_INTEGRITY_SCAN_COMPLETED")
            except Exception:
                pass

        except Exception as error:
            QMessageBox.critical(self, "File Integrity Error", str(error))

        finally:
            self.scan_button.setEnabled(True)
            self.update_buttons()

    def populate_results(self, results):

        self.results_table.setRowCount(0)

        counts = {"UNCHANGED": 0, "MODIFIED": 0, "NEW": 0, "DELETED": 0}

        colors = {
            "UNCHANGED": "#00ff66",
            "MODIFIED": "#ffbf3f",
            "NEW": "#4dd2ff",
            "DELETED": "#ff4444",
        }

        for result in results:

            status = str(result.get("status", "UNKNOWN")).upper()
            counts[status] = counts.get(status, 0) + 1

            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            self.results_table.setItem(
                row, 0, QTableWidgetItem(str(result.get("file", ""))))

            status_item = QTableWidgetItem(status)
            if status in colors:
                status_item.setForeground(QBrush(QColor(colors[status])))
            self.results_table.setItem(row, 1, status_item)

            self.results_table.setItem(
                row, 2, QTableWidgetItem(str(result.get("old_hash", ""))))
            self.results_table.setItem(
                row, 3, QTableWidgetItem(str(result.get("new_hash", ""))))

        self.update_counts(
            total=len(results),
            unchanged=counts["UNCHANGED"],
            modified=counts["MODIFIED"],
            new=counts["NEW"],
            deleted=counts["DELETED"],
        )

    def update_counts(self, total, unchanged, modified, new, deleted):
        self.total_label.setText(f"TOTAL: {total}")
        self.unchanged_label.setText(f"UNCHANGED: {unchanged}")
        self.modified_label.setText(f"MODIFIED: {modified}")
        self.new_label.setText(f"NEW: {new}")
        self.deleted_label.setText(f"DELETED: {deleted}")

    def clear_baseline(self):

        if not self.integrity.baseline_exists():
            QMessageBox.information(self, "File Integrity", "No baseline exists.")
            return

        reply = QMessageBox.question(
            self,
            "Clear Baseline",
            "Are you sure you want to delete the current baseline?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        try:
            self.integrity.clear_baseline()

            self.results_table.setRowCount(0)
            self.update_counts(0, 0, 0, 0, 0)

            try:
                log_event("FILE_INTEGRITY_BASELINE_CLEARED")
            except Exception:
                pass

            QMessageBox.information(
                self, "File Integrity", "Baseline cleared successfully."
            )

        except Exception as error:
            QMessageBox.critical(self, "File Integrity Error", str(error))

        self.update_buttons()

    def update_buttons(self):

        has_folder = bool(self.selected_folder)
        has_baseline = self.integrity.baseline_exists()

        self.baseline_button.setEnabled(has_folder)
        self.scan_button.setEnabled(has_folder and has_baseline)
        self.clear_button.setEnabled(has_baseline)

    def refresh(self):
        self.update_buttons()


# ============================================================
# Network Audit Page
# ============================================================


class NetworkAuditPage(QWidget):

    def __init__(self, main_window=None):
        super().__init__()

        self.main_window = main_window
        self.audit = NetworkAudit()
        self.last_network_results = None

        layout = QVBoxLayout()
        layout.setContentsMargins(25, 20, 25, 20)
        layout.setSpacing(15)

        subtitle = QLabel("LOCAL NETWORK SECURITY ASSESSMENT  //  READ-ONLY AUDIT")
        subtitle.setStyleSheet(f"color: {GRAY}; font-size: 11px;")

        layout.addWidget(page_title("> NETWORK AUDIT", 24))
        layout.addWidget(subtitle)

        # Buttons
        button_row = QHBoxLayout()
        button_row.setSpacing(12)

        self.run_button = QPushButton("▶ RUN NETWORK AUDIT")
        self.run_button.setMinimumHeight(42)
        self.run_button.setStyleSheet(ACTION_BUTTON_STYLE)
        self.run_button.clicked.connect(self.run_audit)
        button_row.addWidget(self.run_button)

        self.export_pdf_button = QPushButton("EXPORT NETWORK REPORT PDF")
        self.export_pdf_button.setMinimumHeight(42)
        self.export_pdf_button.setStyleSheet(ACTION_BUTTON_STYLE)
        self.export_pdf_button.clicked.connect(self.export_network_report_pdf)
        button_row.addWidget(self.export_pdf_button)

        layout.addLayout(button_row)

        # Summary cards
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(10)

        self.ip_card = self.create_card("LOCAL IP", "Unknown")
        self.gateway_card = self.create_card("GATEWAY", "Unknown")
        self.dns_card = self.create_card("DNS SERVERS", "0")
        self.connection_card = self.create_card("ACTIVE CONNECTIONS", "0")
        self.port_card = self.create_card("LISTENING PORTS", "0")

        for card in (self.ip_card, self.gateway_card, self.dns_card,
                     self.connection_card, self.port_card):
            summary_layout.addWidget(card)

        layout.addLayout(summary_layout)

        # Risk panel
        risk_frame = QFrame()
        risk_frame.setObjectName("networkRisk")
        risk_frame.setStyleSheet(
            f"""
            QFrame#networkRisk {{
                background-color: #080808;
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}
            """
        )

        risk_layout = QHBoxLayout()
        risk_layout.setContentsMargins(15, 10, 15, 10)

        risk_title = QLabel("NETWORK RISK")
        risk_title.setStyleSheet(f"color: {GRAY}; font-size: 10px; font-weight: bold;")

        self.risk_score_label = QLabel("100/100")
        self.risk_score_label.setStyleSheet(
            f"color: {GREEN}; font-size: 20px; font-weight: bold;"
        )

        self.risk_level_label = QLabel("LOW")
        self.risk_level_label.setStyleSheet(
            f"color: {GREEN}; font-size: 13px; font-weight: bold;"
        )

        self.warning_label = QLabel("WARNINGS: 0")
        self.warning_label.setStyleSheet(f"color: {GRAY}; font-size: 10px;")

        self.info_label = QLabel("INFO: 0")
        self.info_label.setStyleSheet(f"color: {GRAY}; font-size: 10px;")

        risk_layout.addWidget(risk_title)
        risk_layout.addStretch()
        risk_layout.addWidget(self.risk_score_label)
        risk_layout.addSpacing(15)
        risk_layout.addWidget(self.risk_level_label)
        risk_layout.addSpacing(25)
        risk_layout.addWidget(self.warning_label)
        risk_layout.addSpacing(15)
        risk_layout.addWidget(self.info_label)

        risk_frame.setLayout(risk_layout)
        layout.addWidget(risk_frame)

        # Tabs
        self.tabs = QTabWidget()

        self.adapter_table = QTableWidget()
        self.adapter_table.setColumnCount(1)
        self.adapter_table.setHorizontalHeaderLabels(["NETWORK ADAPTER"])
        self.configure_table(self.adapter_table)
        self.tabs.addTab(self.adapter_table, "NETWORK ADAPTERS")

        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(7)
        self.connection_table.setHorizontalHeaderLabels(
            ["PROTOCOL", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", "ANALYSIS"]
        )
        self.configure_table(self.connection_table)
        self.tabs.addTab(self.connection_table, "ACTIVE CONNECTIONS")

        self.port_table = QTableWidget()
        self.port_table.setColumnCount(6)
        self.port_table.setHorizontalHeaderLabels(
            ["ADDRESS", "PORT", "PID", "PROCESS", "ANALYSIS", "REASON"]
        )
        self.configure_table(self.port_table)
        self.tabs.addTab(self.port_table, "LISTENING PORTS")

        layout.addWidget(self.tabs)

        self.status_label = QLabel("STATUS: READY")
        self.status_label.setStyleSheet(f"color: {GRAY}; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def create_card(self, title, value):

        frame = QFrame()
        frame.setObjectName("netCard")
        frame.setStyleSheet(
            f"""
            QFrame#netCard {{
                background-color: #080808;
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}
            """
        )

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 10, 12, 10)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {GRAY}; font-size: 9px; font-weight: bold;")

        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {GREEN}; font-size: 18px; font-weight: bold;")

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        frame.setLayout(layout)
        frame.value_label = value_label

        return frame

    def configure_table(self, table):

        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setWordWrap(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setStyleSheet(TABLE_STYLE)

    def fill_table(self, table, rows):

        table.setRowCount(len(rows))

        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                text = str(value)
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                table.setItem(row, column, item)

    def color_analysis_cell(self, table, row, column, analysis):

        item = table.item(row, column)

        if item is None:
            return

        analysis = str(analysis).upper()

        if analysis == "WARNING":
            color = "#ff4d4d"
        elif analysis == "INFO":
            color = "#4da6ff"
        else:
            color = "#00d084"

        item.setForeground(QBrush(QColor(color)))

    def update_risk_display(self, risk):

        score = risk.get("score", 100)
        level = risk.get("level", "LOW")
        warnings = risk.get("warnings", 0)
        info = risk.get("info", 0)

        self.risk_score_label.setText(f"{score}/100")
        self.risk_level_label.setText(str(level))
        self.warning_label.setText(f"WARNINGS: {warnings}")
        self.info_label.setText(f"INFO: {info}")

        if level == "HIGH":
            color = "#ff4d4d"
        elif level == "MEDIUM":
            color = "#ffbf3f"
        else:
            color = GREEN

        self.risk_score_label.setStyleSheet(
            f"color: {color}; font-size: 20px; font-weight: bold;"
        )
        self.risk_level_label.setStyleSheet(
            f"color: {color}; font-size: 13px; font-weight: bold;"
        )

    def run_audit(self):

        self.run_button.setEnabled(False)
        self.status_label.setText("STATUS: RUNNING NETWORK AUDIT...")

        QApplication.processEvents()

        try:

            result = self.audit.run_full_audit()

            # Saved for PDF export
            self.last_network_results = result

            # Update the dashboard from this completed local audit
            try:
                dashboard = getattr(self.main_window, "dashboard", None)
                if dashboard is not None:
                    dashboard.update_network_status(result)
            except Exception as dashboard_error:
                print(f"[NETWORK] Dashboard update error: {dashboard_error}")

            network = result.get("network", {})
            summary = result.get("summary", {})

            self.ip_card.value_label.setText(str(network.get("local_ip", "Unknown")))
            self.gateway_card.value_label.setText(str(network.get("gateway", "Unknown")))
            self.dns_card.value_label.setText(str(summary.get("dns_servers", 0)))
            self.connection_card.value_label.setText(
                str(summary.get("active_connections", 0))
            )
            self.port_card.value_label.setText(str(summary.get("listening_ports", 0)))

            risk = result.get("risk", {})
            self.update_risk_display(risk)

            # Adapters
            adapters = network.get("adapters", [])
            self.fill_table(self.adapter_table, [[adapter] for adapter in adapters])

            # Connections
            connections = result.get("connections", [])

            self.fill_table(
                self.connection_table,
                [
                    [
                        c.get("protocol", ""),
                        c.get("local", ""),
                        c.get("remote", ""),
                        c.get("state", ""),
                        c.get("pid", ""),
                        c.get("process", "Unknown"),
                        c.get("analysis", ""),
                    ]
                    for c in connections
                ]
            )

            for row, connection in enumerate(connections):
                self.color_analysis_cell(
                    self.connection_table, row, 6, connection.get("analysis", "")
                )

            # Listening ports
            ports = result.get("listening_ports", [])

            self.fill_table(
                self.port_table,
                [
                    [
                        p.get("address", ""),
                        p.get("port", ""),
                        p.get("pid", ""),
                        p.get("process", "Unknown"),
                        p.get("analysis", ""),
                        p.get("reason", ""),
                    ]
                    for p in ports
                ]
            )

            for row, port in enumerate(ports):
                self.color_analysis_cell(self.port_table, row, 4, port.get("analysis", ""))

            risk_level = risk.get("level", "LOW")

            self.status_label.setText(
                f"STATUS: NETWORK AUDIT COMPLETED  //  RISK: {risk_level}"
            )

            try:
                log_event("NETWORK_AUDIT_COMPLETED")
            except Exception:
                pass

        except Exception as error:

            self.status_label.setText(f"STATUS: AUDIT ERROR - {error}")

        finally:

            self.run_button.setEnabled(True)

    def refresh(self):
        # Do not automatically run a network audit.
        pass

    def export_network_report_pdf(self):
        """Export the latest network audit results to a real PDF report."""

        from pathlib import Path
        from xml.sax.saxutils import escape

        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                PageBreak,
            )
        except ImportError:
            QMessageBox.critical(
                self,
                "Missing ReportLab",
                "Install ReportLab using:\npy -m pip install reportlab"
            )
            return

        results = getattr(self, "last_network_results", None)

        if not isinstance(results, dict) or not results:
            QMessageBox.warning(
                self, "No Audit Results", "Run the Network Audit before exporting the PDF."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Network Security Report",
            "CyberFaceGuard_Network_Report.pdf",
            "PDF Files (*.pdf)"
        )

        if not file_path:
            return

        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"

        def safe(value):
            if value is None:
                return "N/A"
            return str(value).strip() or "N/A"

        def paragraph(value, style):
            return Paragraph(escape(safe(value)).replace("\n", "<br/>"), style)

        try:
            network = results.get("network") or {}
            summary = results.get("summary") or {}
            risk = results.get("risk") or {}
            adapters = network.get("adapters") or []
            connections = results.get("connections") or []
            ports = results.get("listening_ports") or []

            styles = getSampleStyleSheet()

            styles.add(ParagraphStyle(
                name="CFTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=23,
                leading=29,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#007F91"),
                spaceAfter=5 * mm,
            ))

            styles.add(ParagraphStyle(
                name="CFSubtitle",
                parent=styles["Normal"],
                alignment=TA_CENTER,
                fontSize=10,
                textColor=colors.HexColor("#52666A"),
                spaceAfter=4 * mm,
            ))

            styles.add(ParagraphStyle(
                name="CFSection",
                parent=styles["Heading2"],
                fontSize=13,
                leading=17,
                textColor=colors.HexColor("#007F91"),
                spaceBefore=5 * mm,
                spaceAfter=3 * mm,
                keepWithNext=True,
            ))

            styles.add(ParagraphStyle(
                name="CFCell",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=7,
                leading=9,
                splitLongWords=True,
            ))

            styles.add(ParagraphStyle(
                name="CFCellHeader",
                parent=styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=7,
                leading=9,
                textColor=colors.white,
                splitLongWords=True,
            ))

            def make_table(headers, rows, widths):
                data = [[paragraph(h, styles["CFCellHeader"]) for h in headers]]

                for row in rows:
                    data.append([paragraph(v, styles["CFCell"]) for v in row])

                if not rows:
                    data.append(
                        [paragraph("No records available", styles["CFCell"])]
                        + [paragraph("", styles["CFCell"]) for _ in headers[1:]]
                    )

                table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")

                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12343B")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CAD5D8")),
                    (
                        "ROWBACKGROUNDS", (0, 1), (-1, -1),
                        [colors.white, colors.HexColor("#F1F6F7")],
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))

                return table

            story = [
                Spacer(1, 18 * mm),
                paragraph("CYBERFACEGUARD", styles["CFTitle"]),
                paragraph("NETWORK SECURITY AUDIT REPORT", styles["CFSubtitle"]),
                Spacer(1, 3 * mm),
                paragraph(
                    "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    styles["Normal"]
                ),
                Spacer(1, 8 * mm),
                paragraph("1. Executive Summary", styles["CFSection"]),
            ]

            overview_rows = [
                ["Local IP", network.get("local_ip", "Unknown")],
                ["Gateway", network.get("gateway", "Unknown")],
                ["DNS servers", summary.get("dns_servers", 0)],
                ["Active connections", summary.get("active_connections", len(connections))],
                ["Listening ports", summary.get("listening_ports", len(ports))],
                ["Risk score", risk.get("score", "N/A")],
                ["Risk level", risk.get("level", "N/A")],
                ["Warnings", risk.get("warnings", 0)],
                ["Information items", risk.get("info", 0)],
            ]

            story.append(make_table(
                ["Metric", "Result"], overview_rows, [55 * mm, 115 * mm]
            ))

            story += [
                paragraph("2. Network Adapters", styles["CFSection"]),
                make_table(
                    ["Network Adapter"],
                    [[adapter] for adapter in adapters],
                    [170 * mm],
                ),
                paragraph("3. Active Connections", styles["CFSection"]),
                make_table(
                    ["Protocol", "Local", "Remote", "State", "PID", "Process", "Analysis"],
                    [[
                        c.get("protocol", ""),
                        c.get("local", ""),
                        c.get("remote", ""),
                        c.get("state", ""),
                        c.get("pid", ""),
                        c.get("process", "Unknown"),
                        c.get("analysis", ""),
                    ] for c in connections],
                    [17 * mm, 30 * mm, 30 * mm, 19 * mm, 12 * mm, 34 * mm, 28 * mm],
                ),
                PageBreak(),
                paragraph("4. Listening Ports", styles["CFSection"]),
                make_table(
                    ["Address", "Port", "PID", "Process", "Analysis", "Reason"],
                    [[
                        p.get("address", ""),
                        p.get("port", ""),
                        p.get("pid", ""),
                        p.get("process", "Unknown"),
                        p.get("analysis", ""),
                        p.get("reason", ""),
                    ] for p in ports],
                    [27 * mm, 14 * mm, 14 * mm, 33 * mm, 23 * mm, 59 * mm],
                ),
                Spacer(1, 8 * mm),
                paragraph(
                    "End of report. Results reflect the latest completed "
                    "local network audit.",
                    styles["Italic"]
                ),
            ]

            def draw_page(canvas, doc):
                canvas.saveState()

                page_width, page_height = landscape(A4)

                canvas.setStrokeColor(colors.HexColor("#007F91"))
                canvas.setLineWidth(1)
                canvas.line(
                    15 * mm, page_height - 12 * mm,
                    page_width - 15 * mm, page_height - 12 * mm,
                )

                canvas.setFont("Helvetica", 8)
                canvas.setFillColor(colors.HexColor("#52666A"))

                canvas.drawString(15 * mm, 8 * mm, "CYBERFACEGUARD | NETWORK AUDIT")
                canvas.drawRightString(
                    page_width - 15 * mm, 8 * mm, f"Page {doc.page}"
                )

                canvas.restoreState()

            doc = SimpleDocTemplate(
                file_path,
                pagesize=landscape(A4),
                rightMargin=15 * mm,
                leftMargin=15 * mm,
                topMargin=18 * mm,
                bottomMargin=15 * mm,
                title="CyberFaceGuard Network Security Audit",
                author="CyberFaceGuard",
            )

            doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)

            if not Path(file_path).is_file() or Path(file_path).stat().st_size == 0:
                raise OSError("The PDF file was not created correctly.")

        except Exception as error:
            QMessageBox.critical(
                self, "PDF Export Error", f"Could not generate the PDF report:\n{error}"
            )
            return

        QMessageBox.information(
            self, "Report Exported", f"Network report saved successfully:\n{file_path}"
        )


# ============================================================
# Main Window
# ============================================================


class MainWindow(QMainWindow):

    NAV_ACTIVE = """
        QPushButton {{ text-align:left; padding:9px 12px; border-radius:8px;
            background:#073326; color:{green}; border:1px solid {green};
            font-size:10px; font-weight:700; }}
    """

    NAV_IDLE = """
        QPushButton {{ text-align:left; padding:9px 12px; border-radius:8px;
            background:#061218; color:#9ab8b0; border:1px solid #123746;
            font-size:10px; font-weight:600; }}
        QPushButton:hover {{ background:#0a2922; color:{green}; border:1px solid #087d66; }}
    """

    def __init__(self):
        super().__init__()

        self.setWindowIcon(QIcon(resource_path("assets/cyberfaceguard.ico")))
        self.setWindowTitle("CyberFaceGuard")
        self.resize(1200, 750)
        self.setStyleSheet(GLOBAL_STYLE)

        # Security counters
        self.authorized_count = 0
        self.unknown_count = 0
        self.threat_count = 0

        # Enrollment manager
        self.enrollment = UserEnrollment()

        central = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ====================================================
        # SIDEBAR
        # ====================================================

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(230)
        sidebar.setStyleSheet(
            f"QFrame#sidebar {{ background-color: #030303; "
            f"border-right: 1px solid {BORDER}; }}"
        )

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(10, 15, 10, 15)
        sidebar_layout.setSpacing(7)

        logo = QLabel()
        logo_pixmap = QPixmap(resource_path("assets/cyberfaceguard_icon.png"))

        if not logo_pixmap.isNull():
            logo.setPixmap(
                logo_pixmap.scaled(85, 85, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )

        logo.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(logo)

        logo_text = QLabel("CYBERFACEGUARD")
        logo_text.setStyleSheet(f"color: {GREEN}; font-size: 18px; font-weight: bold;")
        logo_text.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(logo_text)

        version = QLabel("SECURITY CONTROL PANEL")
        version.setStyleSheet(f"color: {GRAY}; font-size: 10px;")
        version.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(version)

        sidebar_layout.addSpacing(20)

        self.dashboard_button = QPushButton("⌂   DASHBOARD")
        self.face_button = QPushButton("◉   FACE AUTHENTICATION")
        self.vault_button = QPushButton("▣   SECURE VAULT")
        self.users_button = QPushButton("♙   USER PROFILES")
        self.logs_button = QPushButton("▤   SECURITY LOGS")
        self.audit_button = QPushButton("⬡   SECURITY AUDIT")
        self.integrity_button = QPushButton("◇   FILE INTEGRITY")
        self.network_button = QPushButton("◎   NETWORK AUDIT")
        self.settings_button = QPushButton("⚙   SETTINGS")

        # Visual order: Dashboard, Security Audit, Network Audit, File Integrity,
        # Secure Vault, Security Logs, Face Authentication, User Profiles, Settings.
        nav_buttons = (
            self.dashboard_button,
            self.audit_button,
            self.network_button,
            self.integrity_button,
            self.vault_button,
            self.logs_button,
            self.face_button,
            self.users_button,
            self.settings_button,
        )
        for button in nav_buttons:
            button.setMinimumHeight(39)
            button.setCursor(Qt.PointingHandCursor)
            button.setStyleSheet(self.NAV_IDLE.format(green=GREEN))
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch()

        footer = QLabel("SYSTEM: ONLINE\nENGINE: YuNet + SFace\nMODE: LOCAL")
        footer.setStyleSheet(f"color: {GRAY}; font-size: 10px;")
        footer.setAlignment(Qt.AlignLeft)
        sidebar_layout.addWidget(footer)

        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)

        # ====================================================
        # PAGES
        # ====================================================

        self.pages = QStackedWidget()

        self.dashboard = DashboardPage(self)            # 0
        self.face_auth = FaceAuthPage(self)             # 1
        self.vault = VaultPage(self)                    # 2
        self.users = UsersPage(self)                    # 3
        self.logs = LogsPage()                          # 4
        self.settings = SettingsPage()                  # 5
        self.security_audit = SecurityAuditPage(self)   # 6
        self.file_integrity = FileIntegrityPage(self)   # 7
        self.network_audit = NetworkAuditPage(self)     # 8

        for page in (self.dashboard, self.face_auth, self.vault,
                     self.users, self.logs, self.settings,
                     self.security_audit, self.file_integrity,
                     self.network_audit):
            self.pages.addWidget(page)

        main_layout.addWidget(self.pages, 1)

        central.setLayout(main_layout)
        self.setCentralWidget(central)

        # ====================================================
        # NAVIGATION
        # ====================================================

        self.dashboard_button.clicked.connect(lambda: self.change_page(0))
        self.face_button.clicked.connect(lambda: self.change_page(1))
        self.vault_button.clicked.connect(lambda: self.change_page(2))
        self.users_button.clicked.connect(lambda: self.change_page(3))
        self.logs_button.clicked.connect(lambda: self.change_page(4))
        self.settings_button.clicked.connect(lambda: self.change_page(5))
        self.audit_button.clicked.connect(lambda: self.change_page(6))
        self.integrity_button.clicked.connect(lambda: self.change_page(7))
        self.network_button.clicked.connect(lambda: self.change_page(8))
        self.change_page(0)

        # Dashboard timer
        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self.dashboard.refresh)
        self.dashboard_timer.start(1000)

    def change_page(self, index):

        if index != 1:
            try:
                if self.face_auth.running:
                    self.face_auth.stop_camera()
            except Exception:
                pass

        self.pages.setCurrentIndex(index)

        nav_by_index = {
            0: self.dashboard_button, 1: self.face_button, 2: self.vault_button,
            3: self.users_button, 4: self.logs_button, 5: self.settings_button,
            6: self.audit_button, 7: self.integrity_button, 8: self.network_button,
        }

        for page_index, button in nav_by_index.items():
            template = self.NAV_ACTIVE if page_index == index else self.NAV_IDLE
            button.setStyleSheet(template.format(green=GREEN))

        try:
            if index == 0:
                self.dashboard.refresh()
            elif index == 2:
                self.vault.refresh()
            elif index == 3:
                self.users.refresh_users()
            elif index == 4:
                self.logs.load_logs()
            elif index == 6:
                self.security_audit.refresh()
            elif index == 7:
                self.file_integrity.refresh()
            elif index == 8:
                self.network_audit.refresh()
        except Exception:
            pass

    def closeEvent(self, event):

        try:
            if hasattr(self, "face_auth"):
                self.face_auth.stop_camera()
        except Exception:
            pass

        try:
            if hasattr(self, "dashboard_timer"):
                self.dashboard_timer.stop()
        except Exception:
            pass

        # Always lock vault on exit
        try:
            if hasattr(self, "vault") and self.vault.vault.is_unlocked():
                self.vault.vault.lock()
                log_event("VAULT_AUTO_LOCKED_ON_EXIT")
        except Exception:
            pass

        event.accept()


# ============================================================
# First Run Enrollment
# ============================================================


def first_run_enrollment(window):

    print("[FIRST RUN] Starting user registration.")

    while True:

        username, ok = QInputDialog.getText(
            window, "CyberFaceGuard - Create User", "Create your username:"
        )

        if not ok:
            print("[FIRST RUN] Registration cancelled.")
            return False

        username = username.strip()

        valid, error = window.enrollment.validate_username(username)

        if not valid:
            QMessageBox.warning(window, "Invalid Username", error)
            continue

        if window.enrollment.user_exists(username):
            QMessageBox.warning(
                window,
                "User Already Exists",
                f"The username '{username}' already exists."
            )
            continue

        QMessageBox.information(
            window,
            "Face Registration",
            f"Username: {username}\n\n"
            "Next, the camera will open.\n"
            "Look at the camera and register your face."
        )

        enrollment_camera = EnrollmentCamera(window, window, username)
        result = enrollment_camera.exec()

        if result:
            users = window.enrollment.get_users()

            if any(user.get("username") == username for user in users):
                print(f"[FIRST RUN] User '{username}' registered successfully.")

                QMessageBox.information(
                    window,
                    "Registration Complete",
                    f"Welcome, {username}!\n\n"
                    "Your face has been registered successfully.\n"
                    "CyberFaceGuard is ready."
                )
                return True

        answer = QMessageBox.question(
            window,
            "Registration Not Completed",
            "Face registration was not completed.\n\n"
            "Do you want to try again?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        if answer == QMessageBox.No:
            print("[FIRST RUN] Registration cancelled.")
            return False


# ============================================================
# Application Start
# ============================================================


def main():

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    window = MainWindow()

    users = window.enrollment.get_users()

    # ---------------- FIRST RUN ----------------
    if len(users) == 0:

        print("[SYSTEM] No enrolled users found.")
        print("[SYSTEM] Starting first-run registration.")

        window.hide()

        # dialogs closing while the main window is hidden could
        # make the app quit before the dashboard is shown.
        app.setQuitOnLastWindowClosed(False)

        success = first_run_enrollment(window)

        app.setQuitOnLastWindowClosed(True)

        if success:
            print("[SYSTEM] First user registered.")
            print("[SYSTEM] Opening dashboard.")
            window.show()
            window.dashboard.refresh()
        else:
            print("[SYSTEM] Registration cancelled.")
            print("[SYSTEM] Closing application.")
            window.close()
            return

    # ---------------- EXISTING USER ----------------
    else:

        print(f"[SYSTEM] {len(users)} enrolled user(s) found.")
        print("[SYSTEM] Starting security lock.")

        window.hide()

        lock_screen = LockScreen(window)
        lock_screen.show()

        window.lock_screen = lock_screen

    sys.exit(app.exec())


if __name__ == "__main__":
    main()