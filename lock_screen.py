import cv2

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QVBoxLayout,
    QPushButton,
    QDialog,
    QLineEdit
)

from PySide6.QtCore import (
    Qt,
    QTimer
)

from PySide6.QtGui import QImage, QPixmap

from verify_engine import FaceRecognitionEngine
from liveness import LivenessDetector

# IMPORTANT:
# This is the APPLICATION password.
# It is NOT the Secure Vault password.
from app_password_manager import (
    password_exists,
    create_password,
    verify_password,
    password_requirements
)


# ============================================================
# Application Password Dialog
# ============================================================

class AppPasswordDialog(QDialog):

    def __init__(self, mode="unlock", username="", parent=None):

        super().__init__(parent)

        self.mode = mode
        self.username = username

        if mode == "create":
            self.setWindowTitle(
                "CyberFaceGuard - Create Application Password"
            )
        else:
            self.setWindowTitle(
                "CyberFaceGuard - Password Authentication"
            )

        self.setModal(True)
        self.setMinimumWidth(450)

        self.setStyleSheet("""
            QDialog {
                background-color: #020202;
                color: #00ff66;
            }

            QLabel {
                color: #00ff66;
            }

            QLineEdit {
                background-color: #050505;
                color: #00ff66;
                border: 1px solid #1d5c35;
                padding: 10px;
                font-size: 15px;
            }

            QPushButton {
                background-color: #050505;
                color: #00ff66;
                border: 1px solid #1d5c35;
                padding: 10px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #12351f;
                border: 1px solid #00ff66;
            }
        """)

        layout = QVBoxLayout()

        # ----------------------------------------------------
        # Title
        # ----------------------------------------------------

        if mode == "create":

            title_text = "🔐 CREATE APPLICATION PASSWORD"

        else:

            title_text = "🔐 PASSWORD AUTHENTICATION"

        title = QLabel(title_text)

        title.setAlignment(
            Qt.AlignCenter
        )

        title.setStyleSheet("""
            color: #00ff66;
            font-size: 22px;
            font-weight: bold;
        """)

        layout.addWidget(title)

        # ----------------------------------------------------
        # User
        # ----------------------------------------------------

        user_label = QLabel(
            f"Face verified: {username}"
        )

        user_label.setAlignment(
            Qt.AlignCenter
        )

        user_label.setStyleSheet("""
            color: #00ff66;
            font-size: 14px;
        """)

        layout.addWidget(user_label)

        layout.addSpacing(15)

        # ----------------------------------------------------
        # Information
        # ----------------------------------------------------

        if mode == "create":

            info_text = (
                "This is your CyberFaceGuard application password.\n\n"
                "You will need this password after Face ID "
                "on future launches."
            )

        else:

            info_text = (
                "Face verification successful.\n"
                "Enter your application password to continue."
            )

        info = QLabel(info_text)

        info.setAlignment(
            Qt.AlignCenter
        )

        info.setWordWrap(True)

        layout.addWidget(info)

        layout.addSpacing(10)

        # ----------------------------------------------------
        # Password
        # ----------------------------------------------------

        self.password_input = QLineEdit()

        self.password_input.setEchoMode(
            QLineEdit.Password
        )

        if mode == "create":

            self.password_input.setPlaceholderText(
                "Create password"
            )

        else:

            self.password_input.setPlaceholderText(
                "Enter password"
            )

        layout.addWidget(
            self.password_input
        )

        # ----------------------------------------------------
        # Confirm password
        # ----------------------------------------------------

        self.confirm_input = None

        if mode == "create":

            self.confirm_input = QLineEdit()

            self.confirm_input.setEchoMode(
                QLineEdit.Password
            )

            self.confirm_input.setPlaceholderText(
                "Confirm password"
            )

            layout.addWidget(
                self.confirm_input
            )

        # ----------------------------------------------------
        # Strength
        # ----------------------------------------------------

        self.strength_label = QLabel("")

        self.strength_label.setAlignment(
            Qt.AlignCenter
        )

        self.strength_label.setWordWrap(True)

        self.strength_label.setStyleSheet("""
            color: #ffaa00;
            font-size: 13px;
        """)

        layout.addWidget(
            self.strength_label
        )

        # ----------------------------------------------------
        # Error
        # ----------------------------------------------------

        self.error_label = QLabel("")

        self.error_label.setAlignment(
            Qt.AlignCenter
        )

        self.error_label.setWordWrap(True)

        self.error_label.setStyleSheet("""
            color: #ff4444;
            font-size: 13px;
        """)

        layout.addWidget(
            self.error_label
        )

        layout.addSpacing(10)

        # ----------------------------------------------------
        # Action button
        # ----------------------------------------------------

        if mode == "create":

            button_text = "CREATE PASSWORD"

        else:

            button_text = "UNLOCK APPLICATION"

        self.action_button = QPushButton(
            button_text
        )

        self.action_button.clicked.connect(
            self.handle_action
        )

        layout.addWidget(
            self.action_button
        )

        # ----------------------------------------------------
        # Cancel
        # ----------------------------------------------------

        self.cancel_button = QPushButton(
            "CANCEL"
        )

        self.cancel_button.clicked.connect(
            self.reject
        )

        layout.addWidget(
            self.cancel_button
        )

        # ----------------------------------------------------
        # Events
        # ----------------------------------------------------

        self.password_input.textChanged.connect(
            self.update_strength
        )

        self.password_input.returnPressed.connect(
            self.handle_action
        )

        if self.confirm_input:

            self.confirm_input.returnPressed.connect(
                self.handle_action
            )

        self.setLayout(
            layout
        )

        self.password_input.setFocus()

    # ========================================================
    # Password strength
    # ========================================================

    def update_strength(self):

        if self.mode != "create":
            return

        password = self.password_input.text()

        if not password:

            self.strength_label.setText("")

            return

        try:

            valid, message = password_requirements(
                password
            )

            if valid:

                self.strength_label.setStyleSheet("""
                    color: #00ff66;
                    font-size: 13px;
                """)

                self.strength_label.setText(
                    "✓ " + message
                )

            else:

                self.strength_label.setStyleSheet("""
                    color: #ffaa00;
                    font-size: 13px;
                """)

                self.strength_label.setText(
                    message
                )

        except Exception:

            self.strength_label.setText("")

    # ========================================================
    # Create / Verify
    # ========================================================

    def handle_action(self):

        password = self.password_input.text()

        self.error_label.setText("")

        if not password:

            self.error_label.setText(
                "Please enter your password."
            )

            return

        # ----------------------------------------------------
        # CREATE PASSWORD
        # ----------------------------------------------------

        if self.mode == "create":

            if self.confirm_input is None:

                return

            confirm = self.confirm_input.text()

            if not confirm:

                self.error_label.setText(
                    "Please confirm your password."
                )

                return

            if password != confirm:

                self.error_label.setText(
                    "Passwords do not match."
                )

                return

            try:

                success, message = create_password(
                    password
                )

                if success:

                    print(
                        "[AUTH] Application password created."
                    )

                    self.accept()

                else:

                    self.error_label.setText(
                        message
                    )

            except Exception as error:

                print(
                    "[AUTH ERROR]",
                    error
                )

                self.error_label.setText(
                    "Unable to create application password."
                )

            return

        # ----------------------------------------------------
        # VERIFY PASSWORD
        # ----------------------------------------------------

        try:

            if not password_exists():

                self.error_label.setText(
                    "No application password is configured."
                )

                return

            success, message = verify_password(
                password
            )

            if success:

                print(
                    "[AUTH] Application password authentication successful."
                )

                self.accept()

            else:

                print(
                    "[AUTH] Application password authentication failed."
                )

                self.error_label.setText(
                    "Incorrect password."
                )

                self.password_input.clear()

                self.password_input.setFocus()

        except Exception as error:

            print(
                "[AUTH ERROR]",
                error
            )

            self.error_label.setText(
                "Authentication error."
            )


# ============================================================
# LOCK SCREEN
# ============================================================

class LockScreen(QWidget):

    def __init__(self, main_window):

        super().__init__()

        self.main_window = main_window

        self.camera = None
        self.engine = None

        self.liveness = LivenessDetector()

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.update_camera
        )

        self.running = False

        self.user_features = []

        self.access_granted = False

        self.last_user = None

        self.password_dialog_open = False

        self.setWindowTitle(
            "CyberFaceGuard - Security Lock"
        )

        self.setWindowFlags(
            Qt.Window
        )

        self.setWindowState(
            Qt.WindowFullScreen
        )

        self.setStyleSheet("""
            QWidget {
                background-color: #020202;
                color: #00ff66;
                font-family: Consolas;
            }

            QLabel {
                color: #00ff66;
            }

            QPushButton {
                background-color: #050505;
                color: #00ff66;
                border: 1px solid #1d5c35;
                padding: 12px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #12351f;
                border: 1px solid #00ff66;
            }
        """)

        self.build_ui()

        self.start_security_check()

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):

        layout = QVBoxLayout()

        layout.setAlignment(
            Qt.AlignCenter
        )

        self.title = QLabel(
            "🛡 CYBERFACEGUARD"
        )

        self.title.setAlignment(
            Qt.AlignCenter
        )

        self.title.setStyleSheet("""
            color: #00ff66;
            font-size: 36px;
            font-weight: bold;
        """)

        layout.addWidget(
            self.title
        )

        self.subtitle = QLabel(
            "SECURITY ACCESS CONTROL"
        )

        self.subtitle.setAlignment(
            Qt.AlignCenter
        )

        self.subtitle.setStyleSheet("""
            color: #777777;
            font-size: 14px;
        """)

        layout.addWidget(
            self.subtitle
        )

        layout.addSpacing(25)

        self.status = QLabel(
            "🔒 SYSTEM LOCKED"
        )

        self.status.setAlignment(
            Qt.AlignCenter
        )

        self.status.setStyleSheet("""
            color: #ff4444;
            font-size: 26px;
            font-weight: bold;
        """)

        layout.addWidget(
            self.status
        )

        self.camera_label = QLabel(
            "INITIALIZING CAMERA..."
        )

        self.camera_label.setAlignment(
            Qt.AlignCenter
        )

        self.camera_label.setMinimumSize(
            720,
            480
        )

        self.camera_label.setStyleSheet("""
            background-color: #000000;
            border: 2px solid #1d5c35;
            color: #00ff66;
            font-size: 18px;
        """)

        layout.addWidget(
            self.camera_label
        )

        self.info = QLabel(
            "LOOK AT THE CAMERA"
        )

        self.info.setAlignment(
            Qt.AlignCenter
        )

        self.info.setStyleSheet("""
            color: #00ff66;
            font-size: 18px;
        """)

        layout.addWidget(
            self.info
        )

        self.similarity = QLabel(
            "SIMILARITY: --"
        )

        self.similarity.setAlignment(
            Qt.AlignCenter
        )

        self.similarity.setStyleSheet("""
            color: #777777;
            font-size: 13px;
        """)

        layout.addWidget(
            self.similarity
        )

        self.exit_button = QPushButton(
            "EXIT APPLICATION"
        )

        self.exit_button.setFixedWidth(
            220
        )

        self.exit_button.clicked.connect(
            self.exit_application
        )

        layout.addWidget(
            self.exit_button,
            alignment=Qt.AlignCenter
        )

        self.setLayout(
            layout
        )

    # ========================================================
    # Start security
    # ========================================================

    def start_security_check(self):

        try:

            self.engine = FaceRecognitionEngine()

            self.load_users()

            if len(self.user_features) == 0:

                self.status.setText(
                    "⚠ NO ENROLLED USERS"
                )

                self.status.setStyleSheet("""
                    color: #ffaa00;
                    font-size: 26px;
                    font-weight: bold;
                """)

                self.info.setText(
                    "Open the application and enroll a user first."
                )

                return

            self.camera = cv2.VideoCapture(
                0
            )

            if not self.camera.isOpened():

                self.status.setText(
                    "⚠ CAMERA ERROR"
                )

                self.info.setText(
                    "Unable to access the camera."
                )

                return

            self.running = True

            self.liveness.reset()

            self.timer.start(
                30
            )

            self.info.setText(
                "LOOK AT THE CAMERA"
            )

        except Exception as error:

            self.status.setText(
                "⚠ SECURITY ENGINE ERROR"
            )

            self.info.setText(
                str(error)
            )

            print(
                "[LOCK ERROR]",
                error
            )

    # ========================================================
    # Load users
    # ========================================================

    def load_users(self):

        self.user_features = []

        users = (
            self.main_window.enrollment
            .get_users()
        )

        for user in users:

            username = user.get(
                "username"
            )

            face_path = user.get(
                "face_path"
            )

            if not username:
                continue

            if not face_path:
                continue

            image = cv2.imread(
                face_path
            )

            if image is None:
                continue

            try:

                feature = (
                    self.engine
                    ._create_feature(image)
                )

                self.user_features.append({
                    "username": username,
                    "feature": feature
                })

                print(
                    "[LOCK] Loaded:",
                    username
                )

            except Exception as error:

                print(
                    "[LOCK] Failed:",
                    username,
                    error
                )

    # ========================================================
    # Convert frame
    # ========================================================

    def frame_to_pixmap(
        self,
        frame
    ):

        rgb = cv2.cvtColor(
            frame,
            cv2.COLOR_BGR2RGB
        )

        height, width, channels = (
            rgb.shape
        )

        bytes_per_line = (
            channels * width
        )

        image = QImage(
            rgb.data,
            width,
            height,
            bytes_per_line,
            QImage.Format_RGB888
        )

        return QPixmap.fromImage(
            image
        )

    # ========================================================
    # Match user
    # ========================================================

    def match_user(
        self,
        frame,
        face
    ):

        try:

            aligned = (
                self.engine
                .recognizer
                .alignCrop(
                    frame,
                    face
                )
            )

            feature = (
                self.engine
                .recognizer
                .feature(
                    aligned
                )
            )

            best_user = None
            best_similarity = 0.0

            for user in self.user_features:

                similarity = (
                    self.engine
                    .recognizer
                    .match(
                        user["feature"],
                        feature,
                        cv2.FaceRecognizerSF_FR_COSINE
                    )
                )

                similarity = float(
                    similarity
                )

                if similarity > best_similarity:

                    best_similarity = (
                        similarity
                    )

                    best_user = (
                        user["username"]
                    )

            if (
                best_user is not None
                and best_similarity >= 0.363
            ):

                return (
                    best_user,
                    best_similarity
                )

            return (
                None,
                best_similarity
            )

        except Exception as error:

            print(
                "[MATCH ERROR]",
                error
            )

            return (
                None,
                0.0
            )

    # ========================================================
    # Camera update
    # ========================================================

    def update_camera(self):

        if self.camera is None:
            return

        if self.password_dialog_open:
            return

        success, frame = (
            self.camera.read()
        )

        if not success:
            return

        frame = cv2.flip(
            frame,
            1
        )

        face = (
            self.engine
            .detect_face(frame)
        )

        # ----------------------------------------------------
        # No face
        # ----------------------------------------------------

        if face is None:

            self.info.setText(
                "NO FACE DETECTED"
            )

            self.similarity.setText(
                "SIMILARITY: --"
            )

            self.show_frame(
                frame
            )

            return

        # ----------------------------------------------------
        # Face rectangle
        # ----------------------------------------------------

        x, y, w, h = (
            face[:4].astype(int)
        )

        cv2.rectangle(
            frame,
            (x, y),
            (x + w, y + h),
            (0, 255, 100),
            3
        )

        # ----------------------------------------------------
        # Liveness
        # ----------------------------------------------------

        live = self.liveness.check(
            face
        )

        if not live:

            self.status.setText(
                "🔒 SYSTEM LOCKED"
            )

            self.info.setText(
                "LIVENESS CHECK..."
            )

            cv2.putText(
                frame,
                "LIVENESS CHECK",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 100),
                2
            )

            self.show_frame(
                frame
            )

            return

        # ----------------------------------------------------
        # Recognition
        # ----------------------------------------------------

        username, similarity = (
            self.match_user(
                frame,
                face
            )
        )

        self.similarity.setText(
            f"SIMILARITY: {similarity:.3f}"
        )

        # ----------------------------------------------------
        # Authorized
        # ----------------------------------------------------

        if username is not None:

            self.access_granted = True

            self.last_user = username

            self.status.setText(
                "✓ FACE VERIFIED"
            )

            self.status.setStyleSheet("""
                color: #00ff66;
                font-size: 30px;
                font-weight: bold;
            """)

            self.info.setText(
                "FACE VERIFIED - PASSWORD REQUIRED"
            )

            cv2.rectangle(
                frame,
                (x, y),
                (x + w, y + h),
                (0, 255, 100),
                4
            )

            cv2.putText(
                frame,
                f"FACE VERIFIED: {username}",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 100),
                2
            )

            self.show_frame(
                frame
            )

            self.running = False

            self.timer.stop()

            QTimer.singleShot(
                500,
                self.request_password
            )

        else:

            self.status.setText(
                "🔒 ACCESS DENIED"
            )

            self.status.setStyleSheet("""
                color: #ff4444;
                font-size: 30px;
                font-weight: bold;
            """)

            self.info.setText(
                "UNKNOWN USER"
            )

            cv2.rectangle(
                frame,
                (x, y),
                (x + w, y + h),
                (0, 0, 255),
                3
            )

            cv2.putText(
                frame,
                "UNKNOWN USER",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 0, 255),
                2
            )

            self.show_frame(
                frame
            )

    # ========================================================
    # Password authentication
    # ========================================================

    def request_password(self):

        if not self.access_granted:
            return

        if self.password_dialog_open:
            return

        self.password_dialog_open = True

        try:

            # =================================================
            # FIRST TIME:
            # Face verified -> Create password
            # =================================================

            if not password_exists():

                print(
                    "[AUTH] No application password found."
                )

                print(
                    "[AUTH] Starting first-time password creation."
                )

                create_dialog = AppPasswordDialog(
                    mode="create",
                    username=self.last_user,
                    parent=self
                )

                create_result = create_dialog.exec()

                if create_result != QDialog.Accepted:

                    print(
                        "[AUTH] Password creation cancelled."
                    )

                    self.password_dialog_open = False

                    self.reset_lock_screen()

                    return

                print(
                    "[AUTH] Application password created."
                )

            # =================================================
            # EVERY TIME:
            # Enter application password
            # =================================================

            print(
                "[AUTH] Requesting application password."
            )

            login_dialog = AppPasswordDialog(
                mode="unlock",
                username=self.last_user,
                parent=self
            )

            login_result = login_dialog.exec()

            if login_result == QDialog.Accepted:

                print(
                    "[AUTH] Face + Application Password authentication successful."
                )

                self.unlock()

            else:

                print(
                    "[AUTH] Application password authentication cancelled."
                )

                self.reset_lock_screen()

        except Exception as error:

            print(
                "[AUTH ERROR]",
                error
            )

            self.reset_lock_screen()

        finally:

            self.password_dialog_open = False

    # ========================================================
    # Reset lock screen
    # ========================================================

    def reset_lock_screen(self):

        self.access_granted = False

        self.last_user = None

        self.status.setText(
            "🔒 SYSTEM LOCKED"
        )

        self.status.setStyleSheet("""
            color: #ff4444;
            font-size: 26px;
            font-weight: bold;
        """)

        self.info.setText(
            "LOOK AT THE CAMERA"
        )

        self.similarity.setText(
            "SIMILARITY: --"
        )

        self.running = True

        self.liveness.reset()

        if self.camera is None:

            self.camera = cv2.VideoCapture(
                0
            )

        if self.camera.isOpened():

            self.timer.start(
                30
            )

    # ========================================================
    # Unlock
    # ========================================================

    def unlock(self):

        if not self.access_granted:
            return

        self.stop_camera()

        self.hide()

        self.main_window.show()

        self.main_window.raise_()

        self.main_window.activateWindow()

        print(
            f"[LOCK] FULL AUTHENTICATION GRANTED: {self.last_user}"
        )

    # ========================================================
    # Show frame
    # ========================================================

    def show_frame(
        self,
        frame
    ):

        pixmap = self.frame_to_pixmap(
            frame
        )

        self.camera_label.setPixmap(
            pixmap.scaled(
                self.camera_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
        )

    # ========================================================
    # Stop camera
    # ========================================================

    def stop_camera(self):

        self.timer.stop()

        if self.camera is not None:

            self.camera.release()

            self.camera = None

        self.running = False

    # ========================================================
    # Exit
    # ========================================================

    def exit_application(self):

        self.stop_camera()

        self.main_window.close()

        self.close()

    # ========================================================
    # Close
    # ========================================================

    def closeEvent(
        self,
        event
    ):

        self.stop_camera()

        event.accept()