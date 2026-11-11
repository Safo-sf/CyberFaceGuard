import sys

from PySide6.QtWidgets import QApplication

from gui import MainWindow, first_run_enrollment
from lock_screen import LockScreen
from license_manager import require_license


APP_NAME = "CyberFaceGuard"


def main():

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    # ============================================================
    # LICENSE CHECK
    # ============================================================

    print("=" * 60)
    print("[SYSTEM] CyberFaceGuard starting...")
    print("[SYSTEM] Checking license...")

    if not require_license():

        print("[SYSTEM] License not activated.")
        print("[SYSTEM] Closing CyberFaceGuard.")

        return

    print("[SYSTEM] License activated.")
    print("=" * 60)

    # ============================================================
    # MAIN WINDOW
    # ============================================================

    window = MainWindow()

    users = window.enrollment.get_users()

    # ============================================================
    # FIRST RUN
    # ============================================================

    if len(users) == 0:

        print("=" * 60)
        print("[SYSTEM] No enrolled users found.")
        print("[SYSTEM] Starting first-run registration.")
        print("=" * 60)

        window.hide()

        success = first_run_enrollment(window)

        if success:

            print("=" * 60)
            print("[SYSTEM] First user registered successfully.")
            print("[SYSTEM] Opening CyberFaceGuard dashboard.")
            print("=" * 60)

            window.show()
            window.dashboard.refresh()

        else:

            print("=" * 60)
            print("[SYSTEM] First-run registration cancelled.")
            print("[SYSTEM] Closing CyberFaceGuard.")
            print("=" * 60)

            window.close()

            return

    # ============================================================
    # EXISTING USER
    # ============================================================

    else:

        print("=" * 60)
        print(
            f"[SYSTEM] {len(users)} enrolled user(s) found."
        )
        print("[SYSTEM] Starting security lock.")
        print("=" * 60)

        window.hide()

        lock_screen = LockScreen(window)

        lock_screen.show()

        window.lock_screen = lock_screen

    # ============================================================
    # START APPLICATION
    # ============================================================

    sys.exit(app.exec())


if __name__ == "__main__":
    main()