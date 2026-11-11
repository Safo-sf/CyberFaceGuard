import os
from datetime import datetime


# ============================================================
# CyberFaceGuard - Security Logger
# ============================================================

APP_NAME = "CyberFaceGuard"

# ------------------------------------------------------------
# Writable application data directory
# ------------------------------------------------------------

LOCAL_APPDATA = os.getenv("LOCALAPPDATA")

if not LOCAL_APPDATA:
    LOCAL_APPDATA = os.path.expanduser("~")

APP_DATA_DIR = os.path.join(
    LOCAL_APPDATA,
    APP_NAME
)

LOG_DIR = os.path.join(
    APP_DATA_DIR,
    "logs"
)

LOG_FILE = os.path.join(
    LOG_DIR,
    "security.log"
)


# ============================================================
# Create logs folder automatically
# ============================================================

os.makedirs(
    LOG_DIR,
    exist_ok=True
)


# ============================================================
# Log security event
# ============================================================

def log_event(status, similarity=None):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # Event with similarity score
    # --------------------------------------------------------

    if similarity is not None:

        message = (
            f"[{timestamp}] "
            f"STATUS={status} "
            f"SIMILARITY={similarity:.3f}"
        )

    # --------------------------------------------------------
    # Event without similarity score
    # --------------------------------------------------------

    else:

        message = (
            f"[{timestamp}] "
            f"STATUS={status}"
        )

    # --------------------------------------------------------
    # Save event to log file
    # --------------------------------------------------------

    try:

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                message + "\n"
            )

    except Exception as error:

        print(
            f"[LOGGER ERROR] Unable to write security log: {error}"
        )

    # --------------------------------------------------------
    # Display event in terminal
    # --------------------------------------------------------

    print(message)