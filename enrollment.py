import os
import json
import re
from datetime import datetime

import cv2


# ============================================================
# CyberFaceGuard - User Enrollment
# ============================================================

APP_NAME = "CyberFaceGuard"


# ============================================================
# USER DATA DIRECTORY
# ============================================================

LOCAL_APPDATA = os.getenv(
    "LOCALAPPDATA"
)

if not LOCAL_APPDATA:

    LOCAL_APPDATA = os.path.expanduser(
        "~"
    )

APP_DATA_DIR = os.path.join(
    LOCAL_APPDATA,
    APP_NAME
)

USERS_DIR = os.path.join(
    APP_DATA_DIR,
    "users"
)


# ============================================================
# USER ENROLLMENT
# ============================================================

class UserEnrollment:

    def __init__(self):

        os.makedirs(
            USERS_DIR,
            exist_ok=True
        )

        print(
            "[ENROLLMENT] User directory:"
        )

        print(
            f"                {USERS_DIR}"
        )

        print(
            "[ENROLLMENT] READY"
        )

    # ========================================================
    # USERNAME VALIDATION
    # ========================================================

    def validate_username(self, username):

        username = username.strip()

        if not username:

            return (
                False,
                "Username cannot be empty."
            )

        if len(username) < 2:

            return (
                False,
                "Username must contain at least 2 characters."
            )

        if len(username) > 30:

            return (
                False,
                "Username is too long."
            )

        if not re.match(
            r"^[A-Za-z0-9_-]+$",
            username
        ):

            return (
                False,
                "Username can contain only letters, numbers, "
                "underscore and hyphen."
            )

        return (
            True,
            ""
        )

    # ========================================================
    # USER DIRECTORY
    # ========================================================

    def get_user_directory(self, username):

        return os.path.join(
            USERS_DIR,
            username
        )

    # ========================================================
    # USER EXISTS
    # ========================================================

    def user_exists(self, username):

        user_dir = self.get_user_directory(
            username
        )

        return os.path.exists(
            os.path.join(
                user_dir,
                "face.jpg"
            )
        )

    # ========================================================
    # SAVE USER
    # ========================================================

    def save_user(
        self,
        username,
        face_image
    ):

        valid, error = self.validate_username(
            username
        )

        if not valid:
            raise ValueError(error)

        if self.user_exists(username):

            raise FileExistsError(
                f"User '{username}' already exists."
            )

        if face_image is None:

            raise ValueError(
                "Face image is empty."
            )

        user_dir = self.get_user_directory(
            username
        )

        os.makedirs(
            user_dir,
            exist_ok=True
        )

        face_path = os.path.join(
            user_dir,
            "face.jpg"
        )

        profile_path = os.path.join(
            user_dir,
            "profile.json"
        )

        # ----------------------------------------------------
        # Save face
        # ----------------------------------------------------

        success = cv2.imwrite(
            face_path,
            face_image
        )

        if not success:

            raise RuntimeError(
                "Unable to save face image."
            )

        # ----------------------------------------------------
        # Profile
        # ----------------------------------------------------

        profile = {

            "username": username,

            "created_at":
                datetime.now().isoformat(),

            "face_file":
                "face.jpg",

            "status":
                "ACTIVE"
        }

        with open(
            profile_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                profile,
                file,
                indent=4
            )

        print(
            f"[ENROLLMENT] User '{username}' "
            "enrolled successfully."
        )

        return face_path

    # ========================================================
    # GET USERS
    # ========================================================

    def get_users(self):

        users = []

        if not os.path.exists(
            USERS_DIR
        ):

            return users

        for username in sorted(
            os.listdir(USERS_DIR)
        ):

            user_dir = os.path.join(
                USERS_DIR,
                username
            )

            if not os.path.isdir(
                user_dir
            ):

                continue

            face_path = os.path.join(
                user_dir,
                "face.jpg"
            )

            profile_path = os.path.join(
                user_dir,
                "profile.json"
            )

            if not os.path.exists(
                face_path
            ):

                continue

            profile = {

                "username":
                    username,

                "face_path":
                    face_path,

                "profile_path":
                    profile_path
            }

            if os.path.exists(
                profile_path
            ):

                try:

                    with open(
                        profile_path,
                        "r",
                        encoding="utf-8"
                    ) as file:

                        data = json.load(
                            file
                        )

                        if isinstance(
                            data,
                            dict
                        ):

                            profile.update(
                                data
                            )

                except Exception as error:

                    print(
                        f"[ENROLLMENT] Profile error "
                        f"for {username}: {error}"
                    )

            users.append(
                profile
            )

        return users

    # ========================================================
    # REMOVE USER
    # ========================================================

    def remove_user(
        self,
        username
    ):

        user_dir = self.get_user_directory(
            username
        )

        if not os.path.exists(
            user_dir
        ):

            return False

        try:

            for filename in (
                "face.jpg",
                "profile.json"
            ):

                file_path = os.path.join(
                    user_dir,
                    filename
                )

                if os.path.exists(
                    file_path
                ):

                    os.remove(
                        file_path
                    )

            try:

                os.rmdir(
                    user_dir
                )

            except OSError:
                pass

            print(
                f"[ENROLLMENT] User "
                f"'{username}' removed."
            )

            return True

        except Exception as error:

            print(
                f"[ENROLLMENT] Remove error: "
                f"{error}"
            )

            return False