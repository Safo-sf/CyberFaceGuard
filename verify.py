import cv2
import os
import sys
from pathlib import Path


# ============================================================
# CyberFaceGuard - Face Recognition Engine
# YuNet + SFace
# ============================================================


# ============================================================
# Application Base Directory
# ============================================================

def get_base_dir():
    """
    Returns the correct application directory.

    When running normally:
        C:/Users/.../CyberFaceGuard

    When running as a PyInstaller application:
        PyInstaller temporary/extracted directory
    """

    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)

    return Path(__file__).resolve().parent


BASE_DIR = get_base_dir()


# ============================================================
# Model Paths
# ============================================================

DETECTOR_MODEL = str(
    BASE_DIR
    / "models"
    / "face_detection_yunet_2023mar.onnx"
)

RECOGNIZER_MODEL = str(
    BASE_DIR
    / "models"
    / "face_recognition_sface_2021dec.onnx"
)


# ============================================================
# Authorized Face
# ============================================================

AUTHORIZED_FACE = str(
    BASE_DIR
    / "data"
    / "faces"
    / "authorized_face.jpg"
)


# ============================================================
# Recognition Settings
# ============================================================

THRESHOLD = 0.363


# ============================================================
# Debug Information
# ============================================================

print()
print("=" * 60)
print("CyberFaceGuard - Face Recognition Engine")
print("=" * 60)

print(
    f"[ENGINE] Base directory:\n"
    f"         {BASE_DIR}"
)

print(
    f"[ENGINE] YuNet:\n"
    f"         {DETECTOR_MODEL}"
)

print(
    f"[ENGINE] SFace:\n"
    f"         {RECOGNIZER_MODEL}"
)

print(
    f"[ENGINE] Authorized face:\n"
    f"         {AUTHORIZED_FACE}"
)

print()


# ============================================================
# Check Required Files
# ============================================================

def check_required_files():

    required_files = {
        "YuNet model": DETECTOR_MODEL,
        "SFace model": RECOGNIZER_MODEL,
        "Authorized face": AUTHORIZED_FACE,
    }

    missing = []

    for name, file_path in required_files.items():

        if not os.path.isfile(file_path):

            missing.append(
                f"{name}: {file_path}"
            )

    if missing:

        message = (
            "CyberFaceGuard could not find "
            "the required files:\n\n"
            + "\n".join(missing)
        )

        print("[ENGINE ERROR]")
        print(message)

        raise FileNotFoundError(
            message
        )


# ============================================================
# Face Recognition Engine
# ============================================================

class FaceRecognitionEngine:

    def __init__(self):

        print(
            "[ENGINE] Initializing "
            "face recognition engine..."
        )

        # ----------------------------------------------------
        # Check models
        # ----------------------------------------------------

        check_required_files()

        # ----------------------------------------------------
        # Load YuNet
        # ----------------------------------------------------

        print(
            "[ENGINE] Loading YuNet..."
        )

        try:

            self.detector = cv2.FaceDetectorYN.create(
                DETECTOR_MODEL,
                "",
                (320, 320),
                0.9,
                0.3,
                5000
            )

        except Exception as error:

            raise RuntimeError(
                "Failed to load YuNet face detector.\n\n"
                f"Model:\n{DETECTOR_MODEL}\n\n"
                f"OpenCV error:\n{error}"
            ) from error

        print(
            "[ENGINE] YuNet loaded."
        )

        # ----------------------------------------------------
        # Load SFace
        # ----------------------------------------------------

        print(
            "[ENGINE] Loading SFace..."
        )

        try:

            self.recognizer = cv2.FaceRecognizerSF.create(
                RECOGNIZER_MODEL,
                ""
            )

        except Exception as error:

            raise RuntimeError(
                "Failed to load SFace recognition model.\n\n"
                f"Model:\n{RECOGNIZER_MODEL}\n\n"
                f"OpenCV error:\n{error}"
            ) from error

        print(
            "[ENGINE] SFace loaded."
        )

        # ----------------------------------------------------
        # Load authorized face
        # ----------------------------------------------------

        print(
            "[ENGINE] Loading authorized face..."
        )

        authorized_image = cv2.imread(
            AUTHORIZED_FACE
        )

        if authorized_image is None:

            raise RuntimeError(
                "Could not load authorized face image.\n\n"
                f"File:\n{AUTHORIZED_FACE}"
            )

        # ----------------------------------------------------
        # Create authorized feature
        # ----------------------------------------------------

        self.authorized_feature = (
            self._create_feature(
                authorized_image
            )
        )

        print(
            "[ENGINE] Authorized face loaded."
        )

        print(
            "[ENGINE] Face recognition engine READY."
        )

        print("=" * 60)
        print()

    # ========================================================
    # Detect Face
    # ========================================================

    def detect_face(self, frame):

        if frame is None:

            return None

        if frame.size == 0:

            return None

        height, width = frame.shape[:2]

        # Update detector input size
        self.detector.setInputSize(
            (width, height)
        )

        try:

            _, faces = self.detector.detect(
                frame
            )

        except Exception as error:

            print(
                f"[ENGINE] Face detection error: "
                f"{error}"
            )

            return None

        if faces is None:

            return None

        if len(faces) == 0:

            return None

        # Return the first detected face
        return faces[0]

    # ========================================================
    # Create Face Feature
    # ========================================================

    def _create_feature(self, image):

        face = self.detect_face(
            image
        )

        if face is None:

            raise RuntimeError(
                "No face detected in authorized image."
            )

        try:

            aligned = self.recognizer.alignCrop(
                image,
                face
            )

            feature = self.recognizer.feature(
                aligned
            )

        except Exception as error:

            raise RuntimeError(
                "Could not create face feature.\n\n"
                f"OpenCV error:\n{error}"
            ) from error

        return feature

    # ========================================================
    # Verify Face
    # ========================================================

    def verify(
        self,
        frame,
        face=None
    ):

        try:

            # ------------------------------------------------
            # Detect face if not supplied
            # ------------------------------------------------

            if face is None:

                face = self.detect_face(
                    frame
                )

            if face is None:

                return False, 0.0

            # ------------------------------------------------
            # Align face
            # ------------------------------------------------

            aligned = self.recognizer.alignCrop(
                frame,
                face
            )

            # ------------------------------------------------
            # Extract feature
            # ------------------------------------------------

            feature = self.recognizer.feature(
                aligned
            )

            # ------------------------------------------------
            # Calculate similarity
            # ------------------------------------------------

            similarity = self.recognizer.match(
                self.authorized_feature,
                feature,
                cv2.FaceRecognizerSF_FR_COSINE
            )

            similarity = float(
                similarity
            )

            # ------------------------------------------------
            # Authentication decision
            # ------------------------------------------------

            authorized = (
                similarity >= THRESHOLD
            )

            return (
                authorized,
                similarity
            )

        except Exception as error:

            print(
                f"[ENGINE ERROR] "
                f"Face verification failed: "
                f"{error}"
            )

            return False, 0.0