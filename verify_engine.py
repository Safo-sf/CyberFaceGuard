import cv2
import os
import sys
from pathlib import Path


# ============================================================
# CyberFaceGuard - Face Recognition Engine
# ============================================================

THRESHOLD = 0.363


# ============================================================
# RESOURCE PATH
# ============================================================

def get_base_dirs():

    directories = []

    if getattr(sys, "frozen", False):

        meipass = getattr(sys, "_MEIPASS", None)

        if meipass:
            directories.append(Path(meipass))

        directories.append(
            Path(sys.executable).resolve().parent
        )

    else:

        directories.append(
            Path(__file__).resolve().parent
        )

    return directories


BASE_DIRS = get_base_dirs()


def find_resource(*parts):

    for base_dir in BASE_DIRS:

        resource = base_dir.joinpath(*parts)

        if resource.exists():
            return str(resource)

    return str(
        BASE_DIRS[0].joinpath(*parts)
    )


# ============================================================
# MODELS
# ============================================================

DETECTOR_MODEL = find_resource(
    "models",
    "face_detection_yunet_2023mar.onnx"
)

RECOGNIZER_MODEL = find_resource(
    "models",
    "face_recognition_sface_2021dec.onnx"
)


# ============================================================
# CHECK MODELS
# ============================================================

if not os.path.isfile(DETECTOR_MODEL):

    raise FileNotFoundError(
        "YuNet model not found:\n"
        f"{DETECTOR_MODEL}"
    )


if not os.path.isfile(RECOGNIZER_MODEL):

    raise FileNotFoundError(
        "SFace model not found:\n"
        f"{RECOGNIZER_MODEL}"
    )


# ============================================================
# FACE RECOGNITION ENGINE
# ============================================================

class FaceRecognitionEngine:

    def __init__(self):

        print("[ENGINE] Loading YuNet...")

        self.detector = cv2.FaceDetectorYN.create(
            DETECTOR_MODEL,
            "",
            (320, 320),
            0.9,
            0.3,
            5000
        )

        print("[ENGINE] Loading SFace...")

        self.recognizer = cv2.FaceRecognizerSF.create(
            RECOGNIZER_MODEL,
            ""
        )

        print(
            "[ENGINE] Face recognition engine READY"
        )

    # ========================================================
    # DETECT FACE
    # ========================================================

    def detect_face(self, frame):

        if frame is None:
            return None

        if frame.size == 0:
            return None

        height, width = frame.shape[:2]

        self.detector.setInputSize(
            (width, height)
        )

        try:

            _, faces = self.detector.detect(
                frame
            )

        except Exception as error:

            print(
                f"[ENGINE ERROR] Face detection failed: {error}"
            )

            return None

        if faces is None:
            return None

        if len(faces) == 0:
            return None

        return faces[0]

    # ========================================================
    # CREATE FACE FEATURE
    # ========================================================

    def _create_feature(self, image):

        if image is None:
            raise RuntimeError(
                "Invalid face image."
            )

        face = self.detect_face(image)

        if face is None:

            raise RuntimeError(
                "No face detected in image."
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
                "Unable to create face feature:\n"
                f"{error}"
            ) from error

        return feature

    # ========================================================
    # VERIFY
    # ========================================================

    def verify(
        self,
        frame,
        face=None,
        authorized_feature=None
    ):

        try:

            if authorized_feature is None:

                return False, 0.0

            if face is None:

                face = self.detect_face(
                    frame
                )

            if face is None:

                return False, 0.0

            aligned = self.recognizer.alignCrop(
                frame,
                face
            )

            feature = self.recognizer.feature(
                aligned
            )

            similarity = self.recognizer.match(
                authorized_feature,
                feature,
                cv2.FaceRecognizerSF_FR_COSINE
            )

            similarity = float(
                similarity
            )

            authorized = (
                similarity >= THRESHOLD
            )

            return (
                authorized,
                similarity
            )

        except Exception as error:

            print(
                f"[ENGINE ERROR] Face verification failed: {error}"
            )

            return False, 0.0