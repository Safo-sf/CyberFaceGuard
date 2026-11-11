import cv2
import os
import time

MODEL_PATH = "models/face_detection_yunet_2023mar.onnx"
SAVE_DIR = "data/faces"

os.makedirs(SAVE_DIR, exist_ok=True)

detector = cv2.FaceDetectorYN.create(
    MODEL_PATH,
    "",
    (320, 320),
    0.8,
    0.3,
    5000
)

camera = cv2.VideoCapture(0)

if not camera.isOpened():
    print("[ERROR] Camera not found.")
    exit()

print("=" * 50)
print("       CyberFaceGuard - Face Enrollment")
print("=" * 50)
print()
print("[INFO] Look at the camera.")
print("[INFO] Press S to capture your face.")
print("[INFO] Press Q to cancel.")
print()

while True:
    ret, frame = camera.read()

    if not ret:
        print("[ERROR] Camera frame unavailable.")
        break

    height, width = frame.shape[:2]

    detector.setInputSize((width, height))

    _, faces = detector.detect(frame)

    face_count = 0

    if faces is not None:
        face_count = len(faces)

        for face in faces:
            x, y, w, h = face[:4].astype(int)

            cv2.rectangle(
                frame,
                (x, y),
                (x + w, y + h),
                (0, 255, 0),
                2
            )

            cv2.putText(
                frame,
                "FACE DETECTED",
                (x, max(y - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 0),
                2
            )

    cv2.putText(
        frame,
        f"Faces: {face_count}",
        (20, 40),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.8,
        (255, 255, 255),
        2
    )

    cv2.putText(
        frame,
        "Press S to enroll | Q to quit",
        (20, height - 20),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.7,
        (255, 255, 255),
        2
    )

    cv2.imshow(
        "CyberFaceGuard - Enrollment",
        frame
    )

    key = cv2.waitKey(1) & 0xFF

    if key == ord("s"):

        if face_count == 0:
            print("[!] No face detected.")
            continue

        if face_count > 1:
            print("[!] Please make sure only ONE face is visible.")
            continue

        face = faces[0]

        x, y, w, h = face[:4].astype(int)

        # Add a small margin around the detected face
        margin = 30

        x1 = max(0, x - margin)
        y1 = max(0, y - margin)
        x2 = min(width, x + w + margin)
        y2 = min(height, y + h + margin)

        face_image = frame[y1:y2, x1:x2]

        if face_image.size == 0:
            print("[ERROR] Could not crop face.")
            continue

        filename = os.path.join(
            SAVE_DIR,
            "authorized_face.jpg"
        )

        cv2.imwrite(filename, face_image)

        print()
        print("[+] Face captured successfully!")
        print(f"[+] Saved to: {filename}")
        print()

        time.sleep(1)
        break

    elif key == ord("q"):
        print("[+] Enrollment cancelled.")
        break

camera.release()
cv2.destroyAllWindows()