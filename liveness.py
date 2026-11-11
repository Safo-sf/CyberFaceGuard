import cv2
import time


class LivenessDetector:

    def __init__(self):
        self.start_time = time.time()
        self.last_x = None
        self.movement_detected = False

    def check(self, face):

        x, y, w, h = face[:4].astype(int)

        center_x = x + w // 2

        # First frame
        if self.last_x is None:
            self.last_x = center_x
            return False

        # Detect horizontal movement
        movement = abs(center_x - self.last_x)

        if movement > 8:
            self.movement_detected = True

        self.last_x = center_x

        return self.movement_detected

    def reset(self):

        self.start_time = time.time()
        self.last_x = None
        self.movement_detected = False