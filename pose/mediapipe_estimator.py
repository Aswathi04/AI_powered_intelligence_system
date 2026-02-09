import mediapipe as mp
import cv2
import numpy as np

class PoseEstimator:
    def __init__(self):
        self.mp_pose = mp.solutions.pose
        self.pose = self.mp_pose.Pose(
            static_image_mode=False,
            model_complexity=0,       # 0=Fast, 1=Balanced, 2=Accurate (Use 1 for Laptop, 0 for Pi)
            smooth_landmarks=True,
            min_detection_confidence=0.5,
            min_tracking_confidence=0.5
        )

    def estimate_pose(self, frame, bbox):
        """
        Crop the person out of the frame and find their skeleton.
        """
        h, w, _ = frame.shape
        x1, y1, x2, y2 = map(int, bbox)
        
        # Padding: Give the AI a bit of context around the person
        pad = 10
        x1 = max(0, x1 - pad)
        y1 = max(0, y1 - pad)
        x2 = min(w, x2 + pad)
        y2 = min(h, y2 + pad)

        # Crop the person
        person_crop = frame[y1:y2, x1:x2]
        if person_crop.size == 0:
            return None

        # MediaPipe expects RGB
        rgb_crop = cv2.cvtColor(person_crop, cv2.COLOR_BGR2RGB)
        results = self.pose.process(rgb_crop)

        if results.pose_landmarks:
            # The landmarks are relative to the CROP (0.0 to 1.0)
            # We need to convert them back to the ORIGINAL frame coordinates
            landmarks = []
            for lm in results.pose_landmarks.landmark:
                # Convert relative crop coord to absolute pixel coord
                abs_x = int(lm.x * (x2 - x1) + x1)
                abs_y = int(lm.y * (y2 - y1) + y1)
                landmarks.append({'x': abs_x, 'y': abs_y, 'z': lm.z, 'vis': lm.visibility})
            return landmarks
            
        return None