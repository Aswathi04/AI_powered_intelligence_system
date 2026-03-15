import numpy as np
from collections import deque
from pose.mediapipe_estimator import PoseEstimator

class ThreatScorer:
    def __init__(self):
        # We keep a small history for each person to calculate speed/consistency
        # Format: {track_id: {'positions': deque, 'posture_history': deque, 'hip_positions': deque}}
        self.targets = {}
        self.pose_estimator = PoseEstimator()

    def update(self, track_id, bbox, landmarks):
        """
        Analyze the person's behavior and return a Threat Score (0-100).
        """
        if track_id not in self.targets:
            self.targets[track_id] = {
                'positions': deque(maxlen=30),
                'posture_history': deque(maxlen=30),
                'hip_positions': deque(maxlen=30),
                'state': 'neutral'
            }

        # 1. Update Position History (for speed calculation)
        center_x = bbox[0] + (bbox[2] / 2)
        center_y = bbox[1] + (bbox[3] / 2)
        self.targets[track_id]['positions'].append((center_x, center_y))

        # 2. Detect Postures
        postures = self.pose_estimator.detect_postures(landmarks) if landmarks else []
        self.targets[track_id]['posture_history'].append(postures)

        # 3. Update Hip Positions for velocity
        if landmarks:
            avg_hip_x = (landmarks[23]['x'] + landmarks[24]['x']) / 2
            avg_hip_y = (landmarks[23]['y'] + landmarks[24]['y']) / 2
            self.targets[track_id]['hip_positions'].append((avg_hip_x, avg_hip_y))

        # 4. Calculate sustained postures
        sustained_postures = []
        history = self.targets[track_id]['posture_history']
        for posture in ['CROUCHING', 'ARM_EXTENDED_FORWARD', 'REACHING_WAIST', 'LEANING_FORWARD', 'SURRENDER', 'RUNNING']:
            count = sum(1 for p_list in history if posture in p_list)
            if count > 20:
                sustained_postures.append(posture)

        # 5. Calculate hip velocity for running
        hip_velocity = 0
        hip_pos = self.targets[track_id]['hip_positions']
        if len(hip_pos) >= 2:
            dx = hip_pos[-1][0] - hip_pos[-2][0]
            dy = hip_pos[-1][1] - hip_pos[-2][1]
            hip_velocity = np.sqrt(dx**2 + dy**2)

        # For running, only count as sustained if high velocity
        if 'RUNNING' in sustained_postures and hip_velocity < 0.005:  # threshold
            sustained_postures.remove('RUNNING')

        # --- SCORING ---
        score = 0
        for p in sustained_postures:
            if p == 'CROUCHING':
                score += 25
            elif p == 'ARM_EXTENDED_FORWARD':
                score += 30
            elif p == 'REACHING_WAIST':
                score += 20
            elif p == 'LEANING_FORWARD':
                score += 15
            elif p == 'SURRENDER':
                score += 40
            elif p == 'RUNNING':
                score += 20

        reason = ', '.join(sustained_postures) if sustained_postures else "Scanning..."

        return score, reason