import numpy as np

class ThreatScorer:
    def __init__(self):
        # We keep a small history for each person to calculate speed/consistency
        # Format: {track_id: {'positions': [], 'pose_history': []}}
        self.targets = {}

    def update(self, track_id, bbox, landmarks):
        """
        Analyze the person's behavior and return a Threat Score (0-100).
        """
        if track_id not in self.targets:
            self.targets[track_id] = {'positions': [], 'state': 'neutral'}

        # 1. Update Position History (for speed calculation)
        center_x = bbox[0] + (bbox[2] / 2)
        center_y = bbox[1] + (bbox[3] / 2)
        self.targets[track_id]['positions'].append((center_x, center_y))
        
        # Keep only last 30 frames (1 second) of history
        if len(self.targets[track_id]['positions']) > 30:
            self.targets[track_id]['positions'].pop(0)

        # --- THREAT CHECK 1: SURRENDER (Hands Raised) ---
        is_surrendering = False
        if landmarks:
            # MediaPipe Indices: 11/12 (Shoulders), 15/16 (Wrists)
            # Y-coordinate increases downwards (0 is top of screen)
            l_shoulder_y = landmarks[11]['y']
            r_shoulder_y = landmarks[12]['y']
            l_wrist_y = landmarks[15]['y']
            r_wrist_y = landmarks[16]['y']

            # Check if Wrists are HIGHER (smaller y) than Shoulders
            # We add a 20px buffer so it doesn't flicker
            if l_wrist_y < (l_shoulder_y - 20) and r_wrist_y < (r_shoulder_y - 20):
                is_surrendering = True

        # --- THREAT CHECK 2: AGGRESSIVE APPROACH (Lunge) ---
        is_lunging = False
        # We calculate how fast the bounding box is getting BIGGER (closer)
        if len(self.targets[track_id]['positions']) > 5:
            # Simple check: Is the person much closer now than 0.5s ago?
            # (In a real deployment, we'd use Depth, but Box Area is a good proxy)
            pass 

        # --- SCORING ---
        score = 0
        reason = "Scanning..."

        if is_surrendering:
            score = 90
            reason = "** HANDS RAISED (SURRENDER) **"
        elif is_lunging:
            score = 70
            reason = "AGGRESSIVE APPROACH"
        
        return score, reason