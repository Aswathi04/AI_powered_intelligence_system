# import mediapipe as mp
# import cv2
# import numpy as np

# class PoseEstimator:
#     def __init__(self):
#         self.mp_pose = mp.solutions.pose
#         self.pose = self.mp_pose.Pose(
#             static_image_mode=False,
#             model_complexity=0,       # 0=Fast, 1=Balanced, 2=Accurate (Use 1 for Laptop, 0 for Pi)
#             smooth_landmarks=True,
#             min_detection_confidence=0.5,
#             min_tracking_confidence=0.5
#         )

#     def estimate_pose(self, frame, bbox):
#         """
#         Crop the person out of the frame and find their skeleton.
#         """
#         h, w, _ = frame.shape
#         x1, y1, x2, y2 = map(int, bbox)
        
#         # Padding: Give the AI a bit of context around the person
#         pad = 10
#         x1 = max(0, x1 - pad)
#         y1 = max(0, y1 - pad)
#         x2 = min(w, x2 + pad)
#         y2 = min(h, y2 + pad)

#         # Crop the person
#         person_crop = frame[y1:y2, x1:x2]
#         if person_crop.size == 0:
#             return None

#         # MediaPipe expects RGB
#         rgb_crop = cv2.cvtColor(person_crop, cv2.COLOR_BGR2RGB)
#         results = self.pose.process(rgb_crop)

#         if results.pose_landmarks:
#             # Return landmarks in normalized coordinates (0.0 to 1.0 relative to crop)
#             landmarks = []
#             for lm in results.pose_landmarks.landmark:
#                 landmarks.append({'x': lm.x, 'y': lm.y, 'z': lm.z, 'vis': lm.visibility})
#             return landmarks
            
#         return None

#     def detect_postures(self, landmarks):
#         """
#         Detect specific postures from normalized landmarks.
#         Returns a list of detected postures.
#         """
#         if not landmarks:
#             return []
        
#         postures = []
        
#         # MediaPipe indices:
#         # Nose: 0
#         # Left Shoulder: 11, Right Shoulder: 12
#         # Left Elbow: 13, Right Elbow: 14
#         # Left Wrist: 15, Right Wrist: 16
#         # Left Hip: 23, Right Hip: 24
#         # Left Knee: 25, Right Knee: 26
        
#         # CROUCHING: hip y-position close to knee y-position (difference < 0.1 in normalized coords)
#         left_hip_y = landmarks[23]['y']
#         right_hip_y = landmarks[24]['y']
#         left_knee_y = landmarks[25]['y']
#         right_knee_y = landmarks[26]['y']
#         avg_hip_y = (left_hip_y + right_hip_y) / 2
#         avg_knee_y = (left_knee_y + right_knee_y) / 2
#         if abs(avg_hip_y - avg_knee_y) < 0.1:
#             postures.append('CROUCHING')
        
#         # ARM_EXTENDED_FORWARD: wrist z-coordinate less than elbow z-coordinate (punching motion)
#         # Check both arms
#         for wrist_idx, elbow_idx in [(15, 13), (16, 14)]:
#             if landmarks[wrist_idx]['z'] < landmarks[elbow_idx]['z']:
#                 postures.append('ARM_EXTENDED_FORWARD')
#                 break
        
#         # REACHING_WAIST: wrist y-position close to hip y-position (reaching into pocket/waist)
#         avg_hip_y = (left_hip_y + right_hip_y) / 2
#         for wrist_idx in [15, 16]:
#             if abs(landmarks[wrist_idx]['y'] - avg_hip_y) < 0.1:
#                 postures.append('REACHING_WAIST')
#                 break
        
#         # LEANING_FORWARD: nose x-position significantly ahead of hip x-position (aggressive lean)
#         nose_x = landmarks[0]['x']
#         avg_hip_x = (landmarks[23]['x'] + landmarks[24]['x']) / 2
#         if nose_x > avg_hip_x + 0.1:  # nose ahead by 0.1 normalized
#             postures.append('LEANING_FORWARD')
        
#         # SURRENDER: wrists above shoulders (existing)
#         l_shoulder_y = landmarks[11]['y']
#         r_shoulder_y = landmarks[12]['y']
#         l_wrist_y = landmarks[15]['y']
#         r_wrist_y = landmarks[16]['y']
#         if l_wrist_y < l_shoulder_y and r_wrist_y < r_shoulder_y:
#             postures.append('SURRENDER')
        
#         # RUNNING: both knees bent simultaneously with high hip velocity
#         # Note: Velocity check needs history, so handled in threat scorer
        
#         return postures



"""
pose/mediapipe_estimator.py

Full 33-keypoint MediaPipe Pose estimator with angle-based posture detection.

MediaPipe landmark index reference:
  Face:    0=nose  1=l_eye_inner  2=l_eye  3=l_eye_outer
           4=r_eye_inner  5=r_eye  6=r_eye_outer
           7=l_ear  8=r_ear  9=mouth_l  10=mouth_r
  Torso:   11=l_shoulder  12=r_shoulder  13=l_elbow  14=r_elbow
           15=l_wrist  16=r_wrist  17=l_pinky  18=r_pinky
           19=l_index  20=r_index  21=l_thumb  22=r_thumb
  Hips:    23=l_hip  24=r_hip
  Legs:    25=l_knee  26=r_knee  27=l_ankle  28=r_ankle
           29=l_heel  30=r_heel  31=l_foot  32=r_foot

All (x, y) values stored as absolute pixel coordinates after projection
onto the cropped person bounding box.  Visibility (vis) is the raw
MediaPipe confidence float [0, 1].
"""

import cv2
import math
import numpy as np
import mediapipe as mp


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------

def _angle_3pts(a, b, c):
    """
    Return the interior angle at point B formed by the ray B→A and B→C.
    Points are (x, y) tuples.  Returns degrees in [0, 180].
    """
    ax, ay = a[0] - b[0], a[1] - b[1]
    cx, cy = c[0] - b[0], c[1] - b[1]
    dot = ax * cx + ay * cy
    mag = math.sqrt(ax**2 + ay**2) * math.sqrt(cx**2 + cy**2)
    if mag < 1e-6:
        return 0.0
    return math.degrees(math.acos(max(-1.0, min(1.0, dot / mag))))


def _dist(a, b):
    """Euclidean distance between two (x, y) points."""
    return math.sqrt((a[0] - b[0])**2 + (a[1] - b[1])**2)


def _midpoint(a, b):
    return ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)


def _visible(lm_dict, *indices, threshold=0.45):
    """Return True only if all requested landmark indices meet the visibility threshold."""
    return all(lm_dict[i]['vis'] >= threshold for i in indices)


# ---------------------------------------------------------------------------
# PoseEstimator
# ---------------------------------------------------------------------------

class PoseEstimator:
    """
    Wraps MediaPipe Pose.  Designed to be instantiated once and reused
    across frames.  All public methods are stateless with respect to
    previous frames — state tracking lives in ThreatScorer.
    """

    # Landmark index constants — using names avoids magic numbers everywhere
    NOSE          = 0
    L_EYE         = 2
    R_EYE         = 5
    L_EAR         = 7
    R_EAR         = 8
    L_SHOULDER    = 11
    R_SHOULDER    = 12
    L_ELBOW       = 13
    R_ELBOW       = 14
    L_WRIST       = 15
    R_WRIST       = 16
    L_PINKY       = 17
    R_PINKY       = 18
    L_INDEX       = 19
    R_INDEX       = 20
    L_HIP         = 23
    R_HIP         = 24
    L_KNEE        = 25
    R_KNEE        = 26
    L_ANKLE       = 27
    R_ANKLE       = 28

    def __init__(self,
                 model_complexity: int = 1,
                 min_detection_confidence: float = 0.55,
                 min_tracking_confidence: float = 0.50):
        """
        Args:
            model_complexity: 0 = fastest/least accurate, 2 = slowest/most accurate.
                              1 is a good balance for real-time CCTV.
            min_detection_confidence: Threshold to initialise pose tracking.
            min_tracking_confidence:  Threshold to continue tracking across frames.
        """
        self._mp_pose = mp.solutions.pose
        self._pose = self._mp_pose.Pose(
            static_image_mode=False,
            model_complexity=model_complexity,
            smooth_landmarks=True,
            enable_segmentation=False,
            min_detection_confidence=min_detection_confidence,
            min_tracking_confidence=min_tracking_confidence,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def estimate_pose(self, frame: np.ndarray, bbox: tuple) -> dict | None:
        """
        Run MediaPipe Pose on the person crop defined by bbox and return
        a dict mapping landmark index → {'x', 'y', 'vis'} in frame-pixel
        coordinates.

        Args:
            frame: Full BGR frame from OpenCV.
            bbox:  (x1, y1, x2, y2) OR (x1, y1, w, h) bounding box.
                   The method handles both formats automatically.

        Returns:
            dict[int, dict] with all 33 landmarks, or None if pose not found.
        """
        x1, y1, x2_or_w, y2_or_h = bbox

        # Accept both (x1,y1,x2,y2) and (x1,y1,w,h) formats
        if x2_or_w < x1 or y2_or_h < y1:
            # Likely (x, y, w, h) format
            x2 = x1 + x2_or_w
            y2 = y1 + y2_or_h
        else:
            x2, y2 = x2_or_w, y2_or_h

        x1, y1, x2, y2 = map(int, (x1, y1, x2, y2))

        # Guard against out-of-frame boxes
        h_frame, w_frame = frame.shape[:2]
        x1 = max(0, x1)
        y1 = max(0, y1)
        x2 = min(w_frame, x2)
        y2 = min(h_frame, y2)

        crop_w = x2 - x1
        crop_h = y2 - y1
        if crop_w < 20 or crop_h < 20:
            return None

        # Add a small padding so MediaPipe can see the full body silhouette
        pad_x = int(crop_w * 0.08)
        pad_y = int(crop_h * 0.08)
        px1 = max(0, x1 - pad_x)
        py1 = max(0, y1 - pad_y)
        px2 = min(w_frame, x2 + pad_x)
        py2 = min(h_frame, y2 + pad_y)

        crop = frame[py1:py2, px1:px2]
        crop_rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)
        results = self._pose.process(crop_rgb)

        if not results.pose_landmarks:
            return None

        ch, cw = crop.shape[:2]
        landmarks = {}
        for idx, lm in enumerate(results.pose_landmarks.landmark):
            # Convert normalised crop coords → frame pixel coords
            px = int(lm.x * cw) + px1
            py = int(lm.y * ch) + py1
            landmarks[idx] = {
                'x':   px,
                'y':   py,
                'vis': lm.visibility,
            }

        return landmarks

    def detect_postures(self, landmarks: dict | None) -> list[str]:
        """
        Analyse all 33 landmarks and return a list of active posture
        strings.  Each detection uses multi-joint angle logic to reduce
        false positives.

        Posture strings (match ThreatScorer keys):
            'SURRENDER'           — both hands above head
            'CROUCHING'           — deep knee bend
            'ARM_EXTENDED_FORWARD'— one arm fully extended outward
            'REACHING_WAIST'      — hand near hip/waistband
            'LEANING_FORWARD'     — aggressive forward body lean
            'RUNNING'             — sprint arm/leg alternation

        Returns [] if landmarks is None or no postures are detected.
        """
        if not landmarks:
            return []

        postures = []
        lm = landmarks   # short alias

        if self._check_surrender(lm):
            postures.append('SURRENDER')
        if self._check_crouching(lm):
            postures.append('CROUCHING')
        if self._check_arm_extended(lm):
            postures.append('ARM_EXTENDED_FORWARD')
        if self._check_reaching_waist(lm):
            postures.append('REACHING_WAIST')
        if self._check_leaning_forward(lm):
            postures.append('LEANING_FORWARD')
        if self._check_running(lm):
            postures.append('RUNNING')

        return postures

    def draw_skeleton(self, frame: np.ndarray, landmarks: dict,
                      color: tuple = (0, 255, 0), thickness: int = 2) -> np.ndarray:
        """
        Draw the full 33-point skeleton overlay on frame (in-place).
        Returns the modified frame for convenience.
        """
        connections = self._mp_pose.POSE_CONNECTIONS
        for start_idx, end_idx in connections:
            if start_idx in landmarks and end_idx in landmarks:
                lm_s = landmarks[start_idx]
                lm_e = landmarks[end_idx]
                if lm_s['vis'] > 0.4 and lm_e['vis'] > 0.4:
                    cv2.line(frame,
                             (lm_s['x'], lm_s['y']),
                             (lm_e['x'], lm_e['y']),
                             color, thickness)
        for idx, lm_pt in landmarks.items():
            if lm_pt['vis'] > 0.4:
                cv2.circle(frame, (lm_pt['x'], lm_pt['y']), 3, color, -1)
        return frame

    # ------------------------------------------------------------------
    # Private posture checks
    # ------------------------------------------------------------------

    def _pt(self, lm, idx):
        """Return (x, y) tuple for a landmark index."""
        return (lm[idx]['x'], lm[idx]['y'])

    def _check_surrender(self, lm: dict) -> bool:
        """
        SURRENDER: Both wrists must be above the corresponding ear AND
        the elbow angle on each arm must be >= 70° (arms are raised,
        not just stretched forward).

        Using ears (7, 8) as the height reference is more robust than
        using shoulders because shoulders can themselves rise when arms
        are raised — that was the main false-positive source.
        """
        # Need wrists, elbows, shoulders, and ears visible
        if not _visible(lm, self.L_WRIST, self.R_WRIST,
                            self.L_ELBOW, self.R_ELBOW,
                            self.L_SHOULDER, self.R_SHOULDER,
                            self.L_EAR, self.R_EAR):
            return False

        l_wrist_above_ear = lm[self.L_WRIST]['y'] < lm[self.L_EAR]['y']
        r_wrist_above_ear = lm[self.R_WRIST]['y'] < lm[self.R_EAR]['y']

        if not (l_wrist_above_ear and r_wrist_above_ear):
            return False

        # Verify elbows are also raised (not just wrists reaching forward)
        l_elbow_angle = _angle_3pts(
            self._pt(lm, self.L_SHOULDER),
            self._pt(lm, self.L_ELBOW),
            self._pt(lm, self.L_WRIST))
        r_elbow_angle = _angle_3pts(
            self._pt(lm, self.R_SHOULDER),
            self._pt(lm, self.R_ELBOW),
            self._pt(lm, self.R_WRIST))

        return l_elbow_angle >= 70.0 and r_elbow_angle >= 70.0

    def _check_crouching(self, lm: dict) -> bool:
        """
        CROUCHING: Knee angle < 120° on at least one leg AND the hip is
        significantly lower than normal standing (hip y > knee y * 0.75).

        The knee-angle check alone fires for people sitting in chairs.
        Adding the hip-height condition filters those out because seated
        people have hips at ~the same height as their knees.
        """
        need_left  = _visible(lm, self.L_HIP, self.L_KNEE, self.L_ANKLE)
        need_right = _visible(lm, self.R_HIP, self.R_KNEE, self.R_ANKLE)

        if not (need_left or need_right):
            return False

        crouch_detected = False

        if need_left:
            l_knee_angle = _angle_3pts(
                self._pt(lm, self.L_HIP),
                self._pt(lm, self.L_KNEE),
                self._pt(lm, self.L_ANKLE))
            # Hip y should be clearly above knee y (y axis down on screen)
            hip_above_knee = lm[self.L_HIP]['y'] < lm[self.L_KNEE]['y']
            if l_knee_angle < 120.0 and hip_above_knee:
                # Extra check: hip y must be within 70% of knee y height
                # (filters seated person where hip ≈ knee height)
                hip_knee_gap = lm[self.L_KNEE]['y'] - lm[self.L_HIP]['y']
                ankle_knee_gap = lm[self.L_ANKLE]['y'] - lm[self.L_KNEE]['y']
                if ankle_knee_gap > 0 and (hip_knee_gap / ankle_knee_gap) < 0.75:
                    crouch_detected = True

        if need_right and not crouch_detected:
            r_knee_angle = _angle_3pts(
                self._pt(lm, self.R_HIP),
                self._pt(lm, self.R_KNEE),
                self._pt(lm, self.R_ANKLE))
            hip_above_knee = lm[self.R_HIP]['y'] < lm[self.R_KNEE]['y']
            if r_knee_angle < 120.0 and hip_above_knee:
                hip_knee_gap = lm[self.R_KNEE]['y'] - lm[self.R_HIP]['y']
                ankle_knee_gap = lm[self.R_ANKLE]['y'] - lm[self.R_KNEE]['y']
                if ankle_knee_gap > 0 and (hip_knee_gap / ankle_knee_gap) < 0.75:
                    crouch_detected = True

        return crouch_detected

    def _check_arm_extended(self, lm: dict) -> bool:
        """
        ARM_EXTENDED_FORWARD: At least one arm is nearly fully extended
        (elbow angle > 150°) AND the wrist is laterally beyond the
        shoulder width by more than 40% of shoulder width.

        This separates genuine pointing/reaching from normal arm swing
        and crossed-arm resting postures.
        """
        need_left  = _visible(lm, self.L_SHOULDER, self.L_ELBOW, self.L_WRIST)
        need_right = _visible(lm, self.R_SHOULDER, self.R_ELBOW, self.R_WRIST)

        if not (need_left or need_right):
            return False

        # Shoulder width as normalisation baseline
        if _visible(lm, self.L_SHOULDER, self.R_SHOULDER):
            shoulder_width = abs(lm[self.R_SHOULDER]['x'] - lm[self.L_SHOULDER]['x'])
        else:
            shoulder_width = 80  # fallback pixel estimate

        if shoulder_width < 10:
            return False

        if need_left:
            l_angle = _angle_3pts(
                self._pt(lm, self.L_SHOULDER),
                self._pt(lm, self.L_ELBOW),
                self._pt(lm, self.L_WRIST))
            l_reach = abs(lm[self.L_WRIST]['x'] - lm[self.L_SHOULDER]['x'])
            if l_angle > 150.0 and (l_reach / shoulder_width) > 0.40:
                return True

        if need_right:
            r_angle = _angle_3pts(
                self._pt(lm, self.R_SHOULDER),
                self._pt(lm, self.R_ELBOW),
                self._pt(lm, self.R_WRIST))
            r_reach = abs(lm[self.R_WRIST]['x'] - lm[self.R_SHOULDER]['x'])
            if r_angle > 150.0 and (r_reach / shoulder_width) > 0.40:
                return True

        return False

    def _check_reaching_waist(self, lm: dict) -> bool:
        """
        REACHING_WAIST: A wrist is within 40 px of the same-side hip AND
        the elbow is bent in the 60°–120° range (active reach, not
        hands-in-pocket rest or arms-at-side neutral).

        Threshold of 40 px scales reasonably with typical CCTV crop sizes.
        For a large person (tall bounding box) you may want to make this
        proportional — see the proportional_threshold comment below.
        """
        need_left  = _visible(lm, self.L_WRIST, self.L_ELBOW, self.L_SHOULDER, self.L_HIP)
        need_right = _visible(lm, self.R_WRIST, self.R_ELBOW, self.R_SHOULDER, self.R_HIP)

        if not (need_left or need_right):
            return False

        # Proportional threshold: 8% of shoulder-to-hip distance
        if _visible(lm, self.L_SHOULDER, self.L_HIP):
            shoulder_hip_dist = _dist(
                self._pt(lm, self.L_SHOULDER), self._pt(lm, self.L_HIP))
            prox_threshold = max(30, shoulder_hip_dist * 0.08)
        else:
            prox_threshold = 40

        if need_left:
            l_wrist_hip_dist = _dist(
                self._pt(lm, self.L_WRIST), self._pt(lm, self.L_HIP))
            l_elbow_angle = _angle_3pts(
                self._pt(lm, self.L_SHOULDER),
                self._pt(lm, self.L_ELBOW),
                self._pt(lm, self.L_WRIST))
            if l_wrist_hip_dist < prox_threshold and 60.0 < l_elbow_angle < 120.0:
                return True

        if need_right:
            r_wrist_hip_dist = _dist(
                self._pt(lm, self.R_WRIST), self._pt(lm, self.R_HIP))
            r_elbow_angle = _angle_3pts(
                self._pt(lm, self.R_SHOULDER),
                self._pt(lm, self.R_ELBOW),
                self._pt(lm, self.R_WRIST))
            if r_wrist_hip_dist < prox_threshold and 60.0 < r_elbow_angle < 120.0:
                return True

        return False

    def _check_leaning_forward(self, lm: dict) -> bool:
        """
        LEANING_FORWARD: The nose is ahead of the hip midpoint by more
        than 15% of the shoulder-to-hip distance, AND the shoulder line
        is tilted more than 15° from horizontal.

        Two-condition requirement means a person leaning slightly to
        look at their phone does NOT trigger this — both forward
        projection AND shoulder tilt must be present.
        """
        need = _visible(lm,
                        self.NOSE,
                        self.L_SHOULDER, self.R_SHOULDER,
                        self.L_HIP, self.R_HIP)
        if not need:
            return False

        hip_mid_x, hip_mid_y = _midpoint(
            self._pt(lm, self.L_HIP), self._pt(lm, self.R_HIP))
        shoulder_mid_x, shoulder_mid_y = _midpoint(
            self._pt(lm, self.L_SHOULDER), self._pt(lm, self.R_SHOULDER))

        # Forward lean: nose x beyond hip midpoint (camera is frontal,
        # so +x direction corresponds to "forward" projection in image space)
        shoulder_hip_dist = _dist(
            (shoulder_mid_x, shoulder_mid_y), (hip_mid_x, hip_mid_y))
        if shoulder_hip_dist < 10:
            return False

        nose_forward_offset = abs(lm[self.NOSE]['x'] - hip_mid_x)
        nose_lean_ratio = nose_forward_offset / shoulder_hip_dist

        # Shoulder tilt: angle of shoulder line from horizontal
        dx = lm[self.R_SHOULDER]['x'] - lm[self.L_SHOULDER]['x']
        dy = lm[self.R_SHOULDER]['y'] - lm[self.L_SHOULDER]['y']
        shoulder_tilt_deg = abs(math.degrees(math.atan2(dy, dx)))

        return nose_lean_ratio > 0.15 and shoulder_tilt_deg > 15.0

    def _check_running(self, lm: dict) -> bool:
        """
        RUNNING: Detect sprint posture by checking for asymmetric knee
        lift (one knee significantly above hip level) combined with
        opposite-arm swing (the arm on the raised-knee side is swung
        back — wrist below elbow — indicating the counter-swing).

        This fires much less than the old speed-based check alone and
        won't trigger for someone standing with one leg raised or doing
        yoga poses because it requires the arm counter-phase condition.
        """
        need_left_leg  = _visible(lm, self.L_HIP, self.L_KNEE)
        need_right_leg = _visible(lm, self.R_HIP, self.R_KNEE)
        need_left_arm  = _visible(lm, self.L_ELBOW, self.L_WRIST)
        need_right_arm = _visible(lm, self.R_ELBOW, self.R_WRIST)

        if not ((need_left_leg or need_right_leg) and
                (need_left_arm or need_right_arm)):
            return False

        # Check left knee raised above left hip
        l_knee_raised = (need_left_leg and
                         lm[self.L_KNEE]['y'] < lm[self.L_HIP]['y'])
        # Check right knee raised above right hip
        r_knee_raised = (need_right_leg and
                         lm[self.R_KNEE]['y'] < lm[self.R_HIP]['y'])

        if not (l_knee_raised or r_knee_raised):
            return False

        # Counter-phase arm swing: when left knee is raised, right arm
        # swings forward (right wrist above right elbow) and vice versa.
        if l_knee_raised and need_right_arm:
            r_wrist_forward = lm[self.R_WRIST]['y'] < lm[self.R_ELBOW]['y']
            if r_wrist_forward:
                return True

        if r_knee_raised and need_left_arm:
            l_wrist_forward = lm[self.L_WRIST]['y'] < lm[self.L_ELBOW]['y']
            if l_wrist_forward:
                return True

        return False