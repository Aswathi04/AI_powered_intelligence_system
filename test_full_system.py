import cv2
import time
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator
from logic.threat_scorer import ThreatScorer

# 1. Initialize The 4 Brains
print("Loading System...")
detector = YOLO('yolo11n.pt')
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()
brain = ThreatScorer()

cap = cv2.VideoCapture(0)

while cap.isOpened():
    ret, frame = cap.read()
    if not ret: break

    # 1. DETECT
    results = detector(frame, classes=[0], verbose=False)
    detections = []
    for box in results[0].boxes.data.tolist():
        x1, y1, x2, y2, conf, cls = box
        detections.append([[x1, y1, x2-x1, y2-y1], conf, int(cls)])

    # 2. TRACK
    tracks = tracker.update(detections, frame)

    for track in tracks:
        track_id = track['id']
        bbox = track['bbox']
        
        # 3. POSE
        landmarks = pose_estimator.estimate_pose(frame, bbox)

        # 4. LOGIC (The New Part)
        threat_level, status = brain.update(track_id, bbox, landmarks)

        # --- DRAWING ---
        x1, y1, x2, y2 = map(int, bbox)
        
        # Color changes based on Threat Level
        # Green = Safe, Red = Danger
        color = (0, 255, 0) 
        if threat_level > 50:
            color = (0, 0, 255) # RED
            # Draw a big warning text
            cv2.putText(frame, f"ALERT: {status}", (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0,0,255), 3)

        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, f"ID: {track_id} | Risk: {threat_level}%", (x1, y1-10), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

    cv2.imshow("Sentinal AI - Alpha", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
cv2.destroyAllWindows()