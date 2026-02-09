import cv2
import time
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# --- CONFIGURATION ---
RED = (0, 0, 255)
GREEN = (0, 255, 0)
YELLOW = (0, 255, 255)

# Performance Settings
FRAME_WIDTH = 640    # SD Resolution (Faster than HD)
FRAME_HEIGHT = 480
SKIP_FRAMES = 3      # Process AI every 3rd frame (Higher = Faster but less reactive)

# --- INITIALIZATION ---
print("Loading Sentinel AI System (Optimized)...")
detector = YOLO('yolo11n.pt') 
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()

# State Memory
threat_history = {}      # Stores how long a person has been a threat
current_draw_list = []   # Stores what to draw between AI updates
frame_count = 0

# Start Camera
cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

while cap.isOpened():
    start_time = time.time()
    ret, frame = cap.read()
    if not ret: break

    frame_count += 1

    # --- OPTIMIZATION: FRAME SKIPPING ---
    # Only run the heavy AI logic if it's the right frame
    if frame_count % SKIP_FRAMES == 0:
        
        # 1. DETECT (YOLO)
        results = detector(frame, classes=[0], verbose=False)
        detections = []
        for box in results[0].boxes.data.tolist():
            x1, y1, x2, y2, conf, cls = box
            detections.append([[x1, y1, x2-x1, y2-y1], conf, int(cls)])

        # 2. TRACK (DeepSORT)
        tracks = tracker.update(detections, frame)

        # 3. POSE & LOGIC (MediaPipe)
        # Reset the draw list for this new update
        new_draw_list = []

        for track in tracks:
            track_id = track['id']
            bbox = track['bbox']
            
            # Run Pose Estimation
            landmarks = pose_estimator.estimate_pose(frame, bbox)

            # Threat Logic: Check for Surrender
            is_threat = False
            if landmarks:
                # MediaPipe: 11/12=Shoulders, 15/16=Wrists
                l_wrist_y = landmarks[15]['y']
                r_wrist_y = landmarks[16]['y']
                l_shoulder_y = landmarks[11]['y']
                r_shoulder_y = landmarks[12]['y']

                # Logic: Are Wrists ABOVE Shoulders? (Remember Y gets smaller going up)
                # We add a 20px buffer to prevent false alarms
                if l_wrist_y < (l_shoulder_y - 20) and r_wrist_y < (r_shoulder_y - 20):
                    is_threat = True

            # Threat Persistence (Anti-Flicker)
            if track_id not in threat_history:
                threat_history[track_id] = 0

            if is_threat:
                threat_history[track_id] += 1
            else:
                # Slowly decay the threat level if they put hands down
                threat_history[track_id] = max(0, threat_history[track_id] - 1)

            # Determine Display Status
            display_color = GREEN
            status_text = "SAFE"
            
            # TRIGGER ALERT: If threat persists for ~10 checks (approx 1 sec)
            if threat_history[track_id] > 5:
                display_color = RED
                status_text = "** HANDS RAISED **"
                # Cap the counter so it doesn't grow forever
                threat_history[track_id] = 10 

            # Add to draw list
            new_draw_list.append((bbox, display_color, status_text, track_id))
        
        # Update the global draw list
        current_draw_list = new_draw_list

    # --- DRAWING (Happens EVERY frame) ---
    # We use 'current_draw_list' which holds the last known data
    for (bbox, color, text, track_id) in current_draw_list:
        x1, y1, x2, y2 = map(int, bbox)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        
        # Draw ID and Status
        label = f"ID:{track_id} | {text}"
        cv2.putText(frame, label, (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

    # Show FPS (To verify speedup)
    fps = 1.0 / (time.time() - start_time)
    cv2.putText(frame, f"FPS: {int(fps)}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, YELLOW, 2)

    cv2.imshow("Sentinel AI - Optimized", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
cv2.destroyAllWindows()