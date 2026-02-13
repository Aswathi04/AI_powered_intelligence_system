import cv2
import time
import numpy as np
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# --- 1. CONFIGURATION ---
RED = (0, 0, 255)      # Danger Color
GREEN = (0, 255, 0)    # Safe Color
YELLOW = (0, 255, 255) # Info Color

# Performance Settings
FRAME_WIDTH = 640    # SD Resolution (Faster than HD)
FRAME_HEIGHT = 480
SKIP_FRAMES = 3      # Process AI every 3rd frame (Higher = Faster)

# Logic Thresholds
LUNGE_THRESHOLD = 1.15  # 15% size increase = Aggression
HANDS_THRESHOLD = 20    # 20px buffer for hands raised

print("Loading Sentinel AI System (Phase 4 Complete)...")
detector = YOLO('yolo11n.pt') 
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()

# --- 2. MEMORY INITIALIZATION ---
threat_history = {}    # Stores how long a threat has persisted (Anti-Flicker)
box_history = {}       # Stores previous box sizes (for Lunge Detection)
current_draw_list = [] # Stores what to draw between AI updates
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

    # --- 3. AI PROCESSING (Every 3rd Frame) ---
    if frame_count % SKIP_FRAMES == 0:
        
        # A. DETECT (YOLOv11)
        results = detector(frame, classes=[0], verbose=False)
        detections = []
        for box in results[0].boxes.data.tolist():
            x1, y1, x2, y2, conf, cls = box
            detections.append([[x1, y1, x2-x1, y2-y1], conf, int(cls)])

        # B. TRACK (DeepSORT)
        tracks = tracker.update(detections, frame)
        
        # Reset the drawing list for this new frame
        new_draw_list = []

        for track in tracks:
            track_id = track['id']
            bbox = track['bbox']
            w, h = bbox[2], bbox[3]
            current_area = w * h

            # --- LOGIC C1: LUNGE DETECTION ---
            is_lunging = False
            if track_id not in box_history:
                box_history[track_id] = []
            
            # Save history (Keep last 10 sizes)
            box_history[track_id].append(current_area)
            if len(box_history[track_id]) > 10: 
                box_history[track_id].pop(0)

            # Compare current size to size ~0.5s ago (index 0)
            if len(box_history[track_id]) >= 5:
                prev_area = box_history[track_id][0]
                # If size increased by 15% quickly -> THREAT
                if (current_area / prev_area) > LUNGE_THRESHOLD:
                    is_lunging = True

            # --- LOGIC C2: SURRENDER DETECTION ---
            landmarks = pose_estimator.estimate_pose(frame, bbox)
            is_surrendering = False
            
            if landmarks:
                # Get key points (Y increases downwards)
                l_wrist_y = landmarks[15]['y']
                r_wrist_y = landmarks[16]['y']
                l_shoulder_y = landmarks[11]['y']
                r_shoulder_y = landmarks[12]['y']

                # Check if Wrists are ABOVE Shoulders
                if l_wrist_y < (l_shoulder_y - HANDS_THRESHOLD) and \
                   r_wrist_y < (r_shoulder_y - HANDS_THRESHOLD):
                    is_surrendering = True

            # --- LOGIC C3: THREAT SMOOTHING (Debounce) ---
            # Combine the two threats
            raw_threat_detected = is_surrendering or is_lunging
            
            if track_id not in threat_history:
                threat_history[track_id] = 0

            if raw_threat_detected:
                threat_history[track_id] += 1
            else:
                # Decay the threat counter slowly if they stop
                threat_history[track_id] = max(0, threat_history[track_id] - 1)

            # --- D. DETERMINE DISPLAY STATUS ---
            display_color = GREEN
            status_text = "SAFE"
            
            # Only trigger RED ALERT if threat persists for >5 checks
            if threat_history[track_id] > 5:
                display_color = RED
                
                # Priority: Surrender overrides Lunge text
                if is_surrendering:
                    status_text = "** HANDS UP **"
                elif is_lunging:
                    status_text = "!! LUNGING !!"
                
                # Cap the counter to prevent overflow
                threat_history[track_id] = 10 

            # Add to the draw list
            new_draw_list.append((bbox, display_color, status_text, track_id))
        
        # Update the global draw list
        current_draw_list = new_draw_list

    # --- 4. VISUALIZATION (Runs Every Frame) ---
    # Draw the data from the last AI update
    for (bbox, color, text, track_id) in current_draw_list:
        x1, y1, x2, y2 = map(int, bbox)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, f"ID:{track_id} | {text}", (x1, y1-10), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

    # Show FPS
    fps = 1.0 / (time.time() - start_time)
    cv2.putText(frame, f"FPS: {int(fps)}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, YELLOW, 2)

    cv2.imshow("Sentinel AI - Phase 4 Logic", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
cv2.destroyAllWindows()