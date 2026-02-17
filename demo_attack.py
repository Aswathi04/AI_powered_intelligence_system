import cv2
import time
import math
import numpy as np
from ultralytics import YOLO

# --- CONFIGURATION (TUNING AREA) ---
# 1. CAMERA SETTINGS
FRAME_WIDTH = 320    # Lower resolution = Higher Speed & Accuracy
FRAME_HEIGHT = 240
SKIP_FRAMES = 2      # Check AI every 2 frames (smooths detection)

# 2. FEATURE 1: LUNGE (Rapid Approach)
# How much the box must grow to count as a lunge (1.15 = 15% growth)
LUNGE_SENSITIVITY = 1.10  
# Minimum size of person to check (ignore background people)
MIN_PERSON_SIZE = 2000    

# 3. FEATURE 2: PROXIMITY (Aggression)
# Pixel distance to count as "Too Close" (Adjust based on your room)
DANGER_DISTANCE_PX = 100  

# --- INITIALIZE ---
print("Initializing Focused Attack Detector (Lunge + Proximity)...")
model = YOLO('yolo11n.pt') 

# State Memory
box_history = {}       # Stores previous sizes for Lunge
history_length = 10    # How many frames to remember

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

frame_count = 0
start_time = time.time()

while cap.isOpened():
    ret, frame = cap.read()
    if not ret: break
    frame_count += 1
    
    # Run AI every N frames
    if frame_count % SKIP_FRAMES == 0:
        
        # 1. DETECT & TRACK (Using YOLO's fast tracker)
        results = model.track(frame, persist=True, verbose=False, classes=[0])
        
        # Data for this frame
        current_frame_data = [] 
        
        if results[0].boxes.id is not None:
            boxes = results[0].boxes.xyxy.cpu().numpy()
            track_ids = results[0].boxes.id.int().cpu().numpy()

            for box, track_id in zip(boxes, track_ids):
                x1, y1, x2, y2 = map(int, box)
                w, h = x2 - x1, y2 - y1
                area = w * h
                center = (int(x1 + w/2), int(y1 + h/2))
                
                # Store data for Proximity check
                current_frame_data.append({
                    "id": track_id, "center": center, "box": (x1, y1, x2, y2), "area": area
                })

                # --- FEATURE 1: LUNGE DETECTION ---
                if track_id not in box_history: box_history[track_id] = []
                box_history[track_id].append(area)
                if len(box_history[track_id]) > history_length: box_history[track_id].pop(0)
                
                is_lunging = False
                growth_rate = 0.0
                
                # Only check lunge if history is full AND person is big enough
                if len(box_history[track_id]) >= 5 and area > MIN_PERSON_SIZE:
                    prev_area = box_history[track_id][0] # Size 0.5s ago
                    growth_rate = area / prev_area
                    
                    if growth_rate > LUNGE_SENSITIVITY:
                        is_lunging = True

                # --- VISUALIZE FEATURE 1 ---
                color = (0, 255, 0) # Green
                status = "Safe"
                
                if is_lunging:
                    color = (0, 0, 255) # Red
                    status = "!! LUNGE !!"
                    # Draw Impact Box
                    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 4)
                else:
                    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)

                # DEBUG INFO (Shows you exactly why it triggers)
                debug_text = f"ID:{track_id} | Gr:{growth_rate:.2f}" 
                cv2.putText(frame, debug_text, (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)
                cv2.putText(frame, status, (x1, y1-25), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

            # --- FEATURE 2: PROXIMITY (Pairwise Check) ---
            # Check every person against every other person
            for i in range(len(current_frame_data)):
                for j in range(i + 1, len(current_frame_data)):
                    p1 = current_frame_data[i]
                    p2 = current_frame_data[j]
                    
                    # Calculate Distance
                    dist = math.sqrt((p1["center"][0] - p2["center"][0])**2 + 
                                     (p1["center"][1] - p2["center"][1])**2)
                    
                    # DRAW CONNECTION LINE
                    line_color = (0, 255, 255) # Yellow (Caution)
                    if dist < DANGER_DISTANCE_PX:
                        line_color = (0, 0, 255) # Red (Danger)
                        
                        # Draw Line between them
                        cv2.line(frame, p1["center"], p2["center"], line_color, 4)
                        
                        # Alert Text
                        midpoint = ((p1["center"][0] + p2["center"][0])//2, 
                                    (p1["center"][1] + p2["center"][1])//2)
                        cv2.putText(frame, f"PROXIMITY ALERT ({int(dist)})", midpoint, 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.6, line_color, 2)
                    else:
                        # Draw safe line
                        cv2.line(frame, p1["center"], p2["center"], (0, 255, 0), 1)

    # Calculate FPS safely
    elapsed = time.time() - start_time
    fps = frame_count / elapsed if elapsed > 0 else 0
    cv2.putText(frame, f"FPS: {int(fps)}", (10, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200, 200, 200), 2)

    cv2.imshow("Focused Review Mode", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
cv2.destroyAllWindows()