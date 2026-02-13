import cv2
import time
import os
import json
import winsound
import math
import numpy as np
from collections import deque
from datetime import datetime
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# --- CONFIGURATION ---
FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FPS_TARGET = 30
SKIP_FRAMES = 3

# Evidence Settings
BUFFER_SECONDS = 5
RECORD_SECONDS = 5
BUFFER_SIZE = BUFFER_SECONDS * FPS_TARGET

# Logic Thresholds
LUNGE_THRESHOLD = 1.15
HANDS_THRESHOLD = 20
FOLLOWING_DISTANCE_LIMIT = 200 # Pixels (Approx 1.5 meters)
FOLLOWING_ANGLE_THRESHOLD = 0.8 # Cosine similarity (1.0 = identical direction)

print("Initializing Sentinel AI - Phase 5 (With Stalking Detection)...")

# --- MODULES ---
detector = YOLO('yolo11n.pt') 
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()

# Memory
video_buffer = deque(maxlen=BUFFER_SIZE)
threat_history = {}    
box_history = {}       
track_history = {} # Stores (x,y) positions for path analysis
following_history = {} # Stores how long A has followed B

is_recording = False
recording_frame_count = 0
current_video_writer = None
current_evidence_path = ""

# Ensure Directory
base_dir = "evidence/alerts"
if not os.path.exists(base_dir): os.makedirs(base_dir)

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
cap.set(cv2.CAP_PROP_FPS, FPS_TARGET)

def start_evidence_recording(track_id, reason, score):
    global is_recording, current_video_writer, recording_frame_count, current_evidence_path
    
    today_str = datetime.now().strftime("%Y%m%d")
    save_dir = os.path.join(base_dir, today_str)
    if not os.path.exists(save_dir): os.makedirs(save_dir)

    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"ALERT_{timestamp}_{reason}.mp4"
    current_evidence_path = os.path.join(save_dir, filename)

    print(f"!!! RECORDING: {filename} !!!")
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    current_video_writer = cv2.VideoWriter(current_evidence_path, fourcc, 20.0, (FRAME_WIDTH, FRAME_HEIGHT))

    for past_frame in video_buffer:
        current_video_writer.write(past_frame)

    meta_filename = current_evidence_path.replace(".mp4", ".json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": reason,
        "track_id": int(track_id),
        "threat_score": score,
        "camera_id": "CAM_01"
    }
    with open(meta_filename, "w") as f:
        json.dump(data, f, indent=4)

    winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
    
    is_recording = True
    recording_frame_count = 0

def calculate_direction_similarity(path_a, path_b):
    """Returns 1.0 if moving same direction, -1.0 if opposite"""
    if len(path_a) < 10 or len(path_b) < 10: return 0
    
    # Vector from 10 frames ago to now
    vec_a = np.array([path_a[-1][0] - path_a[0][0], path_a[-1][1] - path_a[0][1]])
    vec_b = np.array([path_b[-1][0] - path_b[0][0], path_b[-1][1] - path_b[0][1]])
    
    # Normalize
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    
    if norm_a < 5 or norm_b < 5: return 0 # Not moving enough
    
    # Dot product / magnitude = Cosine Similarity
    return np.dot(vec_a, vec_b) / (norm_a * norm_b)

# --- MAIN LOOP ---
frame_counter = 0
current_draw_list = []

while cap.isOpened():
    ret, frame = cap.read()
    if not ret: break
    frame_counter += 1
    video_buffer.append(frame.copy())

    if frame_counter % SKIP_FRAMES == 0:
        results = detector(frame, classes=[0], verbose=False)
        detections = []
        for box in results[0].boxes.data.tolist():
            x1, y1, x2, y2, conf, cls = box
            detections.append([[x1, y1, x2-x1, y2-y1], conf, int(cls)])

        tracks = tracker.update(detections, frame)
        new_draw_list = []
        
        # Update Track History for Stalking Logic
        active_ids = []
        for track in tracks:
            tid = track['id']
            bbox = track['bbox']
            center_x = int(bbox[0] + bbox[2]/2)
            center_y = int(bbox[1] + bbox[3]/2)
            
            if tid not in track_history: track_history[tid] = deque(maxlen=30)
            track_history[tid].append((center_x, center_y))
            active_ids.append(tid)

        # --- LOGIC LOOP ---
        for track in tracks:
            track_id = track['id']
            bbox = track['bbox']
            w, h = bbox[2], bbox[3]
            current_area = w * h

            is_lunging = False
            is_surrendering = False
            is_following = False

            # A. LUNGE
            if track_id not in box_history: box_history[track_id] = []
            box_history[track_id].append(current_area)
            if len(box_history[track_id]) > 10: box_history[track_id].pop(0)
            if len(box_history[track_id]) >= 5:
                if (current_area / box_history[track_id][0]) > LUNGE_THRESHOLD: is_lunging = True

            # B. POSE
            landmarks = pose_estimator.estimate_pose(frame, bbox)
            if landmarks:
                if landmarks[15]['y'] < (landmarks[11]['y'] - HANDS_THRESHOLD): is_surrendering = True

            # C. FOLLOWING (STALKING)
            # Compare this track against all other active tracks
            for other_id in active_ids:
                if track_id == other_id: continue
                
                # 1. Check Distance
                tx, ty = track_history[track_id][-1]
                ox, oy = track_history[other_id][-1]
                dist = math.sqrt((tx-ox)**2 + (ty-oy)**2)
                
                if dist < FOLLOWING_DISTANCE_LIMIT:
                    # 2. Check Direction
                    similarity = calculate_direction_similarity(track_history[track_id], track_history[other_id])
                    
                    if similarity > FOLLOWING_ANGLE_THRESHOLD:
                        # 3. Persistence
                        pair_key = tuple(sorted((track_id, other_id)))
                        if pair_key not in following_history: following_history[pair_key] = 0
                        following_history[pair_key] += 1
                        
                        # Trigger if following for ~2 seconds (checks)
                        if following_history[pair_key] > 10:
                            is_following = True
                    else:
                        # Reset if directions diverge
                        pair_key = tuple(sorted((track_id, other_id)))
                        if pair_key in following_history: following_history[pair_key] = 0

            # --- THREAT SCORING ---
            status_text = f"ID:{track_id}"
            color = (0, 255, 0)
            
            if track_id not in threat_history: threat_history[track_id] = 0
            
            if is_lunging or is_surrendering or is_following:
                threat_history[track_id] += 1
            else:
                threat_history[track_id] = max(0, threat_history[track_id] - 1)

            if threat_history[track_id] > 5:
                color = (0, 0, 255)
                reason = "UNKNOWN"
                if is_surrendering: reason = "SURRENDER"
                elif is_lunging: reason = "LUNGE"
                elif is_following: reason = "STALKING"
                
                status_text = f"ID:{track_id} | {reason}"
                
                if not is_recording:
                    start_evidence_recording(track_id, reason, 90)
                    threat_history[track_id] = 0

            new_draw_list.append((bbox, color, status_text))
        
        current_draw_list = new_draw_list

    # --- DRAWING ---
    for (bbox, color, text) in current_draw_list:
        x1, y1, x2, y2 = map(int, bbox)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, text, (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

    if is_recording:
        current_video_writer.write(frame)
        recording_frame_count += 1
        cv2.circle(frame, (30, 30), 10, (0, 0, 255), -1) 
        if recording_frame_count > (FPS_TARGET * RECORD_SECONDS):
            is_recording = False
            current_video_writer.release()

    cv2.imshow("Sentinel AI - Phase 5 + Stalking", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
if current_video_writer: current_video_writer.release()
cv2.destroyAllWindows()