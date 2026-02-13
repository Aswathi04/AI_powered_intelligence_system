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

# --- 1. CONFIGURATION ---
FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FPS_TARGET = 30
SKIP_FRAMES = 3

# Evidence Settings [cite: 84-87]
BUFFER_SECONDS = 5
RECORD_SECONDS = 5
BUFFER_SIZE = BUFFER_SECONDS * FPS_TARGET

# Logic Thresholds
LUNGE_THRESHOLD = 1.15      # Box growth rate
HANDS_THRESHOLD = 20        # Wrist vs Shoulder
FOLLOWING_DISTANCE = 200    # Pixel distance for proximity
FOLLOWING_ANGLE = 0.8       # Direction similarity

# Scoring Weights 
WEIGHT_FOLLOWING = 30
WEIGHT_PROXIMITY = 20
WEIGHT_AGGRESSION = 25  # Lunge
WEIGHT_DISTRESS = 25    # Hands Up
ALERT_THRESHOLD = 70    # 

print("Initializing Sentinel AI - Full Backend (Weighted Scoring)...")

# --- 2. MODULES ---
detector = YOLO('yolo11n.pt') 
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()

# Memory
video_buffer = deque(maxlen=BUFFER_SIZE)
box_history = {}       
track_history = {}     # For Stalking
following_history = {} # For Stalking Persistence
threat_scores = {}     # Current score per ID

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
    filename = f"ALERT_{timestamp}_ID{track_id}.mp4"
    current_evidence_path = os.path.join(save_dir, filename)

    print(f"!!! ALERT (Score {score}): {filename} !!!")
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    current_video_writer = cv2.VideoWriter(current_evidence_path, fourcc, 20.0, (FRAME_WIDTH, FRAME_HEIGHT))

    # Dump Past
    for past_frame in video_buffer:
        current_video_writer.write(past_frame)

    # Save Metadata [cite: 91]
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
    if len(path_a) < 10 or len(path_b) < 10: return 0
    vec_a = np.array([path_a[-1][0] - path_a[0][0], path_a[-1][1] - path_a[0][1]])
    vec_b = np.array([path_b[-1][0] - path_b[0][0], path_b[-1][1] - path_b[0][1]])
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    if norm_a < 5 or norm_b < 5: return 0 
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
        
        # Update Track History
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

            # Reset Factors
            score = 0
            factors = []

            # 1. AGGRESSION (LUNGE) [25 pts]
            if track_id not in box_history: box_history[track_id] = []
            box_history[track_id].append(current_area)
            if len(box_history[track_id]) > 10: box_history[track_id].pop(0)
            
            if len(box_history[track_id]) >= 5:
                if (current_area / box_history[track_id][0]) > LUNGE_THRESHOLD: 
                    score += WEIGHT_AGGRESSION
                    factors.append("Lunge")

            # 2. DISTRESS (POSE) [25 pts]
            landmarks = pose_estimator.estimate_pose(frame, bbox)
            if landmarks:
                if landmarks[15]['y'] < (landmarks[11]['y'] - HANDS_THRESHOLD): 
                    score += WEIGHT_DISTRESS
                    factors.append("Hands Up")

            # 3. FOLLOWING & PROXIMITY [30 + 20 pts]
            is_following = False
            is_close = False
            
            for other_id in active_ids:
                if track_id == other_id: continue
                
                tx, ty = track_history[track_id][-1]
                ox, oy = track_history[other_id][-1]
                dist = math.sqrt((tx-ox)**2 + (ty-oy)**2)
                
                if dist < FOLLOWING_DISTANCE:
                    is_close = True
                    similarity = calculate_direction_similarity(track_history[track_id], track_history[other_id])
                    
                    if similarity > FOLLOWING_ANGLE:
                        # Check Persistence
                        pair_key = tuple(sorted((track_id, other_id)))
                        if pair_key not in following_history: following_history[pair_key] = 0
                        following_history[pair_key] += 1
                        
                        if following_history[pair_key] > 10: # Sustained following
                            is_following = True
                    else:
                        pair_key = tuple(sorted((track_id, other_id)))
                        if pair_key in following_history: following_history[pair_key] = 0

            if is_close: 
                score += WEIGHT_PROXIMITY
                factors.append("Close Proximity")
            if is_following: 
                score += WEIGHT_FOLLOWING
                factors.append("Following")

            # --- THREAT SCORING  ---
            # Smoothing the score (average over last few frames is ideal, but simplified here)
            threat_scores[track_id] = score
            
            status_text = f"ID:{track_id} | Score:{score}"
            color = (0, 255, 0) # Green

            # ALERT TRIGGER
            if score >= ALERT_THRESHOLD:
                color = (0, 0, 255) # Red
                if not is_recording:
                    reason_str = "+".join(factors)
                    start_evidence_recording(track_id, reason_str, score)

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

    cv2.imshow("Sentinel AI - Weighted Scoring", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
if current_video_writer: current_video_writer.release()
cv2.destroyAllWindows()