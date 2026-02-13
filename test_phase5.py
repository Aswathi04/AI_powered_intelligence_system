import cv2
import time
import os
import json
import winsound
import numpy as np
from collections import deque
from datetime import datetime
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# --- CHECKLIST CONFIGURATION ---
FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FPS_TARGET = 30
BUFFER_SECONDS = 5    # Checklist[cite: 86]: 5 seconds BEFORE alert
RECORD_SECONDS = 5    # Checklist[cite: 87]: 5 seconds AFTER alert

# Calculate buffer size (Frames = Seconds * FPS)
BUFFER_SIZE = BUFFER_SECONDS * FPS_TARGET

# Logic Thresholds
LUNGE_THRESHOLD = 1.15
HANDS_THRESHOLD = 20
THREAT_PERSISTENCE = 5  # Checklist[cite: 53]: Sustained threat validation

# --- SYSTEM INITIALIZATION ---
print("Initializing Sentinel AI - Phase 5 (Evidence Mode)...")
detector = YOLO('yolo11n.pt') 
tracker = PersonTracker(max_age=30)
pose_estimator = PoseEstimator()

# The "Time Machine" Buffer
video_buffer = deque(maxlen=BUFFER_SIZE)

# State Variables
threat_history = {}    
box_history = {}       
is_recording = False
recording_frame_count = 0
current_video_writer = None
current_evidence_path = ""

# Ensure Directory Structure 
base_dir = "evidence/alerts"
if not os.path.exists(base_dir):
    os.makedirs(base_dir)

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
cap.set(cv2.CAP_PROP_FPS, FPS_TARGET)

def start_evidence_recording(track_id, reason):
    """
    Triggers the recording process:
    1. Creates the file structure
    2. Dumps the past (buffer)
    3. Sets state to record the future
    """
    global is_recording, current_video_writer, recording_frame_count, current_evidence_path
    
    # Create Day-Specific Folder 
    today_str = datetime.now().strftime("%Y%m%d")
    save_dir = os.path.join(base_dir, today_str)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    # Generate Filename
    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"ALERT_{timestamp}_ID{track_id}_{reason}.mp4"
    current_evidence_path = os.path.join(save_dir, filename)

    print(f"!!! STARTING RECORDING: {filename} !!!")
    
    # Initialize Video Writer (mp4v codec)
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    current_video_writer = cv2.VideoWriter(current_evidence_path, fourcc, 20.0, (FRAME_WIDTH, FRAME_HEIGHT))

    # 1. DUMP THE PAST (Write all frames currently in buffer)
    for past_frame in video_buffer:
        current_video_writer.write(past_frame)

    # 2. PLAY ALARM 
    winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
    
    is_recording = True
    recording_frame_count = 0

def save_metadata(track_id, reason, score):
    """Saves the alert details to a JSON file """
    meta_filename = current_evidence_path.replace(".mp4", ".json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": reason,
        "track_id": track_id,
        "threat_score": score,
        "camera_id": "CAM_01_MAIN",
        "location": "Entrance Hall"
    }
    with open(meta_filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Metadata saved: {meta_filename}")

# --- MAIN LOOP ---
frame_counter = 0
while cap.isOpened():
    ret, frame = cap.read()
    if not ret: break
    
    frame_counter += 1
    
    # Always add current frame to buffer (RAM)
    # If buffer is full, oldest frame is automatically removed
    video_buffer.append(frame.copy())

    # Only run heavy AI every 3rd frame
    if frame_counter % 3 == 0:
        
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
            w, h = bbox[2], bbox[3]
            current_area = w * h

            # --- LOGIC: LUNGE ---
            is_lunging = False
            if track_id not in box_history: box_history[track_id] = []
            box_history[track_id].append(current_area)
            if len(box_history[track_id]) > 10: box_history[track_id].pop(0)
            
            if len(box_history[track_id]) >= 5:
                if (current_area / box_history[track_id][0]) > LUNGE_THRESHOLD:
                    is_lunging = True

            # --- LOGIC: HANDS UP ---
            landmarks = pose_estimator.estimate_pose(frame, bbox)
            is_surrendering = False
            if landmarks:
                l_wrist_y = landmarks[15]['y']
                l_shoulder_y = landmarks[11]['y']
                if l_wrist_y < (l_shoulder_y - HANDS_THRESHOLD):
                    is_surrendering = True

            # --- THREAT SCORING ---
            is_threat = is_surrendering or is_lunging
            if track_id not in threat_history: threat_history[track_id] = 0
            
            if is_threat:
                threat_history[track_id] += 1
            else:
                threat_history[track_id] = max(0, threat_history[track_id] - 1)

            # --- TRIGGER ALERT ---
            # If threat persists AND we are not already recording
            if threat_history[track_id] > THREAT_PERSISTENCE and not is_recording:
                reason = "SURRENDER" if is_surrendering else "LUNGE"
                
                # Start the "Time Machine" Recording
                start_evidence_recording(track_id, reason)
                save_metadata(track_id, reason, 90) # Mock score 90
                
                # Reset counter to prevent double triggers
                threat_history[track_id] = 0

            # Draw Box
            color = (0, 0, 255) if threat_history[track_id] > 5 else (0, 255, 0)
            x1, y1, x2, y2 = map(int, bbox)
            cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
            cv2.putText(frame, f"ID:{track_id}", (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

    # --- RECORDING LOGIC (The "Future" Part) ---
    if is_recording:
        current_video_writer.write(frame)
        recording_frame_count += 1
        
        # Overlay "REC" indicator
        cv2.circle(frame, (30, 30), 10, (0, 0, 255), -1) 
        
        # Stop after 5 seconds (approx 150 frames)
        if recording_frame_count > (FPS_TARGET * RECORD_SECONDS):
            print("Recording Saved.")
            is_recording = False
            current_video_writer.release()

    cv2.imshow("Sentinel AI - Phase 5", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
if current_video_writer: current_video_writer.release()
cv2.destroyAllWindows()