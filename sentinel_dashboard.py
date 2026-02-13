import streamlit as st
import cv2
import time
import os
import json
import math
import numpy as np
import pandas as pd
import winsound
from datetime import datetime
from collections import deque
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# --- CONFIGURATION [cite: 156] ---
st.set_page_config(page_title="Sentinel AI Dashboard", layout="wide", page_icon="🛡️")

# Constants
FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FPS_TARGET = 30
SKIP_FRAMES = 3
EVIDENCE_DIR = "evidence/alerts"

# Scoring Weights [cite: 49]
WEIGHT_FOLLOWING = 30
WEIGHT_PROXIMITY = 20
WEIGHT_AGGRESSION = 25
WEIGHT_DISTRESS = 25
ALERT_THRESHOLD = 70    # [cite: 52]

# --- UI LAYOUT  ---
st.title("🛡️ Sentinel AI: Crowd Behavior Monitor")

# Sidebar for Status 
st.sidebar.title("System Status")
status_indicator = st.sidebar.empty()
fps_metric = st.sidebar.metric("Processing FPS", "0")
camera_metric = st.sidebar.metric("Active Cameras", "1")
alert_count_metric = st.sidebar.metric("Alerts Today", "0")

# Main View: Video + Stats
col_video, col_stats = st.columns([3, 1])

with col_video:
    st.subheader("Live Surveillance Feed ")
    video_placeholder = st.empty()
    alert_banner = st.empty()

with col_stats:
    st.subheader("Real-Time Threat Analysis")
    score_chart = st.empty()
    st.divider()
    st.subheader("Recent Alerts [cite: 119]")
    history_list = st.empty()

# --- INITIALIZE AI MODELS (Cached) ---
@st.cache_resource
def load_models():
    return YOLO('yolo11n.pt'), PersonTracker(max_age=30), PoseEstimator()

detector, tracker, pose_estimator = load_models()

# --- HELPER FUNCTIONS ---
def save_alert(frame, track_id, score, factors):
    """Saves evidence and plays sound [cite: 84, 116]"""
    today_str = datetime.now().strftime("%Y%m%d")
    save_dir = os.path.join(EVIDENCE_DIR, today_str)
    if not os.path.exists(save_dir): os.makedirs(save_dir)

    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"ALERT_{timestamp}_ID{track_id}.jpg"
    filepath = os.path.join(save_dir, filename)
    
    cv2.imwrite(filepath, frame)
    
    # Save Metadata [cite: 91]
    meta_path = filepath.replace(".jpg", ".json")
    with open(meta_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "score": score,
            "factors": factors,
            "track_id": track_id
        }, f)
    
    # Audio Alert [cite: 116]
    winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
    return filename

def calculate_direction_similarity(path_a, path_b):
    """Math for Stalking Detection [cite: 23]"""
    if len(path_a) < 10 or len(path_b) < 10: return 0
    vec_a = np.array([path_a[-1][0] - path_a[0][0], path_a[-1][1] - path_a[0][1]])
    vec_b = np.array([path_b[-1][0] - path_b[0][0], path_b[-1][1] - path_b[0][1]])
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    if norm_a < 5 or norm_b < 5: return 0 
    return np.dot(vec_a, vec_b) / (norm_a * norm_b)

# --- MAIN SURVEILLANCE LOOP ---
run = st.sidebar.checkbox("Start Surveillance", value=False)

if run:
    cap = cv2.VideoCapture(0)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
    
    # State Memory
    box_history = {}
    track_history = {}
    following_history = {}
    threat_history = {}
    alert_cooldown = {}
    
    frame_count = 0
    start_time = time.time()
    alerts_today = 0

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        frame_count += 1
        
        # AI Processing (Every 3rd Frame)
        if frame_count % SKIP_FRAMES == 0:
            # 1. DETECT & TRACK [cite: 6, 13]
            results = detector(frame, classes=[0], verbose=False)
            detections = []
            for box in results[0].boxes.data.tolist():
                x1, y1, x2, y2, conf, cls = box
                detections.append([[x1, y1, x2-x1, y2-y1], conf, int(cls)])
            
            tracks = tracker.update(detections, frame)
            
            # Update Track History for Stalking
            active_ids = []
            for track in tracks:
                tid = track['id']
                bbox = track['bbox']
                center = (int(bbox[0] + bbox[2]/2), int(bbox[1] + bbox[3]/2))
                if tid not in track_history: track_history[tid] = deque(maxlen=30)
                track_history[tid].append(center)
                active_ids.append(tid)

            # 2. BEHAVIOR ANALYSIS [cite: 19]
            current_scores = {}
            
            for track in tracks:
                tid = track['id']
                bbox = track['bbox']
                w, h = bbox[2], bbox[3]
                area = w * h
                
                score = 0
                factors = []

                # A. Aggression (Lunge) [cite: 41]
                if tid not in box_history: box_history[tid] = []
                box_history[tid].append(area)
                if len(box_history[tid]) > 10: box_history[tid].pop(0)
                if len(box_history[tid]) >= 5:
                    if (area / box_history[tid][0]) > 1.15:
                        score += WEIGHT_AGGRESSION
                        factors.append("Lunge")

                # B. Distress (Pose) [cite: 42]
                landmarks = pose_estimator.estimate_pose(frame, bbox)
                if landmarks:
                    if landmarks[15]['y'] < (landmarks[11]['y'] - 20):
                        score += WEIGHT_DISTRESS
                        factors.append("Hands Up")

                # C. Following (Stalking) [cite: 21]
                is_following = False
                for oid in active_ids:
                    if tid == oid: continue
                    dist = math.sqrt((track_history[tid][-1][0] - track_history[oid][-1][0])**2 + 
                                     (track_history[tid][-1][1] - track_history[oid][-1][1])**2)
                    if dist < 200: # Proximity
                        sim = calculate_direction_similarity(track_history[tid], track_history[oid])
                        if sim > 0.8:
                            pair = tuple(sorted((tid, oid)))
                            following_history[pair] = following_history.get(pair, 0) + 1
                            if following_history[pair] > 10:
                                is_following = True
                        else:
                            following_history[tuple(sorted((tid, oid)))] = 0

                if is_following:
                    score += WEIGHT_FOLLOWING + WEIGHT_PROXIMITY
                    factors.append("Stalking")

                # 3. THREAT SCORING & ALERTS 
                current_scores[tid] = score
                
                # Draw Box
                color = (0, 255, 0) # Green
                if score >= ALERT_THRESHOLD:
                    color = (0, 0, 255) # Red
                    
                    # Check Cooldown (Don't spam alerts)
                    if time.time() - alert_cooldown.get(tid, 0) > 5:
                        save_alert(frame, tid, score, factors)
                        alert_cooldown[tid] = time.time()
                        alerts_today += 1
                        alert_banner.error(f"🚨 THREAT DETECTED: ID {tid} | Score: {score} | Reason: {', '.join(factors)}")

                x1, y1, x2, y2 = map(int, bbox)
                cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
                cv2.putText(frame, f"ID:{tid} Sc:{score}", (x1, y1-10), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

            # Update Charts
            if current_scores:
                score_chart.bar_chart(current_scores)

        # Update UI Elements
        status_indicator.success("System Online • Recording")
        alert_count_metric.metric("Alerts Today", alerts_today)
        
        # Calculate FPS 
        elapsed = time.time() - start_time
        fps = frame_count / elapsed
        fps_metric.metric("Processing FPS", f"{int(fps)}")

        # Show Video
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        video_placeholder.image(frame_rgb, channels="RGB", use_column_width=True)

else:
    status_indicator.warning("System Offline")