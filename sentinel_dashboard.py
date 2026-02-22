 import streamlit as st
import cv2
import time
import math
import os
import json
import numpy as np
from datetime import datetime
from collections import deque
from ultralytics import YOLO

# --- CONFIGURATION ---
st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

FRAME_WIDTH = 640
FRAME_HEIGHT = 480
SKIP_FRAMES = 2

# --- SENSITIVITY SETTINGS ---
SPEED_THRESHOLD = 2.5       
PROXIMITY_LIMIT = 220       
ENCIRCLEMENT_DIST = 300     
MAX_GAP_THRESHOLD = 200     
MIN_ENCIRCLERS = 3          

EVIDENCE_ROOT = "evidence/incidents"
BUFFER_SIZE = 30

# --- HELPER FUNCTIONS ---

def get_stats():
    """Scans all reports to calculate live statistics."""
    total = 0
    confirmed = 0
    false_alarm = 0
    pending = 0
    
    if os.path.exists(EVIDENCE_ROOT):
        for day_folder in os.listdir(EVIDENCE_ROOT):
            day_path = os.path.join(EVIDENCE_ROOT, day_folder)
            if os.path.isdir(day_path):
                for inc_folder in os.listdir(day_path):
                    json_path = os.path.join(day_path, inc_folder, "report.json")
                    if os.path.exists(json_path):
                        total += 1
                        try:
                            with open(json_path, "r") as f:
                                data = json.load(f)
                                status = data.get("review_status", "PENDING")
                                if status == "CONFIRMED": confirmed += 1
                                elif status == "FALSE_ALARM": false_alarm += 1
                                else: pending += 1
                        except:
                            pending += 1
                            
    accuracy = 0
    if (confirmed + false_alarm) > 0:
        accuracy = (confirmed / (confirmed + false_alarm)) * 100
        
    return total, confirmed, false_alarm, pending, int(accuracy)

def update_incident_status(report_path, status, note):
    """Updates the JSON report with the security guard's decision."""
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            data = json.load(f)
        
        data["review_status"] = status
        data["reviewed_by"] = "Security Officer"
        data["reviewed_at"] = datetime.now().isoformat()
        data["review_note"] = note
        
        with open(report_path, "w") as f:
            json.dump(data, f, indent=4)
        return True
    return False

def annotate_frame(frame, text, score, color=(0, 0, 255)):
    annotated = frame.copy()
    h, w = annotated.shape[:2]
    cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
    cv2.putText(annotated, f"ALERT: {text}", (10, 35), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
    cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(annotated, ts, (w - 220, h - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
    return annotated

def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
    timestamp = datetime.now().strftime("%H-%M-%S")
    date_str = datetime.now().strftime("%Y%m%d")
    incident_id = 1
    daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
    if os.path.exists(daily_dir):
        existing = [d for d in os.listdir(daily_dir) if os.path.isdir(os.path.join(daily_dir, d))]
        incident_id = len(existing) + 1
    
    folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
    save_path = os.path.join(daily_dir, folder_name)
    if not os.path.exists(save_path): os.makedirs(save_path)

    idx_before = max(0, len(buffer) - 15)
    frame_before = buffer[idx_before] if buffer else peak_frame
    threat_score = 85 
    
    img_before = annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
    img_peak = annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))
    
    cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
    cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"), img_peak)
    
    report = {
        "incident_id": f"INCIDENT_{incident_id:03d}",
        "detection_type": alert_type,
        "timestamp": datetime.now().isoformat(),
        "threat_score": threat_score,
        "metrics": metrics,
        "review_status": "PENDING",
        "evidence_files": ["snapshot_before.jpg", "snapshot_peak.jpg", "snapshot_after.jpg (pending)"]
    }
    
    with open(os.path.join(save_path, "report.json"), "w") as f:
        json.dump(report, f, indent=4)
        
    return save_path, incident_id

# --- UI LAYOUT ---
st.title("🛡️ Sentinel AI: Security Operations Center")

# --- TOP HEADER STATS ---
total, confirmed, false, pending, accuracy = get_stats()
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Alerts", total)
k2.metric("Confirmed Threats", confirmed, delta="Action Required" if confirmed > 0 else None, delta_color="inverse")
k3.metric("False Alarms", false)
k4.metric("Pending Review", pending, delta="Urgent" if pending > 0 else "All Clear", delta_color="inverse")
k5.metric("System Accuracy", f"{accuracy}%")

st.divider()

# Create Tabs
tab1, tab2 = st.tabs(["🔴 Live Tactical View", "🗂️ Incident Review & Audit"])

# --- TAB 1: LIVE MONITOR ---
with tab1:
    # Top Status Banner Placeholder
    status_placeholder = st.empty()
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("Live Feed")
        video_placeholder = st.empty()
    with col2:
        st.subheader("Active Threats")
        metric_speed = st.empty()
        metric_prox = st.empty()
        metric_encircle = st.empty()
        st.divider()
        st.write("### Live Log")
        log_placeholder = st.empty()

# --- TAB 2: INCIDENT REVIEW ---
with tab2:
    st.header("🗂️ Incident Case Files")
    st.info("Uncheck 'ACTIVATE SYSTEM' to review evidence.")
    evidence_col, viewer_col = st.columns([1, 2])
    
    with evidence_col:
        all_files = []
        if os.path.exists(EVIDENCE_ROOT):
            for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
                day_path = os.path.join(EVIDENCE_ROOT, day_folder)
                if os.path.isdir(day_path):
                    for inc_folder in sorted(os.listdir(day_path), reverse=True):
                        if inc_folder.startswith("INCIDENT"):
                            status_icon = "🟡"
                            try:
                                with open(os.path.join(day_path, inc_folder, "report.json")) as f:
                                    d = json.load(f)
                                    s = d.get("review_status", "PENDING")
                                    if s == "CONFIRMED": status_icon = "🟢"
                                    elif s == "FALSE_ALARM": status_icon = "⚪"
                            except: pass
                            
                            display_name = f"{status_icon} {inc_folder[9:]}"
                            all_files.append((display_name, os.path.join(day_path, inc_folder)))
        
        selected_file = st.selectbox("Select Case:", all_files, format_func=lambda x: x[0]) if all_files else None

    with viewer_col:
        if selected_file:
            folder_path = selected_file[1]
            json_path = os.path.join(folder_path, "report.json")
            
            if os.path.exists(json_path):
                with open(json_path, "r") as f:
                    report = json.load(f)
                
                status = report.get("review_status", "PENDING")
                if status == "CONFIRMED":
                    st.error(f"✅ CONFIRMED THREAT (Verified by {report.get('reviewed_by')})")
                    if report.get("review_note"): st.caption(f"📝 Note: {report.get('review_note')}")
                elif status == "FALSE_ALARM":
                    st.success(f"❌ FALSE ALARM (Verified by {report.get('reviewed_by')})")
                    if report.get("review_note"): st.caption(f"📝 Note: {report.get('review_note')}")
                else:
                    st.warning("⚠️ PENDING SECURITY REVIEW")
                    with st.form("review_form"):
                        note = st.text_input("Add Note (Optional)", placeholder="e.g. Friends greeting, Staff member...")
                        c1, c2 = st.columns(2)
                        confirm = c1.form_submit_button("✅ Confirm Threat", type="primary")
                        false_alarm = c2.form_submit_button("❌ False Alarm")
                        
                        if confirm:
                            update_incident_status(json_path, "CONFIRMED", note)
                            st.rerun()
                        if false_alarm:
                            update_incident_status(json_path, "FALSE_ALARM", note)
                            st.rerun()

                metrics_data = report.get('metrics', {"info": "Legacy Data - No details available"})
                st.json(metrics_data)
                
                c1, c2, c3 = st.columns(3)
                p_before = os.path.join(folder_path, "snapshot_before.jpg")
                p_peak = os.path.join(folder_path, "snapshot_peak.jpg")
                p_after = os.path.join(folder_path, "snapshot_after.jpg")
                
                if os.path.exists(p_before): c1.image(p_before, caption="BEFORE", use_container_width=True)
                if os.path.exists(p_peak): c2.image(p_peak, caption="PEAK (Alert)", use_container_width=True)
                if os.path.exists(p_after): c3.image(p_after, caption="AFTER", use_container_width=True)

# --- AI INIT ---
@st.cache_resource
def load_model():
    return YOLO('yolo11n.pt')

model = load_model()

# --- MAIN LOOP ---
st.sidebar.title("System Control")
system_active = st.sidebar.checkbox("ACTIVATE SURVEILLANCE", value=True)

if system_active:
    cap = cv2.VideoCapture(0)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

    speed_history = {}    
    pos_history = {}      
    
    video_buffer = deque(maxlen=BUFFER_SIZE)
    alert_cooldown = {}
    detection_log = []
    pending_after_snapshots = []
    
    frame_count = 0
    
    while cap.isOpened() and system_active:
        ret, frame = cap.read()
        if not ret: break
        
        frame_count += 1
        video_buffer.append(frame.copy())
        
        for i, (trigger_time, folder_path) in enumerate(pending_after_snapshots):
            if time.time() > trigger_time:
                img_after = annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
                cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
                pending_after_snapshots.pop(i)

        current_alerts = []
        
        if frame_count % SKIP_FRAMES == 0:
            results = model.track(frame, persist=True, verbose=False, classes=[0])
            current_people = [] 
            
            if results[0].boxes.id is not None:
                boxes = results[0].boxes.xyxy.cpu().numpy()
                ids = results[0].boxes.id.int().cpu().numpy()

                for box, track_id in zip(boxes, ids):
                    x1, y1, x2, y2 = map(int, box)
                    w, h = x2 - x1, y2 - y1
                    cx, cy = int(x1 + w/2), int(y1 + h/2)
                    
                    person = {
                        "id": track_id, "box": (x1, y1, x2, y2), 
                        "center": (cx, cy), "role": "NEUTRAL"
                    }
                    current_people.append(person)

                    # 1. SPEED CHECK
                    speed_ratio = 1.0
                    if track_id in pos_history:
                        prev_cx, prev_cy = pos_history[track_id]
                        dist_moved = math.sqrt((cx - prev_cx)**2 + (cy - prev_cy)**2)
                        
                        if track_id not in speed_history: speed_history[track_id] = deque(maxlen=10)
                        speed_history[track_id].append(dist_moved)
                        
                        if len(speed_history[track_id]) >= 5:
                            avg_speed = sum(speed_history[track_id]) / len(speed_history[track_id])
                            if avg_speed > 2.0: speed_ratio = dist_moved / avg_speed
                            
                            if speed_ratio > SPEED_THRESHOLD:
                                current_alerts.append("SPEED CHANGE")
                                person["role"] = "ATTACKER"
                                
                                if time.time() - alert_cooldown.get(f"speed_{track_id}", 0) > 10:
                                    metrics = {"speed_ratio": f"{speed_ratio:.2f}x"}
                                    path, i_id = create_incident_report(list(video_buffer), frame, track_id, "SPEED CHANGE", metrics)
                                    alert_cooldown[f"speed_{track_id}"] = time.time()
                                    detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
                                    pending_after_snapshots.append((time.time() + 2.0, path))

                    pos_history[track_id] = (cx, cy)
                    person["speed_display"] = f"{speed_ratio:.1f}x"

            # 2. PROXIMITY
            min_dist_val = 999
            for i in range(len(current_people)):
                for j in range(i + 1, len(current_people)):
                    p1, p2 = current_people[i], current_people[j]
                    dist = math.sqrt((p1['center'][0] - p2['center'][0])**2 + (p1['center'][1] - p2['center'][1])**2)
                    min_dist_val = min(min_dist_val, dist)
                    
                    if dist < PROXIMITY_LIMIT:
                        current_alerts.append("PROXIMITY")
                        cv2.line(frame, p1['center'], p2['center'], (0, 0, 255), 3)
                        
                        if time.time() - alert_cooldown.get("prox", 0) > 10:
                            metrics = {"distance_px": int(dist)}
                            path, i_id = create_incident_report(list(video_buffer), frame, 0, "PROXIMITY", metrics)
                            alert_cooldown["prox"] = time.time()
                            detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
                            pending_after_snapshots.append((time.time() + 2.0, path))
                    else:
                        cv2.line(frame, p1['center'], p2['center'], (0, 255, 0), 1)

            # 3. ENCIRCLEMENT
            debug_gap = 360
            debug_enclosed = 0
            if len(current_people) >= MIN_ENCIRCLERS:
                min_max_gap = 360
                best_target = None
                
                for target in current_people:
                    angles = []
                    for other in current_people:
                        if target['id'] == other['id']: continue
                        dx = other['center'][0] - target['center'][0]
                        dy = other['center'][1] - target['center'][1]
                        if math.sqrt(dx*dx + dy*dy) < ENCIRCLEMENT_DIST:
                            angle = math.degrees(math.atan2(dy, dx))
                            if angle < 0: angle += 360
                            angles.append(angle)
                    
                    if len(angles) >= (MIN_ENCIRCLERS - 1):
                        angles.sort()
                        max_gap = 0
                        for k in range(len(angles)):
                            gap = angles[(k+1)%len(angles)] - angles[k]
                            if gap < 0: gap += 360
                            max_gap = max(max_gap, gap)
                        
                        if max_gap < min_max_gap:
                            min_max_gap = max_gap
                            best_target = target
                
                debug_gap = min_max_gap
                if min_max_gap < 360: debug_enclosed = int((360 - min_max_gap)/3.6)
                
                if min_max_gap < MAX_GAP_THRESHOLD and best_target:
                    best_target['role'] = "TARGET"
                    current_alerts.append("ENCIRCLEMENT")
                    if time.time() - alert_cooldown.get("circle", 0) > 10:
                        metrics = {"max_gap_deg": int(min_max_gap), "enclosed_pct": debug_enclosed}
                        path, i_id = create_incident_report(list(video_buffer), frame, best_target['id'], "ENCIRCLEMENT", metrics)
                        alert_cooldown["circle"] = time.time()
                        detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
                        pending_after_snapshots.append((time.time() + 2.0, path))

            # DRAWING
            for p in current_people:
                color = (0, 255, 0)
                if p['role'] == "TARGET": color = (0, 0, 255)
                elif p['role'] == "ATTACKER": color = (0, 0, 255)
                cv2.rectangle(frame, p['box'][:2], p['box'][2:], color, 2)
                cv2.putText(frame, f"ID:{p['id']}", (p['box'][0], p['box'][1]-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

            # UI UPDATES (Using Placeholder)
            status_text = "SYSTEM SECURE"
            if current_alerts:
                status_text = f"🚨 ALERT: {' + '.join(set(current_alerts))}"
                status_placeholder.error(status_text)
            else:
                status_placeholder.success(status_text)

            metric_speed.metric("Speed Change", "Active")
            metric_prox.metric("Min Distance", f"{int(min_dist_val) if min_dist_val!=999 else '-'} px")
            metric_encircle.metric("Encirclement", f"{debug_enclosed}% Enclosed", delta=f"Gap: {int(debug_gap)}°", delta_color="inverse")
            
            log_placeholder.text("\n".join(detection_log[:5]))
            
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            video_placeholder.image(frame_rgb, channels="RGB", use_container_width=True)

    cap.release()
else:
    st.info("⏸️ Monitor Paused")