"""
pages/security_page.py

Dashboard for the Security Officer role.

Contains:
  Tab 1 — Live Tactical View  (camera feed + active threat metrics)
  Tab 2 — Incident Review     (evidence snapshots + acknowledge/dismiss)
  Tab 3 — Alert History       (shared with all roles, imported from shared_history)

The entire AI detection loop lives here unchanged from sentinel_dashboard.py.
Only the UI wrapper and the acknowledge/dismiss buttons are new.
"""

import cv2
import time
import math
import os
import json
import numpy as np
import streamlit as st
from datetime import datetime
from collections import deque
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator
from logic.threat_scorer import ThreatScorer
from alerts.gsm_alert import GSMAlert
from auth.db import log_action
from auth.roles import can

# --- CONSTANTS (loaded from sentinel_dashboard config) ---
FRAME_WIDTH      = 640
FRAME_HEIGHT     = 480
SKIP_FRAMES      = 2
SPEED_THRESHOLD  = 2.5
PROXIMITY_LIMIT  = 220
ENCIRCLEMENT_DIST = 300
MAX_GAP_THRESHOLD = 200
MIN_ENCIRCLERS   = 3
EVIDENCE_ROOT    = "evidence/incidents"
BUFFER_SIZE      = 30


# ---------------------------------------------------------------------------
# Helper functions (same as sentinel_dashboard.py)
# ---------------------------------------------------------------------------

def _get_stats():
    total = confirmed = false_alarm = pending = 0
    if os.path.exists(EVIDENCE_ROOT):
        for day_folder in os.listdir(EVIDENCE_ROOT):
            day_path = os.path.join(EVIDENCE_ROOT, day_folder)
            if os.path.isdir(day_path):
                for inc_folder in os.listdir(day_path):
                    json_path = os.path.join(day_path, inc_folder, "report.json")
                    if os.path.exists(json_path):
                        total += 1
                        try:
                            with open(json_path) as f:
                                data = json.load(f)
                            status = data.get("review_status", "PENDING")
                            if status == "CONFIRMED":       confirmed += 1
                            elif status == "FALSE_ALARM":   false_alarm += 1
                            else:                           pending += 1
                        except Exception:
                            pending += 1
    accuracy = 0
    if (confirmed + false_alarm) > 0:
        accuracy = (confirmed / (confirmed + false_alarm)) * 100
    return total, confirmed, false_alarm, pending, int(accuracy)


def _update_incident_status(report_path, status, note, reviewed_by):
    if os.path.exists(report_path):
        with open(report_path) as f:
            data = json.load(f)
        data["review_status"] = status
        data["reviewed_by"]   = reviewed_by
        data["reviewed_at"]   = datetime.now().isoformat()
        data["review_note"]   = note
        with open(report_path, "w") as f:
            json.dump(data, f, indent=4)
        return True
    return False


def _annotate_frame(frame, text, score, color=(0, 0, 255)):
    annotated = frame.copy()
    h, w = annotated.shape[:2]
    cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
    cv2.putText(annotated, f"ALERT: {text}", (10, 35),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
    cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(annotated, ts, (w - 220, h - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
    return annotated


def _calculate_threat_score(alert_type, metrics):
    score = 50
    if alert_type == "SPEED CHANGE":
        try:
            ratio = float(metrics.get("speed_ratio", "2.5x").replace("x", ""))
            score = min(95, int(40 + (ratio - 2.5) * 16))
        except (ValueError, AttributeError):
            score = 50
    elif alert_type == "PROXIMITY":
        dist  = metrics.get("distance_px", 110)
        closeness = max(0.0, 1.0 - (dist / PROXIMITY_LIMIT))
        score = min(95, int(40 + closeness * 40))
    elif alert_type == "ENCIRCLEMENT":
        enclosed_pct = metrics.get("enclosed_pct", 50)
        score = min(80, int(30 + enclosed_pct * 0.5))
    elif "threat_score" in metrics:
        score = min(100, int(metrics["threat_score"]))
    return max(0, score)


def _create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
    timestamp  = datetime.now().strftime("%H-%M-%S")
    date_str   = datetime.now().strftime("%Y%m%d")
    incident_id = 1
    daily_dir  = os.path.join(EVIDENCE_ROOT, date_str)
    if os.path.exists(daily_dir):
        existing = [d for d in os.listdir(daily_dir)
                    if os.path.isdir(os.path.join(daily_dir, d))]
        incident_id = len(existing) + 1

    folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ','_')}_{timestamp}"
    save_path   = os.path.join(daily_dir, folder_name)
    os.makedirs(save_path, exist_ok=True)

    threat_score = _calculate_threat_score(alert_type, metrics)

    frame_before = buffer[-15] if len(buffer) > 15 else (buffer[0] if buffer else peak_frame)
    img_before   = _annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
    img_peak     = _annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))

    cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
    cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"),   img_peak)

    report = {
        "incident_id":    f"INCIDENT_{incident_id:03d}",
        "detection_type": alert_type,
        "timestamp":      datetime.now().isoformat(),
        "threat_score":   threat_score,
        "metrics":        metrics,
        "review_status":  "PENDING",
        "evidence_files": ["snapshot_before.jpg", "snapshot_peak.jpg",
                           "snapshot_after.jpg (pending)"],
    }
    with open(os.path.join(save_path, "report.json"), "w") as f:
        json.dump(report, f, indent=4)

    return save_path, incident_id


def _is_valid_person(box, frame_shape, min_area_ratio=0.04, min_aspect=1.2):
    x1, y1, x2, y2 = box
    w, h = x2 - x1, y2 - y1
    if w <= 0 or h <= 0: return False
    fh, fw = frame_shape
    if (w * h) / (fh * fw) < min_area_ratio: return False
    if (h / w) < min_aspect: return False
    return True


def _iou(a, b):
    ax1,ay1,ax2,ay2 = a; bx1,by1,bx2,by2 = b
    ix1,iy1 = max(ax1,bx1), max(ay1,by1)
    ix2,iy2 = min(ax2,bx2), min(ay2,by2)
    inter = max(0,ix2-ix1)*max(0,iy2-iy1)
    if inter == 0: return 0.0
    union = (ax2-ax1)*(ay2-ay1)+(bx2-bx1)*(by2-by1)-inter
    return inter/union if union > 0 else 0.0


def _center_inside(center, box):
    cx,cy = center; x1,y1,x2,y2 = box
    return x1<=cx<=x2 and y1<=cy<=y2


# ---------------------------------------------------------------------------
# AI model loader (cached so it loads only once across reruns)
# ---------------------------------------------------------------------------

@st.cache_resource
def _load_ai_models():
    model         = YOLO('yolo11n.pt')
    tracker       = PersonTracker()
    pose_estimator = PoseEstimator()
    threat_scorer  = ThreatScorer()
    return model, tracker, pose_estimator, threat_scorer


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def show_security_page(user: dict):
    """
    Render the full Security Officer dashboard.
    Called from sentinel_dashboard.py when role == 'security'.
    """

    # Permission gate — belt-and-suspenders check
    if not can(user['role'], 'view_live_feed'):
        st.error("⛔ You do not have permission to access this page.")
        return

    # --- Page header ---
    st.title("🛡️ Sentinel AI — Security Operations Center")
    st.caption(f"Logged in as **{user['full_name']}** · Role: `SECURITY OFFICER`")

    # --- Top stats bar ---
    total, confirmed, false_alarms, pending, accuracy = _get_stats()
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Total Alerts",     total)
    k2.metric("Confirmed Threats", confirmed,
              delta="Action Required" if confirmed > 0 else None,
              delta_color="inverse")
    k3.metric("False Alarms",     false_alarms)
    k4.metric("Pending Review",   pending,
              delta="Urgent" if pending > 0 else "All Clear",
              delta_color="inverse")
    k5.metric("System Accuracy",  f"{accuracy}%")

    st.divider()

    # --- Tabs ---
    tab1, tab2, tab3 = st.tabs([
        "🔴 Live Tactical View",
        "🗂️ Incident Review",
        "📋 Alert History",
    ])

    # -----------------------------------------------------------------------
    # TAB 1 — LIVE FEED
    # -----------------------------------------------------------------------
    with tab1:
        status_placeholder = st.empty()

        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("Live Feed")
            video_placeholder = st.empty()
        with col2:
            st.subheader("Active Threats")
            metric_speed    = st.empty()
            metric_prox     = st.empty()
            metric_encircle = st.empty()
            st.divider()
            st.write("### Live Log")
            log_placeholder = st.empty()

    # -----------------------------------------------------------------------
    # TAB 2 — INCIDENT REVIEW
    # -----------------------------------------------------------------------
    with tab2:
        st.header("🗂️ Incident Case Files")
        st.info("Stop the live feed first to review evidence without lag.")

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
                                    with open(os.path.join(day_path, inc_folder,
                                                           "report.json")) as f:
                                        d = json.load(f)
                                    s = d.get("review_status", "PENDING")
                                    if s == "CONFIRMED":    status_icon = "🟢"
                                    elif s == "FALSE_ALARM": status_icon = "⚪"
                                except Exception:
                                    pass
                                display_name = f"{status_icon} {inc_folder[9:]}"
                                all_files.append(
                                    (display_name, os.path.join(day_path, inc_folder)))

            selected_file = (
                st.selectbox("Select Case:", all_files, format_func=lambda x: x[0])
                if all_files else None
            )

        with viewer_col:
            if selected_file:
                folder_path = selected_file[1]
                json_path   = os.path.join(folder_path, "report.json")

                if os.path.exists(json_path):
                    with open(json_path) as f:
                        report = json.load(f)

                    status = report.get("review_status", "PENDING")

                    if status == "CONFIRMED":
                        st.error(
                            f"✅ CONFIRMED THREAT — verified by "
                            f"{report.get('reviewed_by', 'Unknown')}"
                        )
                        if report.get("review_note"):
                            st.caption(f"📝 {report['review_note']}")

                    elif status == "FALSE_ALARM":
                        st.success(
                            f"❌ FALSE ALARM — verified by "
                            f"{report.get('reviewed_by', 'Unknown')}"
                        )
                        if report.get("review_note"):
                            st.caption(f"📝 {report['review_note']}")

                    else:
                        # PENDING — show action buttons
                        st.warning("⚠️ PENDING SECURITY REVIEW")

                        # Threat score badge
                        score = report.get("threat_score", 0)
                        score_color = (
                            "🔴" if score >= 70
                            else "🟠" if score >= 40
                            else "🟡"
                        )
                        st.markdown(
                            f"**Threat Score:** {score_color} `{score}/100`  "
                            f"&nbsp;&nbsp; **Type:** `{report.get('detection_type','?')}`"
                        )

                        st.divider()

                        # --- Acknowledge / Dismiss form ---
                        with st.form(f"review_{folder_path}"):
                            note = st.text_input(
                                "Add Note (optional)",
                                placeholder="e.g. Friends greeting, staff member, maintenance..."
                            )
                            c1, c2 = st.columns(2)
                            confirm_btn = c1.form_submit_button(
                                "✅ Acknowledge — Confirm Threat",
                                type="primary",
                                use_container_width=True,
                            )
                            dismiss_btn = c2.form_submit_button(
                                "❌ Dismiss — False Alarm",
                                use_container_width=True,
                            )

                            if confirm_btn:
                                _update_incident_status(
                                    json_path, "CONFIRMED", note, user['full_name'])
                                log_action(
                                    user['username'], "ALERT_ACK",
                                    f"{report.get('incident_id')} — {note}")
                                st.success("Incident confirmed and logged.")
                                st.rerun()

                            if dismiss_btn:
                                _update_incident_status(
                                    json_path, "FALSE_ALARM", note, user['full_name'])
                                log_action(
                                    user['username'], "ALERT_DISMISS",
                                    f"{report.get('incident_id')} — {note}")
                                st.success("Incident marked as false alarm.")
                                st.rerun()

                    # Metrics JSON
                    with st.expander("📊 Detection Metrics", expanded=False):
                        st.json(report.get("metrics",
                                           {"info": "No metrics available"}))

                    # Evidence snapshots
                    st.subheader("Evidence Snapshots")
                    c1, c2, c3 = st.columns(3)
                    p_before = os.path.join(folder_path, "snapshot_before.jpg")
                    p_peak   = os.path.join(folder_path, "snapshot_peak.jpg")
                    p_after  = os.path.join(folder_path, "snapshot_after.jpg")
                    if os.path.exists(p_before):
                        c1.image(p_before, caption="BEFORE",     use_container_width=True)
                    if os.path.exists(p_peak):
                        c2.image(p_peak,   caption="PEAK (Alert)", use_container_width=True)
                    if os.path.exists(p_after):
                        c3.image(p_after,  caption="AFTER",      use_container_width=True)

    # -----------------------------------------------------------------------
    # TAB 3 — ALERT HISTORY (shared component)
    # -----------------------------------------------------------------------
    with tab3:
        try:
            from pages.shared_history import show_alert_history
            show_alert_history(user)
        except ImportError:
            st.info("Alert history will be available after Step 9 is complete.")

    # -----------------------------------------------------------------------
    # AI MODELS — loaded once, cached across reruns
    # -----------------------------------------------------------------------
    model, tracker, pose_estimator, threat_scorer = _load_ai_models()

    # -----------------------------------------------------------------------
    # SIDEBAR — surveillance controls
    # -----------------------------------------------------------------------
    st.sidebar.divider()
    st.sidebar.subheader("Surveillance Control")
    system_active = st.sidebar.checkbox("🎥 Activate Camera", value=False)
    gsm_port      = st.sidebar.text_input(
        "GSM Port", value="COM3",
        help="Windows: COM3  |  Linux: /dev/ttyUSB0")
    gsm_alert     = GSMAlert(port=gsm_port)

    # -----------------------------------------------------------------------
    # MAIN DETECTION LOOP — unchanged from sentinel_dashboard.py
    # -----------------------------------------------------------------------
    if system_active:
        cap = cv2.VideoCapture(0)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH,  FRAME_WIDTH)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

        speed_history          = {}
        pos_history            = {}
        video_buffer           = deque(maxlen=BUFFER_SIZE)
        alert_cooldown         = {}
        detection_log          = []
        pending_after_snapshots = []
        frame_count            = 0

        stop_btn = st.sidebar.button("⏹ Stop Feed")

        while cap.isOpened() and not stop_btn:
            ret, frame = cap.read()
            if not ret:
                break

            frame_count += 1
            video_buffer.append(frame.copy())

            # Post-event snapshot writer
            remaining = []
            for trigger_time, folder_path in pending_after_snapshots:
                if time.time() > trigger_time:
                    img_after = _annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
                    cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
                else:
                    remaining.append((trigger_time, folder_path))
            pending_after_snapshots = remaining

            current_alerts = []
            min_dist_val   = 999

            if frame_count % SKIP_FRAMES == 0:
                results        = model.track(frame, persist=True, verbose=False, classes=[0])
                current_people = []

                if results[0].boxes.id is not None:
                    boxes     = results[0].boxes.xyxy.cpu().numpy()
                    ids       = results[0].boxes.id.int().cpu().numpy()

                    for box, track_id in zip(boxes, ids):
                        x1, y1, x2, y2 = map(int, box)
                        w, h   = x2 - x1, y2 - y1
                        cx, cy = x1 + w // 2, y1 + h // 2

                        person = {
                            "id": track_id, "box": (x1,y1,x2,y2),
                            "center": (cx,cy), "role": "NEUTRAL",
                            "threat_score": 0, "threat_reason": "Scanning...",
                            "speed_display": "1.0x",
                        }

                        landmarks          = pose_estimator.estimate_pose(frame, (x1,y1,x2,y2))
                        score, reason      = threat_scorer.update(track_id, (x1,y1,w,h), landmarks)
                        person["threat_score"]  = score
                        person["threat_reason"] = reason

                        # Speed check
                        speed_ratio = 1.0
                        if track_id in pos_history:
                            prev_cx, prev_cy = pos_history[track_id]
                            dist_moved = math.sqrt((cx-prev_cx)**2+(cy-prev_cy)**2)
                            if track_id not in speed_history:
                                speed_history[track_id] = deque(maxlen=10)
                            speed_history[track_id].append(dist_moved)
                            if len(speed_history[track_id]) >= 5:
                                avg_speed = sum(speed_history[track_id])/len(speed_history[track_id])
                                if avg_speed > 2.0:
                                    speed_ratio = dist_moved / avg_speed
                                if speed_ratio > SPEED_THRESHOLD:
                                    current_alerts.append("SPEED CHANGE")
                                    person["role"] = "ATTACKER"
                                    ckey = f"speed_{track_id}"
                                    if time.time() - alert_cooldown.get(ckey, 0) > 10:
                                        path, i_id = _create_incident_report(
                                            list(video_buffer), frame, track_id,
                                            "SPEED CHANGE", {"speed_ratio": f"{speed_ratio:.2f}x"})
                                        alert_cooldown[ckey] = time.time()
                                        detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
                                        pending_after_snapshots.append((time.time()+2.0, path))

                        pos_history[track_id]   = (cx, cy)
                        person["speed_display"] = f"{speed_ratio:.1f}x"
                        current_people.append(person)

                # Clean stale targets
                current_ids = [p['id'] for p in current_people]
                for tid in list(threat_scorer.targets.keys()):
                    if tid not in current_ids:
                        del threat_scorer.targets[tid]

                # Proximity check
                fh, fw       = frame.shape[:2]
                valid_people = [p for p in current_people
                                if _is_valid_person(p['box'], (fh, fw))]
                for i in range(len(valid_people)):
                    for j in range(i+1, len(valid_people)):
                        p1, p2 = valid_people[i], valid_people[j]
                        if _center_inside(p1['center'], p2['box']): continue
                        if _center_inside(p2['center'], p1['box']): continue
                        if _iou(p1['box'], p2['box']) > 0.30:       continue
                        dist = math.sqrt(
                            (p1['center'][0]-p2['center'][0])**2 +
                            (p1['center'][1]-p2['center'][1])**2)
                        min_dist_val = min(min_dist_val, dist)
                        if dist < PROXIMITY_LIMIT:
                            current_alerts.append("PROXIMITY")
                            cv2.line(frame, p1['center'], p2['center'], (0,0,255), 3)
                            if time.time() - alert_cooldown.get("prox", 0) > 10:
                                path, i_id = _create_incident_report(
                                    list(video_buffer), frame, 0,
                                    "PROXIMITY", {"distance_px": int(dist)})
                                alert_cooldown["prox"] = time.time()
                                detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
                                pending_after_snapshots.append((time.time()+2.0, path))
                        else:
                            cv2.line(frame, p1['center'], p2['center'], (0,255,0), 1)

                # Encirclement check
                debug_gap = 360; debug_enclosed = 0
                if len(current_people) >= MIN_ENCIRCLERS:
                    min_max_gap = 360; best_target = None
                    for target in current_people:
                        angles = []
                        for other in current_people:
                            if target['id'] == other['id']: continue
                            dx = other['center'][0]-target['center'][0]
                            dy = other['center'][1]-target['center'][1]
                            if math.sqrt(dx*dx+dy*dy) < ENCIRCLEMENT_DIST:
                                angle = math.degrees(math.atan2(dy,dx))
                                if angle < 0: angle += 360
                                angles.append(angle)
                        if len(angles) >= (MIN_ENCIRCLERS-1):
                            angles.sort()
                            max_gap = 0
                            for k in range(len(angles)):
                                gap = angles[(k+1)%len(angles)] - angles[k]
                                if gap < 0: gap += 360
                                max_gap = max(max_gap, gap)
                            if max_gap < min_max_gap:
                                min_max_gap = max_gap; best_target = target
                    debug_gap = min_max_gap
                    if min_max_gap < 360:
                        debug_enclosed = int((360-min_max_gap)/3.6)
                    if min_max_gap < MAX_GAP_THRESHOLD and best_target:
                        best_target['role'] = "TARGET"
                        current_alerts.append("ENCIRCLEMENT")
                        if time.time() - alert_cooldown.get("circle", 0) > 10:
                            path, i_id = _create_incident_report(
                                list(video_buffer), frame, best_target['id'],
                                "ENCIRCLEMENT",
                                {"max_gap_deg": int(min_max_gap), "enclosed_pct": debug_enclosed})
                            alert_cooldown["circle"] = time.time()
                            detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
                            pending_after_snapshots.append((time.time()+2.0, path))

                # Posture threats
                for p in current_people:
                    if p["threat_score"] > 0:
                        current_alerts.append(p["threat_reason"])
                        ckey = f"posture_{p['id']}"
                        if time.time() - alert_cooldown.get(ckey, 0) > 10:
                            path, i_id = _create_incident_report(
                                list(video_buffer), frame, p['id'],
                                p["threat_reason"],
                                {"threat_score": p["threat_score"],
                                 "reason": p["threat_reason"]})
                            alert_cooldown[ckey] = time.time()
                            detection_log.insert(0, f"⚠️ INCIDENT #{i_id}: {p['threat_reason']}")
                            if p["threat_score"] > 70:
                                gsm_alert.send_sms(
                                    "+1234567890",
                                    f"High threat: {p['threat_reason']}, Score: {p['threat_score']}")

                # Drawing
                for p in current_people:
                    color = (0,255,0)
                    if p['role'] in ("TARGET","ATTACKER") or p.get("threat_score",0) > 0:
                        color = (0,0,255)
                    x1,y1,x2,y2 = p['box']
                    cv2.rectangle(frame, (x1,y1), (x2,y2), color, 2)
                    cv2.putText(frame, f"ID:{p['id']}", (x1,y1-10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

                # UI updates
                with tab1:
                    if current_alerts:
                        status_placeholder.error(
                            f"🚨 ALERT: {' + '.join(set(current_alerts))}")
                    else:
                        status_placeholder.success("✅ SYSTEM SECURE")

                    metric_speed.metric("Speed Change", "Active")
                    metric_prox.metric(
                        "Min Distance",
                        f"{int(min_dist_val)} px" if min_dist_val != 999 else "-")
                    metric_encircle.metric(
                        "Encirclement", f"{debug_enclosed}% Enclosed",
                        delta=f"Gap: {int(debug_gap)}°", delta_color="inverse")
                    log_placeholder.text("\n".join(detection_log[:5]))
                    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    video_placeholder.image(
                        frame_rgb, channels="RGB", use_container_width=True)

        cap.release()

    else:
        with tab1:
            status_placeholder.info("⏸️ Camera paused — check 'Activate Camera' in the sidebar to start.")