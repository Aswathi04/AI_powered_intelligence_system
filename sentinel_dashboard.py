# # # # import streamlit as st
# # # # import cv2
# # # # import time
# # # # import math
# # # # import os
# # # # import json
# # # # import numpy as np
# # # # from datetime import datetime
# # # # from collections import deque
# # # # from ultralytics import YOLO
# # # # from tracking.deepsort_tracker import PersonTracker
# # # # from pose.mediapipe_estimator import PoseEstimator
# # # # from logic.threat_scorer import ThreatScorer
# # # # from alerts.gsm_alert import GSMAlert

# # # # # --- CONFIGURATION ---
# # # # st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

# # # # FRAME_WIDTH = 640
# # # # FRAME_HEIGHT = 480
# # # # SKIP_FRAMES = 2

# # # # # --- SENSITIVITY SETTINGS ---
# # # # SPEED_THRESHOLD = 2.5
# # # # PROXIMITY_LIMIT = 220
# # # # ENCIRCLEMENT_DIST = 300
# # # # MAX_GAP_THRESHOLD = 200
# # # # MIN_ENCIRCLERS = 3

# # # # EVIDENCE_ROOT = "evidence/incidents"
# # # # BUFFER_SIZE = 30

# # # # # --- HELPER FUNCTIONS ---

# # # # def get_stats():
# # # #     """Scans all reports to calculate live statistics."""
# # # #     total = confirmed = false_alarm = pending = 0

# # # #     if os.path.exists(EVIDENCE_ROOT):
# # # #         for day_folder in os.listdir(EVIDENCE_ROOT):
# # # #             day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# # # #             if os.path.isdir(day_path):
# # # #                 for inc_folder in os.listdir(day_path):
# # # #                     json_path = os.path.join(day_path, inc_folder, "report.json")
# # # #                     if os.path.exists(json_path):
# # # #                         total += 1
# # # #                         try:
# # # #                             with open(json_path, "r") as f:
# # # #                                 data = json.load(f)
# # # #                             status = data.get("review_status", "PENDING")
# # # #                             if status == "CONFIRMED":
# # # #                                 confirmed += 1
# # # #                             elif status == "FALSE_ALARM":
# # # #                                 false_alarm += 1
# # # #                             else:
# # # #                                 pending += 1
# # # #                         except Exception:
# # # #                             pending += 1

# # # #     accuracy = 0
# # # #     if (confirmed + false_alarm) > 0:
# # # #         accuracy = (confirmed / (confirmed + false_alarm)) * 100

# # # #     return total, confirmed, false_alarm, pending, int(accuracy)


# # # # def update_incident_status(report_path, status, note):
# # # #     """Updates the JSON report with the security guard's decision."""
# # # #     if os.path.exists(report_path):
# # # #         with open(report_path, "r") as f:
# # # #             data = json.load(f)
# # # #         data["review_status"] = status
# # # #         data["reviewed_by"] = "Security Officer"
# # # #         data["reviewed_at"] = datetime.now().isoformat()
# # # #         data["review_note"] = note
# # # #         with open(report_path, "w") as f:
# # # #             json.dump(data, f, indent=4)
# # # #         return True
# # # #     return False


# # # # def annotate_frame(frame, text, score, color=(0, 0, 255)):
# # # #     annotated = frame.copy()
# # # #     h, w = annotated.shape[:2]
# # # #     cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
# # # #     cv2.putText(annotated, f"ALERT: {text}", (10, 35),
# # # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
# # # #     cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
# # # #     cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
# # # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
# # # #     ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# # # #     cv2.putText(annotated, ts, (w - 220, h - 10),
# # # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
# # # #     return annotated


# # # # def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
# # # #     timestamp = datetime.now().strftime("%H-%M-%S")
# # # #     date_str = datetime.now().strftime("%Y%m%d")
# # # #     incident_id = 1
# # # #     daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
# # # #     if os.path.exists(daily_dir):
# # # #         existing = [d for d in os.listdir(daily_dir)
# # # #                     if os.path.isdir(os.path.join(daily_dir, d))]
# # # #         incident_id = len(existing) + 1

# # # #     folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
# # # #     save_path = os.path.join(daily_dir, folder_name)
# # # #     os.makedirs(save_path, exist_ok=True)

# # # #     threat_score = metrics.get("threat_score", 85)

# # # #     # FIX 7: Use the actual rolling buffer correctly.
# # # #     # buffer is a plain list snapshot of the deque passed in.
# # # #     # We want the frame ~15 steps before the end of that snapshot.
# # # #     if len(buffer) > 15:
# # # #         frame_before = buffer[-15]
# # # #     elif buffer:
# # # #         frame_before = buffer[0]
# # # #     else:
# # # #         frame_before = peak_frame

# # # #     img_before = annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
# # # #     img_peak = annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))

# # # #     cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
# # # #     cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"), img_peak)

# # # #     report = {
# # # #         "incident_id": f"INCIDENT_{incident_id:03d}",
# # # #         "detection_type": alert_type,
# # # #         "timestamp": datetime.now().isoformat(),
# # # #         "threat_score": threat_score,
# # # #         "metrics": metrics,
# # # #         "review_status": "PENDING",
# # # #         "evidence_files": [
# # # #             "snapshot_before.jpg",
# # # #             "snapshot_peak.jpg",
# # # #             "snapshot_after.jpg (pending)"
# # # #         ]
# # # #     }

# # # #     with open(os.path.join(save_path, "report.json"), "w") as f:
# # # #         json.dump(report, f, indent=4)

# # # #     return save_path, incident_id


# # # # # --- UI LAYOUT ---
# # # # st.title("🛡️ Sentinel AI: Security Operations Center")

# # # # total, confirmed, false_alarms, pending, accuracy = get_stats()
# # # # k1, k2, k3, k4, k5 = st.columns(5)
# # # # k1.metric("Total Alerts", total)
# # # # k2.metric("Confirmed Threats", confirmed,
# # # #           delta="Action Required" if confirmed > 0 else None,
# # # #           delta_color="inverse")
# # # # k3.metric("False Alarms", false_alarms)
# # # # k4.metric("Pending Review", pending,
# # # #           delta="Urgent" if pending > 0 else "All Clear",
# # # #           delta_color="inverse")
# # # # k5.metric("System Accuracy", f"{accuracy}%")

# # # # st.divider()

# # # # tab1, tab2 = st.tabs(["🔴 Live Tactical View", "🗂️ Incident Review & Audit"])

# # # # # --- TAB 1: LIVE MONITOR ---
# # # # with tab1:
# # # #     status_placeholder = st.empty()
# # # #     col1, col2 = st.columns([3, 1])
# # # #     with col1:
# # # #         st.subheader("Live Feed")
# # # #         video_placeholder = st.empty()
# # # #     with col2:
# # # #         st.subheader("Active Threats")
# # # #         metric_speed = st.empty()
# # # #         metric_prox = st.empty()
# # # #         metric_encircle = st.empty()
# # # #         st.divider()
# # # #         st.write("### Live Log")
# # # #         log_placeholder = st.empty()

# # # # # --- TAB 2: INCIDENT REVIEW ---
# # # # with tab2:
# # # #     st.header("🗂️ Incident Case Files")
# # # #     st.info("Uncheck 'ACTIVATE SYSTEM' to review evidence.")
# # # #     evidence_col, viewer_col = st.columns([1, 2])

# # # #     with evidence_col:
# # # #         all_files = []
# # # #         if os.path.exists(EVIDENCE_ROOT):
# # # #             for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
# # # #                 day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# # # #                 if os.path.isdir(day_path):
# # # #                     for inc_folder in sorted(os.listdir(day_path), reverse=True):
# # # #                         if inc_folder.startswith("INCIDENT"):
# # # #                             status_icon = "🟡"
# # # #                             try:
# # # #                                 with open(os.path.join(day_path, inc_folder, "report.json")) as f:
# # # #                                     d = json.load(f)
# # # #                                 s = d.get("review_status", "PENDING")
# # # #                                 if s == "CONFIRMED":
# # # #                                     status_icon = "🟢"
# # # #                                 elif s == "FALSE_ALARM":
# # # #                                     status_icon = "⚪"
# # # #                             except Exception:
# # # #                                 pass
# # # #                             display_name = f"{status_icon} {inc_folder[9:]}"
# # # #                             all_files.append((display_name,
# # # #                                               os.path.join(day_path, inc_folder)))

# # # #         selected_file = (st.selectbox("Select Case:", all_files,
# # # #                                        format_func=lambda x: x[0])
# # # #                          if all_files else None)

# # # #     with viewer_col:
# # # #         if selected_file:
# # # #             folder_path = selected_file[1]
# # # #             json_path = os.path.join(folder_path, "report.json")

# # # #             if os.path.exists(json_path):
# # # #                 with open(json_path, "r") as f:
# # # #                     report = json.load(f)

# # # #                 status = report.get("review_status", "PENDING")
# # # #                 if status == "CONFIRMED":
# # # #                     st.error(f"✅ CONFIRMED THREAT (Verified by {report.get('reviewed_by')})")
# # # #                     if report.get("review_note"):
# # # #                         st.caption(f"📝 Note: {report.get('review_note')}")
# # # #                 elif status == "FALSE_ALARM":
# # # #                     st.success(f"❌ FALSE ALARM (Verified by {report.get('reviewed_by')})")
# # # #                     if report.get("review_note"):
# # # #                         st.caption(f"📝 Note: {report.get('review_note')}")
# # # #                 else:
# # # #                     st.warning("⚠️ PENDING SECURITY REVIEW")
# # # #                     with st.form("review_form"):
# # # #                         note = st.text_input("Add Note (Optional)",
# # # #                                              placeholder="e.g. Friends greeting, Staff member...")
# # # #                         c1, c2 = st.columns(2)
# # # #                         confirm_btn = c1.form_submit_button("✅ Confirm Threat", type="primary")
# # # #                         false_alarm_btn = c2.form_submit_button("❌ False Alarm")

# # # #                         if confirm_btn:
# # # #                             update_incident_status(json_path, "CONFIRMED", note)
# # # #                             st.rerun()
# # # #                         if false_alarm_btn:
# # # #                             update_incident_status(json_path, "FALSE_ALARM", note)
# # # #                             st.rerun()

# # # #                 metrics_data = report.get(
# # # #                     'metrics', {"info": "Legacy Data - No details available"})
# # # #                 st.json(metrics_data)

# # # #                 c1, c2, c3 = st.columns(3)
# # # #                 p_before = os.path.join(folder_path, "snapshot_before.jpg")
# # # #                 p_peak = os.path.join(folder_path, "snapshot_peak.jpg")
# # # #                 p_after = os.path.join(folder_path, "snapshot_after.jpg")

# # # #                 if os.path.exists(p_before):
# # # #                     c1.image(p_before, caption="BEFORE", use_container_width=True)
# # # #                 if os.path.exists(p_peak):
# # # #                     c2.image(p_peak, caption="PEAK (Alert)", use_container_width=True)
# # # #                 if os.path.exists(p_after):
# # # #                     c3.image(p_after, caption="AFTER", use_container_width=True)

# # # # # --- AI INIT ---
# # # # @st.cache_resource
# # # # def load_model():
# # # #     return YOLO('yolo11n.pt')

# # # # model = load_model()
# # # # tracker = PersonTracker()
# # # # pose_estimator = PoseEstimator()
# # # # threat_scorer = ThreatScorer()

# # # # # --- SIDEBAR CONTROLS ---
# # # # st.sidebar.title("System Control")
# # # # system_active = st.sidebar.checkbox("ACTIVATE SURVEILLANCE", value=True)

# # # # # FIX 5: Make GSM port configurable from the sidebar, not hardcoded.
# # # # gsm_port = st.sidebar.text_input("GSM Port", value="COM3",
# # # #                                   help="Windows: COM3  |  Linux: /dev/ttyUSB0")
# # # # gsm_alert = GSMAlert(port=gsm_port)

# # # # # --- MAIN LOOP ---
# # # # if system_active:
# # # #     cap = cv2.VideoCapture(0)
# # # #     cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
# # # #     cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

# # # #     speed_history = {}
# # # #     pos_history = {}

# # # #     video_buffer = deque(maxlen=BUFFER_SIZE)
# # # #     alert_cooldown = {}
# # # #     detection_log = []
# # # #     pending_after_snapshots = []

# # # #     frame_count = 0

# # # #     # FIX 6: Use a Streamlit stop_button so the loop can be broken cleanly
# # # #     # from the UI without relying on a variable that Streamlit can't refresh
# # # #     # mid-loop. The loop also re-checks the checkbox state each iteration
# # # #     # by reading the session_state key directly.
# # # #     stop_btn = st.sidebar.button("⏹ Stop Feed")

# # # #     while cap.isOpened() and not stop_btn:
# # # #         ret, frame = cap.read()
# # # #         if not ret:
# # # #             break

# # # #         frame_count += 1
# # # #         video_buffer.append(frame.copy())

# # # #         # Save post-event snapshot after 2-second delay
# # # #         remaining = []
# # # #         for trigger_time, folder_path in pending_after_snapshots:
# # # #             if time.time() > trigger_time:
# # # #                 img_after = annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
# # # #                 cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
# # # #             else:
# # # #                 remaining.append((trigger_time, folder_path))
# # # #         pending_after_snapshots = remaining

# # # #         current_alerts = []

# # # #         # FIX 3: Initialise min_dist_val before any proximity check so it
# # # #         # is always defined when metric_prox reads it below.
# # # #         min_dist_val = 999

# # # #         if frame_count % SKIP_FRAMES == 0:
# # # #             results = model.track(frame, persist=True, verbose=False, classes=[0])
# # # #             current_people = []

# # # #             if results[0].boxes.id is not None:
# # # #                 boxes = results[0].boxes.xyxy.cpu().numpy()
# # # #                 ids = results[0].boxes.id.int().cpu().numpy()

# # # #                 for box, track_id in zip(boxes, ids):
# # # #                     # FIX 4: Cast all coords to int immediately so every
# # # #                     # downstream cv2 call receives integer values.
# # # #                     x1, y1, x2, y2 = map(int, box)
# # # #                     w, h = x2 - x1, y2 - y1
# # # #                     cx, cy = x1 + w // 2, y1 + h // 2

# # # #                     person = {
# # # #                         "id": track_id,
# # # #                         "box": (x1, y1, x2, y2),
# # # #                         "center": (cx, cy),
# # # #                         "role": "NEUTRAL",
# # # #                         "threat_score": 0,
# # # #                         "threat_reason": "Scanning...",
# # # #                         "speed_display": "1.0x",
# # # #                     }

# # # #                     # Pose estimation and threat scoring
# # # #                     landmarks = pose_estimator.estimate_pose(frame, (x1, y1, x2, y2))
# # # #                     score, reason = threat_scorer.update(track_id, (x1, y1, w, h), landmarks)
# # # #                     person["threat_score"] = score
# # # #                     person["threat_reason"] = reason

# # # #                     # --------------------------------------------------
# # # #                     # FIX 1 + FIX 2: Speed check moved INSIDE the per-person
# # # #                     # loop, using the local track_id / cx / cy / person vars
# # # #                     # that are defined right above.
# # # #                     # --------------------------------------------------
# # # #                     speed_ratio = 1.0
# # # #                     if track_id in pos_history:
# # # #                         prev_cx, prev_cy = pos_history[track_id]
# # # #                         dist_moved = math.sqrt(
# # # #                             (cx - prev_cx) ** 2 + (cy - prev_cy) ** 2)

# # # #                         if track_id not in speed_history:
# # # #                             speed_history[track_id] = deque(maxlen=10)
# # # #                         speed_history[track_id].append(dist_moved)

# # # #                         if len(speed_history[track_id]) >= 5:
# # # #                             avg_speed = (sum(speed_history[track_id])
# # # #                                          / len(speed_history[track_id]))
# # # #                             if avg_speed > 2.0:
# # # #                                 speed_ratio = dist_moved / avg_speed

# # # #                             if speed_ratio > SPEED_THRESHOLD:
# # # #                                 current_alerts.append("SPEED CHANGE")
# # # #                                 person["role"] = "ATTACKER"

# # # #                                 cooldown_key = f"speed_{track_id}"
# # # #                                 if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# # # #                                     metrics = {"speed_ratio": f"{speed_ratio:.2f}x"}
# # # #                                     path, i_id = create_incident_report(
# # # #                                         list(video_buffer), frame,
# # # #                                         track_id, "SPEED CHANGE", metrics)
# # # #                                     alert_cooldown[cooldown_key] = time.time()
# # # #                                     detection_log.insert(
# # # #                                         0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
# # # #                                     pending_after_snapshots.append(
# # # #                                         (time.time() + 2.0, path))

# # # #                     pos_history[track_id] = (cx, cy)
# # # #                     person["speed_display"] = f"{speed_ratio:.1f}x"

# # # #                     current_people.append(person)

# # # #             # Clean up stale tracker targets
# # # #             current_ids = [p['id'] for p in current_people]
# # # #             for tid in list(threat_scorer.targets.keys()):
# # # #                 if tid not in current_ids:
# # # #                     del threat_scorer.targets[tid]

# # # #             # ----------------------------------------------------------
# # # #             # 2. PROXIMITY
# # # #             # ----------------------------------------------------------
# # # #             for i in range(len(current_people)):
# # # #                 for j in range(i + 1, len(current_people)):
# # # #                     p1, p2 = current_people[i], current_people[j]
# # # #                     dist = math.sqrt(
# # # #                         (p1['center'][0] - p2['center'][0]) ** 2 +
# # # #                         (p1['center'][1] - p2['center'][1]) ** 2)
# # # #                     min_dist_val = min(min_dist_val, dist)

# # # #                     if dist < PROXIMITY_LIMIT:
# # # #                         current_alerts.append("PROXIMITY")
# # # #                         cv2.line(frame, p1['center'], p2['center'],
# # # #                                  (0, 0, 255), 3)

# # # #                         if time.time() - alert_cooldown.get("prox", 0) > 10:
# # # #                             metrics = {"distance_px": int(dist)}
# # # #                             path, i_id = create_incident_report(
# # # #                                 list(video_buffer), frame,
# # # #                                 0, "PROXIMITY", metrics)
# # # #                             alert_cooldown["prox"] = time.time()
# # # #                             detection_log.insert(
# # # #                                 0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
# # # #                             pending_after_snapshots.append(
# # # #                                 (time.time() + 2.0, path))
# # # #                     else:
# # # #                         cv2.line(frame, p1['center'], p2['center'],
# # # #                                  (0, 255, 0), 1)

# # # #             # ----------------------------------------------------------
# # # #             # 3. ENCIRCLEMENT
# # # #             # ----------------------------------------------------------
# # # #             debug_gap = 360
# # # #             debug_enclosed = 0
# # # #             if len(current_people) >= MIN_ENCIRCLERS:
# # # #                 min_max_gap = 360
# # # #                 best_target = None

# # # #                 for target in current_people:
# # # #                     angles = []
# # # #                     for other in current_people:
# # # #                         if target['id'] == other['id']:
# # # #                             continue
# # # #                         dx = other['center'][0] - target['center'][0]
# # # #                         dy = other['center'][1] - target['center'][1]
# # # #                         if math.sqrt(dx * dx + dy * dy) < ENCIRCLEMENT_DIST:
# # # #                             angle = math.degrees(math.atan2(dy, dx))
# # # #                             if angle < 0:
# # # #                                 angle += 360
# # # #                             angles.append(angle)

# # # #                     if len(angles) >= (MIN_ENCIRCLERS - 1):
# # # #                         angles.sort()
# # # #                         max_gap = 0
# # # #                         for k in range(len(angles)):
# # # #                             gap = angles[(k + 1) % len(angles)] - angles[k]
# # # #                             if gap < 0:
# # # #                                 gap += 360
# # # #                             max_gap = max(max_gap, gap)

# # # #                         if max_gap < min_max_gap:
# # # #                             min_max_gap = max_gap
# # # #                             best_target = target

# # # #                 debug_gap = min_max_gap
# # # #                 if min_max_gap < 360:
# # # #                     debug_enclosed = int((360 - min_max_gap) / 3.6)

# # # #                 if min_max_gap < MAX_GAP_THRESHOLD and best_target:
# # # #                     best_target['role'] = "TARGET"
# # # #                     current_alerts.append("ENCIRCLEMENT")
# # # #                     if time.time() - alert_cooldown.get("circle", 0) > 10:
# # # #                         metrics = {
# # # #                             "max_gap_deg": int(min_max_gap),
# # # #                             "enclosed_pct": debug_enclosed
# # # #                         }
# # # #                         path, i_id = create_incident_report(
# # # #                             list(video_buffer), frame,
# # # #                             best_target['id'], "ENCIRCLEMENT", metrics)
# # # #                         alert_cooldown["circle"] = time.time()
# # # #                         detection_log.insert(
# # # #                             0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
# # # #                         pending_after_snapshots.append(
# # # #                             (time.time() + 2.0, path))

# # # #             # ----------------------------------------------------------
# # # #             # 4. POSTURE THREATS (from ThreatScorer)
# # # #             # ----------------------------------------------------------
# # # #             for p in current_people:
# # # #                 if p["threat_score"] > 0:
# # # #                     current_alerts.append(p["threat_reason"])
# # # #                     cooldown_key = f"posture_{p['id']}"
# # # #                     if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# # # #                         metrics = {
# # # #                             "threat_score": p["threat_score"],
# # # #                             "reason": p["threat_reason"]
# # # #                         }
# # # #                         path, i_id = create_incident_report(
# # # #                             list(video_buffer), frame,
# # # #                             p['id'], p["threat_reason"], metrics)
# # # #                         alert_cooldown[cooldown_key] = time.time()
# # # #                         detection_log.insert(
# # # #                             0, f"⚠️ INCIDENT #{i_id}: {p['threat_reason']}")
# # # #                         if p["threat_score"] > 70:
# # # #                             gsm_alert.send_sms(
# # # #                                 "+1234567890",
# # # #                                 f"High threat: {p['threat_reason']}, "
# # # #                                 f"Score: {p['threat_score']}")

# # # #             # ----------------------------------------------------------
# # # #             # DRAWING
# # # #             # ----------------------------------------------------------
# # # #             for p in current_people:
# # # #                 color = (0, 255, 0)
# # # #                 if p['role'] in ("TARGET", "ATTACKER"):
# # # #                     color = (0, 0, 255)
# # # #                 elif p.get("threat_score", 0) > 0:
# # # #                     color = (0, 0, 255)

# # # #                 x1, y1, x2, y2 = p['box']   # already ints (FIX 4)
# # # #                 cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
# # # #                 cv2.putText(frame, f"ID:{p['id']}",
# # # #                             (x1, y1 - 10),
# # # #                             cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

# # # #             # ----------------------------------------------------------
# # # #             # UI UPDATES
# # # #             # ----------------------------------------------------------
# # # #             status_text = "SYSTEM SECURE"
# # # #             if current_alerts:
# # # #                 status_text = f"🚨 ALERT: {' + '.join(set(current_alerts))}"
# # # #                 status_placeholder.error(status_text)
# # # #             else:
# # # #                 status_placeholder.success(status_text)

# # # #             metric_speed.metric("Speed Change", "Active")
# # # #             metric_prox.metric(
# # # #                 "Min Distance",
# # # #                 f"{int(min_dist_val)} px" if min_dist_val != 999 else "-"
# # # #             )
# # # #             metric_encircle.metric(
# # # #                 "Encirclement",
# # # #                 f"{debug_enclosed}% Enclosed",
# # # #                 delta=f"Gap: {int(debug_gap)}°",
# # # #                 delta_color="inverse"
# # # #             )

# # # #             log_placeholder.text("\n".join(detection_log[:5]))

# # # #             frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
# # # #             video_placeholder.image(frame_rgb, channels="RGB",
# # # #                                     use_container_width=True)

# # # #     cap.release()
# # # # else:
# # # #     status_placeholder = st.empty()
# # # #     status_placeholder.info("⏸️ Monitor Paused")

# # # import streamlit as st
# # # import cv2
# # # import time
# # # import math
# # # import os
# # # import json
# # # import numpy as np
# # # from datetime import datetime
# # # from collections import deque
# # # from ultralytics import YOLO
# # # from tracking.deepsort_tracker import PersonTracker
# # # from pose.mediapipe_estimator import PoseEstimator
# # # from logic.threat_scorer import ThreatScorer
# # # from alerts.gsm_alert import GSMAlert

# # # # --- CONFIGURATION ---
# # # st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

# # # FRAME_WIDTH = 640
# # # FRAME_HEIGHT = 480
# # # SKIP_FRAMES = 2

# # # # --- SENSITIVITY SETTINGS ---
# # # SPEED_THRESHOLD = 2.5
# # # PROXIMITY_LIMIT = 220
# # # ENCIRCLEMENT_DIST = 300
# # # MAX_GAP_THRESHOLD = 200
# # # MIN_ENCIRCLERS = 3

# # # EVIDENCE_ROOT = "evidence/incidents"
# # # BUFFER_SIZE = 30

# # # # --- HELPER FUNCTIONS ---

# # # def get_stats():
# # #     """Scans all reports to calculate live statistics."""
# # #     total = confirmed = false_alarm = pending = 0

# # #     if os.path.exists(EVIDENCE_ROOT):
# # #         for day_folder in os.listdir(EVIDENCE_ROOT):
# # #             day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# # #             if os.path.isdir(day_path):
# # #                 for inc_folder in os.listdir(day_path):
# # #                     json_path = os.path.join(day_path, inc_folder, "report.json")
# # #                     if os.path.exists(json_path):
# # #                         total += 1
# # #                         try:
# # #                             with open(json_path, "r") as f:
# # #                                 data = json.load(f)
# # #                             status = data.get("review_status", "PENDING")
# # #                             if status == "CONFIRMED":
# # #                                 confirmed += 1
# # #                             elif status == "FALSE_ALARM":
# # #                                 false_alarm += 1
# # #                             else:
# # #                                 pending += 1
# # #                         except Exception:
# # #                             pending += 1

# # #     accuracy = 0
# # #     if (confirmed + false_alarm) > 0:
# # #         accuracy = (confirmed / (confirmed + false_alarm)) * 100

# # #     return total, confirmed, false_alarm, pending, int(accuracy)


# # # def update_incident_status(report_path, status, note):
# # #     """Updates the JSON report with the security guard's decision."""
# # #     if os.path.exists(report_path):
# # #         with open(report_path, "r") as f:
# # #             data = json.load(f)
# # #         data["review_status"] = status
# # #         data["reviewed_by"] = "Security Officer"
# # #         data["reviewed_at"] = datetime.now().isoformat()
# # #         data["review_note"] = note
# # #         with open(report_path, "w") as f:
# # #             json.dump(data, f, indent=4)
# # #         return True
# # #     return False


# # # def annotate_frame(frame, text, score, color=(0, 0, 255)):
# # #     annotated = frame.copy()
# # #     h, w = annotated.shape[:2]
# # #     cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
# # #     cv2.putText(annotated, f"ALERT: {text}", (10, 35),
# # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
# # #     cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
# # #     cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
# # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
# # #     ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# # #     cv2.putText(annotated, ts, (w - 220, h - 10),
# # #                 cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
# # #     return annotated


# # # def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
# # #     timestamp = datetime.now().strftime("%H-%M-%S")
# # #     date_str = datetime.now().strftime("%Y%m%d")
# # #     incident_id = 1
# # #     daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
# # #     if os.path.exists(daily_dir):
# # #         existing = [d for d in os.listdir(daily_dir)
# # #                     if os.path.isdir(os.path.join(daily_dir, d))]
# # #         incident_id = len(existing) + 1

# # #     folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
# # #     save_path = os.path.join(daily_dir, folder_name)
# # #     os.makedirs(save_path, exist_ok=True)

# # #     threat_score = metrics.get("threat_score", 85)

# # #     # FIX 7: Use the actual rolling buffer correctly.
# # #     # buffer is a plain list snapshot of the deque passed in.
# # #     # We want the frame ~15 steps before the end of that snapshot.
# # #     if len(buffer) > 15:
# # #         frame_before = buffer[-15]
# # #     elif buffer:
# # #         frame_before = buffer[0]
# # #     else:
# # #         frame_before = peak_frame

# # #     img_before = annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
# # #     img_peak = annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))

# # #     cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
# # #     cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"), img_peak)

# # #     report = {
# # #         "incident_id": f"INCIDENT_{incident_id:03d}",
# # #         "detection_type": alert_type,
# # #         "timestamp": datetime.now().isoformat(),
# # #         "threat_score": threat_score,
# # #         "metrics": metrics,
# # #         "review_status": "PENDING",
# # #         "evidence_files": [
# # #             "snapshot_before.jpg",
# # #             "snapshot_peak.jpg",
# # #             "snapshot_after.jpg (pending)"
# # #         ]
# # #     }

# # #     with open(os.path.join(save_path, "report.json"), "w") as f:
# # #         json.dump(report, f, indent=4)

# # #     return save_path, incident_id


# # # def is_valid_person_detection(box, frame_shape, min_area_ratio=0.04, min_aspect=1.2):
# # #     """
# # #     Returns True only if the bounding box looks like a real standing person.
# # #     Filters out ghost detections caused by raised hands, fists, or partial limbs.
# # #       - min_area_ratio: box must cover at least this fraction of the frame area
# # #       - min_aspect:     box height/width must exceed this (portrait shape check)
# # #     """
# # #     x1, y1, x2, y2 = box
# # #     w = x2 - x1
# # #     h = y2 - y1
# # #     if w <= 0 or h <= 0:
# # #         return False
# # #     frame_h, frame_w = frame_shape
# # #     if (w * h) / (frame_h * frame_w) < min_area_ratio:
# # #         return False
# # #     if (h / w) < min_aspect:
# # #         return False
# # #     return True


# # # def compute_iou(box_a, box_b):
# # #     """Intersection-over-Union of two (x1, y1, x2, y2) boxes. Returns [0, 1]."""
# # #     ax1, ay1, ax2, ay2 = box_a
# # #     bx1, by1, bx2, by2 = box_b
# # #     inter_x1, inter_y1 = max(ax1, bx1), max(ay1, by1)
# # #     inter_x2, inter_y2 = min(ax2, bx2), min(ay2, by2)
# # #     inter_area = max(0, inter_x2 - inter_x1) * max(0, inter_y2 - inter_y1)
# # #     if inter_area == 0:
# # #         return 0.0
# # #     union_area = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter_area
# # #     return inter_area / union_area if union_area > 0 else 0.0


# # # def is_center_inside_box(center, box):
# # #     """Returns True if point (cx, cy) lies inside (x1, y1, x2, y2)."""
# # #     cx, cy = center
# # #     x1, y1, x2, y2 = box
# # #     return x1 <= cx <= x2 and y1 <= cy <= y2


# # # # --- UI LAYOUT ---
# # # st.title("🛡️ Sentinel AI: Security Operations Center")

# # # total, confirmed, false_alarms, pending, accuracy = get_stats()
# # # k1, k2, k3, k4, k5 = st.columns(5)
# # # k1.metric("Total Alerts", total)
# # # k2.metric("Confirmed Threats", confirmed,
# # #           delta="Action Required" if confirmed > 0 else None,
# # #           delta_color="inverse")
# # # k3.metric("False Alarms", false_alarms)
# # # k4.metric("Pending Review", pending,
# # #           delta="Urgent" if pending > 0 else "All Clear",
# # #           delta_color="inverse")
# # # k5.metric("System Accuracy", f"{accuracy}%")

# # # st.divider()

# # # tab1, tab2 = st.tabs(["🔴 Live Tactical View", "🗂️ Incident Review & Audit"])

# # # # --- TAB 1: LIVE MONITOR ---
# # # with tab1:
# # #     status_placeholder = st.empty()
# # #     col1, col2 = st.columns([3, 1])
# # #     with col1:
# # #         st.subheader("Live Feed")
# # #         video_placeholder = st.empty()
# # #     with col2:
# # #         st.subheader("Active Threats")
# # #         metric_speed = st.empty()
# # #         metric_prox = st.empty()
# # #         metric_encircle = st.empty()
# # #         st.divider()
# # #         st.write("### Live Log")
# # #         log_placeholder = st.empty()

# # # # --- TAB 2: INCIDENT REVIEW ---
# # # with tab2:
# # #     st.header("🗂️ Incident Case Files")
# # #     st.info("Uncheck 'ACTIVATE SYSTEM' to review evidence.")
# # #     evidence_col, viewer_col = st.columns([1, 2])

# # #     with evidence_col:
# # #         all_files = []
# # #         if os.path.exists(EVIDENCE_ROOT):
# # #             for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
# # #                 day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# # #                 if os.path.isdir(day_path):
# # #                     for inc_folder in sorted(os.listdir(day_path), reverse=True):
# # #                         if inc_folder.startswith("INCIDENT"):
# # #                             status_icon = "🟡"
# # #                             try:
# # #                                 with open(os.path.join(day_path, inc_folder, "report.json")) as f:
# # #                                     d = json.load(f)
# # #                                 s = d.get("review_status", "PENDING")
# # #                                 if s == "CONFIRMED":
# # #                                     status_icon = "🟢"
# # #                                 elif s == "FALSE_ALARM":
# # #                                     status_icon = "⚪"
# # #                             except Exception:
# # #                                 pass
# # #                             display_name = f"{status_icon} {inc_folder[9:]}"
# # #                             all_files.append((display_name,
# # #                                               os.path.join(day_path, inc_folder)))

# # #         selected_file = (st.selectbox("Select Case:", all_files,
# # #                                        format_func=lambda x: x[0])
# # #                          if all_files else None)

# # #     with viewer_col:
# # #         if selected_file:
# # #             folder_path = selected_file[1]
# # #             json_path = os.path.join(folder_path, "report.json")

# # #             if os.path.exists(json_path):
# # #                 with open(json_path, "r") as f:
# # #                     report = json.load(f)

# # #                 status = report.get("review_status", "PENDING")
# # #                 if status == "CONFIRMED":
# # #                     st.error(f"✅ CONFIRMED THREAT (Verified by {report.get('reviewed_by')})")
# # #                     if report.get("review_note"):
# # #                         st.caption(f"📝 Note: {report.get('review_note')}")
# # #                 elif status == "FALSE_ALARM":
# # #                     st.success(f"❌ FALSE ALARM (Verified by {report.get('reviewed_by')})")
# # #                     if report.get("review_note"):
# # #                         st.caption(f"📝 Note: {report.get('review_note')}")
# # #                 else:
# # #                     st.warning("⚠️ PENDING SECURITY REVIEW")
# # #                     with st.form("review_form"):
# # #                         note = st.text_input("Add Note (Optional)",
# # #                                              placeholder="e.g. Friends greeting, Staff member...")
# # #                         c1, c2 = st.columns(2)
# # #                         confirm_btn = c1.form_submit_button("✅ Confirm Threat", type="primary")
# # #                         false_alarm_btn = c2.form_submit_button("❌ False Alarm")

# # #                         if confirm_btn:
# # #                             update_incident_status(json_path, "CONFIRMED", note)
# # #                             st.rerun()
# # #                         if false_alarm_btn:
# # #                             update_incident_status(json_path, "FALSE_ALARM", note)
# # #                             st.rerun()

# # #                 metrics_data = report.get(
# # #                     'metrics', {"info": "Legacy Data - No details available"})
# # #                 st.json(metrics_data)

# # #                 c1, c2, c3 = st.columns(3)
# # #                 p_before = os.path.join(folder_path, "snapshot_before.jpg")
# # #                 p_peak = os.path.join(folder_path, "snapshot_peak.jpg")
# # #                 p_after = os.path.join(folder_path, "snapshot_after.jpg")

# # #                 if os.path.exists(p_before):
# # #                     c1.image(p_before, caption="BEFORE", use_container_width=True)
# # #                 if os.path.exists(p_peak):
# # #                     c2.image(p_peak, caption="PEAK (Alert)", use_container_width=True)
# # #                 if os.path.exists(p_after):
# # #                     c3.image(p_after, caption="AFTER", use_container_width=True)

# # # # --- AI INIT ---
# # # @st.cache_resource
# # # def load_model():
# # #     return YOLO('yolo11n.pt')

# # # model = load_model()
# # # tracker = PersonTracker()
# # # pose_estimator = PoseEstimator()
# # # threat_scorer = ThreatScorer()

# # # # --- SIDEBAR CONTROLS ---
# # # st.sidebar.title("System Control")
# # # system_active = st.sidebar.checkbox("ACTIVATE SURVEILLANCE", value=True)

# # # # FIX 5: Make GSM port configurable from the sidebar, not hardcoded.
# # # gsm_port = st.sidebar.text_input("GSM Port", value="COM3",
# # #                                   help="Windows: COM3  |  Linux: /dev/ttyUSB0")
# # # gsm_alert = GSMAlert(port=gsm_port)

# # # # --- MAIN LOOP ---
# # # if system_active:
# # #     cap = cv2.VideoCapture(0)
# # #     cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
# # #     cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

# # #     speed_history = {}
# # #     pos_history = {}

# # #     video_buffer = deque(maxlen=BUFFER_SIZE)
# # #     alert_cooldown = {}
# # #     detection_log = []
# # #     pending_after_snapshots = []

# # #     frame_count = 0

# # #     # FIX 6: Use a Streamlit stop_button so the loop can be broken cleanly
# # #     # from the UI without relying on a variable that Streamlit can't refresh
# # #     # mid-loop. The loop also re-checks the checkbox state each iteration
# # #     # by reading the session_state key directly.
# # #     stop_btn = st.sidebar.button("⏹ Stop Feed")

# # #     while cap.isOpened() and not stop_btn:
# # #         ret, frame = cap.read()
# # #         if not ret:
# # #             break

# # #         frame_count += 1
# # #         video_buffer.append(frame.copy())

# # #         # Save post-event snapshot after 2-second delay
# # #         remaining = []
# # #         for trigger_time, folder_path in pending_after_snapshots:
# # #             if time.time() > trigger_time:
# # #                 img_after = annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
# # #                 cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
# # #             else:
# # #                 remaining.append((trigger_time, folder_path))
# # #         pending_after_snapshots = remaining

# # #         current_alerts = []

# # #         # FIX 3: Initialise min_dist_val before any proximity check so it
# # #         # is always defined when metric_prox reads it below.
# # #         min_dist_val = 999

# # #         if frame_count % SKIP_FRAMES == 0:
# # #             results = model.track(frame, persist=True, verbose=False, classes=[0])
# # #             current_people = []

# # #             if results[0].boxes.id is not None:
# # #                 boxes = results[0].boxes.xyxy.cpu().numpy()
# # #                 ids = results[0].boxes.id.int().cpu().numpy()

# # #                 for box, track_id in zip(boxes, ids):
# # #                     # FIX 4: Cast all coords to int immediately so every
# # #                     # downstream cv2 call receives integer values.
# # #                     x1, y1, x2, y2 = map(int, box)
# # #                     w, h = x2 - x1, y2 - y1
# # #                     cx, cy = x1 + w // 2, y1 + h // 2

# # #                     person = {
# # #                         "id": track_id,
# # #                         "box": (x1, y1, x2, y2),
# # #                         "center": (cx, cy),
# # #                         "role": "NEUTRAL",
# # #                         "threat_score": 0,
# # #                         "threat_reason": "Scanning...",
# # #                         "speed_display": "1.0x",
# # #                     }

# # #                     # Pose estimation and threat scoring
# # #                     landmarks = pose_estimator.estimate_pose(frame, (x1, y1, x2, y2))
# # #                     score, reason = threat_scorer.update(track_id, (x1, y1, w, h), landmarks)
# # #                     person["threat_score"] = score
# # #                     person["threat_reason"] = reason

# # #                     # --------------------------------------------------
# # #                     # FIX 1 + FIX 2: Speed check moved INSIDE the per-person
# # #                     # loop, using the local track_id / cx / cy / person vars
# # #                     # that are defined right above.
# # #                     # --------------------------------------------------
# # #                     speed_ratio = 1.0
# # #                     if track_id in pos_history:
# # #                         prev_cx, prev_cy = pos_history[track_id]
# # #                         dist_moved = math.sqrt(
# # #                             (cx - prev_cx) ** 2 + (cy - prev_cy) ** 2)

# # #                         if track_id not in speed_history:
# # #                             speed_history[track_id] = deque(maxlen=10)
# # #                         speed_history[track_id].append(dist_moved)

# # #                         if len(speed_history[track_id]) >= 5:
# # #                             avg_speed = (sum(speed_history[track_id])
# # #                                          / len(speed_history[track_id]))
# # #                             if avg_speed > 2.0:
# # #                                 speed_ratio = dist_moved / avg_speed

# # #                             if speed_ratio > SPEED_THRESHOLD:
# # #                                 current_alerts.append("SPEED CHANGE")
# # #                                 person["role"] = "ATTACKER"

# # #                                 cooldown_key = f"speed_{track_id}"
# # #                                 if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# # #                                     metrics = {"speed_ratio": f"{speed_ratio:.2f}x"}
# # #                                     path, i_id = create_incident_report(
# # #                                         list(video_buffer), frame,
# # #                                         track_id, "SPEED CHANGE", metrics)
# # #                                     alert_cooldown[cooldown_key] = time.time()
# # #                                     detection_log.insert(
# # #                                         0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
# # #                                     pending_after_snapshots.append(
# # #                                         (time.time() + 2.0, path))

# # #                     pos_history[track_id] = (cx, cy)
# # #                     person["speed_display"] = f"{speed_ratio:.1f}x"

# # #                     current_people.append(person)

# # #             # Clean up stale tracker targets
# # #             current_ids = [p['id'] for p in current_people]
# # #             for tid in list(threat_scorer.targets.keys()):
# # #                 if tid not in current_ids:
# # #                     del threat_scorer.targets[tid]

# # #             # ----------------------------------------------------------
# # #             # 2. PROXIMITY
# # #             # ----------------------------------------------------------
# # #             # Pre-filter: discard ghost detections (raised hands, fists,
# # #             # partial limbs) before running any pairwise distance checks.
# # #             frame_h, frame_w = frame.shape[:2]
# # #             valid_people = [
# # #                 p for p in current_people
# # #                 if is_valid_person_detection(p['box'], (frame_h, frame_w))
# # #             ]

# # #             for i in range(len(valid_people)):
# # #                 for j in range(i + 1, len(valid_people)):
# # #                     p1, p2 = valid_people[i], valid_people[j]

# # #                     # Skip if one detection's center sits inside the other box —
# # #                     # that means the same person was detected twice (e.g. full
# # #                     # body + raised-arm crop both tracked simultaneously).
# # #                     if is_center_inside_box(p1['center'], p2['box']):
# # #                         continue
# # #                     if is_center_inside_box(p2['center'], p1['box']):
# # #                         continue

# # #                     # Skip if the boxes overlap heavily — two separate people
# # #                     # cannot physically occupy the same space.
# # #                     if compute_iou(p1['box'], p2['box']) > 0.30:
# # #                         continue

# # #                     dist = math.sqrt(
# # #                         (p1['center'][0] - p2['center'][0]) ** 2 +
# # #                         (p1['center'][1] - p2['center'][1]) ** 2)
# # #                     min_dist_val = min(min_dist_val, dist)

# # #                     if dist < PROXIMITY_LIMIT:
# # #                         current_alerts.append("PROXIMITY")
# # #                         cv2.line(frame, p1['center'], p2['center'],
# # #                                  (0, 0, 255), 3)

# # #                         if time.time() - alert_cooldown.get("prox", 0) > 10:
# # #                             metrics = {"distance_px": int(dist)}
# # #                             path, i_id = create_incident_report(
# # #                                 list(video_buffer), frame,
# # #                                 0, "PROXIMITY", metrics)
# # #                             alert_cooldown["prox"] = time.time()
# # #                             detection_log.insert(
# # #                                 0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
# # #                             pending_after_snapshots.append(
# # #                                 (time.time() + 2.0, path))
# # #                     else:
# # #                         cv2.line(frame, p1['center'], p2['center'],
# # #                                  (0, 255, 0), 1)

# # #             # ----------------------------------------------------------
# # #             # 3. ENCIRCLEMENT
# # #             # ----------------------------------------------------------
# # #             debug_gap = 360
# # #             debug_enclosed = 0
# # #             if len(current_people) >= MIN_ENCIRCLERS:
# # #                 min_max_gap = 360
# # #                 best_target = None

# # #                 for target in current_people:
# # #                     angles = []
# # #                     for other in current_people:
# # #                         if target['id'] == other['id']:
# # #                             continue
# # #                         dx = other['center'][0] - target['center'][0]
# # #                         dy = other['center'][1] - target['center'][1]
# # #                         if math.sqrt(dx * dx + dy * dy) < ENCIRCLEMENT_DIST:
# # #                             angle = math.degrees(math.atan2(dy, dx))
# # #                             if angle < 0:
# # #                                 angle += 360
# # #                             angles.append(angle)

# # #                     if len(angles) >= (MIN_ENCIRCLERS - 1):
# # #                         angles.sort()
# # #                         max_gap = 0
# # #                         for k in range(len(angles)):
# # #                             gap = angles[(k + 1) % len(angles)] - angles[k]
# # #                             if gap < 0:
# # #                                 gap += 360
# # #                             max_gap = max(max_gap, gap)

# # #                         if max_gap < min_max_gap:
# # #                             min_max_gap = max_gap
# # #                             best_target = target

# # #                 debug_gap = min_max_gap
# # #                 if min_max_gap < 360:
# # #                     debug_enclosed = int((360 - min_max_gap) / 3.6)

# # #                 if min_max_gap < MAX_GAP_THRESHOLD and best_target:
# # #                     best_target['role'] = "TARGET"
# # #                     current_alerts.append("ENCIRCLEMENT")
# # #                     if time.time() - alert_cooldown.get("circle", 0) > 10:
# # #                         metrics = {
# # #                             "max_gap_deg": int(min_max_gap),
# # #                             "enclosed_pct": debug_enclosed
# # #                         }
# # #                         path, i_id = create_incident_report(
# # #                             list(video_buffer), frame,
# # #                             best_target['id'], "ENCIRCLEMENT", metrics)
# # #                         alert_cooldown["circle"] = time.time()
# # #                         detection_log.insert(
# # #                             0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
# # #                         pending_after_snapshots.append(
# # #                             (time.time() + 2.0, path))

# # #             # ----------------------------------------------------------
# # #             # 4. POSTURE THREATS (from ThreatScorer)
# # #             # ----------------------------------------------------------
# # #             for p in current_people:
# # #                 if p["threat_score"] > 0:
# # #                     current_alerts.append(p["threat_reason"])
# # #                     cooldown_key = f"posture_{p['id']}"
# # #                     if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# # #                         metrics = {
# # #                             "threat_score": p["threat_score"],
# # #                             "reason": p["threat_reason"]
# # #                         }
# # #                         path, i_id = create_incident_report(
# # #                             list(video_buffer), frame,
# # #                             p['id'], p["threat_reason"], metrics)
# # #                         alert_cooldown[cooldown_key] = time.time()
# # #                         detection_log.insert(
# # #                             0, f"⚠️ INCIDENT #{i_id}: {p['threat_reason']}")
# # #                         if p["threat_score"] > 70:
# # #                             gsm_alert.send_sms(
# # #                                 "+1234567890",
# # #                                 f"High threat: {p['threat_reason']}, "
# # #                                 f"Score: {p['threat_score']}")

# # #             # ----------------------------------------------------------
# # #             # DRAWING
# # #             # ----------------------------------------------------------
# # #             for p in current_people:
# # #                 color = (0, 255, 0)
# # #                 if p['role'] in ("TARGET", "ATTACKER"):
# # #                     color = (0, 0, 255)
# # #                 elif p.get("threat_score", 0) > 0:
# # #                     color = (0, 0, 255)

# # #                 x1, y1, x2, y2 = p['box']   # already ints (FIX 4)
# # #                 cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
# # #                 cv2.putText(frame, f"ID:{p['id']}",
# # #                             (x1, y1 - 10),
# # #                             cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

# # #             # ----------------------------------------------------------
# # #             # UI UPDATES
# # #             # ----------------------------------------------------------
# # #             status_text = "SYSTEM SECURE"
# # #             if current_alerts:
# # #                 status_text = f"🚨 ALERT: {' + '.join(set(current_alerts))}"
# # #                 status_placeholder.error(status_text)
# # #             else:
# # #                 status_placeholder.success(status_text)

# # #             metric_speed.metric("Speed Change", "Active")
# # #             metric_prox.metric(
# # #                 "Min Distance",
# # #                 f"{int(min_dist_val)} px" if min_dist_val != 999 else "-"
# # #             )
# # #             metric_encircle.metric(
# # #                 "Encirclement",
# # #                 f"{debug_enclosed}% Enclosed",
# # #                 delta=f"Gap: {int(debug_gap)}°",
# # #                 delta_color="inverse"
# # #             )

# # #             log_placeholder.text("\n".join(detection_log[:5]))

# # #             frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
# # #             video_placeholder.image(frame_rgb, channels="RGB",
# # #                                     use_container_width=True)

# # #     cap.release()
# # # else:
# # #     status_placeholder = st.empty()
# # #     status_placeholder.info("⏸️ Monitor Paused")

# # # WORKSSSSSSSSSSSSSSSSSSSSS


# # import streamlit as st
# # import cv2
# # import time
# # import math
# # import os
# # import json
# # import numpy as np
# # from datetime import datetime
# # from collections import deque
# # from ultralytics import YOLO
# # from tracking.deepsort_tracker import PersonTracker
# # from pose.mediapipe_estimator import PoseEstimator
# # from logic.threat_scorer import ThreatScorer
# # from alerts.gsm_alert import GSMAlert

# # # --- CONFIGURATION ---
# # st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

# # FRAME_WIDTH = 640
# # FRAME_HEIGHT = 480
# # SKIP_FRAMES = 2

# # # --- SENSITIVITY SETTINGS ---
# # SPEED_THRESHOLD = 2.5
# # PROXIMITY_LIMIT = 220
# # ENCIRCLEMENT_DIST = 300
# # MAX_GAP_THRESHOLD = 200
# # MIN_ENCIRCLERS = 3

# # EVIDENCE_ROOT = "evidence/incidents"
# # BUFFER_SIZE = 30

# # # --- HELPER FUNCTIONS ---

# # def get_stats():
# #     """Scans all reports to calculate live statistics."""
# #     total = confirmed = false_alarm = pending = 0

# #     if os.path.exists(EVIDENCE_ROOT):
# #         for day_folder in os.listdir(EVIDENCE_ROOT):
# #             day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# #             if os.path.isdir(day_path):
# #                 for inc_folder in os.listdir(day_path):
# #                     json_path = os.path.join(day_path, inc_folder, "report.json")
# #                     if os.path.exists(json_path):
# #                         total += 1
# #                         try:
# #                             with open(json_path, "r") as f:
# #                                 data = json.load(f)
# #                             status = data.get("review_status", "PENDING")
# #                             if status == "CONFIRMED":
# #                                 confirmed += 1
# #                             elif status == "FALSE_ALARM":
# #                                 false_alarm += 1
# #                             else:
# #                                 pending += 1
# #                         except Exception:
# #                             pending += 1

# #     accuracy = 0
# #     if (confirmed + false_alarm) > 0:
# #         accuracy = (confirmed / (confirmed + false_alarm)) * 100

# #     return total, confirmed, false_alarm, pending, int(accuracy)


# # def update_incident_status(report_path, status, note):
# #     """Updates the JSON report with the security guard's decision."""
# #     if os.path.exists(report_path):
# #         with open(report_path, "r") as f:
# #             data = json.load(f)
# #         data["review_status"] = status
# #         data["reviewed_by"] = "Security Officer"
# #         data["reviewed_at"] = datetime.now().isoformat()
# #         data["review_note"] = note
# #         with open(report_path, "w") as f:
# #             json.dump(data, f, indent=4)
# #         return True
# #     return False


# # def annotate_frame(frame, text, score, color=(0, 0, 255)):
# #     annotated = frame.copy()
# #     h, w = annotated.shape[:2]
# #     cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
# #     cv2.putText(annotated, f"ALERT: {text}", (10, 35),
# #                 cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
# #     cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
# #     cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
# #                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
# #     ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# #     cv2.putText(annotated, ts, (w - 220, h - 10),
# #                 cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
# #     return annotated


# # def calculate_threat_score(alert_type: str, metrics: dict) -> int:
# #     """
# #     Calculate a meaningful threat score (0–100) based on alert type
# #     and the measured metrics that triggered it.

# #     Replaces the previous hardcoded value of 85.

# #     Scoring rationale:
# #       SPEED CHANGE    — scaled by how far above the threshold the ratio is.
# #                         Ratio 2.5x (threshold) → 40.  Ratio 5x+ → 80.
# #       PROXIMITY       — scaled by how close the pair is relative to the limit.
# #                         At the limit boundary → 40.  At 0 px → 80.
# #       ENCIRCLEMENT    — scaled by how enclosed the target is (0–100%).
# #                         50% enclosed → 55.  90% enclosed → 79.
# #       Posture threats — use the score already calculated by ThreatScorer,
# #                         capped at 100.
# #       Unknown types   — conservative default of 50.
# #     """
# #     score = 50  # safe default for unknown alert types

# #     if alert_type == "SPEED CHANGE":
# #         try:
# #             ratio = float(metrics.get("speed_ratio", "2.5x").replace("x", ""))
# #             # Maps ratio 2.5 → 40, 5.0 → 80, capped at 95
# #             score = min(95, int(40 + (ratio - 2.5) * 16))
# #         except (ValueError, AttributeError):
# #             score = 50

# #     elif alert_type == "PROXIMITY":
# #         dist = metrics.get("distance_px", 110)
# #         limit = PROXIMITY_LIMIT  # global constant
# #         # Closer = higher score. At limit → 40, at 0px → 80
# #         closeness = max(0.0, 1.0 - (dist / limit))
# #         score = min(95, int(40 + closeness * 40))

# #     elif alert_type == "ENCIRCLEMENT":
# #         enclosed_pct = metrics.get("enclosed_pct", 50)
# #         # 50% → 55,  90% → 75,  100% → 80
# #         score = min(80, int(30 + enclosed_pct * 0.5))

# #     elif "threat_score" in metrics:
# #         # Posture threat — ThreatScorer already computed this
# #         score = min(100, int(metrics["threat_score"]))

# #     return max(0, score)


# # def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
# #     timestamp = datetime.now().strftime("%H-%M-%S")
# #     date_str = datetime.now().strftime("%Y%m%d")
# #     incident_id = 1
# #     daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
# #     if os.path.exists(daily_dir):
# #         existing = [d for d in os.listdir(daily_dir)
# #                     if os.path.isdir(os.path.join(daily_dir, d))]
# #         incident_id = len(existing) + 1

# #     folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
# #     save_path = os.path.join(daily_dir, folder_name)
# #     os.makedirs(save_path, exist_ok=True)

# #     threat_score = calculate_threat_score(alert_type, metrics)

# #     # FIX 7: Use the actual rolling buffer correctly.
# #     # buffer is a plain list snapshot of the deque passed in.
# #     # We want the frame ~15 steps before the end of that snapshot.
# #     if len(buffer) > 15:
# #         frame_before = buffer[-15]
# #     elif buffer:
# #         frame_before = buffer[0]
# #     else:
# #         frame_before = peak_frame

# #     img_before = annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
# #     img_peak = annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))

# #     cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
# #     cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"), img_peak)

# #     report = {
# #         "incident_id": f"INCIDENT_{incident_id:03d}",
# #         "detection_type": alert_type,
# #         "timestamp": datetime.now().isoformat(),
# #         "threat_score": threat_score,
# #         "metrics": metrics,
# #         "review_status": "PENDING",
# #         "evidence_files": [
# #             "snapshot_before.jpg",
# #             "snapshot_peak.jpg",
# #             "snapshot_after.jpg (pending)"
# #         ]
# #     }

# #     with open(os.path.join(save_path, "report.json"), "w") as f:
# #         json.dump(report, f, indent=4)

# #     return save_path, incident_id


# # def is_valid_person_detection(box, frame_shape, min_area_ratio=0.04, min_aspect=1.2):
# #     """
# #     Returns True only if the bounding box looks like a real standing person.
# #     Filters out ghost detections caused by raised hands, fists, or partial limbs.
# #       - min_area_ratio: box must cover at least this fraction of the frame area
# #       - min_aspect:     box height/width must exceed this (portrait shape check)
# #     """
# #     x1, y1, x2, y2 = box
# #     w = x2 - x1
# #     h = y2 - y1
# #     if w <= 0 or h <= 0:
# #         return False
# #     frame_h, frame_w = frame_shape
# #     if (w * h) / (frame_h * frame_w) < min_area_ratio:
# #         return False
# #     if (h / w) < min_aspect:
# #         return False
# #     return True


# # def compute_iou(box_a, box_b):
# #     """Intersection-over-Union of two (x1, y1, x2, y2) boxes. Returns [0, 1]."""
# #     ax1, ay1, ax2, ay2 = box_a
# #     bx1, by1, bx2, by2 = box_b
# #     inter_x1, inter_y1 = max(ax1, bx1), max(ay1, by1)
# #     inter_x2, inter_y2 = min(ax2, bx2), min(ay2, by2)
# #     inter_area = max(0, inter_x2 - inter_x1) * max(0, inter_y2 - inter_y1)
# #     if inter_area == 0:
# #         return 0.0
# #     union_area = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter_area
# #     return inter_area / union_area if union_area > 0 else 0.0


# # def is_center_inside_box(center, box):
# #     """Returns True if point (cx, cy) lies inside (x1, y1, x2, y2)."""
# #     cx, cy = center
# #     x1, y1, x2, y2 = box
# #     return x1 <= cx <= x2 and y1 <= cy <= y2


# # # --- UI LAYOUT ---
# # st.title("🛡️ Sentinel AI: Security Operations Center")

# # total, confirmed, false_alarms, pending, accuracy = get_stats()
# # k1, k2, k3, k4, k5 = st.columns(5)
# # k1.metric("Total Alerts", total)
# # k2.metric("Confirmed Threats", confirmed,
# #           delta="Action Required" if confirmed > 0 else None,
# #           delta_color="inverse")
# # k3.metric("False Alarms", false_alarms)
# # k4.metric("Pending Review", pending,
# #           delta="Urgent" if pending > 0 else "All Clear",
# #           delta_color="inverse")
# # k5.metric("System Accuracy", f"{accuracy}%")

# # st.divider()

# # tab1, tab2 = st.tabs(["🔴 Live Tactical View", "🗂️ Incident Review & Audit"])

# # # --- TAB 1: LIVE MONITOR ---
# # with tab1:
# #     status_placeholder = st.empty()
# #     col1, col2 = st.columns([3, 1])
# #     with col1:
# #         st.subheader("Live Feed")
# #         video_placeholder = st.empty()
# #     with col2:
# #         st.subheader("Active Threats")
# #         metric_speed = st.empty()
# #         metric_prox = st.empty()
# #         metric_encircle = st.empty()
# #         st.divider()
# #         st.write("### Live Log")
# #         log_placeholder = st.empty()

# # # --- TAB 2: INCIDENT REVIEW ---
# # with tab2:
# #     st.header("🗂️ Incident Case Files")
# #     st.info("Uncheck 'ACTIVATE SYSTEM' to review evidence.")
# #     evidence_col, viewer_col = st.columns([1, 2])

# #     with evidence_col:
# #         all_files = []
# #         if os.path.exists(EVIDENCE_ROOT):
# #             for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
# #                 day_path = os.path.join(EVIDENCE_ROOT, day_folder)
# #                 if os.path.isdir(day_path):
# #                     for inc_folder in sorted(os.listdir(day_path), reverse=True):
# #                         if inc_folder.startswith("INCIDENT"):
# #                             status_icon = "🟡"
# #                             try:
# #                                 with open(os.path.join(day_path, inc_folder, "report.json")) as f:
# #                                     d = json.load(f)
# #                                 s = d.get("review_status", "PENDING")
# #                                 if s == "CONFIRMED":
# #                                     status_icon = "🟢"
# #                                 elif s == "FALSE_ALARM":
# #                                     status_icon = "⚪"
# #                             except Exception:
# #                                 pass
# #                             display_name = f"{status_icon} {inc_folder[9:]}"
# #                             all_files.append((display_name,
# #                                               os.path.join(day_path, inc_folder)))

# #         selected_file = (st.selectbox("Select Case:", all_files,
# #                                        format_func=lambda x: x[0])
# #                          if all_files else None)

# #     with viewer_col:
# #         if selected_file:
# #             folder_path = selected_file[1]
# #             json_path = os.path.join(folder_path, "report.json")

# #             if os.path.exists(json_path):
# #                 with open(json_path, "r") as f:
# #                     report = json.load(f)

# #                 status = report.get("review_status", "PENDING")
# #                 if status == "CONFIRMED":
# #                     st.error(f"✅ CONFIRMED THREAT (Verified by {report.get('reviewed_by')})")
# #                     if report.get("review_note"):
# #                         st.caption(f"📝 Note: {report.get('review_note')}")
# #                 elif status == "FALSE_ALARM":
# #                     st.success(f"❌ FALSE ALARM (Verified by {report.get('reviewed_by')})")
# #                     if report.get("review_note"):
# #                         st.caption(f"📝 Note: {report.get('review_note')}")
# #                 else:
# #                     st.warning("⚠️ PENDING SECURITY REVIEW")
# #                     with st.form("review_form"):
# #                         note = st.text_input("Add Note (Optional)",
# #                                              placeholder="e.g. Friends greeting, Staff member...")
# #                         c1, c2 = st.columns(2)
# #                         confirm_btn = c1.form_submit_button("✅ Confirm Threat", type="primary")
# #                         false_alarm_btn = c2.form_submit_button("❌ False Alarm")

# #                         if confirm_btn:
# #                             update_incident_status(json_path, "CONFIRMED", note)
# #                             st.rerun()
# #                         if false_alarm_btn:
# #                             update_incident_status(json_path, "FALSE_ALARM", note)
# #                             st.rerun()

# #                 metrics_data = report.get(
# #                     'metrics', {"info": "Legacy Data - No details available"})
# #                 st.json(metrics_data)

# #                 c1, c2, c3 = st.columns(3)
# #                 p_before = os.path.join(folder_path, "snapshot_before.jpg")
# #                 p_peak = os.path.join(folder_path, "snapshot_peak.jpg")
# #                 p_after = os.path.join(folder_path, "snapshot_after.jpg")

# #                 if os.path.exists(p_before):
# #                     c1.image(p_before, caption="BEFORE", use_container_width=True)
# #                 if os.path.exists(p_peak):
# #                     c2.image(p_peak, caption="PEAK (Alert)", use_container_width=True)
# #                 if os.path.exists(p_after):
# #                     c3.image(p_after, caption="AFTER", use_container_width=True)

# # # --- AI INIT ---
# # @st.cache_resource
# # def load_model():
# #     return YOLO('yolo11n.pt')

# # model = load_model()
# # tracker = PersonTracker()
# # pose_estimator = PoseEstimator()
# # threat_scorer = ThreatScorer()

# # # --- SIDEBAR CONTROLS ---
# # st.sidebar.title("System Control")
# # system_active = st.sidebar.checkbox("ACTIVATE SURVEILLANCE", value=True)

# # # FIX 5: Make GSM port configurable from the sidebar, not hardcoded.
# # gsm_port = st.sidebar.text_input("GSM Port", value="COM3",
# #                                   help="Windows: COM3  |  Linux: /dev/ttyUSB0")
# # gsm_alert = GSMAlert(port=gsm_port)

# # # --- MAIN LOOP ---
# # if system_active:
# #     cap = cv2.VideoCapture(0)
# #     cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
# #     cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

# #     speed_history = {}
# #     pos_history = {}

# #     video_buffer = deque(maxlen=BUFFER_SIZE)
# #     alert_cooldown = {}
# #     detection_log = []
# #     pending_after_snapshots = []

# #     frame_count = 0

# #     # FIX 6: Use a Streamlit stop_button so the loop can be broken cleanly
# #     # from the UI without relying on a variable that Streamlit can't refresh
# #     # mid-loop. The loop also re-checks the checkbox state each iteration
# #     # by reading the session_state key directly.
# #     stop_btn = st.sidebar.button("⏹ Stop Feed")

# #     while cap.isOpened() and not stop_btn:
# #         ret, frame = cap.read()
# #         if not ret:
# #             break

# #         frame_count += 1
# #         video_buffer.append(frame.copy())

# #         # Save post-event snapshot after 2-second delay
# #         remaining = []
# #         for trigger_time, folder_path in pending_after_snapshots:
# #             if time.time() > trigger_time:
# #                 img_after = annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
# #                 cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
# #             else:
# #                 remaining.append((trigger_time, folder_path))
# #         pending_after_snapshots = remaining

# #         current_alerts = []

# #         # FIX 3: Initialise min_dist_val before any proximity check so it
# #         # is always defined when metric_prox reads it below.
# #         min_dist_val = 999

# #         if frame_count % SKIP_FRAMES == 0:
# #             results = model.track(frame, persist=True, verbose=False, classes=[0])
# #             current_people = []

# #             if results[0].boxes.id is not None:
# #                 boxes = results[0].boxes.xyxy.cpu().numpy()
# #                 ids = results[0].boxes.id.int().cpu().numpy()

# #                 for box, track_id in zip(boxes, ids):
# #                     # FIX 4: Cast all coords to int immediately so every
# #                     # downstream cv2 call receives integer values.
# #                     x1, y1, x2, y2 = map(int, box)
# #                     w, h = x2 - x1, y2 - y1
# #                     cx, cy = x1 + w // 2, y1 + h // 2

# #                     person = {
# #                         "id": track_id,
# #                         "box": (x1, y1, x2, y2),
# #                         "center": (cx, cy),
# #                         "role": "NEUTRAL",
# #                         "threat_score": 0,
# #                         "threat_reason": "Scanning...",
# #                         "speed_display": "1.0x",
# #                     }

# #                     # Pose estimation and threat scoring
# #                     landmarks = pose_estimator.estimate_pose(frame, (x1, y1, x2, y2))
# #                     score, reason = threat_scorer.update(track_id, (x1, y1, w, h), landmarks)
# #                     person["threat_score"] = score
# #                     person["threat_reason"] = reason

# #                     # --------------------------------------------------
# #                     # FIX 1 + FIX 2: Speed check moved INSIDE the per-person
# #                     # loop, using the local track_id / cx / cy / person vars
# #                     # that are defined right above.
# #                     # --------------------------------------------------
# #                     speed_ratio = 1.0
# #                     if track_id in pos_history:
# #                         prev_cx, prev_cy = pos_history[track_id]
# #                         dist_moved = math.sqrt(
# #                             (cx - prev_cx) ** 2 + (cy - prev_cy) ** 2)

# #                         if track_id not in speed_history:
# #                             speed_history[track_id] = deque(maxlen=10)
# #                         speed_history[track_id].append(dist_moved)

# #                         if len(speed_history[track_id]) >= 5:
# #                             avg_speed = (sum(speed_history[track_id])
# #                                          / len(speed_history[track_id]))
# #                             if avg_speed > 2.0:
# #                                 speed_ratio = dist_moved / avg_speed

# #                             if speed_ratio > SPEED_THRESHOLD:
# #                                 current_alerts.append("SPEED CHANGE")
# #                                 person["role"] = "ATTACKER"

# #                                 cooldown_key = f"speed_{track_id}"
# #                                 if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# #                                     metrics = {"speed_ratio": f"{speed_ratio:.2f}x"}
# #                                     path, i_id = create_incident_report(
# #                                         list(video_buffer), frame,
# #                                         track_id, "SPEED CHANGE", metrics)
# #                                     alert_cooldown[cooldown_key] = time.time()
# #                                     detection_log.insert(
# #                                         0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
# #                                     pending_after_snapshots.append(
# #                                         (time.time() + 2.0, path))

# #                     pos_history[track_id] = (cx, cy)
# #                     person["speed_display"] = f"{speed_ratio:.1f}x"

# #                     current_people.append(person)

# #             # Clean up stale tracker targets
# #             current_ids = [p['id'] for p in current_people]
# #             for tid in list(threat_scorer.targets.keys()):
# #                 if tid not in current_ids:
# #                     del threat_scorer.targets[tid]

# #             # ----------------------------------------------------------
# #             # 2. PROXIMITY
# #             # ----------------------------------------------------------
# #             # Pre-filter: discard ghost detections (raised hands, fists,
# #             # partial limbs) before running any pairwise distance checks.
# #             frame_h, frame_w = frame.shape[:2]
# #             valid_people = [
# #                 p for p in current_people
# #                 if is_valid_person_detection(p['box'], (frame_h, frame_w))
# #             ]

# #             for i in range(len(valid_people)):
# #                 for j in range(i + 1, len(valid_people)):
# #                     p1, p2 = valid_people[i], valid_people[j]

# #                     # Skip if one detection's center sits inside the other box —
# #                     # that means the same person was detected twice (e.g. full
# #                     # body + raised-arm crop both tracked simultaneously).
# #                     if is_center_inside_box(p1['center'], p2['box']):
# #                         continue
# #                     if is_center_inside_box(p2['center'], p1['box']):
# #                         continue

# #                     # Skip if the boxes overlap heavily — two separate people
# #                     # cannot physically occupy the same space.
# #                     if compute_iou(p1['box'], p2['box']) > 0.30:
# #                         continue

# #                     dist = math.sqrt(
# #                         (p1['center'][0] - p2['center'][0]) ** 2 +
# #                         (p1['center'][1] - p2['center'][1]) ** 2)
# #                     min_dist_val = min(min_dist_val, dist)

# #                     if dist < PROXIMITY_LIMIT:
# #                         current_alerts.append("PROXIMITY")
# #                         cv2.line(frame, p1['center'], p2['center'],
# #                                  (0, 0, 255), 3)

# #                         if time.time() - alert_cooldown.get("prox", 0) > 10:
# #                             metrics = {"distance_px": int(dist)}
# #                             path, i_id = create_incident_report(
# #                                 list(video_buffer), frame,
# #                                 0, "PROXIMITY", metrics)
# #                             alert_cooldown["prox"] = time.time()
# #                             detection_log.insert(
# #                                 0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
# #                             pending_after_snapshots.append(
# #                                 (time.time() + 2.0, path))
# #                     else:
# #                         cv2.line(frame, p1['center'], p2['center'],
# #                                  (0, 255, 0), 1)

# #             # ----------------------------------------------------------
# #             # 3. ENCIRCLEMENT
# #             # ----------------------------------------------------------
# #             debug_gap = 360
# #             debug_enclosed = 0
# #             if len(current_people) >= MIN_ENCIRCLERS:
# #                 min_max_gap = 360
# #                 best_target = None

# #                 for target in current_people:
# #                     angles = []
# #                     for other in current_people:
# #                         if target['id'] == other['id']:
# #                             continue
# #                         dx = other['center'][0] - target['center'][0]
# #                         dy = other['center'][1] - target['center'][1]
# #                         if math.sqrt(dx * dx + dy * dy) < ENCIRCLEMENT_DIST:
# #                             angle = math.degrees(math.atan2(dy, dx))
# #                             if angle < 0:
# #                                 angle += 360
# #                             angles.append(angle)

# #                     if len(angles) >= (MIN_ENCIRCLERS - 1):
# #                         angles.sort()
# #                         max_gap = 0
# #                         for k in range(len(angles)):
# #                             gap = angles[(k + 1) % len(angles)] - angles[k]
# #                             if gap < 0:
# #                                 gap += 360
# #                             max_gap = max(max_gap, gap)

# #                         if max_gap < min_max_gap:
# #                             min_max_gap = max_gap
# #                             best_target = target

# #                 debug_gap = min_max_gap
# #                 if min_max_gap < 360:
# #                     debug_enclosed = int((360 - min_max_gap) / 3.6)

# #                 if min_max_gap < MAX_GAP_THRESHOLD and best_target:
# #                     best_target['role'] = "TARGET"
# #                     current_alerts.append("ENCIRCLEMENT")
# #                     if time.time() - alert_cooldown.get("circle", 0) > 10:
# #                         metrics = {
# #                             "max_gap_deg": int(min_max_gap),
# #                             "enclosed_pct": debug_enclosed
# #                         }
# #                         path, i_id = create_incident_report(
# #                             list(video_buffer), frame,
# #                             best_target['id'], "ENCIRCLEMENT", metrics)
# #                         alert_cooldown["circle"] = time.time()
# #                         detection_log.insert(
# #                             0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
# #                         pending_after_snapshots.append(
# #                             (time.time() + 2.0, path))

# #             # ----------------------------------------------------------
# #             # 4. POSTURE THREATS (from ThreatScorer)
# #             # ----------------------------------------------------------
# #             for p in current_people:
# #                 if p["threat_score"] > 0:
# #                     current_alerts.append(p["threat_reason"])
# #                     cooldown_key = f"posture_{p['id']}"
# #                     if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
# #                         metrics = {
# #                             "threat_score": p["threat_score"],
# #                             "reason": p["threat_reason"]
# #                         }
# #                         path, i_id = create_incident_report(
# #                             list(video_buffer), frame,
# #                             p['id'], p["threat_reason"], metrics)
# #                         alert_cooldown[cooldown_key] = time.time()
# #                         detection_log.insert(
# #                             0, f"⚠️ INCIDENT #{i_id}: {p['threat_reason']}")
# #                         if p["threat_score"] > 70:
# #                             gsm_alert.send_sms(
# #                                 "+1234567890",
# #                                 f"High threat: {p['threat_reason']}, "
# #                                 f"Score: {p['threat_score']}")

# #             # ----------------------------------------------------------
# #             # DRAWING
# #             # ----------------------------------------------------------
# #             for p in current_people:
# #                 color = (0, 255, 0)
# #                 if p['role'] in ("TARGET", "ATTACKER"):
# #                     color = (0, 0, 255)
# #                 elif p.get("threat_score", 0) > 0:
# #                     color = (0, 0, 255)

# #                 x1, y1, x2, y2 = p['box']   # already ints (FIX 4)
# #                 cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
# #                 cv2.putText(frame, f"ID:{p['id']}",
# #                             (x1, y1 - 10),
# #                             cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

# #             # ----------------------------------------------------------
# #             # UI UPDATES
# #             # ----------------------------------------------------------
# #             status_text = "SYSTEM SECURE"
# #             if current_alerts:
# #                 status_text = f"🚨 ALERT: {' + '.join(set(current_alerts))}"
# #                 status_placeholder.error(status_text)
# #             else:
# #                 status_placeholder.success(status_text)

# #             metric_speed.metric("Speed Change", "Active")
# #             metric_prox.metric(
# #                 "Min Distance",
# #                 f"{int(min_dist_val)} px" if min_dist_val != 999 else "-"
# #             )
# #             metric_encircle.metric(
# #                 "Encirclement",
# #                 f"{debug_enclosed}% Enclosed",
# #                 delta=f"Gap: {int(debug_gap)}°",
# #                 delta_color="inverse"
# #             )

# #             log_placeholder.text("\n".join(detection_log[:5]))

# #             frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
# #             video_placeholder.image(frame_rgb, channels="RGB",
# #                                     use_container_width=True)

# #     cap.release()
# # else:
# #     status_placeholder = st.empty()
# #     status_placeholder.info("⏸️ Monitor Paused")

# import streamlit as st
# import cv2
# import time
# import math
# import os
# import json
# import numpy as np
# from datetime import datetime
# from collections import deque
# from ultralytics import YOLO
# from tracking.deepsort_tracker import PersonTracker
# from pose.mediapipe_estimator import PoseEstimator
# from logic.threat_scorer import ThreatScorer
# from alerts.gsm_alert import GSMAlert

# # --- CONFIGURATION ---
# st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

# # --- AUTH CHECK ---
# # Must happen right after set_page_config and before any other st.* calls.
# # If no user is logged in, show the login page and stop the rest of this file.
# from auth.auth import get_current_user, logout
# from auth.roles import can
# from pages.login_page import show_login_page

# user = get_current_user()
# if user is None:
#     show_login_page()
#     st.stop()

# FRAME_WIDTH = 640
# FRAME_HEIGHT = 480
# SKIP_FRAMES = 2

# # --- SENSITIVITY SETTINGS ---
# SPEED_THRESHOLD = 2.5
# PROXIMITY_LIMIT = 220
# ENCIRCLEMENT_DIST = 300
# MAX_GAP_THRESHOLD = 200
# MIN_ENCIRCLERS = 3

# EVIDENCE_ROOT = "evidence/incidents"
# BUFFER_SIZE = 30

# # --- HELPER FUNCTIONS ---

# def get_stats():
#     """Scans all reports to calculate live statistics."""
#     total = confirmed = false_alarm = pending = 0

#     if os.path.exists(EVIDENCE_ROOT):
#         for day_folder in os.listdir(EVIDENCE_ROOT):
#             day_path = os.path.join(EVIDENCE_ROOT, day_folder)
#             if os.path.isdir(day_path):
#                 for inc_folder in os.listdir(day_path):
#                     json_path = os.path.join(day_path, inc_folder, "report.json")
#                     if os.path.exists(json_path):
#                         total += 1
#                         try:
#                             with open(json_path, "r") as f:
#                                 data = json.load(f)
#                             status = data.get("review_status", "PENDING")
#                             if status == "CONFIRMED":
#                                 confirmed += 1
#                             elif status == "FALSE_ALARM":
#                                 false_alarm += 1
#                             else:
#                                 pending += 1
#                         except Exception:
#                             pending += 1

#     accuracy = 0
#     if (confirmed + false_alarm) > 0:
#         accuracy = (confirmed / (confirmed + false_alarm)) * 100

#     return total, confirmed, false_alarm, pending, int(accuracy)


# def update_incident_status(report_path, status, note):
#     """Updates the JSON report with the security guard's decision."""
#     if os.path.exists(report_path):
#         with open(report_path, "r") as f:
#             data = json.load(f)
#         data["review_status"] = status
#         data["reviewed_by"] = "Security Officer"
#         data["reviewed_at"] = datetime.now().isoformat()
#         data["review_note"] = note
#         with open(report_path, "w") as f:
#             json.dump(data, f, indent=4)
#         return True
#     return False


# def annotate_frame(frame, text, score, color=(0, 0, 255)):
#     annotated = frame.copy()
#     h, w = annotated.shape[:2]
#     cv2.rectangle(annotated, (0, 0), (w, 50), color, -1)
#     cv2.putText(annotated, f"ALERT: {text}", (10, 35),
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
#     cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
#     cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
#     ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     cv2.putText(annotated, ts, (w - 220, h - 10),
#                 cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
#     return annotated


# def calculate_threat_score(alert_type: str, metrics: dict) -> int:
#     """
#     Calculate a meaningful threat score (0–100) based on alert type
#     and the measured metrics that triggered it.

#     Replaces the previous hardcoded value of 85.

#     Scoring rationale:
#       SPEED CHANGE    — scaled by how far above the threshold the ratio is.
#                         Ratio 2.5x (threshold) → 40.  Ratio 5x+ → 80.
#       PROXIMITY       — scaled by how close the pair is relative to the limit.
#                         At the limit boundary → 40.  At 0 px → 80.
#       ENCIRCLEMENT    — scaled by how enclosed the target is (0–100%).
#                         50% enclosed → 55.  90% enclosed → 79.
#       Posture threats — use the score already calculated by ThreatScorer,
#                         capped at 100.
#       Unknown types   — conservative default of 50.
#     """
#     score = 50  # safe default for unknown alert types

#     if alert_type == "SPEED CHANGE":
#         try:
#             ratio = float(metrics.get("speed_ratio", "2.5x").replace("x", ""))
#             # Maps ratio 2.5 → 40, 5.0 → 80, capped at 95
#             score = min(95, int(40 + (ratio - 2.5) * 16))
#         except (ValueError, AttributeError):
#             score = 50

#     elif alert_type == "PROXIMITY":
#         dist = metrics.get("distance_px", 110)
#         limit = PROXIMITY_LIMIT  # global constant
#         # Closer = higher score. At limit → 40, at 0px → 80
#         closeness = max(0.0, 1.0 - (dist / limit))
#         score = min(95, int(40 + closeness * 40))

#     elif alert_type == "ENCIRCLEMENT":
#         enclosed_pct = metrics.get("enclosed_pct", 50)
#         # 50% → 55,  90% → 75,  100% → 80
#         score = min(80, int(30 + enclosed_pct * 0.5))

#     elif "threat_score" in metrics:
#         # Posture threat — ThreatScorer already computed this
#         score = min(100, int(metrics["threat_score"]))

#     return max(0, score)


# def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
#     timestamp = datetime.now().strftime("%H-%M-%S")
#     date_str = datetime.now().strftime("%Y%m%d")
#     incident_id = 1
#     daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
#     if os.path.exists(daily_dir):
#         existing = [d for d in os.listdir(daily_dir)
#                     if os.path.isdir(os.path.join(daily_dir, d))]
#         incident_id = len(existing) + 1

#     folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
#     save_path = os.path.join(daily_dir, folder_name)
#     os.makedirs(save_path, exist_ok=True)

#     threat_score = calculate_threat_score(alert_type, metrics)

#     # FIX 7: Use the actual rolling buffer correctly.
#     # buffer is a plain list snapshot of the deque passed in.
#     # We want the frame ~15 steps before the end of that snapshot.
#     if len(buffer) > 15:
#         frame_before = buffer[-15]
#     elif buffer:
#         frame_before = buffer[0]
#     else:
#         frame_before = peak_frame

#     img_before = annotate_frame(frame_before, "PRE-EVENT", 0, (0, 255, 0))
#     img_peak = annotate_frame(peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))

#     cv2.imwrite(os.path.join(save_path, "snapshot_before.jpg"), img_before)
#     cv2.imwrite(os.path.join(save_path, "snapshot_peak.jpg"), img_peak)

#     report = {
#         "incident_id": f"INCIDENT_{incident_id:03d}",
#         "detection_type": alert_type,
#         "timestamp": datetime.now().isoformat(),
#         "threat_score": threat_score,
#         "metrics": metrics,
#         "review_status": "PENDING",
#         "evidence_files": [
#             "snapshot_before.jpg",
#             "snapshot_peak.jpg",
#             "snapshot_after.jpg (pending)"
#         ]
#     }

#     with open(os.path.join(save_path, "report.json"), "w") as f:
#         json.dump(report, f, indent=4)

#     return save_path, incident_id


# def is_valid_person_detection(box, frame_shape, min_area_ratio=0.04, min_aspect=1.2):
#     """
#     Returns True only if the bounding box looks like a real standing person.
#     Filters out ghost detections caused by raised hands, fists, or partial limbs.
#       - min_area_ratio: box must cover at least this fraction of the frame area
#       - min_aspect:     box height/width must exceed this (portrait shape check)
#     """
#     x1, y1, x2, y2 = box
#     w = x2 - x1
#     h = y2 - y1
#     if w <= 0 or h <= 0:
#         return False
#     frame_h, frame_w = frame_shape
#     if (w * h) / (frame_h * frame_w) < min_area_ratio:
#         return False
#     if (h / w) < min_aspect:
#         return False
#     return True


# def compute_iou(box_a, box_b):
#     """Intersection-over-Union of two (x1, y1, x2, y2) boxes. Returns [0, 1]."""
#     ax1, ay1, ax2, ay2 = box_a
#     bx1, by1, bx2, by2 = box_b
#     inter_x1, inter_y1 = max(ax1, bx1), max(ay1, by1)
#     inter_x2, inter_y2 = min(ax2, bx2), min(ay2, by2)
#     inter_area = max(0, inter_x2 - inter_x1) * max(0, inter_y2 - inter_y1)
#     if inter_area == 0:
#         return 0.0
#     union_area = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter_area
#     return inter_area / union_area if union_area > 0 else 0.0


# def is_center_inside_box(center, box):
#     """Returns True if point (cx, cy) lies inside (x1, y1, x2, y2)."""
#     cx, cy = center
#     x1, y1, x2, y2 = box
#     return x1 <= cx <= x2 and y1 <= cy <= y2


# # --- UI LAYOUT ---
# st.title("🛡️ Sentinel AI: Security Operations Center")

# total, confirmed, false_alarms, pending, accuracy = get_stats()
# k1, k2, k3, k4, k5 = st.columns(5)
# k1.metric("Total Alerts", total)
# k2.metric("Confirmed Threats", confirmed,
#           delta="Action Required" if confirmed > 0 else None,
#           delta_color="inverse")
# k3.metric("False Alarms", false_alarms)
# k4.metric("Pending Review", pending,
#           delta="Urgent" if pending > 0 else "All Clear",
#           delta_color="inverse")
# k5.metric("System Accuracy", f"{accuracy}%")

# st.divider()

# tab1, tab2 = st.tabs(["🔴 Live Tactical View", "🗂️ Incident Review & Audit"])

# # --- TAB 1: LIVE MONITOR ---
# with tab1:
#     status_placeholder = st.empty()
#     col1, col2 = st.columns([3, 1])
#     with col1:
#         st.subheader("Live Feed")
#         video_placeholder = st.empty()
#     with col2:
#         st.subheader("Active Threats")
#         metric_speed = st.empty()
#         metric_prox = st.empty()
#         metric_encircle = st.empty()
#         st.divider()
#         st.write("### Live Log")
#         log_placeholder = st.empty()

# # --- TAB 2: INCIDENT REVIEW ---
# with tab2:
#     st.header("🗂️ Incident Case Files")
#     st.info("Uncheck 'ACTIVATE SYSTEM' to review evidence.")
#     evidence_col, viewer_col = st.columns([1, 2])

#     with evidence_col:
#         all_files = []
#         if os.path.exists(EVIDENCE_ROOT):
#             for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
#                 day_path = os.path.join(EVIDENCE_ROOT, day_folder)
#                 if os.path.isdir(day_path):
#                     for inc_folder in sorted(os.listdir(day_path), reverse=True):
#                         if inc_folder.startswith("INCIDENT"):
#                             status_icon = "🟡"
#                             try:
#                                 with open(os.path.join(day_path, inc_folder, "report.json")) as f:
#                                     d = json.load(f)
#                                 s = d.get("review_status", "PENDING")
#                                 if s == "CONFIRMED":
#                                     status_icon = "🟢"
#                                 elif s == "FALSE_ALARM":
#                                     status_icon = "⚪"
#                             except Exception:
#                                 pass
#                             display_name = f"{status_icon} {inc_folder[9:]}"
#                             all_files.append((display_name,
#                                               os.path.join(day_path, inc_folder)))

#         selected_file = (st.selectbox("Select Case:", all_files,
#                                        format_func=lambda x: x[0])
#                          if all_files else None)

#     with viewer_col:
#         if selected_file:
#             folder_path = selected_file[1]
#             json_path = os.path.join(folder_path, "report.json")

#             if os.path.exists(json_path):
#                 with open(json_path, "r") as f:
#                     report = json.load(f)

#                 status = report.get("review_status", "PENDING")
#                 if status == "CONFIRMED":
#                     st.error(f"✅ CONFIRMED THREAT (Verified by {report.get('reviewed_by')})")
#                     if report.get("review_note"):
#                         st.caption(f"📝 Note: {report.get('review_note')}")
#                 elif status == "FALSE_ALARM":
#                     st.success(f"❌ FALSE ALARM (Verified by {report.get('reviewed_by')})")
#                     if report.get("review_note"):
#                         st.caption(f"📝 Note: {report.get('review_note')}")
#                 else:
#                     st.warning("⚠️ PENDING SECURITY REVIEW")
#                     with st.form("review_form"):
#                         note = st.text_input("Add Note (Optional)",
#                                              placeholder="e.g. Friends greeting, Staff member...")
#                         c1, c2 = st.columns(2)
#                         confirm_btn = c1.form_submit_button("✅ Confirm Threat", type="primary")
#                         false_alarm_btn = c2.form_submit_button("❌ False Alarm")

#                         if confirm_btn:
#                             update_incident_status(json_path, "CONFIRMED", note)
#                             st.rerun()
#                         if false_alarm_btn:
#                             update_incident_status(json_path, "FALSE_ALARM", note)
#                             st.rerun()

#                 metrics_data = report.get(
#                     'metrics', {"info": "Legacy Data - No details available"})
#                 st.json(metrics_data)

#                 c1, c2, c3 = st.columns(3)
#                 p_before = os.path.join(folder_path, "snapshot_before.jpg")
#                 p_peak = os.path.join(folder_path, "snapshot_peak.jpg")
#                 p_after = os.path.join(folder_path, "snapshot_after.jpg")

#                 if os.path.exists(p_before):
#                     c1.image(p_before, caption="BEFORE", use_container_width=True)
#                 if os.path.exists(p_peak):
#                     c2.image(p_peak, caption="PEAK (Alert)", use_container_width=True)
#                 if os.path.exists(p_after):
#                     c3.image(p_after, caption="AFTER", use_container_width=True)

# # --- AI INIT ---
# @st.cache_resource
# def load_model():
#     return YOLO('yolo11n.pt')

# model = load_model()
# tracker = PersonTracker()
# pose_estimator = PoseEstimator()
# threat_scorer = ThreatScorer()

# # --- SIDEBAR CONTROLS ---
# st.sidebar.title("System Control")

# # Show logged-in user info and logout button
# st.sidebar.markdown(f"**👤 {user['full_name']}**")
# st.sidebar.caption(f"Role: {user['role'].upper()}")
# if st.sidebar.button("🚪 Logout", use_container_width=True):
#     logout()
#     st.rerun()

# st.sidebar.divider()
# system_active = st.sidebar.checkbox("ACTIVATE SURVEILLANCE", value=True)

# # FIX 5: Make GSM port configurable from the sidebar, not hardcoded.
# gsm_port = st.sidebar.text_input("GSM Port", value="COM3",
#                                   help="Windows: COM3  |  Linux: /dev/ttyUSB0")
# gsm_alert = GSMAlert(port=gsm_port)

# # --- MAIN LOOP ---
# if system_active:
#     cap = cv2.VideoCapture(0)
#     cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
#     cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

#     speed_history = {}
#     pos_history = {}

#     video_buffer = deque(maxlen=BUFFER_SIZE)
#     alert_cooldown = {}
#     detection_log = []
#     pending_after_snapshots = []

#     frame_count = 0

#     # FIX 6: Use a Streamlit stop_button so the loop can be broken cleanly
#     # from the UI without relying on a variable that Streamlit can't refresh
#     # mid-loop. The loop also re-checks the checkbox state each iteration
#     # by reading the session_state key directly.
#     stop_btn = st.sidebar.button("⏹ Stop Feed")

#     while cap.isOpened() and not stop_btn:
#         ret, frame = cap.read()
#         if not ret:
#             break

#         frame_count += 1
#         video_buffer.append(frame.copy())

#         # Save post-event snapshot after 2-second delay
#         remaining = []
#         for trigger_time, folder_path in pending_after_snapshots:
#             if time.time() > trigger_time:
#                 img_after = annotate_frame(frame, "POST-EVENT", 0, (0, 255, 255))
#                 cv2.imwrite(os.path.join(folder_path, "snapshot_after.jpg"), img_after)
#             else:
#                 remaining.append((trigger_time, folder_path))
#         pending_after_snapshots = remaining

#         current_alerts = []

#         # FIX 3: Initialise min_dist_val before any proximity check so it
#         # is always defined when metric_prox reads it below.
#         min_dist_val = 999

#         if frame_count % SKIP_FRAMES == 0:
#             results = model.track(frame, persist=True, verbose=False, classes=[0])
#             current_people = []

#             if results[0].boxes.id is not None:
#                 boxes = results[0].boxes.xyxy.cpu().numpy()
#                 ids = results[0].boxes.id.int().cpu().numpy()

#                 for box, track_id in zip(boxes, ids):
#                     # FIX 4: Cast all coords to int immediately so every
#                     # downstream cv2 call receives integer values.
#                     x1, y1, x2, y2 = map(int, box)
#                     w, h = x2 - x1, y2 - y1
#                     cx, cy = x1 + w // 2, y1 + h // 2

#                     person = {
#                         "id": track_id,
#                         "box": (x1, y1, x2, y2),
#                         "center": (cx, cy),
#                         "role": "NEUTRAL",
#                         "threat_score": 0,
#                         "threat_reason": "Scanning...",
#                         "speed_display": "1.0x",
#                     }

#                     # Pose estimation and threat scoring
#                     landmarks = pose_estimator.estimate_pose(frame, (x1, y1, x2, y2))
#                     score, reason = threat_scorer.update(track_id, (x1, y1, w, h), landmarks)
#                     person["threat_score"] = score
#                     person["threat_reason"] = reason

#                     # --------------------------------------------------
#                     # FIX 1 + FIX 2: Speed check moved INSIDE the per-person
#                     # loop, using the local track_id / cx / cy / person vars
#                     # that are defined right above.
#                     # --------------------------------------------------
#                     speed_ratio = 1.0
#                     if track_id in pos_history:
#                         prev_cx, prev_cy = pos_history[track_id]
#                         dist_moved = math.sqrt(
#                             (cx - prev_cx) ** 2 + (cy - prev_cy) ** 2)

#                         if track_id not in speed_history:
#                             speed_history[track_id] = deque(maxlen=10)
#                         speed_history[track_id].append(dist_moved)

#                         if len(speed_history[track_id]) >= 5:
#                             avg_speed = (sum(speed_history[track_id])
#                                          / len(speed_history[track_id]))
#                             if avg_speed > 2.0:
#                                 speed_ratio = dist_moved / avg_speed

#                             if speed_ratio > SPEED_THRESHOLD:
#                                 current_alerts.append("SPEED CHANGE")
#                                 person["role"] = "ATTACKER"

#                                 cooldown_key = f"speed_{track_id}"
#                                 if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
#                                     metrics = {"speed_ratio": f"{speed_ratio:.2f}x"}
#                                     path, i_id = create_incident_report(
#                                         list(video_buffer), frame,
#                                         track_id, "SPEED CHANGE", metrics)
#                                     alert_cooldown[cooldown_key] = time.time()
#                                     detection_log.insert(
#                                         0, f"⚠️ INCIDENT #{i_id}: SPEED CHANGE")
#                                     pending_after_snapshots.append(
#                                         (time.time() + 2.0, path))

#                     pos_history[track_id] = (cx, cy)
#                     person["speed_display"] = f"{speed_ratio:.1f}x"

#                     current_people.append(person)

#             # Clean up stale tracker targets
#             current_ids = [p['id'] for p in current_people]
#             for tid in list(threat_scorer.targets.keys()):
#                 if tid not in current_ids:
#                     del threat_scorer.targets[tid]

#             # ----------------------------------------------------------
#             # 2. PROXIMITY
#             # ----------------------------------------------------------
#             # Pre-filter: discard ghost detections (raised hands, fists,
#             # partial limbs) before running any pairwise distance checks.
#             frame_h, frame_w = frame.shape[:2]
#             valid_people = [
#                 p for p in current_people
#                 if is_valid_person_detection(p['box'], (frame_h, frame_w))
#             ]

#             for i in range(len(valid_people)):
#                 for j in range(i + 1, len(valid_people)):
#                     p1, p2 = valid_people[i], valid_people[j]

#                     # Skip if one detection's center sits inside the other box —
#                     # that means the same person was detected twice (e.g. full
#                     # body + raised-arm crop both tracked simultaneously).
#                     if is_center_inside_box(p1['center'], p2['box']):
#                         continue
#                     if is_center_inside_box(p2['center'], p1['box']):
#                         continue

#                     # Skip if the boxes overlap heavily — two separate people
#                     # cannot physically occupy the same space.
#                     if compute_iou(p1['box'], p2['box']) > 0.30:
#                         continue

#                     dist = math.sqrt(
#                         (p1['center'][0] - p2['center'][0]) ** 2 +
#                         (p1['center'][1] - p2['center'][1]) ** 2)
#                     min_dist_val = min(min_dist_val, dist)

#                     if dist < PROXIMITY_LIMIT:
#                         current_alerts.append("PROXIMITY")
#                         cv2.line(frame, p1['center'], p2['center'],
#                                  (0, 0, 255), 3)

#                         if time.time() - alert_cooldown.get("prox", 0) > 10:
#                             metrics = {"distance_px": int(dist)}
#                             path, i_id = create_incident_report(
#                                 list(video_buffer), frame,
#                                 0, "PROXIMITY", metrics)
#                             alert_cooldown["prox"] = time.time()
#                             detection_log.insert(
#                                 0, f"⚠️ INCIDENT #{i_id}: PROXIMITY")
#                             pending_after_snapshots.append(
#                                 (time.time() + 2.0, path))
#                     else:
#                         cv2.line(frame, p1['center'], p2['center'],
#                                  (0, 255, 0), 1)

#             # ----------------------------------------------------------
#             # 3. ENCIRCLEMENT
#             # ----------------------------------------------------------
#             debug_gap = 360
#             debug_enclosed = 0
#             if len(current_people) >= MIN_ENCIRCLERS:
#                 min_max_gap = 360
#                 best_target = None

#                 for target in current_people:
#                     angles = []
#                     for other in current_people:
#                         if target['id'] == other['id']:
#                             continue
#                         dx = other['center'][0] - target['center'][0]
#                         dy = other['center'][1] - target['center'][1]
#                         if math.sqrt(dx * dx + dy * dy) < ENCIRCLEMENT_DIST:
#                             angle = math.degrees(math.atan2(dy, dx))
#                             if angle < 0:
#                                 angle += 360
#                             angles.append(angle)

#                     if len(angles) >= (MIN_ENCIRCLERS - 1):
#                         angles.sort()
#                         max_gap = 0
#                         for k in range(len(angles)):
#                             gap = angles[(k + 1) % len(angles)] - angles[k]
#                             if gap < 0:
#                                 gap += 360
#                             max_gap = max(max_gap, gap)

#                         if max_gap < min_max_gap:
#                             min_max_gap = max_gap
#                             best_target = target

#                 debug_gap = min_max_gap
#                 if min_max_gap < 360:
#                     debug_enclosed = int((360 - min_max_gap) / 3.6)

#                 if min_max_gap < MAX_GAP_THRESHOLD and best_target:
#                     best_target['role'] = "TARGET"
#                     current_alerts.append("ENCIRCLEMENT")
#                     if time.time() - alert_cooldown.get("circle", 0) > 10:
#                         metrics = {
#                             "max_gap_deg": int(min_max_gap),
#                             "enclosed_pct": debug_enclosed
#                         }
#                         path, i_id = create_incident_report(
#                             list(video_buffer), frame,
#                             best_target['id'], "ENCIRCLEMENT", metrics)
#                         alert_cooldown["circle"] = time.time()
#                         detection_log.insert(
#                             0, f"⚠️ INCIDENT #{i_id}: ENCIRCLEMENT")
#                         pending_after_snapshots.append(
#                             (time.time() + 2.0, path))

#             # ----------------------------------------------------------
#             # 4. POSTURE THREATS (from ThreatScorer)
#             # ----------------------------------------------------------
#             for p in current_people:
#                 if p["threat_score"] > 0:
#                     current_alerts.append(p["threat_reason"])
#                     cooldown_key = f"posture_{p['id']}"
#                     if time.time() - alert_cooldown.get(cooldown_key, 0) > 10:
#                         metrics = {
#                             "threat_score": p["threat_score"],
#                             "reason": p["threat_reason"]
#                         }
#                         path, i_id = create_incident_report(
#                             list(video_buffer), frame,
#                             p['id'], p["threat_reason"], metrics)
#                         alert_cooldown[cooldown_key] = time.time()
#                         detection_log.insert(
#                             0, f"⚠️ INCIDENT #{i_id}: {p['threat_reason']}")
#                         if p["threat_score"] > 70:
#                             gsm_alert.send_sms(
#                                 "+1234567890",
#                                 f"High threat: {p['threat_reason']}, "
#                                 f"Score: {p['threat_score']}")

#             # ----------------------------------------------------------
#             # DRAWING
#             # ----------------------------------------------------------
#             for p in current_people:
#                 color = (0, 255, 0)
#                 if p['role'] in ("TARGET", "ATTACKER"):
#                     color = (0, 0, 255)
#                 elif p.get("threat_score", 0) > 0:
#                     color = (0, 0, 255)

#                 x1, y1, x2, y2 = p['box']   # already ints (FIX 4)
#                 cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
#                 cv2.putText(frame, f"ID:{p['id']}",
#                             (x1, y1 - 10),
#                             cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

#             # ----------------------------------------------------------
#             # UI UPDATES
#             # ----------------------------------------------------------
#             status_text = "SYSTEM SECURE"
#             if current_alerts:
#                 status_text = f"🚨 ALERT: {' + '.join(set(current_alerts))}"
#                 status_placeholder.error(status_text)
#             else:
#                 status_placeholder.success(status_text)

#             metric_speed.metric("Speed Change", "Active")
#             metric_prox.metric(
#                 "Min Distance",
#                 f"{int(min_dist_val)} px" if min_dist_val != 999 else "-"
#             )
#             metric_encircle.metric(
#                 "Encirclement",
#                 f"{debug_enclosed}% Enclosed",
#                 delta=f"Gap: {int(debug_gap)}°",
#                 delta_color="inverse"
#             )

#             log_placeholder.text("\n".join(detection_log[:5]))

#             frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
#             video_placeholder.image(frame_rgb, channels="RGB",
#                                     use_container_width=True)

#     cap.release()
# else:
#     status_placeholder = st.empty()
#     status_placeholder.info("⏸️ Monitor Paused")
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
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator
from logic.threat_scorer import ThreatScorer
from alerts.gsm_alert import GSMAlert

# --- CONFIGURATION ---
st.set_page_config(page_title="Sentinel AI - Security Operations", layout="wide")

# --- AUTH CHECK ---
# Must happen right after set_page_config and before any other st.* calls.
# If no user is logged in, show the login page and stop the rest of this file.
from auth.auth import get_current_user, logout
from auth.roles import can
from pages.login_page import show_login_page

user = get_current_user()
if user is None:
    show_login_page()
    st.stop()

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
                            with open(json_path, "r") as f:
                                data = json.load(f)
                            status = data.get("review_status", "PENDING")
                            if status == "CONFIRMED":
                                confirmed += 1
                            elif status == "FALSE_ALARM":
                                false_alarm += 1
                            else:
                                pending += 1
                        except Exception:
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
    cv2.putText(annotated, f"ALERT: {text}", (10, 35),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.rectangle(annotated, (0, 50), (160, 90), (0, 0, 0), -1)
    cv2.putText(annotated, f"SCORE: {int(score)}/100", (10, 80),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(annotated, ts, (w - 220, h - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
    return annotated


def calculate_threat_score(alert_type: str, metrics: dict) -> int:
    """
    Calculate a meaningful threat score (0–100) based on alert type
    and the measured metrics that triggered it.

    Replaces the previous hardcoded value of 85.

    Scoring rationale:
      SPEED CHANGE    — scaled by how far above the threshold the ratio is.
                        Ratio 2.5x (threshold) → 40.  Ratio 5x+ → 80.
      PROXIMITY       — scaled by how close the pair is relative to the limit.
                        At the limit boundary → 40.  At 0 px → 80.
      ENCIRCLEMENT    — scaled by how enclosed the target is (0–100%).
                        50% enclosed → 55.  90% enclosed → 79.
      Posture threats — use the score already calculated by ThreatScorer,
                        capped at 100.
      Unknown types   — conservative default of 50.
    """
    score = 50  # safe default for unknown alert types

    if alert_type == "SPEED CHANGE":
        try:
            ratio = float(metrics.get("speed_ratio", "2.5x").replace("x", ""))
            # Maps ratio 2.5 → 40, 5.0 → 80, capped at 95
            score = min(95, int(40 + (ratio - 2.5) * 16))
        except (ValueError, AttributeError):
            score = 50

    elif alert_type == "PROXIMITY":
        dist = metrics.get("distance_px", 110)
        limit = PROXIMITY_LIMIT  # global constant
        # Closer = higher score. At limit → 40, at 0px → 80
        closeness = max(0.0, 1.0 - (dist / limit))
        score = min(95, int(40 + closeness * 40))

    elif alert_type == "ENCIRCLEMENT":
        enclosed_pct = metrics.get("enclosed_pct", 50)
        # 50% → 55,  90% → 75,  100% → 80
        score = min(80, int(30 + enclosed_pct * 0.5))

    elif "threat_score" in metrics:
        # Posture threat — ThreatScorer already computed this
        score = min(100, int(metrics["threat_score"]))

    return max(0, score)


def create_incident_report(buffer, peak_frame, track_id, alert_type, metrics):
    timestamp = datetime.now().strftime("%H-%M-%S")
    date_str = datetime.now().strftime("%Y%m%d")
    incident_id = 1
    daily_dir = os.path.join(EVIDENCE_ROOT, date_str)
    if os.path.exists(daily_dir):
        existing = [d for d in os.listdir(daily_dir)
                    if os.path.isdir(os.path.join(daily_dir, d))]
        incident_id = len(existing) + 1

    folder_name = f"INCIDENT_{incident_id:03d}_{alert_type.replace(' ', '_')}_{timestamp}"
    save_path = os.path.join(daily_dir, folder_name)
    os.makedirs(save_path, exist_ok=True)

    threat_score = calculate_threat_score(alert_type, metrics)

    # FIX 7: Use the actual rolling buffer correctly.
    # buffer is a plain list snapshot of the deque passed in.
    # We want the frame ~15 steps before the end of that snapshot.
    if len(buffer) > 15:
        frame_before = buffer[-15]
    elif buffer:
        frame_before = buffer[0]
    else:
        frame_before = peak_frame

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
        "evidence_files": [
            "snapshot_before.jpg",
            "snapshot_peak.jpg",
            "snapshot_after.jpg (pending)"
        ]
    }

    with open(os.path.join(save_path, "report.json"), "w") as f:
        json.dump(report, f, indent=4)

    return save_path, incident_id


def is_valid_person_detection(box, frame_shape, min_area_ratio=0.04, min_aspect=1.2):
    """
    Returns True only if the bounding box looks like a real standing person.
    Filters out ghost detections caused by raised hands, fists, or partial limbs.
      - min_area_ratio: box must cover at least this fraction of the frame area
      - min_aspect:     box height/width must exceed this (portrait shape check)
    """
    x1, y1, x2, y2 = box
    w = x2 - x1
    h = y2 - y1
    if w <= 0 or h <= 0:
        return False
    frame_h, frame_w = frame_shape
    if (w * h) / (frame_h * frame_w) < min_area_ratio:
        return False
    if (h / w) < min_aspect:
        return False
    return True


def compute_iou(box_a, box_b):
    """Intersection-over-Union of two (x1, y1, x2, y2) boxes. Returns [0, 1]."""
    ax1, ay1, ax2, ay2 = box_a
    bx1, by1, bx2, by2 = box_b
    inter_x1, inter_y1 = max(ax1, bx1), max(ay1, by1)
    inter_x2, inter_y2 = min(ax2, bx2), min(ay2, by2)
    inter_area = max(0, inter_x2 - inter_x1) * max(0, inter_y2 - inter_y1)
    if inter_area == 0:
        return 0.0
    union_area = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter_area
    return inter_area / union_area if union_area > 0 else 0.0


def is_center_inside_box(center, box):
    """Returns True if point (cx, cy) lies inside (x1, y1, x2, y2)."""
    cx, cy = center
    x1, y1, x2, y2 = box
    return x1 <= cx <= x2 and y1 <= cy <= y2


# --- SIDEBAR: user info + logout (shown for all roles) ---
st.sidebar.title("Sentinel AI")
st.sidebar.markdown(f"**👤 {user['full_name']}**")
st.sidebar.caption(f"Role: {user['role'].upper()}")
if st.sidebar.button("🚪 Logout", use_container_width=True):
    logout()
    st.rerun()
st.sidebar.divider()

# --- ROLE-BASED ROUTING ---
# The auth check at the top already guaranteed user is not None.
# Now route to the correct page based on their role.

role = user["role"]

if role == "security":
    from pages.security_page import show_security_page
    show_security_page(user)

elif role == "administrator":
    from pages.admin_page import show_admin_page
    show_admin_page(user)

elif role == "supervisor":
    from pages.supervisor_page import show_supervisor_page
    show_supervisor_page(user)

else:
    st.error(f"Unknown role: {role}. Please contact your administrator.")
    st.stop()