"""
core/detector.py

AI detection loop for Sentinel AI — Flask version.

EVIDENCE CHANGES:
  - _video_buffer now stores (timestamp, frame) tuples, maxlen=150
    (~10s of pre-event footage at 15fps)
  - _create_incident_report replaced by _open_evidence_writer:
      * writes pre-event frames into an mp4 VideoWriter
      * saves thumbnail.jpg from the annotated peak frame
      * returns the open writer for the post-event loop to feed
  - _pending_writers replaces _pending_after:
      * each entry is (stop_time, cv2.VideoWriter, folder_path)
      * every live frame is written into all open writers
      * writer.release() is called at stop_time (~5s post-event)
  - Static JPEG snapshots (before/peak/after) removed entirely
"""

import cv2
import math
import time
import os
import json
import threading
import logging
import numpy as np
from datetime import datetime
from collections import deque

from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator
from logic.threat_scorer import ThreatScorer
from alerts.gsm_alert import GSMAlert

logger = logging.getLogger(__name__)

CONFIG_PATH   = "sentinel_config.json"
EVIDENCE_ROOT = "evidence/incidents"

# Target FPS for evidence video.
# 15fps keeps CPU load low while giving smooth playback.
EVIDENCE_FPS = 15

# Pre-event buffer depth.
# 150 frames / 15fps = 10 seconds of footage before the trigger.
PRE_EVENT_FRAMES = 150

# Post-event recording duration in seconds.
POST_EVENT_SECONDS = 5.0

DEFAULT_SETTINGS = {
    "FRAME_WIDTH":        640,
    "FRAME_HEIGHT":       480,
    "SKIP_FRAMES":        2,
    "SPEED_THRESHOLD":    2.5,
    "PROXIMITY_LIMIT":    220,
    "ENCIRCLEMENT_DIST":  300,
    "MAX_GAP_THRESHOLD":  200,
    "MIN_ENCIRCLERS":     3,
    "GSM_PORT":           "COM3",
    "ALERT_NUMBERS":      ["+1234567890"],
}


def _load_settings() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                saved = json.load(f)
            return {**DEFAULT_SETTINGS, **saved}
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()

_shared_state = {
    "active_alerts":   [],
    "detection_log":   [],
    "min_dist_px":     999,
    "encircle_pct":    0,
    "encircle_gap":    360,
    "people_count":    0,
    "threat_score":    0,
    "system_secure":   True,
    "fps":             0,
    "annotated_frame": None,
}


def get_state() -> dict:
    with _state_lock:
        s = dict(_shared_state)
        s.pop("annotated_frame", None)
        return s


def _update_state(**kwargs):
    with _state_lock:
        _shared_state.update(kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_person(box, frame_shape, min_area_ratio=0.005, min_aspect=0.8):
    x1, y1, x2, y2 = box
    w, h = x2 - x1, y2 - y1
    if w <= 0 or h <= 0:
        return False
    fh, fw = frame_shape
    if (w * h) / (fh * fw) < min_area_ratio:
        return False
    if (h / w) < min_aspect:
        return False
    return True


def _iou(a, b):
    ax1, ay1, ax2, ay2 = a
    bx1, by1, bx2, by2 = b
    ix1, iy1 = max(ax1, bx1), max(ay1, by1)
    ix2, iy2 = min(ax2, bx2), min(ay2, by2)
    inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
    if inter == 0:
        return 0.0
    union = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter
    return inter / union if union > 0 else 0.0


def _center_inside(center, box):
    cx, cy = center
    x1, y1, x2, y2 = box
    return x1 <= cx <= x2 and y1 <= cy <= y2


def _calculate_threat_score(alert_type, metrics, proximity_limit):
    score = 50
    if alert_type == "SPEED CHANGE":
        try:
            ratio = float(
                metrics.get("speed_ratio", "2.5x").replace("x", ""))
            score = min(95, int(40 + (ratio - 2.5) * 16))
        except (ValueError, AttributeError):
            score = 50
    elif alert_type == "PROXIMITY":
        dist = metrics.get("distance_px", 110)
        closeness = max(0.0, 1.0 - (dist / proximity_limit))
        score = min(95, int(40 + closeness * 40))
    elif alert_type == "ENCIRCLEMENT":
        enclosed_pct = metrics.get("enclosed_pct", 50)
        score = min(80, int(30 + enclosed_pct * 0.5))
    elif "threat_score" in metrics:
        score = min(100, int(metrics["threat_score"]))
    return max(0, score)


def _stamp_frame(frame, label, score, color=(0, 0, 255)):
    """
    Burn a label + score + timestamp overlay onto a copy of frame.
    Used for the peak frame that becomes the video thumbnail.
    """
    out = frame.copy()
    h, w = out.shape[:2]
    cv2.rectangle(out, (0, 0), (w, 50), color, -1)
    cv2.putText(out, f"ALERT: {label}", (10, 35),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.rectangle(out, (0, 50), (160, 90), (0, 0, 0), -1)
    cv2.putText(out, f"SCORE: {int(score)}/100", (10, 80),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(out, ts, (w - 220, h - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
    return out


def _open_evidence_writer(pre_buffer, peak_frame,
                           alert_type, metrics, proximity_limit):
    """
    Create an incident folder, write pre-event frames into an mp4,
    save the stamped peak frame as thumbnail.jpg, write report.json,
    and return the open VideoWriter so the caller can feed post-event
    frames into it until POST_EVENT_SECONDS have elapsed.
    """
    timestamp   = datetime.now().strftime("%H-%M-%S")
    date_str    = datetime.now().strftime("%Y%m%d")
    daily_dir   = os.path.join(EVIDENCE_ROOT, date_str)
    os.makedirs(daily_dir, exist_ok=True)

    existing    = [d for d in os.listdir(daily_dir)
                   if os.path.isdir(os.path.join(daily_dir, d))]
    incident_id = len(existing) + 1

    folder_name = (
        f"INCIDENT_{incident_id:03d}"
        f"_{alert_type.replace(' ', '_')}_{timestamp}"
    )
    folder_path = os.path.join(daily_dir, folder_name)
    os.makedirs(folder_path, exist_ok=True)

    threat_score = _calculate_threat_score(
        alert_type, metrics, proximity_limit)

    # Thumbnail — stamped peak frame saved as JPEG
    thumb        = _stamp_frame(
        peak_frame, f"{alert_type} DETECTED", threat_score, (0, 0, 255))
    thumb_path   = os.path.join(folder_path, "thumbnail.jpg")
    cv2.imwrite(thumb_path, thumb)

    # VideoWriter — try avc1 (H.264) first, fall back to mp4v, then XVID
    if pre_buffer:
        h, w = pre_buffer[0][1].shape[:2]
    else:
        h, w = peak_frame.shape[:2]

    video_path = os.path.join(folder_path, "evidence.mp4")
    fourcc     = cv2.VideoWriter_fourcc(*'avc1')
    writer     = cv2.VideoWriter(video_path, fourcc, EVIDENCE_FPS, (w, h))

    if not writer.isOpened():
        logger.warning("avc1 unavailable — falling back to mp4v")
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        writer = cv2.VideoWriter(video_path, fourcc, EVIDENCE_FPS, (w, h))

    if not writer.isOpened():
        logger.warning("mp4v unavailable — falling back to XVID/avi")
        video_path = os.path.join(folder_path, "evidence.avi")
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        writer = cv2.VideoWriter(video_path, fourcc, EVIDENCE_FPS, (w, h))

    # Write pre-event frames. Stamp the very first frame so reviewers
    # can see where the clip starts in the timeline.
    for idx, (_, frame) in enumerate(pre_buffer):
        if idx == 0:
            writer.write(_stamp_frame(frame, "PRE-EVENT", 0, (0, 180, 0)))
        else:
            writer.write(frame)

    # Write stamped peak frame into the video
    writer.write(thumb)

    # report.json
    video_filename = os.path.basename(video_path)
    report = {
        "incident_id":    f"INCIDENT_{incident_id:03d}",
        "detection_type": alert_type,
        "timestamp":      datetime.now().isoformat(),
        "threat_score":   threat_score,
        "metrics":        metrics,
        "review_status":  "PENDING",
        "evidence_video": video_filename,       # "evidence.mp4" or .avi
        "thumbnail":      "thumbnail.jpg",
        "pre_event_s":    round(len(pre_buffer) / EVIDENCE_FPS, 1),
        "post_event_s":   POST_EVENT_SECONDS,
    }
    with open(os.path.join(folder_path, "report.json"), "w") as f:
        json.dump(report, f, indent=4)

    logger.info(
        f"Evidence writer opened: INCIDENT_{incident_id:03d} "
        f"({alert_type}) — {len(pre_buffer)} pre-frames written")

    return writer, folder_path, incident_id


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class Detector:

    def __init__(self):
        self._thread         = None
        self._running        = False
        self._camera         = None

        self._model          = None
        self._tracker        = None
        self._pose_estimator = None
        self._threat_scorer  = None
        self._gsm_alert      = None

        self._pos_history    = {}
        self._alert_cooldown = {}
        self._proximity_timers = {}
        self._loitering_alerted = {}
        self._follow_history = {}
        self._follow_start = {}
        self._detection_log  = []

        # Circular pre-event buffer: (timestamp, frame) tuples
        self._video_buffer = deque(maxlen=PRE_EVENT_FRAMES)

        # Open post-event writers: (stop_time, writer, folder_path)
        self._pending_writers = []

    def start(self, camera):
        if self._running:
            return
        self._camera  = camera
        self._running = True
        self._thread  = threading.Thread(
            target=self._detection_loop,
            daemon=True,
            name="DetectorThread"
        )
        self._thread.start()
        logger.info("Detector thread started.")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        for _, writer, _ in self._pending_writers:
            try:
                writer.release()
            except Exception:
                pass
        logger.info("Detector stopped.")

    # ------------------------------------------------------------------

    def _detection_loop(self):
        logger.info("Loading AI models...")
        self._model          = YOLO('yolo11n.pt')
        self._tracker        = PersonTracker()
        self._pose_estimator = PoseEstimator()
        self._threat_scorer  = ThreatScorer()

        settings = _load_settings()
        self._gsm_alert = GSMAlert(port=settings.get("GSM_PORT", "COM3"))
        logger.info("AI models loaded. Detection starting.")

        frame_count = 0
        fps_timer   = time.time()
        fps_counter = 0

        while self._running:
            if frame_count % 300 == 0:
                settings = _load_settings()

            frame = self._camera.get_raw_frame()
            if frame is None:
                time.sleep(0.05)
                continue

            frame_count += 1
            fps_counter += 1

            self._video_buffer.append((time.time(), frame.copy()))

            remaining = []
            for stop_time, writer, folder_path in self._pending_writers:
                try:
                    writer.write(frame)
                except Exception as e:
                    logger.error(f"Writer error ({folder_path}): {e}")

                if time.time() < stop_time:
                    remaining.append((stop_time, writer, folder_path))
                else:
                    writer.release()
                    logger.info(f"Evidence video finalised: {folder_path}")
            self._pending_writers = remaining

            elapsed = time.time() - fps_timer
            if elapsed >= 1.0:
                _update_state(fps=round(fps_counter / elapsed, 1))
                fps_counter = 0
                fps_timer   = time.time()

            skip = int(settings.get("SKIP_FRAMES", 2))
            if frame_count % skip != 0:
                continue

            self._process_frame(frame, settings)

    def _process_frame(self, frame, settings):
        prox_limit        = int(settings.get("PROXIMITY_LIMIT",    220))
        encircle_dist     = int(settings.get("ENCIRCLEMENT_DIST",  300))
        max_gap_threshold = int(settings.get("MAX_GAP_THRESHOLD",  200))
        min_encirclers    = int(settings.get("MIN_ENCIRCLERS",     3))
        alert_numbers     = settings.get("ALERT_NUMBERS", ["+1234567890"])

        current_alerts = []
        min_dist_val   = 999
        debug_gap      = 360
        debug_enclosed = 0

        results        = self._model.track(
            frame, persist=True, verbose=False, classes=[0])
        current_people = []

        if results[0].boxes.id is not None:
            boxes = results[0].boxes.xyxy.cpu().numpy()
            ids   = results[0].boxes.id.int().cpu().numpy()
            confs = results[0].boxes.conf.cpu().numpy() # F5: Extract Confidence

            for box, track_id, conf in zip(boxes, ids, confs):
                x1, y1, x2, y2 = map(int, box)
                w, h   = x2 - x1, y2 - y1
                cx, cy = x1 + w // 2, y1 + h // 2

                person = {
                    "id":            track_id,
                    "conf":          conf, # F5: Store Confidence
                    "box":           (x1, y1, x2, y2),
                    "center":        (cx, cy),
                    "role":          "NEUTRAL",
                    "threat_score":  0,
                    "threat_reason": "Scanning...",
                }

                landmarks = self._pose_estimator.estimate_pose(
                    frame, (x1, y1, x2, y2))
                score, reason = self._threat_scorer.update(
                    track_id, (x1, y1, w, h), landmarks)
                person["threat_score"]  = score
                person["threat_reason"] = reason

                self._pos_history[track_id] = (cx, cy)
                current_people.append(person)

        current_ids = [p['id'] for p in current_people]
        for tid in list(self._threat_scorer.targets.keys()):
            if tid not in current_ids:
                del self._threat_scorer.targets[tid]

        fh, fw       = frame.shape[:2]


        closest_pair = None
        closest_dist = float('inf')
        closest_color = (0, 255, 0)

        for i in range(len(current_people)):
            for j in range(i + 1, len(current_people)):
                p1, p2 = current_people[i], current_people[j]
                if _center_inside(p1['center'], p2['box']): continue
                if _center_inside(p2['center'], p1['box']): continue
                if _iou(p1['box'], p2['box']) > 0.6:       continue

                dist = math.sqrt(
                    (p1['center'][0] - p2['center'][0])**2 +
                    (p1['center'][1] - p2['center'][1])**2)
                min_dist_val = min(min_dist_val, dist)

                key = frozenset({p1['id'], p2['id']})
                mid = ((p1['center'][0] + p2['center'][0]) // 2,
                       (p1['center'][1] + p2['center'][1]) // 2 - 20)

                if dist >= prox_limit:
                    color = (0, 255, 0)
                    cv2.line(frame, p1['center'], p2['center'], color, 1)
                    cv2.circle(frame, p1['center'], 4, color, -1)
                    cv2.circle(frame, p2['center'], 4, color, -1)
                    if key in self._proximity_timers:
                        del self._proximity_timers[key]
                    if key in self._loitering_alerted:
                        del self._loitering_alerted[key]

                elif dist >= prox_limit * 0.5:
                    color = (0, 255, 255)
                    current_alerts.append("PROXIMITY WARNING")
                    cv2.line(frame, p1['center'], p2['center'], color, 2)
                    cv2.circle(frame, p1['center'], 6, color, -1)
                    cv2.circle(frame, p2['center'], 6, color, -1)
                    cv2.putText(frame, "WARNING", mid,
                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
                    if key in self._proximity_timers:
                        del self._proximity_timers[key]
                    if key in self._loitering_alerted:
                        del self._loitering_alerted[key]

                else:
                    color = (0, 0, 255)
                    current_alerts.append("PROXIMITY")

                    # Add distance-based threat contribution to both people
                    proximity_contribution = int((1.0 - dist / prox_limit) * 40)
                    p1["threat_score"] = min(100, p1["threat_score"] + proximity_contribution)
                    p2["threat_score"] = min(100, p2["threat_score"] + proximity_contribution)

                    cv2.line(frame, p1['center'], p2['center'], color, 4)
                    cv2.circle(frame, p1['center'], 10, color, -1)
                    cv2.circle(frame, p2['center'], 10, color, -1)
                    cv2.circle(frame, p1['center'], 18, color, 2)
                    cv2.circle(frame, p2['center'], 18, color, 2)
                    cv2.putText(frame, "THREAT DETECTED", mid,
                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
                    prox_key = f"prox_{min(p1['id'], p2['id'])}_{max(p1['id'], p2['id'])}"
                    if time.time() - self._alert_cooldown.get(prox_key, 0) > 3:
                        self._trigger_incident(
                            frame, "PROXIMITY",
                            {"distance_px": int(dist)},
                            prox_limit)
                        self._alert_cooldown[prox_key] = time.time()

                    if key not in self._proximity_timers:
                        self._proximity_timers[key] = time.time()
                    elif time.time() - self._proximity_timers[key] > 15 and key not in self._loitering_alerted:
                        current_alerts.append("LOITERING")
                        self._loitering_alerted[key] = True
                        elapsed = time.time() - self._proximity_timers[key]

                        # Determine which person is stationary (moved less)
                        prev_p1 = self._pos_history.get(p1['id'], p1['center'])
                        prev_p2 = self._pos_history.get(p2['id'], p2['center'])
                        move_p1 = math.sqrt((p1['center'][0] - prev_p1[0])**2 + (p1['center'][1] - prev_p1[1])**2)
                        move_p2 = math.sqrt((p2['center'][0] - prev_p2[0])**2 + (p2['center'][1] - prev_p2[1])**2)

                        # Add score to the loiterer based on duration (scales: 0-40 points over 0-30s)
                        loiterer = p1 if move_p1 < move_p2 else p2
                        loiter_contribution = int(min(elapsed / 30, 1.0) * 40)
                        loiterer["threat_score"] = min(100, loiterer["threat_score"] + loiter_contribution)

                        cooldown_key = f"loiter_{min(p1['id'], p2['id'])}_{max(p1['id'], p2['id'])}"
                        if time.time() - self._alert_cooldown.get(cooldown_key, 0) > 20:
                            self._trigger_incident(
                                frame, "LOITERING",
                                {"duration_s": int(elapsed), "distance_px": int(dist)},
                                prox_limit)
                            self._alert_cooldown[cooldown_key] = time.time()

                if dist < closest_dist:
                    closest_dist = dist
                    closest_pair = (p1, p2)
                    closest_color = color

        if closest_pair is not None:
            cv2.circle(frame, closest_pair[0]['center'], 6, closest_color, -1)
            cv2.circle(frame, closest_pair[1]['center'], 6, closest_color, -1)

        # Tailgating detection
        if len(current_people) >= 2:
            for i in range(len(current_people)):
                for j in range(len(current_people)):
                    if i == j: continue
                    p1 = current_people[i]
                    p2 = current_people[j]
                    if p1['id'] not in self._pos_history or p2['id'] not in self._pos_history:
                        continue
                    prev_p1 = self._pos_history[p1['id']]
                    prev_p2 = self._pos_history[p2['id']]
                    curr_p1 = p1['center']
                    curr_p2 = p2['center']
                    move_p1 = (curr_p1[0] - prev_p1[0], curr_p1[1] - prev_p1[1])
                    dist_moved_p1 = math.sqrt(move_p1[0]**2 + move_p1[1]**2)
                    if dist_moved_p1 < 3:
                        continue
                    move_p2 = (curr_p2[0] - prev_p2[0], curr_p2[1] - prev_p2[1])
                    angle_p1 = math.degrees(math.atan2(move_p1[1], move_p1[0]))
                    angle_p2 = math.degrees(math.atan2(move_p2[1], move_p2[0]))
                    angle_diff = abs(angle_p1 - angle_p2)
                    if angle_diff > 180:
                        angle_diff = 360 - angle_diff
                    dist_between = math.sqrt((curr_p1[0] - curr_p2[0])**2 + (curr_p1[1] - curr_p2[1])**2)
                    match = angle_diff < 45 and dist_between < prox_limit * 2
                    pair_key = (p1['id'], p2['id'])
                    if pair_key not in self._follow_history:
                        self._follow_history[pair_key] = deque(maxlen=60)
                    self._follow_history[pair_key].append(match)
                    if len(self._follow_history[pair_key]) >= 30:
                        true_count = sum(self._follow_history[pair_key])
                        if true_count > 0.7 * len(self._follow_history[pair_key]):
                            if pair_key not in self._follow_start:
                                self._follow_start[pair_key] = time.time()
                            elapsed = time.time() - self._follow_start[pair_key]
                            if elapsed > 30:
                                current_alerts.append("TAILGATING")
                                p1['role'] = "ATTACKER"
                                p2['role'] = "TARGET"
                                cooldown_key = f"tail_{p1['id']}_{p2['id']}"
                                if time.time() - self._alert_cooldown.get(cooldown_key, 0) > 30:
                                    # Add score contribution to follower (p1 is the ATTACKER/follower)
                                    tailgate_contribution = 40
                                    p1["threat_score"] = min(100, p1["threat_score"] + tailgate_contribution)

                                    self._trigger_incident(
                                        frame, "TAILGATING",
                                        {"follower_id": int(p1['id']), "target_id": int(p2['id']), "follow_duration_s": 30},
                                        prox_limit)
                                    self._alert_cooldown[cooldown_key] = time.time()
                        else:
                            if pair_key in self._follow_start:
                                del self._follow_start[pair_key]

        if len(current_people) >= min_encirclers:
            min_max_gap = 360
            best_target = None

            for target in current_people:
                angles = []
                for other in current_people:
                    if target['id'] == other['id']:
                        continue
                    dx = other['center'][0] - target['center'][0]
                    dy = other['center'][1] - target['center'][1]
                    if math.sqrt(dx*dx + dy*dy) < encircle_dist:
                        angle = math.degrees(math.atan2(dy, dx))
                        if angle < 0:
                            angle += 360
                        angles.append(angle)

                if len(angles) >= (min_encirclers - 1):
                    angles.sort()
                    max_gap_found = 0
                    for k in range(len(angles)):
                        gap = angles[(k + 1) % len(angles)] - angles[k]
                        if gap < 0:
                            gap += 360
                        max_gap_found = max(max_gap_found, gap)
                    if max_gap_found < min_max_gap:
                        min_max_gap = max_gap_found
                        best_target = target

            debug_gap = min_max_gap
            if min_max_gap < 360:
                debug_enclosed = int((360 - min_max_gap) / 3.6)

            if min_max_gap < max_gap_threshold and best_target:
                best_target['role'] = "TARGET"
                current_alerts.append("ENCIRCLEMENT")
                if time.time() - self._alert_cooldown.get(
                        "circle", 0) > 10:
                    # Add score contributions based on enclosed_pct
                    # Large contribution to the enclosed person (target)
                    enclosed_score_contribution = int((debug_enclosed / 100.0) * 50)
                    best_target["threat_score"] = min(100, best_target["threat_score"] + enclosed_score_contribution)

                    # Find encirclers and add smaller contributions
                    encircler_score_contribution = int((debug_enclosed / 100.0) * 20)
                    for other in current_people:
                        if other['id'] == best_target['id']:
                            continue
                        dist_to_target = math.sqrt(
                            (other['center'][0] - best_target['center'][0])**2 +
                            (other['center'][1] - best_target['center'][1])**2)
                        if dist_to_target < encircle_dist:
                            other["threat_score"] = min(100, other["threat_score"] + encircler_score_contribution)

                    self._trigger_incident(
                        frame, "ENCIRCLEMENT",
                        {"max_gap_deg":  int(min_max_gap),
                         "enclosed_pct": debug_enclosed},
                        prox_limit)
                    self._alert_cooldown["circle"] = time.time()

        for p in current_people:
            if p["threat_score"] > 0:
                current_alerts.append(p["threat_reason"])
                ckey = f"posture_{p['id']}"
                if time.time() - self._alert_cooldown.get(ckey, 0) > 10:
                    self._trigger_incident(
                        frame, p["threat_reason"],
                        {"threat_score": p["threat_score"],
                         "reason":       p["threat_reason"]},
                        prox_limit)
                    self._alert_cooldown[ckey] = time.time()
                    if p["threat_score"] > 70:
                        for number in alert_numbers:
                            self._gsm_alert.send_sms(
                                number,
                                f"High threat: {p['threat_reason']}, "
                                f"Score: {p['threat_score']}")

        # --- F5: Per-Detection Confidence Overlay & Box Drawing ---
        for p in current_people:
            color = (0, 255, 0)
            if p['role'] in ("TARGET", "ATTACKER") or \
               p.get("threat_score", 0) > 0:
                color = (0, 0, 255)
            x1, y1, x2, y2 = p['box']
            cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
            
            # Format the label to include the confidence percentage
            label = f"ID:{p['id']} ({p['conf']:.0%})" 
            cv2.putText(frame, label, (x1, y1 - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

        _, jpeg = cv2.imencode(
            '.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
        jpeg_bytes = jpeg.tobytes()

        self._detection_log = self._detection_log[:20]
        self._camera.set_annotated_frame(jpeg_bytes)

        _update_state(
            active_alerts  = list(set(current_alerts)),
            detection_log  = list(self._detection_log),
            min_dist_px    = int(min_dist_val) if min_dist_val != 999 else 999,
            encircle_pct   = debug_enclosed,
            encircle_gap   = int(debug_gap),
            people_count   = len(current_people),
            threat_score   = max(
                (p.get("threat_score", 0) for p in current_people),
                default=0),
            system_secure  = len(current_alerts) == 0,
            annotated_frame= jpeg_bytes,
        )

    def _trigger_incident(self, peak_frame, alert_type,
                           metrics, proximity_limit):
        """
        Snapshot the circular buffer, open a VideoWriter for this
        incident, and register it in _pending_writers so the main
        loop feeds post-event frames into it.
        """
        pre_frames = list(self._video_buffer)

        writer, folder_path, incident_id = _open_evidence_writer(
            pre_frames, peak_frame,
            alert_type, metrics, proximity_limit)

        stop_time = time.time() + POST_EVENT_SECONDS
        self._pending_writers.append((stop_time, writer, folder_path))

        self._detection_log.insert(
            0, f"⚠️ INCIDENT #{incident_id}: {alert_type}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
detector = Detector()