# Sentinel AI: Security Operations Center

Sentinel AI is an AI-driven surveillance system built to monitor video feeds, detect suspicious human behaviors, and capture threat evidence automatically. It combines object detection, tracking, pose estimation, and alerting into a single security operations workflow.


## 🔍 Core Capabilities

- Real-time person detection using YOLO.
- Persistent multi-object tracking with DeepSORT.
- Pose estimation via MediaPipe to identify suspicious postures.
- Threat scoring and classification for events such as proximity, encirclement, speed changes, and aggressive movement.
- Incident evidence recording into date-based folders under `evidence/incidents/`.
- Optional Twilio SMS alerts for verified incidents.
- Flask-based dashboard with user authentication and live stream support.

## 📂 Main Project Structure

### Root
- `app.py` — Flask application entry point.
- `demo_attack.py` — Demo detection script for lunge and proximity testing.
- `test_full_system.py` — Example pipeline for YOLO detection, tracking, and pose-based scoring.
- `sentinel_config.json` — Runtime configuration for camera settings, thresholds, Twilio, and demo mode.
- `yolo11n.pt` — YOLO model weights used for person detection.
- `requirements.txt` — currently empty; install dependencies manually or populate this file.

### Modules
- `auth/` — login and role-based access support.
- `core/` — camera capture and detection pipeline.
- `logic/` — threat scoring logic and risk assessment.
- `tracking/` — DeepSORT tracker wrapper.
- `pose/` — MediaPipe pose estimation.
- `alerts/` — Twilio SMS alert support.
- `evidence/` — incident recordings and reports.
- `templates/` — Flask HTML templates.
- `static/` — CSS and JavaScript for UI.

## 🧠 How the System Works

1. `app.py` runs the Flask web application, managing authentication, dashboard views, and camera stream delivery.
2. `core/detector.py` implements the main surveillance logic:
   - Loads YOLO for person detection.
   - Uses `tracking/deepsort_tracker.py` to maintain consistent IDs.
   - Uses `pose/mediapipe_estimator.py` for posture detection.
   - Uses `logic/threat_scorer.py` to calculate threat scores.
   - Buffers pre-event frames and writes incident videos post-trigger.
3. `alerts/twilio_alert.py` handles sending SMS notifications for alerts when configured.

## ⚙️ Dependencies

Install the primary dependencies manually in a Python environment:

```bash
pip install flask opencv-python ultralytics mediapipe numpy twilio deep_sort_realtime
```

> Note: `requirements.txt` is empty in this repository, so dependency installation is currently manual.

## 🚀 Running the System

1. Activate your Python virtual environment.
2. Install the required packages.
3. Configure `sentinel_config.json` with your camera source, thresholds, and optional Twilio credentials.
4. Run the Flask app:

```bash
python app.py
```

5. Open the web app at the URL shown in the console.

## 📝 Configuration Notes

`sentinel_config.json` includes:
- `FRAME_WIDTH`, `FRAME_HEIGHT`, `SKIP_FRAMES`
- `SPEED_THRESHOLD`, `PROXIMITY_LIMIT`, `ENCIRCLEMENT_DIST`, `MIN_ENCIRCLERS`
- `CAMERA_PORT`, `CAMERA_LOCATION`
- `DEMO_MODE`, `DEMO_VIDEO`
- `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`, `ALERT_NUMBERS`

## 🧪 Useful Scripts

- `python test_full_system.py` — run the core detection and tracking logic in an OpenCV window.
- `python demo_attack.py` — demo script tuned for lunge and proximity detection.
- `python test_cam.py`, `python test_pose.py`, `python test_tracking.py` — debugging and component tests.

## 📌 Important Note

Although older documentation mentions Streamlit, the active application in this repository is currently Flask-based with a Flask dashboard and camera streaming support.


## ⚙️ Configuration & Thresholds

System sensitivity can be adjusted by modifying the global variables at the top of the scripts:

* `SPEED_THRESHOLD`: Multiplier for detecting sudden acceleration (default: 2.5x).
* `PROXIMITY_LIMIT`: Pixel distance to trigger proximity alerts (default: 220px).
* `ENCIRCLEMENT_DIST`: Radius to check for surrounding attackers (default: 300px).
* `LUNGE_THRESHOLD`: Bounding box growth percentage to flag aggressive approaches (default: 1.15).

## 📝 Incident Auditing Protocol

When the system detects a threat, it generates a folder under `evidence/incidents/YYYYMMDD/` containing:

1. `snapshot_before.jpg`: The scene moments before the incident.
2. `snapshot_peak.jpg`: The exact moment the threat threshold was breached.
3. `snapshot_after.jpg`: The scene shortly after the incident.
4. `report.json`: Contains detection metrics, timestamps, and the review status.

Security personnel must use the Dashboard's **Review** tab to mark these pending incidents as either `CONFIRMED` (True Threat) or `FALSE_ALARM`.

