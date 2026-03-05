 
## Sentinel AI: Security Operations Center

Sentinel AI is an advanced, AI-powered intelligence and surveillance system designed to analyze crowd behavior and detect potential physical threats in real-time. Built with a focus on enhancing public safety, the system utilizes state-of-the-art computer vision to monitor video feeds, track individuals, analyze body posture, and alert security personnel to suspicious or dangerous activities via a centralized dashboard.

## ✨ Key Features

* **Real-Time Threat Detection:** Analyzes live camera feeds to detect anomalous behaviors, including:
    * **Proximity & Stalking:** Flags individuals maintaining unusually close distances to others.
    * **Encirclement:** Detects when a target is surrounded by multiple individuals based on angle and gap calculations.
    * **Aggressive Approach (Lunge):** Identifies sudden, aggressive movements towards the camera or others by analyzing bounding box expansion.
    * **Speed Anomalies:** Tracks sudden, unnatural accelerations in movement.
    * **Surrender Detection:** Uses pose estimation to detect when a person has their hands raised above their shoulders.
* **Security Operations Dashboard:** A dedicated Streamlit web interface for security personnel to monitor the live tactical view, view active threats, and audit past incidents.
* **Automated Incident Reporting:** Automatically captures "Pre-Event", "Peak", and "Post-Event" snapshots when a threat is detected and logs them into structured JSON reports for manual review.
* **Multi-Object Tracking:** Assigns consistent IDs to individuals across frames to maintain movement history and reduce false alarms (threat smoothing/debouncing).

## 🛠️ Technology Stack

* **UI/Dashboard:** [Streamlit](https://streamlit.io/)
* **Computer Vision:** [OpenCV](https://opencv.org/)
* **Object Detection:** [Ultralytics YOLOv11](https://docs.ultralytics.com/) (`yolo11n.pt`)
* **Object Tracking:** DeepSORT
* **Pose Estimation:** [Google MediaPipe](https://developers.google.com/mediapipe)
* **Language:** Python 3.x

## 📂 Project Structure

* `sentinel_dashboard.py`: The primary Streamlit application. Acts as the SOC (Security Operations Center), providing a UI for live camera feeds, live logs, threat metrics, and an incident case file review system.
* `test_full_system.py`: The core surveillance pipeline. Integrates YOLO detection, DeepSORT tracking, and MediaPipe pose estimation to process frames, apply logic thresholds, and render visual alerts.
* `logic/threat_scorer.py`: Contains the `ThreatScorer` class which evaluates individual tracking history and body landmarks to assign threat scores (0-100) based on poses (e.g., surrendering) or movements (e.g., lunging).
* `tracking/deepsort_tracker.py`: *(Module)* Handles the persistence of object IDs across video frames.
* `pose/mediapipe_estimator.py`: *(Module)* Extracts skeletal landmarks to determine body posture.
* `evidence/incidents/`: *(Auto-generated)* Directory where the system saves incident reports (`report.json`) and snapshot evidence.

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <your-repository-url>
   cd AI_powered_intelligence_system

```

2. **Install the required dependencies:**
Ensure you have Python installed, then run:
```bash
pip install streamlit opencv-python ultralytics mediapipe numpy

```


*(Note: Ensure you also have the necessary dependencies for DeepSORT if not included in the primary requirements).*
3. **Download YOLO Weights:**
Ensure the YOLOv11 nano weights file (`yolo11n.pt`) is present in the root directory. If missing, Ultralytics will typically download it automatically upon the first run.

## 💻 Usage

### 1. Launching the Security Dashboard

To open the Sentinel AI Operations Center interface, run the Streamlit app:

```bash
streamlit run sentinel_dashboard.py

```

* **Live Tactical View:** Toggle "ACTIVATE SURVEILLANCE" in the sidebar to start the webcam feed and begin threat detection.
* **Incident Review:** Navigate to the "Incident Review & Audit" tab to review captured evidence, confirm threats, or dismiss false alarms.

### 2. Running the Standalone System (Phase 4 Logic)

To test the core detection and tracking logic (without the web dashboard) directly via an OpenCV window:

```bash
python test_full_system.py

```

*Press `q` to quit the video stream.*

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

