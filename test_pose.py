import cv2
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker
from pose.mediapipe_estimator import PoseEstimator

# 1. Initialize All 3 Brains
model = YOLO('yolo11n.pt')
tracker = PersonTracker()
pose_estimator = PoseEstimator()

cap = cv2.VideoCapture(0)

while cap.isOpened():
    ret, frame = cap.read()
    if not ret: break

    # 1. Detect
    results = model(frame, classes=[0], verbose=False)
    
    detections = []
    for box in results[0].boxes.data.tolist():
        x1, y1, x2, y2, conf, cls = box
        detections.append([[x1, y1, x2-x1, y2-y1], conf, cls])

    # 2. Track
    tracks = tracker.update(detections, frame)

    for track in tracks:
        bbox = track['bbox']
        track_id = track['id']
        
        # 3. Analyze Pose
        landmarks = pose_estimator.estimate_pose(frame, bbox)
        
        # Draw Box
        x1, y1, x2, y2 = map(int, bbox)
        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
        cv2.putText(frame, f"ID: {track_id}", (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0,255,0), 2)

        # Draw Skeleton (if found)
        if landmarks:
            # Draw Wrist-to-Elbow-to-Shoulder connections
            # Indices: 11=L.Shoulder, 13=L.Elbow, 15=L.Wrist
            # Indices: 12=R.Shoulder, 14=R.Elbow, 16=R.Wrist
            
            # Draw Left Arm (Red)
            if landmarks[11]['vis'] > 0.5 and landmarks[13]['vis'] > 0.5:
                cv2.line(frame, (landmarks[11]['x'], landmarks[11]['y']), (landmarks[13]['x'], landmarks[13]['y']), (0,0,255), 3)
            if landmarks[13]['vis'] > 0.5 and landmarks[15]['vis'] > 0.5:
                cv2.line(frame, (landmarks[13]['x'], landmarks[13]['y']), (landmarks[15]['x'], landmarks[15]['y']), (0,0,255), 3)

            # Draw Right Arm (Blue)
            if landmarks[12]['vis'] > 0.5 and landmarks[14]['vis'] > 0.5:
                cv2.line(frame, (landmarks[12]['x'], landmarks[12]['y']), (landmarks[14]['x'], landmarks[14]['y']), (255,0,0), 3)
            
            # Check for "Hands Raised" (Basic Threat/Distress logic)
            # If Wrist Y < Shoulder Y (remember Y=0 is top of screen)
            if landmarks[15]['y'] < landmarks[11]['y'] and landmarks[16]['y'] < landmarks[12]['y']:
                cv2.putText(frame, "** HANDS RAISED **", (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (0,0,255), 3)

    cv2.imshow("Pose Test", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'): break

cap.release()
cv2.destroyAllWindows()