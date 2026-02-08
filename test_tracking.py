import cv2
from ultralytics import YOLO
from tracking.deepsort_tracker import PersonTracker

# 1. Initialize Models
model = YOLO('yolo11n.pt')
tracker = PersonTracker(max_age=100, n_init=3)

# 2. Open Camera
cap = cv2.VideoCapture(0)

while cap.isOpened():
    success, frame = cap.read()
    if not success:
        break

    # 3. Detect (YOLO)
    # results[0].boxes.data returns [x1, y1, x2, y2, conf, class]
    yolo_results = model(frame, classes=[0], verbose=False)
    
    # Format detections for DeepSORT: [[left, top, w, h], confidence, class_id]
    detections_for_sort = []
    
    for box in yolo_results[0].boxes.data.tolist():
        x1, y1, x2, y2, conf, cls_id = box
        w = x2 - x1
        h = y2 - y1
        # DeepSORT expects [left, top, w, h], conf, class_id
        detections_for_sort.append([[x1, y1, w, h], conf, int(cls_id)])

    # 4. Track (DeepSORT)
    tracked_objects = tracker.update(detections_for_sort, frame)

    # 5. Visualize
    for obj in tracked_objects:
        # Draw Bounding Box
        x1, y1, x2, y2 = map(int, obj['bbox'])
        track_id = obj['id']
        
        # Color: Green for tracked objects
        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
        
        # Draw ID Label (The "Memory")
        cv2.putText(frame, f"ID: {track_id}", (x1, y1 - 10), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)

    cv2.imshow("Tracking Test - Look for persistent IDs", frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()