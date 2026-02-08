import cv2
from ultralytics import YOLO

# Load the model defined in your Spec (YOLOv11 Nano)
# It will auto-download the first time you run it.
model = YOLO('yolo11n.pt') 

# Open webcam (0 is usually the default laptop cam)
cap = cv2.VideoCapture(0)

while cap.isOpened():
    success, frame = cap.read()
    if not success:
        break

    # Run inference
    # We filter classes=[0] because class 0 is 'person' in COCO dataset
    results = model(frame, classes=[0], verbose=False)

    # Visualize results on the frame
    annotated_frame = results[0].plot()

    # Display
    cv2.imshow("Security Feed Test", annotated_frame)

    # Break loop with 'q' key
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()