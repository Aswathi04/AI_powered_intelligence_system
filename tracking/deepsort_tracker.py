from deep_sort_realtime.deepsort_tracker import DeepSort

class PersonTracker:
    def __init__(self, max_age=30, n_init=3):
        """
        Initialize DeepSORT tracker.
        """
        self.tracker = DeepSort(
            max_age=max_age,
            n_init=n_init,
            nms_max_overlap=1.0,
            max_cosine_distance=0.2,
            embedder="mobilenet", # Lightweight for Pi
        )

    def update(self, detections, frame):
        """
        Update tracker with new YOLO detections.
        """
        # Update tracker
        tracks = self.tracker.update_tracks(detections, frame=frame)
        
        results = []
        for track in tracks:
            if not track.is_confirmed():
                continue
                
            track_id = track.track_id
            # Get the bounding box as [left, top, w, h]
            ltrb = track.to_ltrb() 
            
            results.append({
                'id': track_id,
                'bbox': ltrb
                # We removed 'trace' to fix the error
            })
            
        return results