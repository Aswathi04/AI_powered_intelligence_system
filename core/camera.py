"""
core/camera.py

Camera feed reader for Sentinel AI — Flask version.

Runs in a background thread so the video stream is never
blocked by the AI detection loop.

Key design decisions:
  - Queue maxsize=1 — always drops old frames, keeps only latest.
    This is the single biggest lag reduction technique.
  - Separate thread for reading — cv2.VideoCapture.read()
    blocks until a frame arrives. Running it in a thread means
    Flask routes never wait for the camera.
  - Works with webcam (index 0) or ESP32-CAM (http URL).
    Change CAMERA_SOURCE to switch between them.

FIX LOG:
  - FIX 1: generate_mjpeg now serves annotated frames from the
    detector (via set_annotated_frame / get_annotated_jpeg)
    rather than raw camera frames. This is the primary reason
    detection boxes were not appearing in the browser.
  - FIX 2: CAP_DSHOW replaced with cross-platform backend
    selection — DSHOW only on Windows, default elsewhere.
  - FIX 3: Added a fallback placeholder frame so the browser
    shows "Camera offline" rather than a frozen black screen
    when the camera hasn't connected yet.
"""

import sys
import cv2
import time
import threading
import queue
import logging
import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Change this to switch camera source:
#   Webcam    : 0  (or 1, 2 for second/third camera)
#   ESP32-CAM : "http://192.168.x.x/stream"
# ---------------------------------------------------------------------------
CAMERA_SOURCE = 0

FRAME_WIDTH  = 640
FRAME_HEIGHT = 480
JPEG_QUALITY = 80


class Camera:
    """
    Background-threaded camera reader.

    Two separate frame slots:
      _raw_frame        — latest BGR numpy array, read by detector
      _annotated_jpeg   — latest annotated JPEG bytes from detector,
                          served to the browser by generate_mjpeg

    The detector calls set_annotated_frame() after drawing boxes.
    generate_mjpeg calls get_annotated_jpeg() to serve the browser.
    This keeps the video stream decoupled from detection speed.
    """

    def __init__(self, source=CAMERA_SOURCE,
                 width=FRAME_WIDTH, height=FRAME_HEIGHT):
        self.source = source
        self.width  = width
        self.height = height

        # Raw frame for the detector
        self._raw_frame  = None
        self._raw_lock   = threading.Lock()

        # FIX 1: Annotated frame written by detector, read by generate_mjpeg.
        # Previously this slot existed in _shared_state inside detector.py
        # but generate_mjpeg was reading from the raw queue instead.
        self._annotated_jpeg  = None
        self._annotated_lock  = threading.Lock()

        self._cap       = None
        self._thread    = None
        self._running   = False
        self._connected = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Start the background capture thread."""
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="CameraThread"
        )
        self._thread.start()
        logger.info(f"Camera thread started — source: {self.source}")

    def stop(self):
        """Stop the capture thread and release the camera."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._cap:
            self._cap.release()
        self._connected = False
        logger.info("Camera stopped.")

    def get_raw_frame(self):
        """
        Return the latest raw numpy frame (BGR) for the detector.
        Returns None if no frame is available yet.
        """
        with self._raw_lock:
            return self._raw_frame.copy() if self._raw_frame is not None else None

    def set_annotated_frame(self, jpeg_bytes: bytes):
        """
        FIX 1: Called by the detector after drawing boxes onto a frame.
        Stores the annotated JPEG so generate_mjpeg can serve it.

        This is the bridge between the detection pipeline and the browser.
        Without this, the detector's work is invisible — raw frames
        go to the browser while annotated frames sit unused in
        _shared_state["annotated_frame"].
        """
        with self._annotated_lock:
            self._annotated_jpeg = jpeg_bytes

    def get_annotated_jpeg(self) -> bytes | None:
        """
        Return the latest annotated JPEG for the MJPEG stream.
        Falls back to a raw JPEG if detector hasn't produced one yet,
        and to a placeholder frame if the camera isn't connected.
        """
        with self._annotated_lock:
            if self._annotated_jpeg is not None:
                return self._annotated_jpeg

        # Detector hasn't run yet — serve raw frame so stream isn't blank
        with self._raw_lock:
            if self._raw_frame is not None:
                ok, jpeg = cv2.imencode(
                    '.jpg', self._raw_frame,
                    [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
                if ok:
                    return jpeg.tobytes()

        # Camera not connected yet — return placeholder
        return _make_placeholder_frame()

    def is_connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Internal capture loop
    # ------------------------------------------------------------------

    def _capture_loop(self):
        """
        Continuously read frames from the camera.
        Reconnects automatically if the feed drops.
        """
        while self._running:
            # FIX 2: CAP_DSHOW is Windows-only.
            # Using it on Linux/Mac causes VideoCapture to silently
            # fail — isOpened() returns True but read() always fails.
            if sys.platform == "win32":
                self._cap = cv2.VideoCapture(self.source, cv2.CAP_DSHOW)
            else:
                self._cap = cv2.VideoCapture(self.source)

            self._cap.set(cv2.CAP_PROP_FRAME_WIDTH,  self.width)
            self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
            self._cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

            if not self._cap.isOpened():
                logger.warning(
                    f"Could not open camera source: {self.source}. "
                    f"Retrying in 3s...")
                self._connected = False
                time.sleep(3)
                continue

            self._connected = True
            logger.info(f"Camera connected: {self.source}")

            fail_count = 0

            while self._running:
                ret, frame = self._cap.read()

                if not ret:
                    fail_count += 1
                    logger.warning(
                        f"Frame read failed (attempt {fail_count})...")
                    time.sleep(0.1)
                    # After 10 consecutive failures, force reconnect
                    if fail_count >= 10:
                        logger.error(
                            "10 consecutive frame failures — reconnecting.")
                        break
                    continue

                fail_count = 0  # reset on success

                # Store raw frame for detector
                with self._raw_lock:
                    self._raw_frame = frame

                time.sleep(0.03)  # ~33 FPS cap

            if self._cap:
                self._cap.release()
            self._connected = False

        logger.info("Camera thread exited.")


# ---------------------------------------------------------------------------
# MJPEG stream generator
# ---------------------------------------------------------------------------

def generate_mjpeg(camera: Camera):
    """
    Generator for Flask's MJPEG streaming route.

    FIX 1: Now reads from camera.get_annotated_jpeg() instead of
    camera.get_jpeg() (the raw queue). This means the browser receives
    frames with YOLO bounding boxes, track IDs, and alert overlays.

    Falls back to raw frame → placeholder if detector hasn't run yet.
    """
    while True:
        jpeg = camera.get_annotated_jpeg()

        if jpeg is None:
            time.sleep(0.03)
            continue

        yield (
            b'--frame\r\n'
            b'Content-Type: image/jpeg\r\n\r\n'
            + jpeg +
            b'\r\n'
        )


def _make_placeholder_frame() -> bytes:
    """Generate a dark gray 'Camera offline' placeholder JPEG."""
    frame = np.zeros((FRAME_HEIGHT, FRAME_WIDTH, 3), dtype='uint8')
    frame[:] = (40, 40, 40)
    cv2.putText(frame, "Camera offline",
                (FRAME_WIDTH // 2 - 120, FRAME_HEIGHT // 2 - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 1.0, (160, 160, 160), 2)
    cv2.putText(frame, "Check connection and refresh",
                (FRAME_WIDTH // 2 - 160, FRAME_HEIGHT // 2 + 30),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (100, 100, 100), 1)
    _, jpeg = cv2.imencode('.jpg', frame,
                           [cv2.IMWRITE_JPEG_QUALITY, 70])
    return jpeg.tobytes()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
camera = Camera()