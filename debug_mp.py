import sys
import os

try:
    import mediapipe
    print(f"✅ MediaPipe found at: {os.path.dirname(mediapipe.__file__)}")
except ImportError:
    print("❌ MediaPipe not installed.")
except AttributeError:
    print("❌ MediaPipe imported, but broken (AttributeError).")
    # This usually means it imported a local file/folder instead of the library
    print(f"⚠️  It likely loaded this file instead: {mediapipe.__file__}")

print(f"\nPython is running from: {sys.executable}")