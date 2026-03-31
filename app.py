"""
app.py

Flask main application for Sentinel AI.

Routes:
  GET  /                    → redirect to login or dashboard
  GET  /login               → login page
  POST /login               → handle login form
  GET  /logout              → logout
  GET  /security            → security officer dashboard
  GET  /admin               → administrator panel
  GET  /supervisor          → supervisor panel
  GET  /video_feed          → MJPEG stream
  GET  /alerts_stream       → SSE live alerts
  GET  /api/state           → JSON snapshot of detector state
  POST /api/config          → save configuration (admin only)
  POST /api/incident/review → acknowledge or dismiss incident
  GET  /api/incidents       → list incidents (JSON)
  GET  /evidence/<path>     → serve evidence snapshots
  GET  /history             → alert history page
"""

import os
import json
import time
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, Response, jsonify,
    send_from_directory, stream_with_context
)
from functools import wraps

from auth.db    import init_db, log_action, get_all_users
from auth.roles import can
from core.camera   import camera, generate_mjpeg
from core.detector import detector, get_state

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SENTINEL_SECRET", "sentinel-ai-secret-2026")

EVIDENCE_ROOT = "evidence/incidents"
CONFIG_PATH   = "sentinel_config.json"

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    """Decorator — redirects to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorator — returns 403 if user role not in allowed roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            if session["user"]["role"] not in roles:
                return render_template("403.html"), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def get_current_user():
    return session.get("user", None)


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    role = session["user"]["role"]
    return redirect(url_for(role))   # → /security, /admin, /supervisor


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        from auth.db   import get_user, verify_password, update_last_login
        user = get_user(username)

        if user and verify_password(password, user["password_hash"], user["salt"]):
            session["user"] = {
                "id":        user["id"],
                "username":  user["username"],
                "role":      user["role"],
                "full_name": user["full_name"],
                "email":     user["email"],
            }
            update_last_login(username)
            log_action(username, "LOGIN", f"Role: {user['role']}")
            return redirect(url_for("index"))
        else:
            log_action(username, "LOGIN_FAILED", "Wrong credentials")
            error = "Incorrect username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = session.get("user")
    if user:
        log_action(user["username"], "LOGOUT", "")
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Routes — Role dashboards
# ---------------------------------------------------------------------------

@app.route("/security")
@role_required("security")
def security():
    return render_template("security.html", user=get_current_user())


@app.route("/admin")
@role_required("administrator")
def administrator():
    config = _load_config()
    users  = [dict(u) for u in get_all_users()]
    return render_template("admin.html",
                           user=get_current_user(),
                           config=config,
                           users=users)


@app.route("/supervisor")
@role_required("supervisor")
def supervisor():
    incidents = _get_all_incidents()
    by_type   = _count_by_type(incidents)
    by_status = _count_by_status(incidents)
    return render_template("supervisor.html",
                           user=get_current_user(),
                           total=len(incidents),
                           by_type=by_type,
                           by_status=by_status)


@app.route("/history")
@login_required
def history():
    # --- F3: Load all incidents to populate the replay viewer UI ---
    incidents = _get_all_incidents()
    return render_template("history.html", user=get_current_user(), incidents=incidents)


# ---------------------------------------------------------------------------
# Routes — Video + SSE
# ---------------------------------------------------------------------------

@app.route("/video_feed")
@login_required
def video_feed():
    """MJPEG stream — lowest possible lag."""
    return Response(
        generate_mjpeg(camera),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )


@app.route("/alerts_stream")
@login_required
def alerts_stream():
    """
    Server-Sent Events stream.
    Browser connects once, Flask pushes alert updates instantly.
    No polling needed — browser receives updates within ~50ms.
    """
    def event_stream():
        last_alerts = []
        while True:
            state = get_state()
            alerts = state.get("active_alerts", [])

            # Only push when alerts change
            if alerts != last_alerts:
                data = json.dumps({
                    "alerts":       alerts,
                    "secure":       state.get("system_secure", True),
                    "min_dist":     state.get("min_dist_px",   999),
                    "encircle_pct": state.get("encircle_pct",  0),
                    "encircle_gap": state.get("encircle_gap",  360),
                    "people":       state.get("people_count",  0),
                    "threat_score": state.get("threat_score",  0),
                    "fps":          state.get("fps",           0),
                    "log":          state.get("detection_log", [])[:5],
                })
                yield f"data: {data}\n\n"
                last_alerts = alerts

            time.sleep(0.2)   # check 5 times per second

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.route("/api/state")
@login_required
def api_state():
    """JSON snapshot of current detector state."""
    return jsonify(get_state())


@app.route("/api/config", methods=["POST"])
@role_required("administrator")
def api_config():
    """Save configuration from admin panel."""
    config = _load_config()
    data   = request.form

    config.update({
        "CAMERA_PORT":       int(data.get("camera_port",       0)),
        "CAMERA_LOCATION":   data.get("camera_location",       "Main Entrance"),
        "FRAME_WIDTH":       int(data.get("frame_width",        640)),
        "FRAME_HEIGHT":      int(data.get("frame_height",       480)),
        "SKIP_FRAMES":       int(data.get("skip_frames",        2)),
        "PROXIMITY_LIMIT":   int(data.get("proximity_limit",    220)),
        "SPEED_THRESHOLD":   float(data.get("speed_threshold",  2.5)),
        "ENCIRCLEMENT_DIST": int(data.get("encirclement_dist",  300)),
        "MAX_GAP_THRESHOLD": int(data.get("max_gap_threshold",  200)),
        "MIN_ENCIRCLERS":    int(data.get("min_encirclers",     3)),
        "GSM_PORT":          data.get("gsm_port",               "COM3"),
        # --- F4: Demo Mode Configuration Support ---
        "DEMO_MODE":         data.get("demo_mode") == "on",
        "DEMO_VIDEO":        data.get("demo_video", "demo_attack.mp4"),
    })
    _save_config(config)

    user = get_current_user()
    log_action(user["username"], "CONFIG_CHANGE",
               f"proximity={config['PROXIMITY_LIMIT']}, "
               f"speed={config['SPEED_THRESHOLD']}, "
               f"demo_mode={config['DEMO_MODE']}")

    return redirect(url_for("administrator"))


@app.route("/api/incident/review", methods=["POST"])
@role_required("security")
def api_incident_review():
    """Acknowledge or dismiss an incident."""
    data        = request.get_json()
    report_path = data.get("report_path", "")
    status      = data.get("status", "")
    note        = data.get("note",   "")
    user        = get_current_user()

    if status not in ("CONFIRMED", "FALSE_ALARM"):
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    report_path = os.path.join(EVIDENCE_ROOT, report_path)

    if not os.path.exists(report_path):
        return jsonify({"ok": False, "error": "Report not found"}), 404

    with open(report_path) as f:
        report = json.load(f)

    report["review_status"] = status
    report["reviewed_by"]   = user["full_name"]
    report["reviewed_at"]   = datetime.now().isoformat()
    report["review_note"]   = note

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    action = "ALERT_ACK" if status == "CONFIRMED" else "ALERT_DISMISS"
    log_action(user["username"], action,
               f"{report.get('incident_id')} — {note}")

    return jsonify({"ok": True})


@app.route("/api/incidents")
@login_required
def api_incidents():
    """Return filtered incident list as JSON."""
    from_date = request.args.get("from", "")
    to_date   = request.args.get("to",   "")
    status    = request.args.get("status", "")
    inc_type  = request.args.get("type",   "")

    incidents = _get_all_incidents(
        from_date=from_date or None,
        to_date=to_date or None
    )
    if status:
        incidents = [i for i in incidents
                     if i.get("review_status") == status]
    if inc_type:
        incidents = [i for i in incidents
                     if i.get("detection_type") == inc_type]

    # Remove internal keys (except _folder) before sending
    clean = [{k: v for k, v in i.items()
              if not k.startswith("_") or k == "_folder"} for i in incidents]
    return jsonify(clean)


@app.route("/api/users/toggle", methods=["POST"])
@role_required("administrator")
def api_toggle_user():
    from auth.db import set_user_active
    data     = request.get_json()
    username = data.get("username", "")
    active   = data.get("active",   True)
    user     = get_current_user()

    if username == user["username"]:
        return jsonify({"ok": False,
                        "error": "Cannot disable your own account"}), 400

    set_user_active(username, active)
    action = "ENABLE_USER" if active else "DISABLE_USER"
    log_action(user["username"], action, username)
    return jsonify({"ok": True})


@app.route("/api/users/add", methods=["POST"])
@role_required("administrator")
def api_add_user():
    from auth.db import add_user
    data = request.get_json()
    ok   = add_user(
        data.get("username",  ""),
        data.get("password",  ""),
        data.get("role",      "security"),
        data.get("full_name", ""),
        data.get("email",     ""),
    )
    user = get_current_user()
    if ok:
        log_action(user["username"], "ADD_USER",
                   f"Created {data.get('username')} "
                   f"role={data.get('role')}")
    return jsonify({"ok": ok,
                    "error": "Username already exists" if not ok else ""})


@app.route("/api/recipients", methods=["POST"])
@role_required("administrator")
def api_recipients():
    config  = _load_config()
    action  = request.form.get("action", "")
    number  = request.form.get("number", "").strip()
    user    = get_current_user()

    if action == "add" and number:
        numbers = config.get("ALERT_NUMBERS", [])
        if number not in numbers:
            numbers.append(number)
            config["ALERT_NUMBERS"] = numbers
            _save_config(config)
            log_action(user["username"], "CONFIG_CHANGE",
                       f"Added recipient {number}")
    elif action == "remove" and number:
        numbers = config.get("ALERT_NUMBERS", [])
        if number in numbers:
            numbers.remove(number)
            config["ALERT_NUMBERS"] = numbers
            _save_config(config)
            log_action(user["username"], "CONFIG_CHANGE",
                       f"Removed recipient {number}")

    return redirect(url_for("administrator") + "#recipients")


@app.route("/api/report/export")
@role_required("supervisor")
def api_report_export():
    """Download incident report as CSV."""
    import csv, io
    from_date = request.args.get("from", "")
    to_date   = request.args.get("to",   "")

    incidents = _get_all_incidents(
        from_date=from_date or None,
        to_date=to_date or None
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["incident_id", "detection_type", "timestamp",
                     "threat_score", "review_status",
                     "reviewed_by", "review_note"])
    for inc in incidents:
        writer.writerow([
            inc.get("incident_id",    ""),
            inc.get("detection_type", ""),
            inc.get("timestamp",      "")[:19],
            inc.get("threat_score",   ""),
            inc.get("review_status",  ""),
            inc.get("reviewed_by",    ""),
            inc.get("review_note",    ""),
        ])

    user = get_current_user()
    log_action(user["username"], "REPORT_GEN",
               f"CSV export {from_date} to {to_date}")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=sentinel_report.csv"}
    )


# Replace this block in app.py
@app.route("/evidence/<path:filename>")
@login_required
def evidence(filename):
    """Serve evidence files — images AND video with range request support."""
    file_path = os.path.join(EVIDENCE_ROOT, filename)
    if not os.path.exists(file_path):
        return "File not found", 404

    # Use send_file with conditional=True to enable range requests (needed for video seeking)
    from flask import send_file
    return send_file(file_path, conditional=True)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "FRAME_WIDTH": 640, "FRAME_HEIGHT": 480, "SKIP_FRAMES": 2,
    "SPEED_THRESHOLD": 2.5, "PROXIMITY_LIMIT": 220,
    "ENCIRCLEMENT_DIST": 300, "MAX_GAP_THRESHOLD": 200,
    "MIN_ENCIRCLERS": 3, "CAMERA_PORT": 0,
    "CAMERA_LOCATION": "Main Entrance", "GSM_PORT": "COM3",
    "ALERT_NUMBERS": ["+1234567890"],
    # --- F4 Default Defaults ---
    "DEMO_MODE": False,
    "DEMO_VIDEO": "demo_attack.mp4",
}

def _load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def _save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)

def _get_all_incidents(from_date=None, to_date=None):
    incidents = []
    if not os.path.exists(EVIDENCE_ROOT):
        return incidents
    
    # We walk the directories to extract the incident logic
    for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
        if from_date and day_folder < from_date: continue
        if to_date   and day_folder > to_date:   continue
        day_path = os.path.join(EVIDENCE_ROOT, day_folder)
        if not os.path.isdir(day_path): continue
        for inc_folder in sorted(os.listdir(day_path), reverse=True):
            json_path = os.path.join(day_path, inc_folder, "report.json")
            if not os.path.exists(json_path): continue
            try:
                with open(json_path) as f:
                    data = json.load(f)
                
                # We need to construct the URL path for F3 to easily request the thumbnail/video
                url_path = f"{day_folder}/{inc_folder}"
                data["_folder"] = url_path 
                
                incidents.append(data)
            except Exception:
                pass
    return incidents

def _count_by_type(incidents):
    counts = {}
    for i in incidents:
        t = i.get("detection_type", "UNKNOWN")
        counts[t] = counts.get(t, 0) + 1
    return counts

def _count_by_status(incidents):
    counts = {"PENDING": 0, "CONFIRMED": 0, "FALSE_ALARM": 0}
    for i in incidents:
        s = i.get("review_status", "PENDING")
        counts[s] = counts.get(s, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Initialise database
    init_db()

    # Start camera and detector
    camera.start()
    detector.start(camera)

    print("\n✅ Sentinel AI is running!")
    print("   Open http://localhost:5000 in your browser\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,      # Never True in production — breaks threads
        threaded=True,    # Allows concurrent requests
        use_reloader=False  # Prevents double-starting threads
    )