"""
pages/supervisor_page.py

Dashboard for the Supervisor role.

Tabs:
  Tab 1 — System Health       (uptime, FPS, incident counts, camera status)
  Tab 2 — Incident Reports    (generate + export CSV/JSON reports by date range)
  Tab 3 — Model Management    (view active model, update instructions)
  Tab 4 — Audit Log           (full action trail — who did what and when)
  Tab 5 — Alert History       (shared component)
"""

import os
import json
import csv
import io
import streamlit as st
from datetime import datetime, timedelta
from auth.db import get_audit_log, log_action
from auth.roles import can

EVIDENCE_ROOT = "evidence/incidents"
CONFIG_PATH   = "sentinel_config.json"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _get_all_incidents(from_date: str = None, to_date: str = None) -> list[dict]:
    """
    Scan the evidence folder and return a list of incident dicts.
    Optionally filter by date range (YYYYMMDD strings).
    """
    incidents = []

    if not os.path.exists(EVIDENCE_ROOT):
        return incidents

    for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
        # Filter by date range if provided
        if from_date and day_folder < from_date:
            continue
        if to_date and day_folder > to_date:
            continue

        day_path = os.path.join(EVIDENCE_ROOT, day_folder)
        if not os.path.isdir(day_path):
            continue

        for inc_folder in sorted(os.listdir(day_path), reverse=True):
            json_path = os.path.join(day_path, inc_folder, "report.json")
            if not os.path.exists(json_path):
                continue
            try:
                with open(json_path) as f:
                    data = json.load(f)
                data["_folder"] = os.path.join(day_path, inc_folder)
                data["_date"]   = day_folder
                incidents.append(data)
            except Exception:
                pass

    return incidents


def _count_by_type(incidents: list[dict]) -> dict:
    counts = {}
    for inc in incidents:
        t = inc.get("detection_type", "UNKNOWN")
        counts[t] = counts.get(t, 0) + 1
    return counts


def _count_by_status(incidents: list[dict]) -> dict:
    counts = {"PENDING": 0, "CONFIRMED": 0, "FALSE_ALARM": 0}
    for inc in incidents:
        s = inc.get("review_status", "PENDING")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _incidents_to_csv(incidents: list[dict]) -> str:
    """Convert incident list to a CSV string for download."""
    output  = io.StringIO()
    writer  = csv.writer(output)
    headers = [
        "incident_id", "detection_type", "timestamp",
        "threat_score", "review_status", "reviewed_by",
        "reviewed_at", "review_note",
    ]
    writer.writerow(headers)
    for inc in incidents:
        writer.writerow([
            inc.get("incident_id",    ""),
            inc.get("detection_type", ""),
            inc.get("timestamp",      ""),
            inc.get("threat_score",   ""),
            inc.get("review_status",  ""),
            inc.get("reviewed_by",    ""),
            inc.get("reviewed_at",    ""),
            inc.get("review_note",    ""),
        ])
    return output.getvalue()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def show_supervisor_page(user: dict):
    """
    Render the full Supervisor dashboard.
    Called from sentinel_dashboard.py when role == 'supervisor'.
    """

    if not can(user['role'], 'view_system_health'):
        st.error("⛔ You do not have permission to access this page.")
        return

    st.title("📊 Sentinel AI — Supervisor Panel")
    st.caption(f"Logged in as **{user['full_name']}** · Role: `SUPERVISOR`")
    st.divider()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🖥️ System Health",
        "📄 Incident Reports",
        "🤖 Model Management",
        "🔍 Audit Log",
        "📋 Alert History",
    ])

    # -----------------------------------------------------------------------
    # TAB 1 — SYSTEM HEALTH
    # -----------------------------------------------------------------------
    with tab1:
        st.header("🖥️ System Health")

        # Config snapshot
        config = _load_config()

        # Incident summary — all time
        all_incidents = _get_all_incidents()
        by_status     = _count_by_status(all_incidents)
        by_type       = _count_by_type(all_incidents)

        # Top metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Incidents (all time)", len(all_incidents))
        m2.metric("Confirmed Threats",  by_status.get("CONFIRMED",   0))
        m3.metric("False Alarms",        by_status.get("FALSE_ALARM", 0))
        m4.metric("Pending Review",      by_status.get("PENDING",     0))

        st.divider()

        # Accuracy calculation
        confirmed   = by_status.get("CONFIRMED",   0)
        false_alarm = by_status.get("FALSE_ALARM", 0)
        reviewed    = confirmed + false_alarm
        accuracy    = int((confirmed / reviewed) * 100) if reviewed > 0 else 0

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Detection Accuracy")
            st.metric("Overall Accuracy", f"{accuracy}%",
                      delta=f"{reviewed} incidents reviewed")

            st.subheader("Alerts by Type")
            if by_type:
                for alert_type, count in sorted(
                        by_type.items(), key=lambda x: x[1], reverse=True):
                    pct = int((count / len(all_incidents)) * 100) if all_incidents else 0
                    st.markdown(f"**{alert_type}** — {count} incidents ({pct}%)")
                    st.progress(pct / 100)
            else:
                st.info("No incidents recorded yet.")

        with col2:
            st.subheader("Active Configuration")
            if config:
                st.markdown(f"📷 **Camera Port:** `{config.get('CAMERA_PORT', 0)}`")
                st.markdown(f"📍 **Location:** `{config.get('CAMERA_LOCATION', 'Not set')}`")
                st.markdown(f"📐 **Resolution:** `{config.get('FRAME_WIDTH', 640)}×{config.get('FRAME_HEIGHT', 480)}`")
                st.markdown(f"⚡ **Skip Frames:** `{config.get('SKIP_FRAMES', 2)}`")
                st.divider()
                st.markdown(f"📏 **Proximity Limit:** `{config.get('PROXIMITY_LIMIT', 220)} px`")
                st.markdown(f"💨 **Speed Threshold:** `{config.get('SPEED_THRESHOLD', 2.5)}×`")
                st.markdown(f"🔄 **Encirclement Dist:** `{config.get('ENCIRCLEMENT_DIST', 300)} px`")
                st.markdown(f"👥 **Min Encirclers:** `{config.get('MIN_ENCIRCLERS', 3)}`")
            else:
                st.info("No saved configuration found. Default values are in use.")
                st.caption("Ask the Administrator to save configuration from their panel.")

        st.divider()

        # Today's activity
        st.subheader("Today's Activity")
        today_str      = datetime.now().strftime("%Y%m%d")
        today_incidents = _get_all_incidents(from_date=today_str, to_date=today_str)

        t1, t2, t3 = st.columns(3)
        t1.metric("Incidents Today",  len(today_incidents))
        t2.metric("Confirmed Today",  _count_by_status(today_incidents).get("CONFIRMED",  0))
        t3.metric("Pending Today",    _count_by_status(today_incidents).get("PENDING",    0))

    # -----------------------------------------------------------------------
    # TAB 2 — INCIDENT REPORTS
    # -----------------------------------------------------------------------
    with tab2:
        st.header("📄 Incident Reports")
        st.caption("Generate and export incident reports for any date range.")

        col1, col2 = st.columns(2)
        with col1:
            from_date_input = st.date_input(
                "From Date",
                value=datetime.now() - timedelta(days=7),
            )
        with col2:
            to_date_input = st.date_input(
                "To Date",
                value=datetime.now(),
            )

        from_str = from_date_input.strftime("%Y%m%d")
        to_str   = to_date_input.strftime("%Y%m%d")

        # Filter selector
        filter_status = st.multiselect(
            "Filter by Status",
            options=["PENDING", "CONFIRMED", "FALSE_ALARM"],
            default=["PENDING", "CONFIRMED", "FALSE_ALARM"],
        )
        filter_type = st.multiselect(
            "Filter by Alert Type",
            options=["PROXIMITY", "SPEED CHANGE", "ENCIRCLEMENT",
                     "SURRENDER", "CROUCHING", "ARM_EXTENDED_FORWARD",
                     "REACHING_WAIST", "LEANING_FORWARD", "RUNNING"],
            default=[],
            placeholder="All types (leave empty for all)",
        )

        if st.button("🔍 Generate Report", type="primary", use_container_width=True):
            incidents = _get_all_incidents(from_date=from_str, to_date=to_str)

            # Apply filters
            if filter_status:
                incidents = [i for i in incidents
                             if i.get("review_status") in filter_status]
            if filter_type:
                incidents = [i for i in incidents
                             if i.get("detection_type") in filter_type]

            if not incidents:
                st.warning("No incidents found for the selected filters.")
            else:
                st.success(f"Found **{len(incidents)}** incidents.")
                log_action(
                    user['username'], "REPORT_GEN",
                    f"Date range {from_str}–{to_str}, {len(incidents)} incidents"
                )

                # Summary stats
                by_s = _count_by_status(incidents)
                by_t = _count_by_type(incidents)

                s1, s2, s3, s4 = st.columns(4)
                s1.metric("Total",      len(incidents))
                s2.metric("Confirmed",  by_s.get("CONFIRMED",   0))
                s3.metric("False Alarm", by_s.get("FALSE_ALARM", 0))
                s4.metric("Pending",    by_s.get("PENDING",     0))

                st.divider()

                # Incident table
                st.subheader("Incident Details")
                for inc in incidents:
                    status = inc.get("review_status", "PENDING")
                    icon   = {"CONFIRMED": "🔴", "FALSE_ALARM": "⚪",
                              "PENDING": "🟡"}.get(status, "🟡")
                    score  = inc.get("threat_score", 0)

                    with st.expander(
                        f"{icon} {inc.get('incident_id','?')} — "
                        f"{inc.get('detection_type','?')} — "
                        f"Score: {score}/100 — {status}"
                    ):
                        c1, c2 = st.columns(2)
                        c1.markdown(f"**Timestamp:** {inc.get('timestamp','')[:19]}")
                        c1.markdown(f"**Threat Score:** {score}/100")
                        c1.markdown(f"**Status:** {status}")
                        if inc.get("reviewed_by"):
                            c1.markdown(f"**Reviewed by:** {inc['reviewed_by']}")
                        if inc.get("review_note"):
                            c1.markdown(f"**Note:** {inc['review_note']}")
                        c2.json(inc.get("metrics", {}))

                st.divider()

                # Export buttons
                st.subheader("Export")
                ec1, ec2 = st.columns(2)

                # CSV download
                csv_data = _incidents_to_csv(incidents)
                ec1.download_button(
                    label="⬇️ Download CSV",
                    data=csv_data,
                    file_name=f"sentinel_report_{from_str}_to_{to_str}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

                # JSON download
                json_data = json.dumps(
                    [{k: v for k, v in inc.items() if not k.startswith("_")}
                     for inc in incidents],
                    indent=4
                )
                ec2.download_button(
                    label="⬇️ Download JSON",
                    data=json_data,
                    file_name=f"sentinel_report_{from_str}_to_{to_str}.json",
                    mime="application/json",
                    use_container_width=True,
                )

    # -----------------------------------------------------------------------
    # TAB 3 — MODEL MANAGEMENT
    # -----------------------------------------------------------------------
    with tab3:
        st.header("🤖 Model Management")

        # Current model info
        st.subheader("Active Models")

        models = [
            ("YOLO Detection Model", "yolo11n.pt"),
            ("Pose Estimation",      "MediaPipe Pose (built-in)"),
        ]

        for model_name, model_file in models:
            col1, col2, col3 = st.columns([2, 2, 1])
            col1.markdown(f"**{model_name}**")

            if os.path.exists(model_file):
                size_mb  = os.path.getsize(model_file) / (1024 * 1024)
                mod_time = datetime.fromtimestamp(
                    os.path.getmtime(model_file)
                ).strftime("%Y-%m-%d %H:%M")
                col2.markdown(f"`{model_file}` — {size_mb:.1f} MB")
                col3.success("Found")
                st.caption(f"Last modified: {mod_time}")
            else:
                col2.markdown(f"`{model_file}`")
                if "built-in" in model_file:
                    col3.success("Built-in")
                else:
                    col3.error("Missing")
                    st.warning(
                        f"⚠️ {model_file} not found in project root. "
                        f"Run the system once to auto-download it."
                    )
            st.divider()

        # Update instructions
        st.subheader("🔄 How to Update Models")
        with st.expander("View update instructions", expanded=False):
            st.markdown("""
            **To update the YOLO model:**
            1. Download the new model from [Ultralytics](https://docs.ultralytics.com)
            2. Place the `.pt` file in your project root folder
            3. Ask the Administrator to update `YOLO_MODEL` in system configuration
            4. Restart the Streamlit app

            **Available YOLO models (fastest → most accurate):**
            - `yolo11n.pt` — Nano (current, fastest, good for real-time)
            - `yolo11s.pt` — Small (better accuracy, slightly slower)
            - `yolo11m.pt` — Medium (high accuracy, requires good GPU)

            **MediaPipe Pose** updates automatically with:
            ```bash
            pip install --upgrade mediapipe
            ```
            """)

        # System info
        st.subheader("📦 Environment")
        try:
            import sys
            import cv2
            from ultralytics import __version__ as yolo_ver
            import mediapipe as mp

            st.markdown(f"- **Python:** `{sys.version.split()[0]}`")
            st.markdown(f"- **OpenCV:** `{cv2.__version__}`")
            st.markdown(f"- **Ultralytics (YOLO):** `{yolo_ver}`")
            st.markdown(f"- **MediaPipe:** `{mp.__version__}`")
        except ImportError as e:
            st.warning(f"Could not read some package versions: {e}")

    # -----------------------------------------------------------------------
    # TAB 4 — AUDIT LOG
    # -----------------------------------------------------------------------
    with tab4:
        st.header("🔍 Audit Log")
        st.caption("Complete record of all user actions across the system.")

        col1, col2 = st.columns([2, 1])
        with col1:
            search_user = st.text_input(
                "Filter by username", placeholder="Leave empty to show all")
        with col2:
            limit = st.selectbox("Show last N entries", [50, 100, 200, 500], index=1)

        # Fetch entries
        if search_user.strip():
            from auth.db import get_audit_log_for_user
            entries = get_audit_log_for_user(search_user.strip(), limit=limit)
        else:
            entries = get_audit_log(limit=limit)

        if entries:
            st.markdown(f"Showing **{len(entries)}** entries")
            st.divider()

            for entry in entries:
                action = entry['action']

                # Colour-code by action type
                if action in ("LOGIN", "ADD_USER", "ENABLE_USER"):
                    icon = "🟢"
                elif action in ("LOGOUT", "CONFIG_CHANGE", "REPORT_GEN"):
                    icon = "🔵"
                elif action in ("ALERT_ACK",):
                    icon = "🔴"
                elif action in ("ALERT_DISMISS", "FALSE_ALARM"):
                    icon = "⚪"
                elif action in ("LOGIN_FAILED", "DISABLE_USER", "RESET_PASSWORD"):
                    icon = "🟠"
                else:
                    icon = "⚫"

                ts = entry['timestamp'][:19].replace("T", " ")
                detail = f" — {entry['detail']}" if entry['detail'] else ""

                st.markdown(
                    f"{icon} `{ts}` &nbsp; **{entry['username']}** &nbsp; "
                    f"`{action}`{detail}"
                )
        else:
            st.info("No audit log entries found.")

        # Export audit log
        st.divider()
        if st.button("⬇️ Export Audit Log as CSV", use_container_width=True):
            all_entries = get_audit_log(limit=10000)
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["timestamp", "username", "action", "detail"])
            for e in all_entries:
                writer.writerow([
                    e['timestamp'], e['username'],
                    e['action'],    e['detail']
                ])
            log_action(user['username'], "REPORT_GEN", "Exported full audit log")
            st.download_button(
                label="⬇️ Download audit_log.csv",
                data=output.getvalue(),
                file_name="sentinel_audit_log.csv",
                mime="text/csv",
                use_container_width=True,
            )

    # -----------------------------------------------------------------------
    # TAB 5 — ALERT HISTORY
    # -----------------------------------------------------------------------
    with tab5:
        try:
            from pages.shared_history import show_alert_history
            show_alert_history(user)
        except ImportError:
            st.info("Alert history will be available after Step 9 is complete.")