"""
pages/shared_history.py

Shared alert history component — visible to all three roles.

Plugs into Tab 3 of security_page.py,
           Tab 4 of admin_page.py,
           Tab 5 of supervisor_page.py.

Features:
  - Filter by date range, alert type, and review status
  - Sortable incident table
  - Click any row to expand and see before/peak/after snapshots
  - Shows who reviewed each incident and when
"""

import os
import json
import streamlit as st
from datetime import datetime, timedelta

EVIDENCE_ROOT = "evidence/incidents"


# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

def _load_all_incidents(from_date: str = None, to_date: str = None) -> list[dict]:
    """
    Load all incidents from the evidence folder.
    Returns a flat list of dicts sorted newest first.
    Optionally filtered by YYYYMMDD date strings.
    """
    incidents = []

    if not os.path.exists(EVIDENCE_ROOT):
        return incidents

    for day_folder in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
        if from_date and day_folder < from_date:
            continue
        if to_date and day_folder > to_date:
            continue

        day_path = os.path.join(EVIDENCE_ROOT, day_folder)
        if not os.path.isdir(day_path):
            continue

        for inc_folder in sorted(os.listdir(day_path), reverse=True):
            if not inc_folder.startswith("INCIDENT"):
                continue
            json_path = os.path.join(day_path, inc_folder, "report.json")
            if not os.path.exists(json_path):
                continue
            try:
                with open(json_path) as f:
                    data = json.load(f)
                # Attach folder path for snapshot loading
                data["_folder"]     = os.path.join(day_path, inc_folder)
                data["_day"]        = day_folder
                data["_inc_folder"] = inc_folder
                incidents.append(data)
            except Exception:
                pass

    return incidents


# ---------------------------------------------------------------------------
# Main component
# ---------------------------------------------------------------------------

def show_alert_history(user: dict):
    """
    Render the shared alert history view.
    Called from the Alert History tab of all three role pages.

    Args:
        user : the logged-in user dict from session state
    """

    st.header("📋 Alert History")
    st.caption("Complete record of all detected incidents. Available to all roles.")

    # -----------------------------------------------------------------------
    # FILTERS
    # -----------------------------------------------------------------------
    st.subheader("🔍 Filters")

    fc1, fc2, fc3 = st.columns(3)

    with fc1:
        from_date_input = st.date_input(
            "From Date",
            value=datetime.now() - timedelta(days=30),
            key="history_from_date",
        )
        filter_status = st.multiselect(
            "Review Status",
            options=["PENDING", "CONFIRMED", "FALSE_ALARM"],
            default=["PENDING", "CONFIRMED", "FALSE_ALARM"],
            key="history_filter_status",
        )

    with fc2:
        to_date_input = st.date_input(
            "To Date",
            value=datetime.now(),
            key="history_to_date",
        )
        filter_type = st.multiselect(
            "Alert Type",
            options=[
                "PROXIMITY", "SPEED CHANGE", "ENCIRCLEMENT",
                "SURRENDER", "CROUCHING", "ARM_EXTENDED_FORWARD",
                "REACHING_WAIST", "LEANING_FORWARD", "RUNNING",
            ],
            default=[],
            placeholder="All types",
            key="history_filter_type",
        )

    with fc3:
        sort_by = st.selectbox(
            "Sort By",
            options=["Newest First", "Oldest First",
                     "Highest Score", "Lowest Score"],
            key="history_sort_by",
        )
        show_snapshots = st.checkbox(
            "Show snapshots in expanded view",
            value=True,
            key="history_show_snapshots",
        )

    st.divider()

    # -----------------------------------------------------------------------
    # LOAD + FILTER
    # -----------------------------------------------------------------------
    from_str = from_date_input.strftime("%Y%m%d")
    to_str   = to_date_input.strftime("%Y%m%d")

    incidents = _load_all_incidents(from_date=from_str, to_date=to_str)

    # Status filter
    if filter_status:
        incidents = [i for i in incidents
                     if i.get("review_status", "PENDING") in filter_status]

    # Type filter
    if filter_type:
        incidents = [i for i in incidents
                     if i.get("detection_type", "") in filter_type]

    # Sort
    if sort_by == "Newest First":
        incidents.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    elif sort_by == "Oldest First":
        incidents.sort(key=lambda x: x.get("timestamp", ""), reverse=False)
    elif sort_by == "Highest Score":
        incidents.sort(key=lambda x: x.get("threat_score", 0), reverse=True)
    elif sort_by == "Lowest Score":
        incidents.sort(key=lambda x: x.get("threat_score", 0), reverse=False)

    # -----------------------------------------------------------------------
    # SUMMARY ROW
    # -----------------------------------------------------------------------
    if not incidents:
        st.info("No incidents found for the selected filters.")
        return

    total     = len(incidents)
    confirmed = sum(1 for i in incidents if i.get("review_status") == "CONFIRMED")
    false_al  = sum(1 for i in incidents if i.get("review_status") == "FALSE_ALARM")
    pending   = sum(1 for i in incidents if i.get("review_status") == "PENDING")

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Showing",       total)
    s2.metric("Confirmed",     confirmed)
    s3.metric("False Alarms",  false_al)
    s4.metric("Pending",       pending)

    st.divider()

    # -----------------------------------------------------------------------
    # INCIDENT LIST
    # -----------------------------------------------------------------------
    st.subheader(f"Incidents ({total})")

    for inc in incidents:
        status        = inc.get("review_status", "PENDING")
        alert_type    = inc.get("detection_type", "UNKNOWN")
        incident_id   = inc.get("incident_id",   "?")
        threat_score  = inc.get("threat_score",   0)
        timestamp     = inc.get("timestamp",      "")[:19].replace("T", " ")
        reviewed_by   = inc.get("reviewed_by",    "")
        review_note   = inc.get("review_note",    "")

        # Status icon and color label
        status_icon  = {"CONFIRMED": "🔴", "FALSE_ALARM": "⚪",
                        "PENDING": "🟡"}.get(status, "🟡")
        status_label = {"CONFIRMED": "CONFIRMED",
                        "FALSE_ALARM": "FALSE ALARM",
                        "PENDING": "PENDING REVIEW"}.get(status, status)

        # Score badge
        score_icon = (
            "🔴" if threat_score >= 70
            else "🟠" if threat_score >= 40
            else "🟡"
        )

        # Expander title — compact one-line summary
        expander_title = (
            f"{status_icon} {incident_id}  ·  "
            f"{alert_type}  ·  "
            f"{score_icon} Score: {threat_score}/100  ·  "
            f"{timestamp}  ·  {status_label}"
        )

        with st.expander(expander_title, expanded=False):

            # Detail columns
            d1, d2 = st.columns(2)

            with d1:
                st.markdown(f"**Incident ID:** `{incident_id}`")
                st.markdown(f"**Alert Type:** `{alert_type}`")
                st.markdown(f"**Timestamp:** {timestamp}")
                st.markdown(f"**Threat Score:** {score_icon} `{threat_score}/100`")
                st.markdown(f"**Status:** {status_icon} `{status_label}`")

                if reviewed_by:
                    st.markdown(f"**Reviewed by:** {reviewed_by}")
                    reviewed_at = inc.get("reviewed_at", "")[:19].replace("T", " ")
                    st.markdown(f"**Reviewed at:** {reviewed_at}")
                if review_note:
                    st.markdown(f"**Note:** _{review_note}_")

            with d2:
                # Detection metrics
                metrics = inc.get("metrics", {})
                if metrics:
                    st.markdown("**Detection Metrics:**")
                    for key, val in metrics.items():
                        st.markdown(f"- `{key}`: {val}")
                else:
                    st.caption("No metrics available.")

            # Evidence snapshots
            if show_snapshots:
                folder_path = inc.get("_folder", "")
                p_before = os.path.join(folder_path, "snapshot_before.jpg")
                p_peak   = os.path.join(folder_path, "snapshot_peak.jpg")
                p_after  = os.path.join(folder_path, "snapshot_after.jpg")

                has_any = (os.path.exists(p_before) or
                           os.path.exists(p_peak) or
                           os.path.exists(p_after))

                if has_any:
                    st.markdown("**Evidence Snapshots:**")
                    ic1, ic2, ic3 = st.columns(3)
                    if os.path.exists(p_before):
                        ic1.image(p_before, caption="BEFORE",
                                  use_container_width=True)
                    if os.path.exists(p_peak):
                        ic2.image(p_peak,   caption="PEAK (Alert)",
                                  use_container_width=True)
                    if os.path.exists(p_after):
                        ic3.image(p_after,  caption="AFTER",
                                  use_container_width=True)
                else:
                    st.caption("No snapshots saved for this incident.")