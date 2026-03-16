"""
pages/admin_page.py

Dashboard for the Administrator role.

Tabs:
  Tab 1 — System Configuration  (thresholds, camera settings)
  Tab 2 — User Management       (add/disable/reset password)
  Tab 3 — Alert Recipients      (GSM phone numbers)
  Tab 4 — Alert History         (shared component)
"""

import os
import json
import sqlite3
import streamlit as st
from datetime import datetime
from auth.db import (
    get_connection, get_all_users, add_user,
    update_password, set_user_active, log_action
)
from auth.roles import can, get_all_roles

# Path to config file — stores threshold values so they survive restarts
CONFIG_PATH = "sentinel_config.json"

# Default values (used if config file doesn't exist yet)
DEFAULT_CONFIG = {
    "FRAME_WIDTH":        640,
    "FRAME_HEIGHT":       480,
    "SKIP_FRAMES":        2,
    "SPEED_THRESHOLD":    2.5,
    "PROXIMITY_LIMIT":    220,
    "ENCIRCLEMENT_DIST":  300,
    "MAX_GAP_THRESHOLD":  200,
    "MIN_ENCIRCLERS":     3,
    "CAMERA_PORT":        0,
    "CAMERA_LOCATION":    "Main Entrance",
    "GSM_PORT":           "COM3",
    "ALERT_NUMBERS":      ["+1234567890"],
}


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load config from JSON file, falling back to defaults for missing keys."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                saved = json.load(f)
            # Merge with defaults so new keys added later always have a value
            return {**DEFAULT_CONFIG, **saved}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def _save_config(config: dict):
    """Save config dict to JSON file."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def show_admin_page(user: dict):
    """
    Render the full Administrator dashboard.
    Called from sentinel_dashboard.py when role == 'administrator'.
    """

    if not can(user['role'], 'configure_cameras'):
        st.error("⛔ You do not have permission to access this page.")
        return

    st.title("⚙️ Sentinel AI — Administrator Panel")
    st.caption(f"Logged in as **{user['full_name']}** · Role: `ADMINISTRATOR`")
    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        "🎛️ System Configuration",
        "👥 User Management",
        "📱 Alert Recipients",
        "📋 Alert History",
    ])

    config = _load_config()

    # -----------------------------------------------------------------------
    # TAB 1 — SYSTEM CONFIGURATION
    # -----------------------------------------------------------------------
    with tab1:
        st.header("🎛️ System Configuration")
        st.info(
            "Changes saved here take effect the next time the Security Officer "
            "activates the camera feed."
        )

        # --- Camera Settings ---
        st.subheader("📷 Camera Settings")
        c1, c2 = st.columns(2)
        with c1:
            camera_port = st.number_input(
                "Camera Port",
                min_value=0, max_value=10,
                value=int(config["CAMERA_PORT"]),
                help="0 = default webcam, 1 = second camera, etc."
            )
            frame_width = st.selectbox(
                "Frame Width",
                options=[320, 480, 640, 1280],
                index=[320, 480, 640, 1280].index(int(config["FRAME_WIDTH"]))
            )
        with c2:
            camera_location = st.text_input(
                "Camera Location Name",
                value=config["CAMERA_LOCATION"],
                help="Shown in incident reports e.g. 'Main Entrance', 'Parking Lot'"
            )
            frame_height = st.selectbox(
                "Frame Height",
                options=[240, 360, 480, 720],
                index=[240, 360, 480, 720].index(int(config["FRAME_HEIGHT"]))
            )

        skip_frames = st.slider(
            "Process every N frames (higher = faster, less accurate)",
            min_value=1, max_value=5,
            value=int(config["SKIP_FRAMES"]),
            help="1 = process every frame, 3 = skip 2 frames between detections"
        )

        st.divider()

        # --- Threat Thresholds ---
        st.subheader("🎯 Threat Detection Thresholds")
        st.caption("Increase values to reduce false alarms. Decrease to be more sensitive.")

        c1, c2 = st.columns(2)
        with c1:
            proximity_limit = st.slider(
                "Proximity Alert Distance (px)",
                min_value=50, max_value=500,
                value=int(config["PROXIMITY_LIMIT"]),
                help="Alert fires when two people are closer than this many pixels"
            )
            speed_threshold = st.slider(
                "Speed Change Threshold (multiplier)",
                min_value=1.5, max_value=5.0, step=0.1,
                value=float(config["SPEED_THRESHOLD"]),
                help="Alert fires when a person's speed suddenly increases by this factor"
            )
            encirclement_dist = st.slider(
                "Encirclement Radius (px)",
                min_value=100, max_value=600,
                value=int(config["ENCIRCLEMENT_DIST"]),
                help="Radius within which people are considered part of an encirclement"
            )

        with c2:
            max_gap_threshold = st.slider(
                "Encirclement Max Gap (degrees)",
                min_value=60, max_value=300,
                value=int(config["MAX_GAP_THRESHOLD"]),
                help="Smaller gap = tighter encirclement required to trigger alert"
            )
            min_encirclers = st.slider(
                "Minimum Encirclers",
                min_value=2, max_value=6,
                value=int(config["MIN_ENCIRCLERS"]),
                help="Minimum number of people needed to trigger encirclement alert"
            )

        st.divider()

        # --- Save Button ---
        if st.button("💾 Save Configuration", type="primary", use_container_width=True):
            new_config = {
                **config,
                "CAMERA_PORT":        camera_port,
                "CAMERA_LOCATION":    camera_location,
                "FRAME_WIDTH":        frame_width,
                "FRAME_HEIGHT":       frame_height,
                "SKIP_FRAMES":        skip_frames,
                "PROXIMITY_LIMIT":    proximity_limit,
                "SPEED_THRESHOLD":    speed_threshold,
                "ENCIRCLEMENT_DIST":  encirclement_dist,
                "MAX_GAP_THRESHOLD":  max_gap_threshold,
                "MIN_ENCIRCLERS":     min_encirclers,
            }
            _save_config(new_config)
            log_action(
                user['username'], "CONFIG_CHANGE",
                f"Thresholds updated — proximity={proximity_limit}, "
                f"speed={speed_threshold}, encirclement_dist={encirclement_dist}"
            )
            st.success("✅ Configuration saved successfully!")
            st.rerun()

        # Show current saved values
        with st.expander("📄 View current saved config", expanded=False):
            st.json(config)

    # -----------------------------------------------------------------------
    # TAB 2 — USER MANAGEMENT
    # -----------------------------------------------------------------------
    with tab2:
        st.header("👥 User Management")

        # --- Current users table ---
        st.subheader("Current Accounts")
        users = get_all_users()

        if users:
            for u in users:
                col_name, col_role, col_status, col_actions = st.columns([2, 1.5, 1, 2])

                with col_name:
                    st.markdown(f"**{u['full_name']}**")
                    st.caption(f"@{u['username']}")

                with col_role:
                    role_badge = {
                        "security":      "🔵 Security",
                        "administrator": "🔴 Admin",
                        "supervisor":    "🟢 Supervisor",
                    }.get(u['role'], u['role'])
                    st.markdown(role_badge)

                with col_status:
                    if u['is_active']:
                        st.success("Active")
                    else:
                        st.error("Disabled")

                with col_actions:
                    # Prevent admin from disabling their own account
                    if u['username'] != user['username']:
                        btn_label = "Disable" if u['is_active'] else "Enable"
                        if st.button(
                            f"{'🔒' if u['is_active'] else '🔓'} {btn_label}",
                            key=f"toggle_{u['username']}",
                        ):
                            set_user_active(u['username'], not u['is_active'])
                            action = "DISABLE_USER" if u['is_active'] else "ENABLE_USER"
                            log_action(user['username'], action, u['username'])
                            st.rerun()
                    else:
                        st.caption("(current user)")

                st.divider()

        else:
            st.info("No users found.")

        # --- Add new user ---
        st.subheader("➕ Add New Account")
        with st.form("add_user_form"):
            c1, c2 = st.columns(2)
            with c1:
                new_username  = st.text_input("Username",  placeholder="e.g. officer_john")
                new_fullname  = st.text_input("Full Name", placeholder="e.g. John Smith")
                new_email     = st.text_input("Email (optional)", placeholder="john@example.com")
            with c2:
                new_role      = st.selectbox("Role", get_all_roles())
                new_password  = st.text_input("Password", type="password",
                                               placeholder="Min 8 characters")
                new_password2 = st.text_input("Confirm Password", type="password")

            submitted = st.form_submit_button(
                "➕ Create Account", type="primary", use_container_width=True)

            if submitted:
                if not new_username or not new_fullname or not new_password:
                    st.error("Username, full name, and password are all required.")
                elif new_password != new_password2:
                    st.error("Passwords do not match.")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    success = add_user(
                        new_username, new_password, new_role,
                        new_fullname, new_email
                    )
                    if success:
                        log_action(
                            user['username'], "ADD_USER",
                            f"Created {new_username} with role {new_role}"
                        )
                        st.success(f"✅ Account '{new_username}' created successfully!")
                        st.rerun()
                    else:
                        st.error(f"Username '{new_username}' already exists.")

        # --- Reset password ---
        st.subheader("🔑 Reset Password")
        with st.form("reset_password_form"):
            users_list   = [u['username'] for u in users]
            target_user  = st.selectbox("Select User", users_list)
            new_pw       = st.text_input("New Password", type="password")
            new_pw2      = st.text_input("Confirm New Password", type="password")

            reset_submitted = st.form_submit_button(
                "🔑 Reset Password", use_container_width=True)

            if reset_submitted:
                if not new_pw:
                    st.error("Please enter a new password.")
                elif new_pw != new_pw2:
                    st.error("Passwords do not match.")
                elif len(new_pw) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    update_password(target_user, new_pw)
                    log_action(
                        user['username'], "RESET_PASSWORD",
                        f"Reset password for {target_user}"
                    )
                    st.success(f"✅ Password reset for '{target_user}'.")

    # -----------------------------------------------------------------------
    # TAB 3 — ALERT RECIPIENTS
    # -----------------------------------------------------------------------
    with tab3:
        st.header("📱 Alert Recipients")
        st.caption(
            "These phone numbers receive SMS alerts when a high-threat "
            "incident (score > 70) is detected."
        )

        current_numbers = config.get("ALERT_NUMBERS", [])

        # Display existing numbers
        st.subheader("Current Recipients")
        if current_numbers:
            for idx, number in enumerate(current_numbers):
                col_num, col_del = st.columns([3, 1])
                col_num.markdown(f"📞 `{number}`")
                if col_del.button("Remove", key=f"del_{idx}"):
                    current_numbers.pop(idx)
                    config["ALERT_NUMBERS"] = current_numbers
                    _save_config(config)
                    log_action(
                        user['username'], "CONFIG_CHANGE",
                        f"Removed alert recipient: {number}"
                    )
                    st.rerun()
        else:
            st.info("No recipients configured yet.")

        st.divider()

        # Add new number
        st.subheader("➕ Add Recipient")
        with st.form("add_recipient_form"):
            new_number = st.text_input(
                "Phone Number",
                placeholder="+91XXXXXXXXXX  or  +1XXXXXXXXXX",
                help="Use E.164 format with country code e.g. +919876543210"
            )
            add_submitted = st.form_submit_button(
                "➕ Add Number", type="primary", use_container_width=True)

            if add_submitted:
                if not new_number.startswith("+"):
                    st.error("Phone number must start with + and country code.")
                elif new_number in current_numbers:
                    st.warning("This number is already in the list.")
                else:
                    current_numbers.append(new_number)
                    config["ALERT_NUMBERS"] = current_numbers
                    _save_config(config)
                    log_action(
                        user['username'], "CONFIG_CHANGE",
                        f"Added alert recipient: {new_number}"
                    )
                    st.success(f"✅ {new_number} added.")
                    st.rerun()

        # GSM port setting
        st.divider()
        st.subheader("🔌 GSM Module Port")
        with st.form("gsm_port_form"):
            gsm_port = st.text_input(
                "Serial Port",
                value=config.get("GSM_PORT", "COM3"),
                help="Windows: COM3  |  Linux: /dev/ttyUSB0"
            )
            gsm_submitted = st.form_submit_button("💾 Save Port", use_container_width=True)
            if gsm_submitted:
                config["GSM_PORT"] = gsm_port
                _save_config(config)
                log_action(user['username'], "CONFIG_CHANGE", f"GSM port set to {gsm_port}")
                st.success(f"✅ GSM port saved as '{gsm_port}'.")

    # -----------------------------------------------------------------------
    # TAB 4 — ALERT HISTORY
    # -----------------------------------------------------------------------
    with tab4:
        try:
            from pages.shared_history import show_alert_history
            show_alert_history(user)
        except ImportError:
            st.info("Alert history will be available after Step 9 is complete.")