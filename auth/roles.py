"""
auth/roles.py

Role-based permission system for Sentinel AI.

Every feature in the dashboard is protected by a permission string.
Pages call can(role, action) before showing any feature — if it returns
False, the feature is hidden or blocked with an error message.

Permission strings are grouped by feature area:

  LIVE FEED         view_live_feed, control_surveillance
  ALERTS            view_alerts, acknowledge_alert, dismiss_alert
  EVIDENCE          view_evidence
  INCIDENTS         respond_to_incident
  ANALYTICS         view_analytics
  HISTORY           view_alert_history          ← all 3 roles
  CONFIGURATION     configure_cameras, set_thresholds, manage_recipients
  USER MANAGEMENT   manage_users
  SYSTEM            view_system_health, update_models, generate_reports
  AUDIT             view_audit_log
"""

# ---------------------------------------------------------------------------
# Permissions table
# ---------------------------------------------------------------------------
# Each role maps to a set of permission strings.
# Adding a new permission: add the string to the relevant role(s) here,
# then call can(role, 'new_permission') wherever you want to gate it.

PERMISSIONS: dict[str, set[str]] = {

    "security": {
        # Core job — monitor and respond
        "view_live_feed",
        "control_surveillance",       # start/stop the camera loop
        "view_alerts",
        "acknowledge_alert",
        "dismiss_alert",
        "respond_to_incident",
        "view_evidence",              # before/peak/after snapshots
        "view_analytics",             # read-only stats and charts
        # Shared with all roles
        "view_alert_history",
    },

    "administrator": {
        # Configuration and management
        "configure_cameras",          # camera port, resolution, location name
        "set_thresholds",             # proximity limit, speed threshold, etc.
        "manage_recipients",          # GSM alert phone numbers
        "manage_users",               # add/disable/reset-password for accounts
        "view_analytics",             # read-only stats
        "view_audit_log",             # see who did what and when
        # Shared with all roles
        "view_alert_history",
    },

    "supervisor": {
        # Oversight and reporting
        "view_system_health",         # uptime, FPS, incident counts
        "update_models",              # swap the YOLO / pose model files
        "generate_reports",           # export incident report CSV/PDF
        "view_analytics",             # read-only stats
        "view_audit_log",             # full audit trail access
        # Shared with all roles
        "view_alert_history",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def can(role: str, action: str) -> bool:
    """
    Return True if `role` is allowed to perform `action`.

    Args:
        role   : the user's role string — 'security', 'administrator',
                 or 'supervisor'
        action : a permission string from the table above

    Returns:
        True if allowed, False if not (or if role/action is unrecognised)

    Usage in any page:
        from auth.roles import can

        if can(user['role'], 'configure_cameras'):
            # show the camera config form
        else:
            st.warning("You don't have permission to configure cameras.")
    """
    role_permissions = PERMISSIONS.get(role, set())
    return action in role_permissions


def get_permissions(role: str) -> set[str]:
    """
    Return the full set of permissions for a role.
    Useful for the admin page to display what each role can do.
    """
    return PERMISSIONS.get(role, set())


def get_all_roles() -> list[str]:
    """Return a sorted list of all defined roles."""
    return sorted(PERMISSIONS.keys())