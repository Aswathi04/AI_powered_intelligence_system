# """
# auth/auth.py

# Login, logout, and session management for Sentinel AI.

# How Streamlit session state works:
#   - st.session_state is a dictionary that persists across page reruns
#     for the same browser session.
#   - When a user logs in, we store their info in st.session_state['user'].
#   - Every page checks st.session_state['user'] to know who is logged in.
#   - When they log out, we clear it and the login page appears again.

# Functions
# ---------
#   login(username, password)  → bool
#   logout()                   → None
#   get_current_user()         → dict | None
#   is_logged_in()             → bool
#   require_role(role)         → bool
# """

# import streamlit as st
# from auth.db import get_user, verify_password, update_last_login, log_action


# # ---------------------------------------------------------------------------
# # Core auth functions
# # ---------------------------------------------------------------------------

# def login(username: str, password: str) -> bool:
#     """
#     Attempt to log in with the given credentials.

#     On success:
#       - Stores user info in st.session_state['user']
#       - Updates last_login timestamp in the database
#       - Logs 'LOGIN' action to audit_log

#     On failure:
#       - Logs 'LOGIN_FAILED' action to audit_log
#       - Returns False (does NOT modify session state)

#     Args:
#         username : the username typed by the user
#         password : the plain-text password typed by the user

#     Returns:
#         True if login succeeded, False if credentials are wrong
#     """
#     # Strip whitespace — common cause of "wrong password" confusion
#     username = username.strip()
#     password = password.strip()

#     if not username or not password:
#         return False

#     # Fetch user row from database
#     user = get_user(username)

#     if user is None:
#         # Username not found or account disabled
#         log_action(username, "LOGIN_FAILED", "User not found or disabled")
#         return False

#     # Verify password against stored hash
#     if not verify_password(password, user["password_hash"], user["salt"]):
#         log_action(username, "LOGIN_FAILED", "Wrong password")
#         return False

#     # --- Login successful ---

#     # Store user info in session state as a plain dict
#     # (sqlite3.Row objects can't always be pickled by Streamlit)
#     st.session_state["user"] = {
#         "id":        user["id"],
#         "username":  user["username"],
#         "role":      user["role"],
#         "full_name": user["full_name"],
#         "email":     user["email"],
#     }

#     # Record the login time in DB
#     update_last_login(username)

#     # Write to audit trail
#     log_action(username, "LOGIN", f"Role: {user['role']}")

#     return True


# def logout():
#     """
#     Log out the current user.

#     Clears the user from session state and logs the action.
#     After calling this, get_current_user() will return None
#     and the app will redirect to the login page.
#     """
#     user = get_current_user()
#     if user:
#         log_action(user["username"], "LOGOUT", "")

#     # Clear all session state keys related to the user session
#     for key in ["user", "system_active"]:
#         if key in st.session_state:
#             del st.session_state[key]


# def get_current_user() -> dict | None:
#     """
#     Return the currently logged-in user as a dict, or None if not logged in.

#     The returned dict has these keys:
#         id, username, role, full_name, email

#     Usage in any page:
#         user = get_current_user()
#         if user is None:
#             st.stop()   # not logged in
#         st.write(f"Hello, {user['full_name']}")
#     """
#     return st.session_state.get("user", None)


# def is_logged_in() -> bool:
#     """Return True if a user is currently logged in."""
#     return get_current_user() is not None


# def require_role(*allowed_roles: str) -> bool:
#     """
#     Check if the current user has one of the allowed roles.
#     Returns True if allowed, False otherwise.

#     Usage:
#         if not require_role('administrator', 'supervisor'):
#             st.error("You don't have permission to view this.")
#             st.stop()

#     Args:
#         *allowed_roles: one or more role strings to allow
#                         e.g. require_role('administrator')
#                              require_role('administrator', 'supervisor')
#     """
#     user = get_current_user()
#     if user is None:
#         return False
#     return user["role"] in allowed_roles

"""
auth/auth.py

Login, logout, and session management for Sentinel AI.

How Flask session works:
  - session is a signed cookie stored in the browser.
  - When a user logs in, we store their info in session['user'].
  - Every route checks session['user'] to know who is logged in.
  - When they log out, we clear it and redirect to the login page.
  - Flask's secret_key (set in app.py) signs the cookie so it
    cannot be tampered with by the browser.

Functions
---------
  login(username, password)  → bool
  logout()                   → None
  get_current_user()         → dict | None
  is_logged_in()             → bool
  require_role(*roles)       → bool
"""

from flask import session
from auth.db import get_user, verify_password, update_last_login, log_action


# ---------------------------------------------------------------------------
# Core auth functions
# ---------------------------------------------------------------------------

def login(username: str, password: str) -> bool:
    """
    Attempt to log in with the given credentials.

    On success:
      - Stores user info in Flask session['user']
      - Updates last_login timestamp in the database
      - Logs 'LOGIN' action to audit_log

    On failure:
      - Logs 'LOGIN_FAILED' action to audit_log
      - Returns False (does NOT modify session)
    """
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return False

    user = get_user(username)

    if user is None:
        log_action(username, "LOGIN_FAILED", "User not found or disabled")
        return False

    if not verify_password(password, user["password_hash"], user["salt"]):
        log_action(username, "LOGIN_FAILED", "Wrong password")
        return False

    # Login successful — store in Flask session
    session.permanent = True
    session["user"] = {
        "id":        user["id"],
        "username":  user["username"],
        "role":      user["role"],
        "full_name": user["full_name"],
        "email":     user["email"],
    }

    update_last_login(username)
    log_action(username, "LOGIN", f"Role: {user['role']}")

    return True


def logout():
    """
    Log out the current user.
    Clears Flask session and logs the action.
    """
    user = get_current_user()
    if user:
        log_action(user["username"], "LOGOUT", "")
    session.clear()


def get_current_user() -> dict | None:
    """
    Return the currently logged-in user as a dict, or None if not logged in.

    Usage in any Flask route:
        user = get_current_user()
        if user is None:
            return redirect(url_for('login'))
    """
    return session.get("user", None)


def is_logged_in() -> bool:
    """Return True if a user is currently logged in."""
    return get_current_user() is not None


def require_role(*allowed_roles: str) -> bool:
    """
    Check if the current user has one of the allowed roles.

    Usage:
        if not require_role('administrator'):
            return redirect(url_for('login'))
    """
    user = get_current_user()
    if user is None:
        return False
    return user["role"] in allowed_roles