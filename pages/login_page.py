"""
pages/login_page.py

Login page UI for Sentinel AI.
Renders a centered login card with username/password fields.
On success → stores user in session state and reruns the app.
On failure → shows error message and logs the attempt.
"""

import streamlit as st
from auth.auth import login


def show_login_page():
    """
    Render the full login page.
    Called from sentinel_dashboard.py when no user is in session state.
    """

    # Hide the default Streamlit sidebar and header on the login screen
    st.markdown("""
        <style>
            [data-testid="stSidebar"] { display: none; }
            [data-testid="stHeader"]  { display: none; }
            .block-container { padding-top: 2rem; }
        </style>
    """, unsafe_allow_html=True)

    # --- Centered layout using columns ---
    # Empty columns on left and right act as margins
    left, center, right = st.columns([1, 1.2, 1])

    with center:

        # --- Logo / Title ---
        st.markdown("""
            <div style='text-align:center; padding: 2rem 0 1.5rem 0;'>
                <div style='font-size: 2.8rem;'>🛡️</div>
                <h2 style='margin: 0.4rem 0 0.2rem 0;'>Sentinel AI</h2>
                <p style='color: gray; font-size: 0.9rem; margin:0;'>
                    Security Operations Center
                </p>
            </div>
        """, unsafe_allow_html=True)

        st.divider()

        # --- Login form ---
        # Using st.form so pressing Enter submits — no need to click the button
        with st.form("login_form", clear_on_submit=False):

            st.markdown("#### Sign in to your account")

            username = st.text_input(
                "Username",
                placeholder="Enter your username",
                autocomplete="username",
            )

            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password",
                autocomplete="current-password",
            )

            st.markdown("<br>", unsafe_allow_html=True)

            submitted = st.form_submit_button(
                "🔐  Login",
                use_container_width=True,
                type="primary",
            )

        # --- Handle submission ---
        if submitted:
            if not username or not password:
                st.error("Please enter both username and password.")

            else:
                # Show a spinner while checking credentials
                with st.spinner("Verifying credentials..."):
                    success = login(username.strip(), password.strip())

                if success:
                    # Rerun the app — sentinel_dashboard.py will now
                    # find the user in session state and route to their page
                    st.rerun()
                else:
                    st.error("❌ Incorrect username or password. Please try again.")
                    st.caption(
                        "If you've forgotten your credentials, "
                        "contact your system administrator."
                    )

        # --- Default credentials hint (remove before production) ---
        with st.expander("🔑 Default login credentials", expanded=False):
            st.markdown("""
            | Role | Username | Password |
            |------|----------|----------|
            | Security Officer | `security_officer` | `Security@123` |
            | Administrator | `admin` | `Admin@123` |
            | Supervisor | `supervisor` | `Supervisor@123` |
            """)
            st.caption(
                "⚠️ Change these passwords after your first login. "
                "Remove this hint before deploying."
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # --- Footer ---
        st.markdown("""
            <div style='text-align:center; color:gray; font-size:0.75rem;'>
                Sentinel AI v1.0 &nbsp;|&nbsp; Unauthorized access is prohibited
            </div>
        """, unsafe_allow_html=True)