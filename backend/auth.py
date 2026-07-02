"""
AutoRed -- Authentication backend
==================================
Multi-user login with email-based MFA (OTP).

Flow:
  1. User enters username + password
  2. If valid, a 6-digit OTP is generated and emailed to the
     user's registered email address
  3. User enters the OTP to complete login
  4. On success, a session is considered "active" for the
     lifetime of the running app (no persistent session token
     needed for a single-machine desktop app)

Passwords are stored as salted SHA-256 hashes (no plaintext).
Uses the same SMTP_* .env variables as backend/notifier.py.
"""

import hashlib
import os
import random
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from backend.db import get_connection

OTP_VALID_MINUTES = 10
OTP_MAX_ATTEMPTS  = 5
REMEMBER_ME_DAYS  = 5


# -- DB migration -----------------------------------------------
def _migrate():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            role          TEXT DEFAULT 'analyst',
            created_at    TEXT DEFAULT (datetime('now')),
            last_login    TEXT
        );

        CREATE TABLE IF NOT EXISTS login_otps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            otp_code    TEXT NOT NULL,
            purpose     TEXT DEFAULT 'login',
            expires_at  TEXT NOT NULL,
            attempts    INTEGER DEFAULT 0,
            verified    INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS remember_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            token_hash  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()

    # Safe upgrade for databases created before 'purpose' existed.
    try:
        cursor.execute(
            "ALTER TABLE login_otps ADD COLUMN purpose TEXT DEFAULT 'login'"
        )
        conn.commit()
    except Exception:
        pass

    conn.close()


_migrate()


# -- Password hashing ---------------------------------------------
def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return h, salt


def _verify_password(password, stored_hash, salt):
    h, _ = _hash_password(password, salt)
    return secrets.compare_digest(h, stored_hash)


# -- Password strength policy ----------------------------------
def validate_password_strength(password):
    """
    Strict policy: at least 8 characters, with at least one
    uppercase letter, one lowercase letter, one digit, and one
    special character. Returns (True, "") or (False, reason).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/~`"\'\\')
    if not any(c in special_chars for c in password):
        return False, (
            "Password must contain at least one special character "
            "(e.g. ! @ # $ % ^ & *)."
        )
    return True, ""


# -- User management ------------------------------------------------
def create_user(username, email, password, role='analyst'):
    """
    Register a new user. Returns (True, user_id) or (False, error).
    """
    username = username.strip()
    email    = email.strip()

    if not username or not email or not password:
        return False, "Username, email, and password are required."

    strong, reason = validate_password_strength(password)
    if not strong:
        return False, reason

    pw_hash, salt = _hash_password(password)

    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users "
            "(username, email, password_hash, salt, role) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, email, pw_hash, salt, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return True, user_id
    except Exception as e:
        conn.close()
        if 'UNIQUE' in str(e):
            return False, f"Username '{username}' already exists."
        return False, str(e)


def get_user_by_username(username):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=?", (username.strip(),)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email):
    """
    Case-insensitive lookup by email. Used for password recovery,
    since a user who forgot their username will still know the
    email they registered with.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE LOWER(email)=LOWER(?)",
        (email.strip(),)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def user_count():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def verify_login(username, password):
    """
    Step 1 of login -- checks username/password only.
    Returns (True, user_dict) or (False, error_message).
    Does NOT log the user in yet -- OTP is still required.
    """
    user = get_user_by_username(username)
    if not user:
        return False, "Invalid username or password."

    if not _verify_password(password, user['password_hash'], user['salt']):
        return False, "Invalid username or password."

    return True, user


# -- "Remember Me" persistent login tokens --------------------------
def create_remember_token(user_id):
    """
    Issue a new long-lived token for this user, valid for
    REMEMBER_ME_DAYS days. Only the hash is stored in the DB --
    the raw token is returned once, for the caller to save to a
    local file (~/.autored_session in the GUI layer).
    """
    raw_token  = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (
        datetime.now() + timedelta(days=REMEMBER_ME_DAYS)
    ).isoformat()

    conn   = get_connection()
    cursor = conn.cursor()
    # One active remember-token per user at a time keeps things
    # simple -- logging in fresh on a new device/session replaces
    # the old token rather than accumulating unlimited tokens.
    cursor.execute(
        "DELETE FROM remember_tokens WHERE user_id=?", (user_id,)
    )
    cursor.execute(
        "INSERT INTO remember_tokens (user_id, token_hash, expires_at) "
        "VALUES (?, ?, ?)",
        (user_id, token_hash, expires_at)
    )
    conn.commit()
    conn.close()
    return raw_token


def validate_remember_token(raw_token):
    """
    Returns the user dict if the token is valid and not expired,
    otherwise None. Does NOT consume/rotate the token -- it stays
    valid until it naturally expires or the user logs out.
    """
    if not raw_token:
        return None

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, expires_at FROM remember_tokens "
        "WHERE token_hash=?",
        (token_hash,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    user_id, expires_at = row

    if datetime.now() > datetime.fromisoformat(expires_at):
        cursor.execute(
            "DELETE FROM remember_tokens WHERE token_hash=?",
            (token_hash,)
        )
        conn.commit()
        conn.close()
        return None

    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user_row = cursor.fetchone()
    conn.close()
    return dict(user_row) if user_row else None


def revoke_remember_token(raw_token=None, user_id=None):
    """Used on logout -- removes the saved token by value or by user."""
    conn   = get_connection()
    cursor = conn.cursor()
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        cursor.execute(
            "DELETE FROM remember_tokens WHERE token_hash=?",
            (token_hash,)
        )
    elif user_id:
        cursor.execute(
            "DELETE FROM remember_tokens WHERE user_id=?", (user_id,)
        )
    conn.commit()
    conn.close()



def generate_otp(user_id, purpose='login'):
    """Create and store a fresh 6-digit OTP for this user."""
    code       = f"{random.randint(0, 999999):06d}"
    expires_at = (
        datetime.now() + timedelta(minutes=OTP_VALID_MINUTES)
    ).isoformat()

    conn   = get_connection()
    cursor = conn.cursor()
    # Invalidate any previous unverified OTPs for this purpose
    # only -- a pending password-reset code shouldn't be wiped
    # out by a normal login attempt, and vice versa.
    cursor.execute(
        "DELETE FROM login_otps WHERE user_id=? AND purpose=? "
        "AND verified=0",
        (user_id, purpose)
    )
    cursor.execute(
        "INSERT INTO login_otps (user_id, otp_code, purpose, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (user_id, code, purpose, expires_at)
    )
    conn.commit()
    conn.close()
    return code


def verify_otp(user_id, code, purpose='login'):
    """
    Returns (True, "") on success, or (False, error_message).
    Tracks attempts and expiry; locks out after
    OTP_MAX_ATTEMPTS wrong tries on the same code.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, otp_code, expires_at, attempts FROM login_otps "
        "WHERE user_id=? AND purpose=? AND verified=0 "
        "ORDER BY id DESC LIMIT 1",
        (user_id, purpose)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, (
            "No pending verification code. Please request a new one."
        )

    otp_id, stored_code, expires_at, attempts = row

    if datetime.now() > datetime.fromisoformat(expires_at):
        conn.close()
        return False, "Code expired. Please request a new one."

    if attempts >= OTP_MAX_ATTEMPTS:
        conn.close()
        return False, (
            "Too many incorrect attempts. Please request a new code."
        )

    if code.strip() != stored_code:
        cursor.execute(
            "UPDATE login_otps SET attempts = attempts + 1 WHERE id=?",
            (otp_id,)
        )
        conn.commit()
        conn.close()
        remaining = OTP_MAX_ATTEMPTS - (attempts + 1)
        return False, (
            f"Incorrect code. {remaining} attempt"
            f"{'s' if remaining != 1 else ''} remaining."
        )

    # Correct code
    cursor.execute(
        "UPDATE login_otps SET verified=1 WHERE id=?", (otp_id,)
    )
    if purpose == 'login':
        cursor.execute(
            "UPDATE users SET last_login=? WHERE id=?",
            (datetime.now().isoformat(), user_id)
        )
    conn.commit()
    conn.close()
    return True, ""


# -- Forgot password -------------------------------------------------
def request_password_reset(email):
    """
    Step 1 of password recovery. Looks up the user by EMAIL
    (not username) -- this covers the case where a user has
    forgotten their username but still has access to their inbox,
    since the email is what actually receives the reset code
    regardless of which field was used to find the account.
    Emails a 6-digit reset code (purpose='reset', distinct from
    login OTPs), and returns (True, user_dict) so the caller can
    move to the code-entry step. Returns (False, error) if the
    email doesn't exist, without revealing *why* it failed in a
    way that confirms/denies account existence beyond what's
    needed for a desktop tool with a small trusted user base.
    """
    user = get_user_by_email(email)
    if not user:
        return False, "No account found with that email address."

    code = generate_otp(user['id'], purpose='reset')
    sent = send_otp_email(user, code, purpose='reset')

    if not sent:
        return False, (
            "Could not send the reset email -- check SMTP settings "
            "in .env, or ask an admin for the code shown in the "
            "terminal."
        )

    return True, user


def reset_password(user_id, code, new_password):
    """
    Step 2 of password recovery. Verifies the emailed reset code,
    enforces the same strict password policy as account creation,
    and overwrites the stored password hash. Also revokes any
    "Remember Me" tokens for this user, since the old password
    (and any session built on top of it) should no longer be
    trusted once a reset happens.
    Returns (True, "") or (False, error_message).
    """
    ok, msg = verify_otp(user_id, code, purpose='reset')
    if not ok:
        return False, msg

    strong, reason = validate_password_strength(new_password)
    if not strong:
        return False, reason

    pw_hash, salt = _hash_password(new_password)

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password_hash=?, salt=? WHERE id=?",
        (pw_hash, salt, user_id)
    )
    conn.commit()
    conn.close()

    # Force re-authentication everywhere -- a reset password
    # should invalidate any "remember me" session built on the
    # old credentials.
    revoke_remember_token(user_id=user_id)

    return True, ""


# -- Email delivery (reuses the SMTP_* vars from .env) ---------------
def _load_env():
    cfg      = {}
    env_path = os.path.join(
        os.path.dirname(__file__), '..', '.env'
    )
    if os.path.exists(env_path):
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        cfg[k.strip()] = v.strip()
        except Exception:
            pass
    return cfg


def send_otp_email(user, code, purpose='login'):
    """
    Email the 6-digit code to the user's registered address.
    Uses the same SMTP_HOST/PORT/EMAIL/PASSWORD variables already
    configured for scan reports. purpose='login' or 'reset'
    changes the subject/copy so the email is clear about why it
    was sent.
    """
    cfg  = _load_env()
    host = cfg.get('SMTP_HOST', '')
    port = int(cfg.get('SMTP_PORT', 587))
    smtp_user = cfg.get('SMTP_EMAIL', '')
    smtp_pass = cfg.get('SMTP_PASSWORD', '')

    if not all([host, smtp_user, smtp_pass, user.get('email')]):
        print(
            "[!] OTP email: missing SMTP config in .env "
            "or user has no email on file."
        )
        return False

    if purpose == 'reset':
        subject  = "AutoRed -- Password Reset Code"
        label    = "Password Reset"
        intro    = (
            "A password reset was requested for your AutoRed "
            "account. Use the code below to set a new password."
        )
        footer_note = (
            "If you did not request a password reset, please "
            "secure your account immediately and ignore this "
            "email -- your current password remains unchanged "
            "unless this code is used."
        )
    else:
        subject  = "AutoRed -- Your Login Verification Code"
        label    = "Login Verification"
        intro    = (
            "Someone is attempting to log into your AutoRed "
            "account. Use the verification code below to "
            "complete sign-in."
        )
        footer_note = (
            "If you did not attempt to log in, please secure "
            "your account immediately and ignore this email."
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#07111f;
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',
Arial,sans-serif;color:#e5edf7;">
<div style="max-width:480px;margin:0 auto;padding:32px 16px;">

  <div style="background:#0f172a;border:1px solid #22304a;
  border-top:3px solid #38bdf8;border-radius:12px;
  padding:22px 26px;margin-bottom:20px;">
    <div style="font-size:20px;font-weight:800;color:#e94560;">
      AutoRed
      <span style="color:#475569;font-weight:400;
      font-size:15px;margin-left:8px;">-- {label}</span>
    </div>
    <div style="font-size:12px;color:#475569;margin-top:4px;">
      {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </div>
  </div>

  <div style="background:#0f172a;border:1px solid #22304a;
  border-radius:10px;padding:22px 24px;margin-bottom:20px;">
    <p style="margin:0 0 12px;font-size:14px;color:#e5edf7;">
      Hello {user.get('username', '')},
    </p>
    <p style="margin:0 0 16px;font-size:14px;color:#94a3b8;
    line-height:1.6;">
      {intro}
    </p>

    <div style="background:#0a1628;border:1px solid #1e3a5f;
    border-radius:10px;padding:20px;text-align:center;
    margin-bottom:16px;">
      <div style="font-size:11px;font-weight:700;color:#38bdf8;
      letter-spacing:2px;text-transform:uppercase;
      margin-bottom:10px;">
        Verification Code
      </div>
      <div style="font-size:40px;font-weight:800;color:#e5edf7;
      letter-spacing:12px;font-family:monospace;">{code}</div>
      <div style="font-size:11px;color:#475569;margin-top:10px;">
        This code expires in {OTP_VALID_MINUTES} minutes.
      </div>
    </div>

    <p style="margin:0;font-size:12px;color:#475569;
    line-height:1.6;">
      {footer_note}
    </p>
  </div>

  <div style="text-align:center;font-size:11px;color:#334155;">
    AutoRed &nbsp;.&nbsp; APU FYP 2026
  </div>
</div>
</body></html>"""

    msg            = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = f"AutoRed <{smtp_user}>"
    msg['To']      = user['email']
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(host, port, timeout=30) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, user['email'], msg.as_string())
        print(f"[+] OTP email sent to {user['email']} (code: {code})")
        return True
    except Exception as e:
        print(f"[!] OTP email failed: {e}")
        return False
