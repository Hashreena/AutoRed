"""
AutoRed — Scope / Authorization backend
========================================
Two DB tables:
  scope_blocklist     — IPs/domains blocked by default
  authorized_targets  — allowlist that overrides the blocklist

Full flow:
  1. Default blocklist is seeded on first run (Malaysian banks,
     government, hospitals, critical infrastructure, private IPs)
  2. User enters a target in the Scan Wizard
  3. validate_target() checks blocklist → if blocked, returns
     a specific reason explaining why
  4. User can override by adding the target to the Authorized
     Targets Manager with written authorization
  5. On re-scan, target passes the allowlist check → allowed

Blocklist sources referenced:
  - Bank Negara Malaysia (BNM) licensed institutions
  - National Cyber Security Agency Malaysia (NACSA)
  - CyberSecurity Malaysia (CSM)
  - Ministry of Health Malaysia (MOH)
  - RFC 1918 private IP ranges
  - Computer Crimes Act 1997 (Malaysia)
"""
import ipaddress
import os
import random
import smtplib
from datetime             import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from backend.db import get_connection


# ── DB migration ──────────────────────────────────────────────
def _migrate():
    conn   = get_connection()
    cursor = conn.cursor()

    # Blocklist table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scope_blocklist (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            target   TEXT UNIQUE NOT NULL,
            reason   TEXT,
            added_on TEXT
        )
    ''')

    # Allowlist / authorized targets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authorized_targets (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            target           TEXT UNIQUE NOT NULL,
            authorized_by    TEXT,
            engagement       TEXT,
            notes            TEXT,
            authorizer_email TEXT,
            authorized_on    TEXT,
            status           TEXT DEFAULT 'approved',
            approval_token   TEXT
        )
    ''')

    # Safely add new columns to existing installs
    cols = [
        r[1] for r in cursor.execute(
            "PRAGMA table_info(authorized_targets)"
        ).fetchall()
    ]
    for col, defn in [
        ('authorizer_email', 'TEXT'),
        ('status',           "TEXT DEFAULT 'approved'"),
        ('approval_token',   'TEXT'),
    ]:
        if col not in cols:
            try:
                cursor.execute(
                    f"ALTER TABLE authorized_targets "
                    f"ADD COLUMN {col} {defn}"
                )
            except Exception:
                pass

    conn.commit()
    conn.close()

    # Seed the default blocklist on first run
    try:
        from backend.default_blocklist import (
            seed_default_blocklist,
            is_blocklist_seeded,
        )
        if not is_blocklist_seeded():
            seed_default_blocklist()
    except Exception as e:
        print(f"[!] Default blocklist seeding failed: {e}")


_migrate()


# ── Scope validation ──────────────────────────────────────────
def _matches_entry(target, entry):
    """
    Match a target against a blocklist entry.
    Supports exact match, wildcard (*.domain.com), CIDR.
    """
    t = target.lower().strip()
    e = entry.lower().strip()

    if t == e:
        return True

    # Wildcard domain *.company.com
    if e.startswith('*.'):
        suffix = e[1:]
        if t.endswith(suffix) or t == e[2:]:
            return True

    # CIDR range e.g. 10.0.0.0/8
    try:
        ip  = ipaddress.ip_address(t)
        net = ipaddress.ip_network(e, strict=False)
        if ip in net:
            return True
    except ValueError:
        pass

    return False


def _categorise_blocked_target(target, reason):
    """
    Return a user-friendly category and action message
    based on the blocked target and its reason.
    """
    t = target.lower()
    r = (reason or "").lower()

    if any(k in r for k in ["armed forces", "army", "navy", "air force", "pdrm", "police", "mindef"]):
        category = "Malaysian Security / Military Institution"
        action   = "Scanning security and military infrastructure is a criminal offence under the Computer Crimes Act 1997 (Malaysia). You must obtain written authorization from the relevant authority."

    elif any(k in r for k in ["bank", "bnm", "financial", "e-money", "payment", "paynet", "securities commission", "bursa"]):
        category = "Licensed Financial Institution"
        action   = "Scanning financial institutions requires written authorization from the institution and compliance with Bank Negara Malaysia (BNM) guidelines. Add this target to Authorized Targets with a valid engagement letter."

    elif any(k in r for k in ["government", "gov.my", "nacsa", "mcmc", "cybersecurity"]):
        category = "Malaysian Government Institution"
        action   = "Scanning Malaysian government infrastructure requires written authorization. Refer to NACSA penetration testing guidelines before proceeding."

    elif any(k in r for k in ["hospital", "healthcare", "medical", "health", "moh"]):
        category = "Healthcare Institution"
        action   = "Scanning healthcare systems may violate patient data protection laws under the Personal Data Protection Act 2010 (PDPA). Written authorization is required."

    elif any(k in r for k in ["critical infrastructure", "electricity", "petronas", "gas", "airport", "airline", "telecommunications", "telco"]):
        category = "Critical National Infrastructure"
        action   = "Scanning critical national infrastructure without authorization may violate the Computer Crimes Act 1997 and Communications and Multimedia Act 1998."

    elif any(k in r for k in ["private network", "rfc 1918", "loopback", "link-local"]):
        category = "Private / Reserved IP Range"
        action   = "This IP address belongs to a private or reserved range. Ensure you have explicit permission from the network owner before scanning internal infrastructure."

    elif any(k in r for k in ["google", "microsoft", "amazon", "cloudflare"]):
        category = "Major Public Infrastructure"
        action   = "Scanning major public internet infrastructure is prohibited without explicit written authorization from the provider."

    else:
        category = "Restricted Target"
        action   = "This target is on the AutoRed restricted list. Add it to the Authorized Targets Manager with valid written authorization to proceed."

    return category, action


def validate_target(target):
    """
    Returns {'allowed': bool, 'reason': str, 'authorized': bool,
             'category': str, 'action': str}.

    Logic:
      1. Is the target in the blocklist?  → if no  → allow
      2. Is the target in the allowlist (approved)? → if yes → allow
      3. Otherwise → block with detailed reason and category
    """
    if not target:
        return {
            'allowed':    False,
            'reason':     'No target specified.',
            'authorized': False,
            'category':   '',
            'action':     '',
        }

    # Check blocklist
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT target, reason FROM scope_blocklist")
    blocked = None
    for row in cursor.fetchall():
        if _matches_entry(target, row[0]):
            blocked = row
            break
    conn.close()

    if blocked is None:
        return {
            'allowed':    True,
            'reason':     '',
            'authorized': False,
            'category':   '',
            'action':     '',
        }

    # Blocked — check allowlist override
    if is_authorized(target):
        return {
            'allowed':    True,
            'reason':     '',
            'authorized': True,
            'category':   '',
            'action':     '',
            'note': (
                'Target is in blocklist but has '
                'approved authorization — allowed.'
            ),
        }

    # Build detailed error message
    category, action = _categorise_blocked_target(
        target, blocked[1]
    )

    reason_msg = (
        blocked[1] or
        f"'{target}' is on the AutoRed restricted list."
    )

    return {
        'allowed':    False,
        'authorized': False,
        'reason':     reason_msg,
        'category':   category,
        'action':     action,
    }


# ── Blocklist management ──────────────────────────────────────
def add_to_blocklist(target, reason=''):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO scope_blocklist "
        "(target, reason, added_on) VALUES (?, ?, ?)",
        (target, reason,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()


def remove_from_blocklist(target):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM scope_blocklist WHERE target=?",
        (target,)
    )
    conn.commit()
    conn.close()


def get_blocklist():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT target, reason, added_on "
        "FROM scope_blocklist ORDER BY added_on DESC"
    )
    cols = [d[0] for d in cursor.description]
    rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return rows


# ── Authorized targets (allowlist) ────────────────────────────
def generate_token():
    """6-digit approval code."""
    return str(random.randint(100000, 999999))


def save_authorized_target(
    target, authorized_by, engagement, notes,
    authorizer_email='', token=None, status='approved'
):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO authorized_targets
        (target, authorized_by, engagement, notes,
         authorizer_email, authorized_on,
         status, approval_token)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        target, authorized_by, engagement, notes,
        authorizer_email,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        status, token
    ))
    conn.commit()
    conn.close()


def get_all_authorizations():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT target, authorized_by, engagement, notes, "
        "authorizer_email, authorized_on, status, "
        "approval_token FROM authorized_targets "
        "ORDER BY authorized_on DESC"
    )
    cols = [d[0] for d in cursor.description]
    rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return rows


def remove_authorized_target(target):
    """
    Remove from allowlist (called by Remove button in UI).
    Target returns to being blocked by the blocklist.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM authorized_targets WHERE target=?",
        (target,)
    )
    conn.commit()
    conn.close()


def confirm_authorization(target, token):
    """
    Verify approval code → mark target as approved.
    Returns (True, message) or (False, error).
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT approval_token, status "
        "FROM authorized_targets WHERE target=?",
        (target,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, "Target not found."
    stored_token, status = row
    if status == 'approved':
        conn.close()
        return True, "Already approved."
    if str(stored_token).strip() != str(token).strip():
        conn.close()
        return False, "Invalid approval code. Please try again."
    cursor.execute(
        "UPDATE authorized_targets "
        "SET status='approved', approval_token=NULL "
        "WHERE target=?",
        (target,)
    )
    conn.commit()
    conn.close()
    return True, "Authorization confirmed successfully."


def is_authorized(target):
    """True if target is in allowlist with status=approved."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM authorized_targets "
        "WHERE target=? AND status='approved'",
        (target,)
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


# ── Approval email ────────────────────────────────────────────
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
                    if line and '=' in line and \
                       not line.startswith('#'):
                        k, v = line.split('=', 1)
                        cfg[k.strip()] = v.strip()
        except Exception:
            pass
    return cfg


def send_approval_email(
    target, authorized_by, engagement,
    authorizer_email, token
):
    """Send 6-digit approval code to the authorizer."""
    cfg  = _load_env()
    host = cfg.get('SMTP_HOST', '')
    port = int(cfg.get('SMTP_PORT', 587))
    user = cfg.get('SMTP_EMAIL', '')
    pw   = cfg.get('SMTP_PASSWORD', '')

    if not all([host, user, pw, authorizer_email]):
        print("[!] Approval email: missing SMTP config in .env")
        return False

    subject = (
        f"[Action Required] AutoRed — "
        f"Scan Authorization Request for {target}"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060b14;
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',
Arial,sans-serif;color:#e6edf3;">
<div style="max-width:560px;margin:0 auto;padding:32px 16px;">
  <div style="background:#0f172a;border:1px solid #1e293b;
  border-top:3px solid #e94560;border-radius:12px;
  padding:22px 26px;margin-bottom:20px;">
    <div style="font-size:20px;font-weight:800;color:#e94560;">
      AutoRed
      <span style="color:#475569;font-weight:400;
      font-size:15px;margin-left:8px;">
      — Authorization Request</span>
    </div>
    <div style="font-size:12px;color:#475569;margin-top:4px;">
      {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </div>
  </div>
  <div style="background:#0f172a;border:1px solid #1e293b;
  border-radius:10px;padding:22px 24px;margin-bottom:20px;">
    <p style="margin:0 0 12px;font-size:14px;
    color:#e2e8f0;">Hello,</p>
    <p style="margin:0 0 16px;font-size:14px;
    color:#94a3b8;line-height:1.6;">
      A penetration testing scan authorization request
      requires your approval:
    </p>
    <table style="width:100%;border-collapse:collapse;
    margin-bottom:20px;">
      <tr>
        <td style="padding:8px 0;font-size:12px;
        color:#64748b;width:140px;">Target</td>
        <td style="padding:8px 0;font-size:13px;
        color:#e2e8f0;font-family:monospace;
        font-weight:600;">{target}</td>
      </tr>
      <tr style="border-top:1px solid #1e293b;">
        <td style="padding:8px 0;font-size:12px;
        color:#64748b;">Requested By</td>
        <td style="padding:8px 0;font-size:13px;
        color:#e2e8f0;">{authorized_by}</td>
      </tr>
      <tr style="border-top:1px solid #1e293b;">
        <td style="padding:8px 0;font-size:12px;
        color:#64748b;">Engagement</td>
        <td style="padding:8px 0;font-size:13px;
        color:#e2e8f0;">{engagement}</td>
      </tr>
    </table>
    <div style="background:#0a1628;border:1px solid #1e3a5f;
    border-radius:10px;padding:20px;text-align:center;
    margin-bottom:16px;">
      <div style="font-size:11px;font-weight:700;
      color:#3b82f6;letter-spacing:2px;
      text-transform:uppercase;margin-bottom:10px;">
        Approval Code
      </div>
      <div style="font-size:40px;font-weight:800;
      color:#e2e8f0;letter-spacing:12px;
      font-family:monospace;">{token}</div>
      <div style="font-size:11px;color:#475569;
      margin-top:10px;">
        Provide this code to the requesting analyst
        to confirm authorization in AutoRed.
      </div>
    </div>
    <p style="margin:0;font-size:12px;color:#475569;
    line-height:1.6;">
      If you did not expect this request or
      <strong style="color:#e94560;">do not authorize
      </strong> this scan, please ignore this email
      and notify your security team immediately.
    </p>
  </div>
  <div style="text-align:center;font-size:11px;color:#334155;">
    AutoRed &nbsp;·&nbsp; APU FYP 2026
  </div>
</div>
</body></html>"""

    msg            = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = f"AutoRed <{user}>"
    msg['To']      = authorizer_email
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(host, port, timeout=30) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(user, pw)
            srv.sendmail(
                user, authorizer_email, msg.as_string()
            )
        print(
            f"[+] Approval email → {authorizer_email} "
            f"(code: {token})"
        )
        return True
    except Exception as e:
        print(f"[!] Approval email failed: {e}")
        return False
