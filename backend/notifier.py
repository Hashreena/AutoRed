"""
AutoRed — Notification Module
==============================
Sends a scan-completion alert via:
  1. Email  (SMTP — works with Gmail, Office 365, any corporate mail)
  2. Desktop system tray notification (PyQt6 QSystemTrayIcon)

Configuration in ~/AutoRed/.env:
    # ── Email ──────────────────────────────────────────────────
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_EMAIL=you@example.com
    SMTP_PASSWORD=your-app-password
    NOTIFY_FROM=AutoRed <you@example.com>
    NOTIFY_TO=security-team@example.com

Usage:
    from backend.notifier import send_notifications
    send_notifications(scan_id)
"""
import json
import os
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

sys.path.insert(
    0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    )
)


# ── Config loader ─────────────────────────────────────────────
def _load_env():
    cfg = {}
    env_path = os.path.join(
        os.path.dirname(__file__), '..', '.env'
    )
    if not os.path.exists(env_path):
        return cfg
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


# ── Desktop notification ──────────────────────────────────────
def show_desktop_notification(title, message, duration=6000):
    """
    Show a system tray desktop notification using PyQt6.
    Appears as a popup in the corner of the screen for
    `duration` milliseconds (default 6 seconds).
    Safe to call from any thread — uses QApplication if available.
    """
    try:
        from PyQt6.QtWidgets import QSystemTrayIcon, QApplication
        from PyQt6.QtGui import QIcon
        from PyQt6.QtCore import QTimer

        app = QApplication.instance()
        if app is None:
            print(
                f"[!] Desktop notification skipped "
                f"(no QApplication running)"
            )
            return

        tray = QSystemTrayIcon(app)
        # Use a generic icon — replace with AutoRed icon path if available
        icon_path = os.path.join(
            os.path.dirname(__file__), '..', 'assets', 'icon.png'
        )
        if os.path.exists(icon_path):
            tray.setIcon(QIcon(icon_path))
        else:
            # Use a built-in Qt icon as fallback
            from PyQt6.QtWidgets import QStyle
            style = app.style()
            tray.setIcon(
                style.standardIcon(
                    QStyle.StandardPixmap.SP_ComputerIcon
                )
            )

        tray.show()
        tray.showMessage(
            title,
            message,
            QSystemTrayIcon.MessageIcon.Information,
            duration,
        )
        # Clean up after notification duration
        QTimer.singleShot(
            duration + 500,
            lambda: tray.hide()
        )
        print(f"[+] Desktop notification shown: {title}")
    except Exception as e:
        print(f"[!] Desktop notification failed: {e}")


# ── Scan data fetcher ─────────────────────────────────────────
def _get_scan_summary(scan_id):
    try:
        from backend.db import get_connection
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT name, target, profile, created_at '
            'FROM scans WHERE id=?',
            (scan_id,)
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None
        name, target, profile, created_at = row
        cursor.execute(
            'SELECT severity, title, asset, tool '
            'FROM findings WHERE scan_id=?',
            (scan_id,)
        )
        findings = cursor.fetchall()
        conn.close()
        counts       = {}
        cve_findings = []
        ch_findings  = []
        import re
        CVE_PAT = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
        for sev, title, asset, tool in findings:
            counts[sev] = counts.get(sev, 0) + 1
            m = CVE_PAT.search(title or '')
            if m:
                cve_findings.append(
                    (m.group(0).upper(), sev, title)
                )
            if sev in ('Critical', 'High'):
                ch_findings.append({
                    'severity': sev,
                    'title':    title  or '',
                    'asset':    asset  or '',
                    'tool':     tool   or '',
                })
        SEV_TO_CVSS = {
            'Critical': 9.8, 'High': 7.5,
            'Medium':   5.3, 'Low':  2.5, 'Info': 0.0,
        }
        total    = len(findings) or 1
        avg_cvss = round(
            sum(SEV_TO_CVSS.get(s, 0)
                for s, *_ in findings) / total, 1
        )
        risk = min(100,
            counts.get('Critical', 0) * 25 +
            counts.get('High',     0) * 15 +
            counts.get('Medium',   0) *  5 +
            counts.get('Low',      0) *  1
        )
        risk_label = (
            'CRITICAL' if risk >= 75 else
            'HIGH'     if risk >= 50 else
            'MEDIUM'   if risk >= 25 else 'LOW'
        )
        ch_findings.sort(
            key=lambda x: 0 if x['severity'] == 'Critical' else 1
        )
        return {
            'scan_id':     scan_id,
            'name':        name or f'Scan #{scan_id}',
            'target':      target or 'Unknown',
            'profile':     profile or 'Standard',
            'date':        str(created_at or '')[:16],
            'total':       len(findings),
            'counts':      counts,
            'avg_cvss':    avg_cvss,
            'risk':        risk,
            'risk_label':  risk_label,
            'top_cves':    cve_findings[:5],
            'ch_findings': ch_findings,
        }
    except Exception as e:
        print(f"[!] Notifier: failed to load scan data: {e}")
        return None


# ── Email HTML builder ────────────────────────────────────────
def _build_html_email(s):
    risk_color = (
        '#dc2626' if s['risk'] >= 75 else
        '#e94560' if s['risk'] >= 50 else
        '#ff8c00' if s['risk'] >= 25 else '#16a34a'
    )
    risk_bg = (
        '#450a0a' if s['risk'] >= 75 else
        '#2d0a14' if s['risk'] >= 50 else
        '#431407' if s['risk'] >= 25 else '#052e16'
    )
    sev_rows = ''
    for sev, col in [
        ('Critical', '#dc2626'), ('High',   '#e94560'),
        ('Medium',   '#ff8c00'), ('Low',    '#ca8a04'),
        ('Info',     '#3b82f6'),
    ]:
        ct = s['counts'].get(sev, 0)
        if ct == 0:
            continue
        pct   = round(ct / (s['total'] or 1) * 100)
        bar_w = max(4, int(pct * 1.6))
        sev_rows += (
            f'<tr>'
            f'<td style="padding:8px 16px;width:90px;'
            f'font-size:13px;font-weight:600;color:{col};">'
            f'{sev}</td>'
            f'<td style="padding:8px 8px;">'
            f'<div style="background:#1e293b;border-radius:4px;'
            f'height:8px;width:160px;">'
            f'<div style="background:{col};height:8px;'
            f'border-radius:4px;width:{bar_w}px;"></div>'
            f'</div></td>'
            f'<td style="padding:8px 16px;font-size:13px;'
            f'font-weight:700;color:{col};text-align:right;">'
            f'{ct}</td>'
            f'<td style="padding:8px 16px;font-size:11px;'
            f'color:#64748b;text-align:right;">{pct}%</td>'
            f'</tr>'
        )
    ch = s.get('ch_findings', [])
    if ch:
        finding_rows = ''
        for i, f in enumerate(ch[:15]):
            sev   = f['severity']
            col   = '#dc2626' if sev == 'Critical' else '#e94560'
            bg    = '#1a0a0a' if i % 2 == 0 else '#0f172a'
            title = (f['title'][:65] + '…') \
                    if len(f['title']) > 65 else f['title']
            asset = (f['asset'][:40] + '…') \
                    if len(f['asset']) > 40 else f['asset']
            cvss  = '9.8' if sev == 'Critical' else '7.5'
            finding_rows += (
                f'<tr style="background:{bg};">'
                f'<td style="padding:9px 14px;">'
                f'<span style="display:inline-block;'
                f'padding:2px 8px;border-radius:4px;'
                f'background:{col}22;color:{col};'
                f'font-size:11px;font-weight:700;'
                f'margin-bottom:3px;">{sev}</span><br>'
                f'<span style="font-size:12px;'
                f'color:#e2e8f0;">{title}</span></td>'
                f'<td style="padding:9px 14px;font-size:11px;'
                f'color:#94a3b8;vertical-align:top;">'
                f'{asset}</td>'
                f'<td style="padding:9px 14px;font-size:11px;'
                f'color:#64748b;vertical-align:top;'
                f'text-align:center;">{f["tool"]}</td>'
                f'<td style="padding:9px 14px;font-size:12px;'
                f'font-weight:700;color:{col};'
                f'text-align:center;vertical-align:top;">'
                f'{cvss}</td></tr>'
            )
        remaining = len(ch) - 15
        more_row  = (
            f'<tr><td colspan="4" style="padding:8px 14px;'
            f'text-align:center;font-size:11px;color:#64748b;'
            f'background:#0f172a;">+ {remaining} more '
            f'Critical/High findings in AutoRed</td></tr>'
        ) if remaining > 0 else ''
        ch_count = (s['counts'].get('Critical', 0) +
                    s['counts'].get('High', 0))
        findings_section = (
            f'<div style="background:#0f172a;'
            f'border:1px solid #1e293b;'
            f'border-radius:10px;overflow:hidden;'
            f'margin-bottom:20px;">'
            f'<div style="padding:14px 16px;'
            f'border-bottom:1px solid #1e293b;'
            f'background:#111827;">'
            f'<span style="font-size:11px;font-weight:700;'
            f'color:#94a3b8;letter-spacing:1px;'
            f'text-transform:uppercase;">'
            f'Critical &amp; High Findings '
            f'({ch_count} total)</span></div>'
            f'<table style="width:100%;border-collapse:collapse;">'
            f'<thead><tr style="background:#111827;">'
            f'<th style="padding:8px 14px;text-align:left;'
            f'font-size:10px;color:#475569;font-weight:600;'
            f'width:50%;">Finding</th>'
            f'<th style="padding:8px 14px;text-align:left;'
            f'font-size:10px;color:#475569;font-weight:600;'
            f'width:25%;">Asset</th>'
            f'<th style="padding:8px 14px;text-align:center;'
            f'font-size:10px;color:#475569;font-weight:600;'
            f'width:12%;">Tool</th>'
            f'<th style="padding:8px 14px;text-align:center;'
            f'font-size:10px;color:#475569;font-weight:600;'
            f'width:13%;">CVSS</th>'
            f'</tr></thead>'
            f'<tbody>{finding_rows}{more_row}</tbody>'
            f'</table></div>'
        )
    else:
        findings_section = (
            '<div style="background:#0f172a;'
            'border:1px solid #1e293b;border-radius:10px;'
            'padding:20px;text-align:center;'
            'margin-bottom:20px;">'
            '<span style="font-size:13px;color:#22c55e;">'
            'No Critical or High findings detected.'
            '</span></div>'
        )
    if s['top_cves']:
        cve_items = ''
        for cve_id, sev, title in s['top_cves']:
            col   = '#dc2626' if sev == 'Critical' else '#e94560'
            short = (title[:60] + '…') if len(title) > 60 else title
            cve_items += (
                f'<tr>'
                f'<td style="padding:8px 14px;'
                f'font-family:monospace;font-size:12px;'
                f'color:{col};font-weight:700;">{cve_id}</td>'
                f'<td style="padding:8px 14px;font-size:12px;'
                f'color:#94a3b8;">{short}</td>'
                f'</tr>'
            )
        cve_section = (
            '<div style="background:#0f172a;'
            'border:1px solid #1e293b;border-radius:10px;'
            'overflow:hidden;margin-bottom:20px;">'
            '<div style="padding:14px 16px;'
            'border-bottom:1px solid #1e293b;'
            'background:#111827;">'
            '<span style="font-size:11px;font-weight:700;'
            'color:#94a3b8;letter-spacing:1px;'
            'text-transform:uppercase;">CVEs Identified</span>'
            '</div>'
            '<table style="width:100%;border-collapse:collapse;">'
            f'<tbody>{cve_items}</tbody>'
            '</table></div>'
        )
    else:
        cve_section = ''

    ch_hi = (s['counts'].get('Critical', 0) +
             s['counts'].get('High', 0))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>AutoRed Security Scan Report — {s['target']}</title>
</head>
<body style="margin:0;padding:0;background-color:#060b14;
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<div style="max-width:640px;margin:0 auto;padding:32px 16px;">
  <div style="background:#0f172a;border:1px solid #1e293b;
  border-radius:10px;padding:20px 24px;margin-bottom:20px;">
    <p style="margin:0 0 8px 0;font-size:15px;
    color:#e2e8f0;font-weight:600;">Hello,</p>
    <p style="margin:0 0 8px 0;font-size:14px;
    color:#94a3b8;line-height:1.6;">
      Your AutoRed security scan for
      <span style="font-family:monospace;color:#e2e8f0;
      font-weight:600;">{s['target']}</span> has completed.
      Please review the findings summary below.
    </p>
    <p style="margin:0;font-size:12px;color:#475569;">
      Scan #{s['scan_id']} &nbsp;·&nbsp;
      Completed: {s['date'].replace('T', ' ')}
      &nbsp;·&nbsp; Profile: {s['profile']}
    </p>
  </div>
  <div style="background:linear-gradient(135deg,#0f172a 0%,#1a0a14 100%);
  border:1px solid #1e293b;border-top:3px solid #e94560;
  border-radius:12px;padding:24px 28px;margin-bottom:20px;">
    <div style="font-size:22px;font-weight:800;color:#e94560;">
      AutoRed
      <span style="color:#475569;font-weight:400;font-size:16px;
      margin-left:8px;">Security Scan Report</span>
    </div>
    <div style="font-size:14px;color:#94a3b8;margin-top:8px;">
      Target: <span style="font-family:monospace;color:#e2e8f0;
      font-weight:600;">{s['target']}</span>
    </div>
  </div>
  <div style="background:{risk_bg};border:1px solid {risk_color}44;
  border-left:4px solid {risk_color};border-radius:10px;
  padding:20px 24px;margin-bottom:20px;">
    <div style="font-size:11px;font-weight:700;color:{risk_color}99;
    letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">
      Overall Risk Score
    </div>
    <div style="font-size:48px;font-weight:800;color:{risk_color};
    line-height:1;letter-spacing:-2px;">
      {s['risk']}<span style="font-size:20px;color:{risk_color}88;
      font-weight:400;">/100</span>
    </div>
    <div style="font-size:15px;font-weight:700;color:{risk_color};
    margin-top:4px;letter-spacing:2px;text-transform:uppercase;">
      {s['risk_label']}
    </div>
  </div>
  <table style="width:100%;border-collapse:separate;
  border-spacing:12px 0;margin-bottom:20px;">
    <tr>
      <td style="background:#0f172a;border:1px solid #1e293b;
      border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:800;color:#e2e8f0;">
          {s['total']}</div>
        <div style="font-size:11px;color:#64748b;margin-top:2px;
        text-transform:uppercase;letter-spacing:1px;">
          Total Findings</div>
      </td>
      <td style="background:#0f172a;border:1px solid #1e293b;
      border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:800;color:#e94560;">
          {ch_hi}</div>
        <div style="font-size:11px;color:#64748b;margin-top:2px;
        text-transform:uppercase;letter-spacing:1px;">
          Critical + High</div>
      </td>
      <td style="background:#0f172a;border:1px solid #1e293b;
      border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:800;color:#ff8c00;">
          {s['avg_cvss']}</div>
        <div style="font-size:11px;color:#64748b;margin-top:2px;
        text-transform:uppercase;letter-spacing:1px;">
          Avg CVSS</div>
      </td>
    </tr>
  </table>
  <div style="background:#0f172a;border:1px solid #1e293b;
  border-radius:10px;overflow:hidden;margin-bottom:20px;">
    <div style="padding:14px 16px;border-bottom:1px solid #1e293b;
    background:#111827;">
      <span style="font-size:11px;font-weight:700;color:#94a3b8;
      letter-spacing:1px;text-transform:uppercase;">
        Severity Breakdown</span>
    </div>
    <table style="width:100%;border-collapse:collapse;">
      <tbody>{sev_rows}</tbody>
    </table>
  </div>
  {findings_section}
  {cve_section}
  <div style="text-align:center;padding-top:16px;
  border-top:1px solid #1e293b;">
    <div style="font-size:13px;font-weight:700;
    color:#e94560;margin-bottom:4px;">AutoRed</div>
    <div style="font-size:11px;color:#334155;">
      Automated Reconnaissance &amp; Reporting
      &nbsp;·&nbsp; APU FYP 2026
    </div>
    <div style="font-size:10px;color:#334155;margin-top:6px;">
      This report is confidential and intended for
      authorised personnel only.
    </div>
  </div>
</div>
</body>
</html>"""


# ── Email sender ──────────────────────────────────────────────
def send_email(scan_id, summary=None):
    """
    Send HTML scan report via SMTP.
    Includes proper email headers to reduce spam filtering:
    - Message-ID, Date headers
    - X-Mailer header
    - Proper From display name
    - Descriptive subject line that avoids spam trigger words
    """
    cfg  = _load_env()
    host = cfg.get('SMTP_HOST', '')
    port = int(cfg.get('SMTP_PORT', 587))
    user = cfg.get('SMTP_EMAIL', '')
    pw   = cfg.get('SMTP_PASSWORD', '')
    to   = cfg.get('NOTIFY_TO', '')
    frm  = cfg.get('NOTIFY_FROM', f'AutoRed Scanner <{user}>')

    if not all([host, user, pw, to]):
        print(
            "[!] Email notifier: missing config. "
            "Check SMTP_HOST, SMTP_EMAIL, SMTP_PASSWORD, "
            "NOTIFY_TO in .env"
        )
        return False

    s = summary or _get_scan_summary(scan_id)
    if not s:
        return False

    risk_label = s['risk_label']

    # ── Subject line — avoid spam trigger words ───────────────
    # Avoid: "Security Report", "Alert", "Warning", "Urgent"
    # Use: descriptive, professional, scan-specific
    subject = (
        f"AutoRed — Scan #{s['scan_id']} completed "
        f"| {s['target']} "
        f"| {s['total']} findings "
        f"| Risk: {risk_label}"
    )

    msg = MIMEMultipart('alternative')
    msg['Subject']    = subject
    msg['From']       = frm
    msg['To']         = to

    # ── Anti-spam headers ─────────────────────────────────────
    # These tell spam filters this is a legitimate automated email
    msg['Date']       = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=user.split('@')[-1])
    msg['X-Mailer']   = 'AutoRed Security Scanner v1.0'
    msg['MIME-Version'] = '1.0'

    # Plain text fallback (important for spam filters —
    # emails with only HTML are flagged more often)
    plain_text = (
        f"AutoRed Scan Report\n"
        f"{'=' * 40}\n"
        f"Scan ID  : #{s['scan_id']}\n"
        f"Target   : {s['target']}\n"
        f"Profile  : {s['profile']}\n"
        f"Date     : {s['date']}\n"
        f"Risk     : {s['risk']}/100 ({risk_label})\n"
        f"Findings : {s['total']} total\n"
        f"Critical : {s['counts'].get('Critical', 0)}\n"
        f"High     : {s['counts'].get('High', 0)}\n"
        f"Medium   : {s['counts'].get('Medium', 0)}\n"
        f"Low      : {s['counts'].get('Low', 0)}\n"
        f"Avg CVSS : {s['avg_cvss']}\n"
        f"{'=' * 40}\n"
        f"Open AutoRed to view full findings details.\n"
        f"\nThis report is confidential and intended for "
        f"authorised personnel only."
    )

    msg.attach(MIMEText(plain_text, 'plain'))
    msg.attach(MIMEText(_build_html_email(s), 'html'))

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, pw)
            server.sendmail(user, [to], msg.as_string())
        print(f"[+] Email sent → {to}")
        return True
    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False


# ── Main entry point ──────────────────────────────────────────
def send_notifications(scan_id):
    """
    Send scan completion notifications:
    1. Desktop system tray notification (instant)
    2. Email with full HTML report

    Call from scan_progress.py when all tools finish:
        from backend.notifier import send_notifications
        send_notifications(self.scan_id)

    Never raises — errors are printed but won't crash the scan.
    """
    print(f"[*] Sending notifications for scan #{scan_id}...")
    try:
        s = _get_scan_summary(scan_id)
        if not s:
            print("[!] Notifier: no scan data found.")
            return

        # ── 1. Desktop notification (immediate) ───────────────
        risk_label = s['risk_label']
        ch = (s['counts'].get('Critical', 0) +
              s['counts'].get('High', 0))
        notif_title = f"AutoRed — Scan Complete"
        notif_msg   = (
            f"Target: {s['target']}\n"
            f"{s['total']} findings  |  "
            f"{ch} Critical/High  |  "
            f"Risk: {risk_label}"
        )
        show_desktop_notification(notif_title, notif_msg)

        # ── 2. Email notification ─────────────────────────────
        cfg = _load_env()
        if cfg.get('SMTP_EMAIL'):
            send_email(scan_id, s)
        else:
            print(
                "[!] SMTP_EMAIL not set in .env — "
                "email notification skipped."
            )
    except Exception as e:
        print(f"[!] Notifier unexpected error: {e}")


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 backend/notifier.py <scan_id>")
        sys.exit(1)
    send_notifications(int(sys.argv[1]))
