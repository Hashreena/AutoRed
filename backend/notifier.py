import json
import os
import urllib.request
import urllib.error
from datetime import datetime


def load_telegram_config():
    token   = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID', '')

    if not token or not chat_id:
        env_path = os.path.join(
            os.path.dirname(__file__), '..', '.env'
        )
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('TELEGRAM_BOT_TOKEN='):
                        token = line.split('=', 1)[1]
                    elif line.startswith('TELEGRAM_CHAT_ID='):
                        chat_id = line.split('=', 1)[1]

    return token, chat_id


def send_telegram(message):
    token, chat_id = load_telegram_config()
    if not token or not chat_id:
        print("[!] Telegram not configured — skipping notification")
        return False

    try:
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id":    chat_id,
            "text":       message,
            "parse_mode": "HTML",
        }).encode('utf-8')

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get('ok'):
                print("[+] Telegram notification sent!")
                return True
            else:
                print(f"[!] Telegram error: {result}")
                return False

    except Exception as e:
        print(f"[!] Telegram notification failed: {e}")
        return False


def send_telegram_chunks(messages):
    for msg in messages:
        if msg.strip():
            send_telegram(msg)


def notify_scan_complete(scan_name, target, findings):
    counts = {
        'Critical': 0, 'High': 0,
        'Medium':   0, 'Low':  0, 'Info': 0
    }
    for f in findings:
        sev = f.get('severity', 'Info')
        counts[sev] = counts.get(sev, 0) + 1

    critical = counts['Critical']
    high     = counts['High']
    total    = len(findings)
    now      = datetime.now().strftime('%d %B %Y %H:%M')

    if critical == 0 and high == 0:
        print(
            "[*] No Critical/High findings — "
            "skipping Telegram notification"
        )
        return False

    risk = "CRITICAL RISK" if critical > 0 else "HIGH RISK"

    # ── Message 1: Header + Summary ─────────────────────────
    header = (
        f"🚨 <b>AutoRed Security Alert</b>\n\n"
        f"⚠️ <b>{risk} DETECTED</b>\n\n"
        f"📋 <b>Scan:</b> {scan_name}\n"
        f"🎯 <b>Target:</b> {target}\n"
        f"🕐 <b>Time:</b> {now}\n\n"
        f"📊 <b>Findings Summary:</b>\n"
        f"🔴 Critical : {counts['Critical']}\n"
        f"🟠 High     : {counts['High']}\n"
        f"🟡 Medium   : {counts['Medium']}\n"
        f"🟢 Low      : {counts['Low']}\n"
        f"🔵 Info     : {counts['Info']}\n"
        f"📌 Total    : {total}\n"
    )
    send_telegram(header)

    # ── Message 2: Critical Findings ────────────────────────
    if critical > 0:
        crit_findings = [
            f for f in findings
            if f.get('severity') == 'Critical'
        ]

        crit_msg = (
            f"🚨 <b>Critical Findings "
            f"({counts['Critical']}):</b>\n\n"
        )

        chunk     = crit_msg
        chunk_num = 1
        for i, f in enumerate(crit_findings, 1):
            title = f.get('title', 'N/A')
            tool  = f.get('tool',  'N/A')
            asset = f.get('asset', 'N/A')
            line  = (
                f"{i}. {title}\n"
                f"   Tool: {tool}\n"
                f"   Asset: {asset}\n\n"
            )
            if len(chunk) + len(line) > 3800:
                send_telegram(chunk)
                chunk     = f"🚨 <b>Critical (cont.):</b>\n\n"
                chunk_num += 1
            chunk += line

        if chunk.strip():
            send_telegram(chunk)

    # ── Message 3: High Findings ─────────────────────────────
    if high > 0:
        high_findings = [
            f for f in findings
            if f.get('severity') == 'High'
        ]

        high_msg = (
            f"⚠️ <b>High Findings "
            f"({counts['High']}):</b>\n\n"
        )

        chunk     = high_msg
        chunk_num = 1
        for i, f in enumerate(high_findings, 1):
            title = f.get('title', 'N/A')
            tool  = f.get('tool',  'N/A')
            asset = f.get('asset', 'N/A')
            line  = (
                f"{i}. {title}\n"
                f"   Tool: {tool}\n"
                f"   Asset: {asset}\n\n"
            )
            if len(chunk) + len(line) > 3800:
                send_telegram(chunk)
                chunk     = f"⚠️ <b>High (cont.):</b>\n\n"
                chunk_num += 1
            chunk += line

        if chunk.strip():
            send_telegram(chunk)

    # ── Message 4: Footer ────────────────────────────────────
    send_telegram(
        f"✅ <b>Scan Complete</b>\n\n"
        f"Open AutoRed to:\n"
        f"• View full findings details\n"
        f"• Generate PDF/DOCX report\n"
        f"• Get AI security summary\n"
        f"• Export JSON/CSV data"
    )

    return True


def notify_critical_finding(scan_name, target, finding):
    severity = finding.get('severity', '')
    if severity not in ('Critical', 'High'):
        return False

    emoji = "🚨" if severity == 'Critical' else "⚠️"
    now   = datetime.now().strftime('%d %B %Y %H:%M')

    message = (
        f"{emoji} <b>AutoRed — {severity} Finding</b>\n\n"
        f"📋 <b>Scan:</b> {scan_name}\n"
        f"🎯 <b>Target:</b> {target}\n"
        f"🕐 <b>Time:</b> {now}\n\n"
        f"🔎 <b>Finding:</b> "
        f"{finding.get('title', 'N/A')}\n"
        f"🛠 <b>Tool:</b> "
        f"{finding.get('tool', 'N/A')}\n"
        f"📍 <b>Asset:</b> "
        f"{finding.get('asset', 'N/A')}\n\n"
        f"📝 <b>Description:</b>\n"
        f"{str(finding.get('description', ''))[:300]}\n\n"
        f"✅ <b>Recommendation:</b>\n"
        f"{str(finding.get('recommendation', ''))[:300]}\n\n"
        f"🔍 Open AutoRed for full details."
    )

    return send_telegram(message)


if __name__ == '__main__':
    print("[*] Testing Telegram notification...")
    test_findings = [
        {
            'severity':       'Critical',
            'title':          'Bind Shell on Port 1524',
            'tool':           'Nmap',
            'asset':          '192.168.112.130:1524',
            'description':    'Metasploit bindshell detected.',
            'recommendation': 'Disable immediately.',
        },
        {
            'severity':       'Critical',
            'title':          'Telnet Service on Port 23',
            'tool':           'Nmap',
            'asset':          '192.168.112.130:23',
            'description':    'Cleartext remote access protocol.',
            'recommendation': 'Replace with SSH.',
        },
        {
            'severity':       'High',
            'title':          'vsftpd 2.3.4 Backdoor',
            'tool':           'Nmap',
            'asset':          '192.168.112.130:21',
            'description':    'Known backdoor vulnerability.',
            'recommendation': 'Update vsftpd immediately.',
        },
        {
            'severity':       'High',
            'title':          'MySQL Exposed on Port 3306',
            'tool':           'Nmap',
            'asset':          '192.168.112.130:3306',
            'description':    'Database exposed to network.',
            'recommendation': 'Restrict to localhost.',
        },
        {
            'severity':       'High',
            'title':          'VNC Service on Port 5900',
            'tool':           'Nmap',
            'asset':          '192.168.112.130:5900',
            'description':    'Remote desktop exposed.',
            'recommendation': 'Restrict access with firewall.',
        },
        {
            'severity':       'Medium',
            'title':          'Apache Version Disclosure',
            'tool':           'Nikto',
            'asset':          '192.168.112.130:80',
            'description':    'Server version exposed.',
            'recommendation': 'Hide server version.',
        },
    ]
    notify_scan_complete(
        'Test Scan — Metasploitable 2',
        '192.168.112.130',
        test_findings
    )
    print("[+] Test complete!")
