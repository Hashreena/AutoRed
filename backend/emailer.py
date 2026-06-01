import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

EMPLOYEES = [
    {
        'name':       'Siti Norziah',
        'department': 'Penetration Testing',
        'email':      'sitinorziah25@gmail.com',
    },
    {
        'name':       'Ahmad Fauzi',
        'department': 'IT Administration',
        'email':      'ahmad.fauzi@cybershield.com',
    },
    {
        'name':       'Nurul Ain',
        'department': 'Web Development',
        'email':      'nurul.ain@cybershield.com',
    },
    {
        'name':       'Hafiz Rahman',
        'department': 'Database Administration',
        'email':      'hafiz.rahman@cybershield.com',
    },
    {
        'name':       'Razif Azman',
        'department': 'Network Team',
        'email':      'razif.azman@cybershield.com',
    },
    {
        'name':       'Dr. Amirul Hadi',
        'department': 'Management / CISO',
        'email':      'amirul.hadi@cybershield.com',
    },
    {
        'name':       'Wei Xiang',
        'department': 'SOC / Blue Team',
        'email':      'wei.xiang@cybershield.com',
    },
    {
        'name':       'Priya Nair',
        'department': 'SOC / Blue Team',
        'email':      'priya.nair@cybershield.com',
    },
    {
        'name':       'Chong Wei Lim',
        'department': 'Web Development',
        'email':      'chong.wei@cybershield.com',
    },
    {
        'name':       'Kavitha Raj',
        'department': 'IT Administration',
        'email':      'kavitha.raj@cybershield.com',
    },
    {
        'name':       'Raj Kumar',
        'department': 'Network Team',
        'email':      'raj.kumar@cybershield.com',
    },
]

DEPARTMENTS = sorted(set(e['department'] for e in EMPLOYEES))


def load_smtp_config():
    config = {
        'email':    os.environ.get('SMTP_EMAIL', ''),
        'password': os.environ.get('SMTP_PASSWORD', ''),
        'host':     os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
        'port':     int(os.environ.get('SMTP_PORT', '587')),
    }

    if not config['email'] or not config['password']:
        env_path = os.path.join(
            os.path.dirname(__file__), '..', '.env'
        )
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('SMTP_EMAIL='):
                        config['email'] = line.split('=', 1)[1]
                    elif line.startswith('SMTP_PASSWORD='):
                        config['password'] = line.split('=', 1)[1]
                    elif line.startswith('SMTP_HOST='):
                        config['host'] = line.split('=', 1)[1]
                    elif line.startswith('SMTP_PORT='):
                        config['port'] = int(
                            line.split('=', 1)[1]
                        )
    return config


def get_employees_by_department(department):
    if department == 'All':
        return EMPLOYEES
    return [
        e for e in EMPLOYEES
        if e['department'] == department
    ]


def send_finding_email(
    finding, recipient_name, recipient_email,
    department, sender_notes='', scan_name='',
    target=''
):
    config = load_smtp_config()

    if not config['email'] or not config['password']:
        return False, "SMTP not configured in .env file."

    severity    = finding.get('severity', 'Unknown')
    title       = finding.get('title', 'N/A')
    tool        = finding.get('tool', 'N/A')
    asset       = finding.get('asset', 'N/A')
    description = finding.get('description', 'N/A')
    evidence    = finding.get('evidence', 'N/A')
    rec         = finding.get('recommendation', 'N/A')
    now         = datetime.now().strftime('%d %B %Y %H:%M')

    severity_colors = {
        'Critical': '#8b0000',
        'High':     '#e94560',
        'Medium':   '#ff8c00',
        'Low':      '#b49600',
        'Info':     '#4a9eff',
    }
    color = severity_colors.get(severity, '#555555')

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    body {{
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        margin: 0;
        padding: 0;
    }}
    .container {{
        max-width: 680px;
        margin: 30px auto;
        background: #ffffff;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }}
    .header {{
        background-color: #0d1117;
        padding: 24px 30px;
        text-align: center;
    }}
    .header h1 {{
        color: #e94560;
        margin: 0;
        font-size: 28px;
        letter-spacing: 3px;
    }}
    .header p {{
        color: #8b949e;
        margin: 6px 0 0;
        font-size: 13px;
    }}
    .severity-banner {{
        background-color: {color};
        color: white;
        text-align: center;
        padding: 10px;
        font-size: 16px;
        font-weight: bold;
        letter-spacing: 2px;
    }}
    .body {{
        padding: 30px;
    }}
    .greeting {{
        font-size: 15px;
        color: #333;
        margin-bottom: 20px;
        line-height: 1.6;
    }}
    .section-title {{
        color: #e94560;
        font-size: 12px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin: 20px 0 8px;
        border-bottom: 1px solid #eee;
        padding-bottom: 4px;
    }}
    .info-table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 16px;
    }}
    .info-table td {{
        padding: 8px 12px;
        font-size: 13px;
        border-bottom: 1px solid #f0f0f0;
    }}
    .info-table td:first-child {{
        color: #888;
        font-weight: bold;
        width: 150px;
    }}
    .info-table td:last-child {{
        color: #333;
    }}
    .content-box {{
        background: #f8f9fa;
        border-left: 3px solid {color};
        border-radius: 4px;
        padding: 12px 16px;
        font-size: 13px;
        color: #444;
        line-height: 1.6;
        margin-bottom: 16px;
    }}
    .notes-box {{
        background: #fff8e1;
        border-left: 3px solid #ff8c00;
        border-radius: 4px;
        padding: 12px 16px;
        font-size: 13px;
        color: #444;
        line-height: 1.6;
        margin-bottom: 16px;
    }}
    .action-box {{
        background: #e8f5e9;
        border-left: 3px solid #1d9e75;
        border-radius: 4px;
        padding: 12px 16px;
        font-size: 13px;
        color: #2e7d32;
        line-height: 1.6;
        margin-bottom: 16px;
    }}
    .footer {{
        background: #f8f9fa;
        padding: 16px 30px;
        text-align: center;
        font-size: 11px;
        color: #aaa;
        border-top: 1px solid #eee;
        line-height: 1.8;
    }}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>AutoRed</h1>
        <p>Security Finding — Analysis Request</p>
    </div>

    <div class="severity-banner">
        {severity.upper()} SEVERITY FINDING — ACTION REQUIRED
    </div>

    <div class="body">
        <p class="greeting">
            Dear <b>{recipient_name}</b>,<br><br>
            A <b>{severity}</b> severity security finding has been
            identified during a reconnaissance scan conducted by
            AutoRed and has been assigned to you for further
            manual analysis and verification. Please review the
            details below and take appropriate action within your
            department.
        </p>

        <div class="section-title">Finding Details</div>
        <table class="info-table">
            <tr>
                <td>Finding Title</td>
                <td><b>{title}</b></td>
            </tr>
            <tr>
                <td>Severity</td>
                <td style="color:{color}; font-weight:bold;">
                    {severity}
                </td>
            </tr>
            <tr>
                <td>Tool Detected</td>
                <td>{tool}</td>
            </tr>
            <tr>
                <td>Affected Asset</td>
                <td>{asset}</td>
            </tr>
            <tr>
                <td>Scan Name</td>
                <td>{scan_name}</td>
            </tr>
            <tr>
                <td>Target</td>
                <td>{target}</td>
            </tr>
            <tr>
                <td>Assigned To</td>
                <td>{recipient_name} — {department}</td>
            </tr>
            <tr>
                <td>Date Assigned</td>
                <td>{now}</td>
            </tr>
        </table>

        <div class="section-title">Description</div>
        <div class="content-box">{description}</div>

        <div class="section-title">Evidence</div>
        <div class="content-box">{evidence}</div>

        <div class="section-title">Recommendation</div>
        <div class="action-box">{rec}</div>

        {f'''
        <div class="section-title">Notes from Pentester</div>
        <div class="notes-box">{sender_notes}</div>
        ''' if sender_notes else ''}

        <div class="section-title">Required Action</div>
        <div class="action-box">
            Please review this finding and perform manual
            verification and confirmation. Update the AutoRed
            system with your analysis results and any additional
            notes for inclusion in the final security report.
            Escalate immediately if the finding is confirmed
            as exploitable.
        </div>

    </div>

    <div class="footer">
        This email was sent automatically by
        <b>AutoRed v1.0</b> — Reconnaissance Automation Platform
        <br>
        Asia Pacific University (APU) — FYP 2026
        <br>
        This is a confidential security communication.
        Do not forward without authorization.
    </div>

</div>
</body>
</html>
"""

    try:
        msg            = MIMEMultipart('alternative')
        msg['Subject'] = (
            f"[AutoRed] {severity} Finding — "
            f"{title[:50]} — Action Required"
        )
        msg['From']    = (
            f"AutoRed Security <{config['email']}>"
        )
        msg['To']      = recipient_email

        msg.attach(MIMEText(html, 'html'))

        server = smtplib.SMTP(config['host'], config['port'])
        server.starttls()
        server.login(config['email'], config['password'])
        server.sendmail(
            config['email'],
            recipient_email,
            msg.as_string()
        )
        server.quit()

        print(
            f"[+] Email sent to {recipient_name} "
            f"<{recipient_email}>"
        )
        return True, (
            f"Email sent to {recipient_name} successfully!"
        )

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed.\n"
            "Check your App Password in .env file."
        )
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


if __name__ == '__main__':
    print("[*] Testing email sending...")
    test_finding = {
        'severity':       'Critical',
        'title':          'Bind Shell on Port 1524',
        'tool':           'Nmap',
        'asset':          '192.168.112.130:1524',
        'description':    (
            'A bind shell was detected on port 1524. '
            'This indicates a Metasploit service that provides '
            'direct command execution access to attackers '
            'without authentication.'
        ),
        'evidence':       (
            'Port 1524 open — ingreslock service detected. '
            'Metasploit bindshell confirmed.'
        ),
        'recommendation': (
            'Disable this service immediately. '
            'Investigate how it was installed. '
            'Check for other backdoors on the system.'
        ),
    }
    success, message = send_finding_email(
        finding         = test_finding,
        recipient_name  = 'Siti Norziah',
        recipient_email = 'sitinorziah25@gmail.com',
        department      = 'SOC / Blue Team',
        sender_notes    = (
            'Please verify and escalate if confirmed. '
            'This may indicate a compromised system.'
        ),
        scan_name       = 'Test Scan — Metasploitable 2',
        target          = '192.168.112.130'
    )
    print(f"Result: {message}")
