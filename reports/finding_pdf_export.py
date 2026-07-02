import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import (
    getSampleStyleSheet, ParagraphStyle
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, PageBreak,
)
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from backend.db import get_connection

# ── Register serif font ───────────────────────────────
import os as _os

_FONT_PATHS = [
    '/usr/share/fonts/truetype/liberation/'
    'LiberationSerif-Regular.ttf',
    '/usr/share/fonts/truetype/freefont/'
    'FreeSerif.ttf',
    '/usr/share/fonts/truetype/dejavu/'
    'DejaVuSerif.ttf',
]
_FONT_BOLD_PATHS = [
    '/usr/share/fonts/truetype/liberation/'
    'LiberationSerif-Bold.ttf',
    '/usr/share/fonts/truetype/freefont/'
    'FreeSerifBold.ttf',
    '/usr/share/fonts/truetype/dejavu/'
    'DejaVuSerif-Bold.ttf',
]
_FONT_ITALIC_PATHS = [
    '/usr/share/fonts/truetype/liberation/'
    'LiberationSerif-Italic.ttf',
    '/usr/share/fonts/truetype/freefont/'
    'FreeSerifItalic.ttf',
    '/usr/share/fonts/truetype/dejavu/'
    'DejaVuSerif-Italic.ttf',
]

BODY_FONT   = 'Helvetica'
BODY_BOLD   = 'Helvetica-Bold'
BODY_ITALIC = 'Helvetica-Oblique'

for p in _FONT_PATHS:
    if _os.path.exists(p):
        try:
            pdfmetrics.registerFont(
                TTFont('TimesNR', p)
            )
            BODY_FONT = 'TimesNR'
            break
        except Exception:
            pass

for p in _FONT_BOLD_PATHS:
    if _os.path.exists(p):
        try:
            pdfmetrics.registerFont(
                TTFont('TimesNR-Bold', p)
            )
            BODY_BOLD = 'TimesNR-Bold'
            break
        except Exception:
            pass

for p in _FONT_ITALIC_PATHS:
    if _os.path.exists(p):
        try:
            pdfmetrics.registerFont(
                TTFont('TimesNR-Italic', p)
            )
            BODY_ITALIC = 'TimesNR-Italic'
            break
        except Exception:
            pass

# ── Colors ────────────────────────────────────────────
C_NAVY   = colors.HexColor('#1a2744')
C_RED    = colors.HexColor('#c0392b')
C_DARK   = colors.HexColor('#7b241c')
C_ORANGE = colors.HexColor('#d35400')
C_YELLOW = colors.HexColor('#b7950b')
C_BLUE   = colors.HexColor('#1a5276')
C_TEAL   = colors.HexColor('#0e6655')
C_GREY   = colors.HexColor('#717d7e')
C_LIGHT  = colors.HexColor('#f2f3f4')
C_WHITE  = colors.white
C_BLACK  = colors.HexColor('#1c2833')
C_BORDER = colors.HexColor('#d5d8dc')
C_HBDR   = colors.HexColor('#2c3e50')

SEV_COLORS = {
    'Critical': C_DARK,
    'High':     C_RED,
    'Medium':   C_ORANGE,
    'Low':      C_YELLOW,
    'Info':     C_BLUE,
}

SEV_ORDER = [
    'Critical', 'High', 'Medium', 'Low', 'Info'
]

# ── Page margins ──────────────────────────────────────
LEFT_M  = 2*cm
RIGHT_M = 2*cm
TOP_M   = 2*cm
BOT_M   = 2*cm
# Usable width = A4 width - left - right
# A4 = 21cm, usable = 17cm
COL1 = 5*cm
COL2 = 12*cm


def get_styles():
    S = getSampleStyleSheet()

    cover_title = ParagraphStyle(
        'CoverTitle',
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=C_NAVY,
        spaceAfter=4,
        leading=28,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    cover_sub = ParagraphStyle(
        'CoverSub',
        fontName=BODY_FONT,
        fontSize=12,
        textColor=C_GREY,
        spaceAfter=4,
        leading=16,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    h1 = ParagraphStyle(
        'H1',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=C_NAVY,
        spaceBefore=14,
        spaceAfter=2,
        leading=18,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    h2 = ParagraphStyle(
        'H2',
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=C_TEAL,
        spaceBefore=10,
        spaceAfter=2,
        leading=16,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    body = ParagraphStyle(
        'Body',
        fontName=BODY_FONT,
        fontSize=11,
        textColor=C_BLACK,
        spaceAfter=6,
        leading=17,
        leftIndent=0,
        rightIndent=0,
        alignment=4,
    )
    explain = ParagraphStyle(
        'Explain',
        fontName=BODY_ITALIC,
        fontSize=10,
        textColor=C_GREY,
        spaceAfter=6,
        leading=18,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    bullet = ParagraphStyle(
        'Bullet',
        fontName=BODY_FONT,
        fontSize=11,
        textColor=C_BLACK,
        spaceAfter=4,
        leading=16,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    code = ParagraphStyle(
        'Code',
        fontName='Courier',
        fontSize=9,
        textColor=C_BLUE,
        backColor=colors.HexColor('#eaf2ff'),
        spaceAfter=6,
        leading=14,
        leftIndent=0,
        rightIndent=0,
        alignment=0,
    )
    footer = ParagraphStyle(
        'Footer',
        fontName=BODY_FONT,
        fontSize=8,
        textColor=C_GREY,
        leftIndent=0,
        rightIndent=0,
        alignment=1,
    )

    return {
        'cover_title': cover_title,
        'cover_sub':   cover_sub,
        'h1':          h1,
        'h2':          h2,
        'body':        body,
        'explain':     explain,
        'bullet':      bullet,
        'code':        code,
        'footer':      footer,
        'normal':      S['Normal'],
    }


def make_table(data, col_widths=None,
               header_bg=None, zebra=True):
    if not col_widths:
        col_widths = [COL1, COL2]

    tbl   = Table(
        data,
        colWidths=col_widths,
        repeatRows=1,
        hAlign='LEFT',
    )
    style = [
        ('FONTNAME',  (0,0), (-1,-1), BODY_FONT),
        ('FONTSIZE',  (0,0), (-1,-1), 10),
        ('PADDING',   (0,0), (-1,-1), 7),
        ('GRID',      (0,0), (-1,-1), 0.4, C_BORDER),
        ('VALIGN',    (0,0), (-1,-1), 'MIDDLE'),
        ('TEXTCOLOR', (0,0), (-1,-1), C_BLACK),
        ('ALIGN',     (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME',  (0,1), (0,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0,1), (0,-1), C_HBDR),
    ]

    if header_bg:
        style += [
            ('BACKGROUND',
             (0,0), (-1,0), header_bg),
            ('TEXTCOLOR',
             (0,0), (-1,0), C_WHITE),
            ('FONTNAME',
             (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',
             (0,0), (-1,0), 10),
        ]

    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append((
                    'BACKGROUND',
                    (0,i), (-1,i),
                    C_LIGHT
                ))

    tbl.setStyle(TableStyle(style))
    return tbl


def hr(color=None, thickness=0.5):
    return HRFlowable(
        width='100%',
        thickness=thickness,
        color=color or C_BORDER,
        spaceAfter=6,
        spaceBefore=2,
    )


def severity_hex(severity):
    mapping = {
        'Critical': '7b241c',
        'High':     'c0392b',
        'Medium':   'd35400',
        'Low':      'b7950b',
        'Info':     '1a5276',
    }
    return mapping.get(severity, '717d7e')


def build_business_impact(severity, title, desc):
    t = title.lower()

    if 'telnet' in t:
        return (
            "Telnet transmits all data including "
            "usernames, passwords, and session commands "
            "in plaintext across the network. Any "
            "attacker with the ability to intercept "
            "network traffic through ARP spoofing, "
            "man-in-the-middle attacks, or passive "
            "packet sniffing can capture valid "
            "credentials in real time. Successful "
            "exploitation leads to unauthorised system "
            "access, privilege escalation, and lateral "
            "movement across the internal network."
        )
    if 'ftp' in t and 'weak' in t:
        return (
            "Weak or default FTP credentials allow "
            "unauthenticated attackers to gain access "
            "to the FTP file system. This may expose "
            "web application source code, database "
            "configuration files, and user data. "
            "Attackers may upload malicious files "
            "leading to remote code execution and "
            "full server compromise."
        )
    if 'ftp' in t:
        return (
            "FTP transmits files and authentication "
            "credentials without any encryption. "
            "Attackers on the same network segment "
            "can passively intercept login credentials "
            "and all transferred file contents. This "
            "may result in unauthorised file access, "
            "data exfiltration, and credential theft."
        )
    if 'sql' in t:
        return (
            "SQL Injection enables attackers to "
            "manipulate backend database queries by "
            "injecting malicious SQL syntax through "
            "unsanitised user input fields. This may "
            "lead to unauthorised data access, "
            "modification or deletion of records, "
            "full authentication bypass, and in "
            "severe cases remote code execution "
            "through database stored procedures."
        )
    if 'xss' in t:
        return (
            "Cross-Site Scripting enables attackers "
            "to inject and execute malicious JavaScript "
            "in the browsers of other users. This "
            "results in session token theft, credential "
            "harvesting, malicious redirects, and "
            "defacement. Attackers can impersonate "
            "legitimate users and perform unauthorised "
            "actions on their behalf."
        )
    if 'header' in t or 'missing' in t:
        return (
            "Missing HTTP security headers leave the "
            "web application exposed to common "
            "browser-based attacks including "
            "clickjacking, MIME-type sniffing, and "
            "cross-site scripting. These headers form "
            "a baseline security control required by "
            "modern security standards such as "
            "OWASP and PCI-DSS."
        )
    if 'phpinfo' in t:
        return (
            "The phpinfo() output page exposes "
            "detailed server configuration data "
            "including PHP version, installed "
            "extensions, server file paths, environment "
            "variables, and compilation options. "
            "Attackers use this information to "
            "fingerprint the environment and craft "
            "targeted exploits against specific "
            "software versions."
        )
    if 'phpmyadmin' in t:
        return (
            "An exposed phpMyAdmin panel provides a "
            "web interface to manage all MySQL "
            "databases. Attackers can attempt brute "
            "force authentication, exploit known "
            "phpMyAdmin vulnerabilities, and if "
            "successful, gain full control over all "
            "databases including user credentials "
            "and sensitive application data."
        )
    if 'vnc' in t:
        return (
            "VNC with default or weak credentials "
            "allows attackers to gain full interactive "
            "graphical desktop control of the system. "
            "This enables keylogging, screen capture, "
            "file theft, installation of backdoors, "
            "and complete persistent system takeover."
        )
    if 'bind shell' in t or 'backdoor' in t:
        return (
            "A bind shell or backdoor service provides "
            "unauthenticated remote command execution "
            "access. This critical finding indicates "
            "the system may already be compromised. "
            "Attackers can execute arbitrary commands, "
            "install persistent malware, exfiltrate "
            "sensitive data, and use the host as a "
            "pivot point for further network attacks."
        )
    if 'directory' in t and 'index' in t:
        return (
            "Directory indexing exposes the full "
            "contents of web server directories to "
            "unauthenticated visitors. Attackers can "
            "enumerate and download backup files, "
            "configuration files, and sensitive data "
            "that was not intended to be publicly "
            "accessible."
        )
    if severity == 'Critical':
        return (
            "This critical severity finding represents "
            "an immediately exploitable vulnerability "
            "with severe potential impact. No special "
            "conditions or prior access are required. "
            "Successful attacks could result in "
            "complete system compromise, data breach, "
            "or service disruption. Immediate "
            "remediation is required."
        )
    if severity == 'High':
        return (
            "This high severity finding presents "
            "significant organisational risk. "
            "Exploitation is likely feasible and "
            "could lead to unauthorised access to "
            "sensitive data, system compromise, or "
            "disruption of critical services. "
            "Remediation should be prioritised urgently."
        )
    if severity == 'Medium':
        return (
            "This medium severity finding presents "
            "moderate risk. While not immediately "
            "critical, exploitation may assist "
            "attackers in achieving a broader attack "
            "objective. Remediation should be planned "
            "within a defined timeframe."
        )
    return (
        "This finding presents a potential security "
        "risk to the target environment. Review the "
        "technical description and apply the "
        "recommended remediation steps."
    )


def build_attack_steps(title, asset, level, tool):
    t = title.lower()

    if 'telnet' in t:
        return [
            "Attacker performs network scan and "
            "identifies port 23/TCP open on " + asset,
            "Attacker connects: telnet " + asset,
            "Login credentials submitted — all data "
            "transmitted in cleartext over the wire",
            "Attacker uses Wireshark or tcpdump "
            "to capture credentials in transit",
            "Captured credentials used to establish "
            "an authenticated system shell session",
            "Attacker escalates privileges and begins "
            "lateral movement across the network",
        ]
    if 'ftp' in t and 'weak' in t:
        return [
            "Attacker identifies FTP service "
            "running on " + asset + " port 21",
            "Credential brute force performed "
            "using Hydra or Medusa",
            "Weak credentials accepted — attacker "
            "authenticates to the FTP server",
            "File system enumerated for web root, "
            "configuration files, and sensitive data",
            "Malicious PHP shell uploaded to "
            "web root for remote code execution",
        ]
    if 'ftp' in t:
        return [
            "Attacker discovers FTP service "
            "on " + asset + " port 21",
            "Anonymous login attempted: "
            "ftp " + asset,
            "Anonymous access granted — full "
            "file listing obtained",
            "FTP session intercepted to capture "
            "credentials transmitted in plaintext",
            "Sensitive files downloaded from "
            "the server file system",
        ]
    if 'sql' in t:
        return [
            "Attacker identifies user-controlled "
            "input fields in the web application",
            "SQL injection payload submitted: "
            "' OR 1=1 --",
            "Application returns unexpected data "
            "confirming the injection point",
            "Automated tool (sqlmap) used to "
            "enumerate the database schema",
            "Sensitive data including credentials "
            "extracted from the database",
        ]
    if 'xss' in t:
        return [
            "Attacker identifies input fields "
            "reflected in the HTTP response",
            "Malicious XSS payload crafted "
            "and submitted as input",
            "Payload executes in the victim's "
            "browser upon page load",
            "Session cookies exfiltrated using "
            "document.cookie",
            "Attacker hijacks victim session "
            "and impersonates the user",
        ]
    if 'vnc' in t:
        return [
            "Attacker discovers VNC service "
            "on " + asset + " port 5900",
            "Default credentials attempted: "
            "password / admin / root",
            "VNC session established with full "
            "graphical desktop access",
            "Keylogger deployed to capture "
            "additional credentials",
            "Backdoor installed for persistent "
            "remote access to the system",
        ]
    if 'bind shell' in t or 'backdoor' in t:
        return [
            "Attacker scans and identifies "
            "suspicious open port on " + asset,
            "Netcat connection attempted: "
            "nc " + asset + " <port>",
            "Direct shell access obtained "
            "without any authentication",
            "Attacker confirms root or admin "
            "level access via id / whoami",
            "Persistence established and "
            "lateral movement initiated",
        ]
    if 'phpmyadmin' in t:
        return [
            "Attacker discovers phpMyAdmin at "
            "http://" + asset + "/phpMyAdmin",
            "Default credentials attempted: "
            "root with blank password",
            "Authentication succeeds — full "
            "database management access granted",
            "All databases, tables, and records "
            "enumerated and accessible",
            "Credentials extracted and used "
            "for further exploitation",
        ]
    if 'directory' in t:
        return [
            "Attacker identifies directory listing "
            "at http://" + asset,
            "File listing displayed in browser — "
            "no authentication required",
            "Sensitive files identified including "
            "backups, configs, and source code",
            "Files downloaded and analysed for "
            "credentials and vulnerabilities",
        ]

    return [
        "Attacker discovers " + title +
        " on " + asset + " via " + tool,
        "Vulnerability confirmed through active "
        "enumeration and testing",
        "Exploit applied based on known "
        "CVE or CWE classification",
        "Unauthorised access or sensitive data "
        "exposure achieved",
        "Access leveraged for lateral movement "
        "or data exfiltration",
    ]


def build_immediate_actions(title, tool, asset):
    t = title.lower()

    if 'telnet' in t:
        return [
            "Disable the Telnet service on "
            + asset + " immediately",
            "Block TCP port 23 at both the network "
            "and host-based firewall",
            "Deploy SSH as the replacement protocol "
            "for all remote access",
            "Enforce public key authentication and "
            "disable password-based SSH login",
            "Review system logs for historical "
            "unauthorised Telnet connections",
        ]
    if 'ftp' in t:
        return [
            "Disable FTP anonymous access "
            "on " + asset + " immediately",
            "Replace FTP with SFTP or FTPS for "
            "all file transfer operations",
            "Block TCP port 21 at the perimeter "
            "firewall",
            "Enforce a strong password policy for "
            "all remaining FTP accounts",
            "Audit FTP access logs for signs of "
            "unauthorised activity",
        ]
    if 'sql' in t:
        return [
            "Replace all dynamic string-concatenated "
            "queries with parameterised statements",
            "Implement strict server-side input "
            "validation on all parameters",
            "Apply principle of least privilege "
            "to the database service account",
            "Deploy a Web Application Firewall with "
            "SQL injection detection rules",
            "Perform a full code review to identify "
            "all injection entry points",
        ]
    if 'xss' in t:
        return [
            "Implement context-aware output encoding "
            "for all user-controlled data",
            "Add Content-Security-Policy header to "
            "restrict allowed script sources",
            "Set HTTPOnly and Secure flags on "
            "all session cookies",
            "Sanitise all user input on both "
            "client and server side",
        ]
    if 'header' in t or 'missing' in t:
        return [
            "Add X-Frame-Options: SAMEORIGIN to "
            "prevent clickjacking attacks",
            "Add X-Content-Type-Options: nosniff to "
            "prevent MIME type sniffing",
            "Add Content-Security-Policy header "
            "with appropriate directives",
            "Add Strict-Transport-Security header "
            "to enforce HTTPS connections",
            "Restart the web server after applying "
            "all header changes",
        ]
    if 'phpinfo' in t:
        return [
            "Delete phpinfo.php and all test scripts "
            "from the web root immediately",
            "Search for other exposed test files: "
            "find /var/www -name '*.php' -mtime -30",
            "Set expose_php = Off in php.ini to "
            "suppress version information",
            "Restart Apache or Nginx after applying "
            "configuration changes",
        ]
    if 'vnc' in t:
        return [
            "Change VNC password to a strong "
            "unique value immediately",
            "Bind VNC listener to localhost only: "
            "127.0.0.1:5900",
            "Access VNC exclusively through "
            "an SSH tunnel",
            "Enable VNC session authentication and "
            "disable unauthenticated access",
        ]
    if 'phpmyadmin' in t:
        return [
            "Restrict phpMyAdmin access by IP "
            "address in the web server config",
            "Rename the phpMyAdmin URL from the "
            "default path to a random value",
            "Enable HTTP Basic Authentication as "
            "an additional access control layer",
            "Update phpMyAdmin to the latest "
            "stable version immediately",
        ]

    return [
        "Patch or disable the affected service "
        "on " + asset + " immediately",
        "Apply all available vendor security "
        "patches and software updates",
        "Restrict network-level access using "
        "firewall rules",
        "Monitor system and application logs for "
        "signs of active exploitation",
        "Re-scan the target after remediation to "
        "confirm the vulnerability is resolved",
    ]


def build_validation_steps(title, asset, tool):
    t = title.lower()

    if 'telnet' in t:
        return (
            "# Step 1: Stop and disable Telnet\n"
            "sudo systemctl stop telnet.socket\n"
            "sudo systemctl disable telnet.socket\n\n"
            "# Step 2: Block at firewall\n"
            "sudo ufw deny 23/tcp\n\n"
            "# Step 3: Verify port is closed\n"
            "nmap -p23 " + asset + "\n\n"
            "# Expected output:\n"
            "23/tcp  closed  telnet\n\n"
            "# Step 4: Confirm SSH is available\n"
            "nmap -p22 " + asset
        )
    if 'ftp' in t:
        return (
            "# Step 1: Stop FTP service\n"
            "sudo systemctl stop vsftpd\n"
            "sudo systemctl disable vsftpd\n\n"
            "# Step 2: Verify port is closed\n"
            "nmap -p21 " + asset + "\n\n"
            "# Expected output:\n"
            "21/tcp  closed  ftp\n\n"
            "# Step 3: Test anonymous login\n"
            "ftp " + asset + "\n"
            "Name: anonymous\n"
            "# Expected: Login rejected"
        )
    if 'header' in t or 'missing' in t:
        return (
            "# Step 1: Check response headers\n"
            "curl -I http://" + asset + "\n\n"
            "# Expected headers present:\n"
            "X-Frame-Options: SAMEORIGIN\n"
            "X-Content-Type-Options: nosniff\n"
            "Content-Security-Policy: "
            "default-src 'self'\n"
            "Strict-Transport-Security: "
            "max-age=31536000\n\n"
            "# Step 2: Online validation\n"
            "# Visit: https://securityheaders.com"
        )
    if 'phpinfo' in t:
        return (
            "# Step 1: Remove phpinfo.php\n"
            "sudo rm /var/www/html/phpinfo.php\n\n"
            "# Step 2: Confirm removal\n"
            "curl -o /dev/null -s -w '%{http_code}' "
            "http://" + asset + "/phpinfo.php\n\n"
            "# Expected response code: 404\n\n"
            "# Step 3: Disable PHP exposure\n"
            "# Edit /etc/php/php.ini\n"
            "# Set: expose_php = Off\n"
            "sudo service apache2 restart"
        )
    if 'vnc' in t:
        return (
            "# Step 1: Verify VNC is restricted\n"
            "nmap -p5900 " + asset + "\n\n"
            "# Expected output:\n"
            "5900/tcp  filtered  vnc\n\n"
            "# Step 2: Test direct connection\n"
            "vncviewer " + asset + ":5900\n"
            "# Expected: Connection refused or "
            "strong authentication required"
        )

    return (
        "# Step 1: Re-scan the target\n"
        "nmap -sV -p- " + asset + "\n\n"
        "# Step 2: Run a full AutoRed scan\n"
        "# New Scan -> same target -> all tools\n\n"
        "# Step 3: Use AutoRed Scan Diff\n"
        "# Open Existing Scan -> Compare Scans\n"
        "# Select before and after scans\n\n"
        "# Step 4: Confirm finding resolved\n"
        "# Finding should not appear in new scan"
    )


def generate_finding_pdf(scan_id, finding,
                          enrich_cache=None,
                          output_path=None):
    # ── Load scan data ────────────────────────────
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM scans WHERE id=?', (scan_id,)
    )
    scan = cursor.fetchone()
    conn.close()

    # ── Output path ───────────────────────────────
    finding_id = finding.get('id', 'unknown')
    if not output_path:
        output_path = (
            "storage/" + str(scan_id) +
            "/report/finding_" +
            str(finding_id) + ".pdf"
        )
    os.makedirs(
        os.path.dirname(output_path), exist_ok=True
    )

    # ── Enrichment data ───────────────────────────
    cached = {}
    if enrich_cache:
        cached = enrich_cache.get(finding_id, {})

    nvd      = cached.get('nvd_best') or {}
    cwe_data = cached.get('cwe_data') or {}
    mitre    = cached.get('mitre') or {}
    level    = cached.get('exploit_level', 'Unknown')
    tags     = cached.get('attack_surface', [])
    attack   = cached.get('attack_path', '')
    verify   = cached.get('verify_steps', '')

    cve_id   = nvd.get('cve_id', 'N/A')
    if 'No CVE' in str(cve_id):
        cve_id = 'N/A'
    cvss     = str(nvd.get('cvss_score', 'N/A'))
    version  = nvd.get('cvss_version', '')
    vector   = nvd.get('cvss_vector', 'N/A')
    av       = nvd.get('attack_vector', 'N/A')
    ac       = nvd.get('attack_complexity', 'N/A')
    pr       = nvd.get('privileges_req', 'N/A')
    ui_val   = nvd.get('user_interaction', 'N/A')
    pub      = nvd.get('published', 'N/A')
    nvd_url  = nvd.get('nvd_url', '')
    nvd_desc = nvd.get('description', '')[:400]
    sev_nvd  = nvd.get('cvss_severity', '')

    cwe_id   = cwe_data.get('cwe_id', 'N/A')
    cwe_name = cwe_data.get('name', 'N/A')
    cwe_risk = cwe_data.get('risk', 'N/A')
    cwe_url  = cwe_data.get('url', '')

    tactic    = mitre.get('tactic', 'N/A')
    tactic_id = mitre.get('tactic_id', '')
    tech      = mitre.get('technique', 'N/A')
    tech_id   = mitre.get('tech_id', '')
    mitre_str = (
        tech + " (" + tech_id + ")"
        if tech_id else tech
    )
    mitre_url = mitre.get('url', '')

    severity = finding.get('severity', 'Info')
    title    = finding.get('title', 'Untitled')
    asset    = finding.get('asset', 'N/A')
    tool     = finding.get('tool', 'N/A')
    category = finding.get('category', 'N/A')
    status   = finding.get('status', 'New')
    desc     = finding.get(
        'description', 'N/A'
    ) or 'N/A'
    evidence = finding.get(
        'evidence', 'N/A'
    ) or 'N/A'
    rec      = finding.get(
        'recommendation', 'N/A'
    ) or 'N/A'
    notes    = finding.get(
        'analyst_notes', ''
    ) or ''

    target    = scan['target'] if scan else 'Unknown'
    scan_date = str(
        scan['created_at'] if scan else ''
    )[:10]
    profile   = scan['profile'] if scan else 'N/A'

    year        = datetime.datetime.now().year
    find_num    = str(finding_id).zfill(3)
    finding_ref = "AR-" + str(year) + "-" + find_num

    # ── Document setup ────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=RIGHT_M,
        leftMargin=LEFT_M,
        topMargin=TOP_M,
        bottomMargin=BOT_M,
    )

    S     = get_styles()
    story = []

    # ═══════════════════════════════════════════════
    # PAGE 1 — COVER
    # ═══════════════════════════════════════════════
    story.append(Spacer(1, 1*cm))

    story.append(Paragraph(
        "AutoRed Security Assessment",
        S['cover_title']
    ))
    story.append(Paragraph(
        "Individual Finding Report",
        S['cover_sub']
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(hr(C_NAVY, thickness=1.5))
    story.append(Spacer(1, 0.4*cm))

    sev_hex = severity_hex(severity)
    story.append(Paragraph(
        '<font color="#' + sev_hex + '">'
        '<b>[ ' + severity.upper() + ' ]</b></font>',
        ParagraphStyle(
            'SevLabel',
            fontName='Helvetica-Bold',
            fontSize=13,
            spaceAfter=4,
            leftIndent=0,
        )
    ))
    story.append(Paragraph(
        title,
        ParagraphStyle(
            'FindTitle',
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=C_BLACK,
            spaceAfter=14,
            leading=22,
            leftIndent=0,
            rightIndent=0,
        )
    ))

    story.append(Paragraph(
        "Finding Information", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "The table below provides the key identifiers "
        "for this finding. The Finding ID serves as "
        "a unique reference throughout this report "
        "and in remediation tracking.",
        S['explain']
    ))
    story.append(Spacer(1, 4))
    story.append(make_table(
        [
            ['Field',        'Value'],
            ['Finding ID',   finding_ref],
            ['Target',       target],
            ['Asset',        asset],
            ['Scan Date',    scan_date],
            ['Scan Profile', profile],
            ['Tool',         tool],
            ['Category',     category],
            ['Status',       status],
        ],
        col_widths=[COL1, COL2],
        header_bg=C_NAVY,
    ))
    story.append(Spacer(1, 14))

    story.append(Paragraph(
        "Severity Rating", S['h1']
    ))
    story.append(hr())
    sev_explanations = {
        'Critical': (
            "A CRITICAL severity rating indicates an "
            "immediately exploitable vulnerability with "
            "severe and direct impact on "
            "confidentiality, integrity, or "
            "availability. No special conditions or "
            "prior access are required. Immediate "
            "remediation action is mandatory."
        ),
        'High': (
            "A HIGH severity rating indicates a serious "
            "vulnerability that is likely exploitable "
            "and could lead to significant system "
            "compromise or data exposure. Remediation "
            "should be prioritised as a matter of "
            "urgency."
        ),
        'Medium': (
            "A MEDIUM severity rating indicates a "
            "vulnerability requiring specific conditions "
            "to exploit or with limited standalone "
            "impact. Remediation should be planned and "
            "executed within a defined risk management "
            "timeframe."
        ),
        'Low': (
            "A LOW severity rating indicates a minor "
            "vulnerability or information disclosure "
            "with limited direct impact. This should be "
            "addressed as part of routine security "
            "maintenance activities."
        ),
        'Info': (
            "An INFORMATIONAL finding does not represent "
            "a directly exploitable vulnerability but "
            "provides useful context about the target "
            "environment. Review and address as "
            "appropriate to the organisational risk "
            "appetite."
        ),
    }
    story.append(Paragraph(
        sev_explanations.get(severity, ''),
        S['body']
    ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════
    # PAGE 2 — RISK OVERVIEW & FINDING DETAILS
    # ═══════════════════════════════════════════════
    story.append(Paragraph(
        "Risk Overview", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "The following table summarises the risk "
        "attributes for this finding including the "
        "CVSS score, CVE reference, CWE weakness "
        "classification, and MITRE ATT&CK technique "
        "mapping. All data is sourced from the "
        "National Vulnerability Database (NVD) "
        "and MITRE frameworks.",
        S['explain']
    ))
    story.append(Spacer(1, 4))
    story.append(make_table(
        [
            ['Field',        'Value'],
            ['Severity',     severity],
            ['CVSS Score',
             cvss + (' (v' + version + ')'
                     if version else '')],
            ['NVD Severity', sev_nvd or 'N/A'],
            ['CVSS Vector',  vector],
            ['CVE',          cve_id],
            ['CWE',
             cwe_id + ' — ' + cwe_name],
            ['MITRE ATT&CK', mitre_str],
            ['Published',    pub],
            ['Asset',        asset],
            ['Status',       status],
        ],
        col_widths=[COL1, COL2],
        header_bg=C_NAVY,
    ))
    story.append(Spacer(1, 14))

    story.append(Paragraph(
        "Business Impact", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "This section describes the real-world "
        "consequences of this vulnerability being "
        "successfully exploited. Impact is assessed "
        "in terms of confidentiality, integrity, "
        "and availability of data and systems.",
        S['explain']
    ))
    story.append(Paragraph(
        build_business_impact(
            severity, title, desc
        ),
        S['body']
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Technical Description", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "The technical description explains the "
        "nature of the vulnerability, how it was "
        "identified during the assessment, and the "
        "technical conditions that allow exploitation.",
        S['explain']
    ))
    story.append(Paragraph(desc, S['body']))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Evidence", S['h1']))
    story.append(hr())
    story.append(Paragraph(
        "The following output was collected during "
        "automated reconnaissance and confirms "
        "the presence of this vulnerability.",
        S['explain']
    ))
    story.append(Paragraph(
        evidence.replace('\n', '<br/>'),
        S['code']
    ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════
    # PAGE 3 — THREAT INTELLIGENCE
    # ═══════════════════════════════════════════════
    story.append(Paragraph(
        "Threat Intelligence", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "Threat intelligence data is retrieved from "
        "the National Vulnerability Database (NVD) "
        "API, MITRE CWE, and the MITRE ATT&CK "
        "framework. This provides industry-standard "
        "context for understanding, prioritising, "
        "and communicating the finding.",
        S['explain']
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "CVE and CVSS Details", S['h2']
    ))
    story.append(Paragraph(
        "The Common Vulnerabilities and Exposures "
        "(CVE) system provides a standardised "
        "identifier for known vulnerabilities. The "
        "CVSS score quantifies severity on a scale "
        "of 0.0 to 10.0, where 10.0 is most severe.",
        S['explain']
    ))
    story.append(make_table(
        [
            ['Field',               'Value'],
            ['CVE Identifier',      cve_id],
            ['CVSS Score',          cvss],
            ['CVSS Version',
             version or 'N/A'],
            ['Attack Vector',       av],
            ['Attack Complexity',   ac],
            ['Privileges Required', pr],
            ['User Interaction',    ui_val],
            ['Published Date',      pub],
            ['NVD Reference',
             nvd_url if nvd_url else 'N/A'],
        ],
        col_widths=[COL1, COL2],
        header_bg=colors.HexColor('#2c3e50'),
    ))

    if nvd_desc:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "NVD Description", S['h2']
        ))
        story.append(Paragraph(nvd_desc, S['body']))

    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "CWE Weakness Classification", S['h2']
    ))
    story.append(Paragraph(
        "The Common Weakness Enumeration (CWE) "
        "identifies the underlying software weakness "
        "class. Understanding the root weakness "
        "guides long-term remediation strategy and "
        "helps prevent recurrence of similar issues.",
        S['explain']
    ))
    story.append(make_table(
        [
            ['Field',      'Value'],
            ['CWE ID',     cwe_id],
            ['Name',       cwe_name],
            ['Risk Basis', cwe_risk],
            ['Reference',
             cwe_url if cwe_url else 'N/A'],
        ],
        col_widths=[COL1, COL2],
        header_bg=colors.HexColor('#6e2f1a'),
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "MITRE ATT&CK Mapping", S['h2']
    ))
    story.append(Paragraph(
        "MITRE ATT&CK is a globally recognised "
        "adversary behaviour framework. The mapping "
        "below shows how this vulnerability aligns "
        "with documented attacker tactics and "
        "techniques used in real-world intrusions.",
        S['explain']
    ))
    story.append(make_table(
        [
            ['Field',     'Value'],
            ['Tactic',
             tactic + (' (' + tactic_id + ')'
                       if tactic_id else '')],
            ['Technique', mitre_str],
            ['Reference',
             mitre_url if mitre_url else 'N/A'],
        ],
        col_widths=[COL1, COL2],
        header_bg=colors.HexColor('#1a4a6b'),
    ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════
    # PAGE 4 — ATTACK SCENARIO & EXPLOITABILITY
    # ═══════════════════════════════════════════════
    story.append(Paragraph(
        "Attack Scenario", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "The following attack scenario describes a "
        "realistic sequence of steps an adversary "
        "would follow to exploit this vulnerability. "
        "This is based on known exploitation "
        "techniques aligned to the identified "
        "CVE and CWE classification.",
        S['explain']
    ))
    story.append(Spacer(1, 6))

    for i, step in enumerate(
        build_attack_steps(title, asset, level, tool),
        1
    ):
        story.append(Paragraph(
            "Step " + str(i) + ":  " + step,
            S['bullet']
        ))
    story.append(Spacer(1, 10))

    if attack:
        story.append(Paragraph(
            "AI-Generated Attack Path", S['h2']
        ))
        story.append(Paragraph(
            "The following attack path analysis was "
            "generated by Claude AI using the finding "
            "details and enrichment data as context.",
            S['explain']
        ))
        story.append(Paragraph(attack, S['body']))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Exploitability Assessment", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "Exploitability measures the ease with which "
        "an attacker can leverage this vulnerability. "
        "Factors include network accessibility, "
        "authentication requirements, and the "
        "availability of public exploit code.",
        S['explain']
    ))
    story.append(Spacer(1, 4))
    pub_exploit = (
        'Yes'      if level == 'Easy'     else
        'Possibly' if level == 'Moderate' else
        'Unknown'
    )
    story.append(make_table(
        [
            ['Factor',                   'Assessment'],
            ['Remotely Exploitable',     'Yes'],
            ['Authentication Required',  'Maybe'],
            ['Public Exploit Available', pub_exploit],
            ['Exploit Complexity',
             level or 'Unknown'],
            ['Overall Exploitability',
             level or 'Unknown'],
        ],
        col_widths=[8*cm, 9*cm],
        header_bg=C_TEAL,
    ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════
    # PAGE 5 — REMEDIATION & VALIDATION
    # ═══════════════════════════════════════════════
    story.append(Paragraph(
        "Remediation", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "Remediation guidance is provided in two "
        "categories. Immediate actions should be "
        "taken without delay to reduce risk exposure. "
        "Long-term recommendations address the "
        "underlying weakness and support sustained "
        "security improvement.",
        S['explain']
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "Immediate Actions", S['h2']
    ))
    for action in build_immediate_actions(
        title, tool, asset
    ):
        story.append(Paragraph(
            "\u2022  " + action, S['bullet']
        ))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Long-Term Recommendations", S['h2']
    ))
    story.append(Paragraph(
        "The following recommendation was derived "
        "from the finding details and enrichment "
        "data collected during this assessment:",
        S['explain']
    ))
    story.append(Paragraph(rec, S['body']))
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "Validation Steps", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "After applying remediation steps, use the "
        "following commands to verify the "
        "vulnerability has been successfully resolved.",
        S['explain']
    ))
    story.append(Paragraph(
        build_validation_steps(
            title, asset, tool
        ).replace('\n', '<br/>'),
        S['code']
    ))
    story.append(Spacer(1, 10))

    if verify:
        story.append(Paragraph(
            "AI-Generated Verification Guide", S['h2']
        ))
        story.append(Paragraph(
            "The following manual verification guide "
            "was generated by Claude AI to assist "
            "with confirming remediation effectiveness.",
            S['explain']
        ))
        story.append(Paragraph(verify, S['body']))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Asset Profile", S['h1']
    ))
    story.append(hr())
    story.append(Paragraph(
        "The asset profile provides context about "
        "the affected host and how the finding was "
        "discovered during the assessment.",
        S['explain']
    ))
    story.append(Spacer(1, 4))
    story.append(make_table(
        [
            ['Field',           'Value'],
            ['Host / Asset',    asset],
            ['Target',          target],
            ['Discovery Tool',  tool],
            ['Category',        category],
            ['Finding Status',  status],
            ['Scan Profile',    profile],
        ],
        col_widths=[COL1, COL2],
        header_bg=colors.HexColor('#4a235a'),
    ))
    story.append(Spacer(1, 10))

    if tags:
        story.append(Paragraph(
            "Attack Surface Tags", S['h2']
        ))
        story.append(Paragraph(
            "The following attack surface tags were "
            "identified for this finding:",
            S['explain']
        ))
        story.append(Paragraph(
            '   |   '.join(tags), S['body']
        ))
        story.append(Spacer(1, 10))

    if notes:
        story.append(Paragraph(
            "Analyst Notes", S['h1']
        ))
        story.append(hr())
        story.append(Paragraph(
            "The following notes were recorded by "
            "the security analyst during manual "
            "verification of this finding.",
            S['explain']
        ))
        story.append(Paragraph(notes, S['body']))
        story.append(Spacer(1, 10))

    # ── Footer ────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(hr(C_BORDER))
    story.append(Paragraph(
        "AutoRed Security Assessment Report   |   "
        "Finding " + finding_ref + "   |   "
        "Target: " + target + "   |   "
        "Generated: " +
        str(datetime.date.today()) +
        "   |   CONFIDENTIAL",
        S['footer']
    ))

    doc.build(story)
    return output_path
