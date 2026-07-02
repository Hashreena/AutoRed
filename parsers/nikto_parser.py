import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))

import re
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import post_enrich_cve

# ── CVE / CWE extraction helpers ─────────────────────────────
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Map common OSVDB / finding IDs to CWE
OSVDB_CWE = {
    '000434': 'CWE-16',    # HTTP TRACE → XST
    '750510': 'CWE-200',   # phpinfo exposed
    '750500': 'CWE-548',   # Directory listing
    '600625': 'CWE-1104',  # Outdated PHP
    '600050': 'CWE-1104',  # Outdated Apache
    '001795': 'CWE-284',   # phpMyAdmin accessible
    '013587': 'CWE-693',   # Missing security header
    '001384': 'CWE-200',   # PHP Easter Egg
    '002799': 'CWE-16',    # Apache default files
    '003233': 'CWE-200',   # Apache default files
    '006267': 'CWE-16',    # WebDAV enabled
    '877044': 'CWE-200',   # Apache mod_negotiation inodes
}

# Map message keywords to CWE IDs
KEYWORD_CWE = [
    ('sql injection',      'CWE-89',   9.8),
    ('xss',                'CWE-79',   7.2),
    ('cross-site script',  'CWE-79',   7.2),
    ('command execution',  'CWE-78',   9.8),
    ('remote code',        'CWE-78',   9.8),
    ('rce',                'CWE-78',   9.8),
    ('directory listing',  'CWE-548',  5.3),
    ('directory indexing', 'CWE-548',  5.3),
    ('path traversal',     'CWE-22',   7.5),
    ('directory traversal','CWE-22',   7.5),
    ('http trace',         'CWE-16',   5.3),
    ('xst',                'CWE-16',   5.3),
    ('phpinfo',            'CWE-200',  5.3),
    ('missing',            'CWE-693',  4.0),
    ('header missing',     'CWE-693',  4.0),
    ('outdated',           'CWE-1104', 7.5),
    ('upload',             'CWE-434',  8.8),
    ('arbitrary file',     'CWE-434',  8.8),
    ('information disclos','CWE-200',  5.3),
    ('exposed',            'CWE-200',  5.3),
    ('default',            'CWE-16',   3.1),
    ('easter egg',         'CWE-200',  5.3),
    ('backup',             'CWE-530',  7.5),
    ('admin',              'CWE-284',  7.5),
    ('phpmyadmin',         'CWE-284',  8.8),
]

def get_cwe_and_cvss(message):
    msg = message.lower()
    for keyword, cwe, cvss in KEYWORD_CWE:
        if keyword in msg:
            return cwe, cvss
    return None, None

SEVERITY_KEYWORDS = {
    'Critical': [
        'backdoor', 'shell', 'root', 'command execution',
        'remote code', 'rce', 'sql injection', 'easter egg',
        'phpinfo', 'php easter'
    ],
    'High': [
        'sql', 'xss', 'cross-site', 'injection', 'traversal',
        'directory listing', 'directory indexing', 'admin',
        'phpmyadmin', 'upload', 'arbitrary', 'http trace',
        'xst', 'vulnerable', 'outdated', 'changelog'
    ],
    'Medium': [
        'misconfigured', 'default', 'exposed', 'disclosure',
        'information', 'header missing', 'missing',
        'multiviews', 'mod_negotiation', 'inodes',
        'etags', 'x-frame', 'content-type', 'deprecated'
    ],
    'Low': [
        'suggested', 'recommended', 'should', 'consider',
        'best practice', 'minor', 'uncommon header',
        'interesting', 'readme', 'default file'
    ],
}

def get_severity(message):
    msg = message.lower()
    for sev in ['Critical', 'High', 'Medium', 'Low']:
        for kw in SEVERITY_KEYWORDS[sev]:
            if kw in msg:
                return sev
    return 'Info'


def parse_nikto(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] Nikto: no output to parse")
        insert_audit_log(scan_id, 'nikto_parsed', '0 findings')
        return findings

    lines = raw_output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line.startswith('+'):
            continue
        if any(skip in line for skip in [
            'Target IP', 'Target Hostname', 'Target Port',
            'Start Time', 'End Time', 'host(s) tested',
            'Nikto v', '------', 'Platform',
            'No CGI', 'ERROR', 'requests:'
        ]):
            continue

        line = line.lstrip('+ ').strip()
        if not line:
            continue

        # Extract OSVDB ID
        osvdb_match = re.match(r'^\[(\d+)\]\s*(.*)', line)
        if osvdb_match:
            osvdb_id = osvdb_match.group(1)
            message  = osvdb_match.group(2).strip()
        else:
            osvdb_id = ''
            message  = line

        if not message or len(message) < 10:
            continue

        # Extract CVE ID from message text
        cve_match = CVE_RE.search(message)
        cve_id    = cve_match.group(0).upper() if cve_match else None

        # Get CWE from OSVDB map or keyword match
        cwe_id    = OSVDB_CWE.get(osvdb_id)
        cwe_id, cvss_score = get_cwe_and_cvss(message) if not cwe_id else (cwe_id, None)

        # Parse URL part
        if ': ' in message:
            parts        = message.split(': ', 1)
            url_part     = parts[0].strip()
            desc_text    = parts[1].strip()
        else:
            url_part  = '/'
            desc_text = message

        asset    = (
            f"http://{target}{url_part}"
            if url_part.startswith('/')
            else f"http://{target}"
        )
        severity = get_severity(message)

        # Build title — include CVE and CWE if found
        if cve_id and cwe_id:
            title = f"[{cwe_id}][{cve_id}] {message[:70]}"
        elif cve_id:
            title = f"[{cve_id}] {message[:75]}"
        elif cwe_id:
            title = f"[{cwe_id}] {message[:75]}"
        else:
            title = f"Nikto: {message[:80]}"
        if len(title) > 100:
            title = title[:97] + '...'

        description = (
            f"Nikto web scanner detected an issue on {asset}.\n"
            f"Finding: {message}"
        )
        if cve_id:
            description += f"\nCVE: {cve_id}"
        if cwe_id:
            description += f"\nCWE: {cwe_id}"
        if cvss_score:
            description += f"\nCVSS Score: {cvss_score}"

        evidence = f"Nikto scan result: {message}"
        if osvdb_id:
            evidence += f" (OSVDB-{osvdb_id})"

        if severity == 'Critical':
            recommendation = (
                f"Critical issue: {message[:60]}. "
                "Investigate and remediate immediately."
            )
        elif severity == 'High':
            recommendation = (
                f"High severity: {message[:60]}. "
                "Restrict access, update software and remove "
                "sensitive files immediately."
            )
        elif severity == 'Medium':
            recommendation = (
                "Review this finding and apply appropriate "
                "security headers or configuration changes."
            )
        else:
            recommendation = (
                "Review as part of your security "
                "hardening process."
            )

        finding = {
            'scan_id':        scan_id,
            'tool':           'nikto',
            'asset':          asset,
            'category':       'web_vulnerability',
            'severity':       severity,
            'title':          title,
            'description':    description,
            'evidence':       evidence,
            'recommendation': recommendation,
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id, tool='nikto',
            asset=asset, category='web_vulnerability',
            severity=severity, title=title,
            description=description, evidence=evidence,
            recommendation=recommendation
        )

        # Write CVE / CWE / CVSS to DB
        if cve_id or cwe_id:
            post_enrich_cve(
                scan_id, 'nikto', asset,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score
            )

        print(f"[{severity.upper()}] {title[:70]}")

    insert_audit_log(
        scan_id, 'nikto_parsed',
        f"{len(findings)} web vulnerabilities found"
    )
    print(f"[+] Nikto parser done — {len(findings)} findings saved")
    return findings


if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """- Nikto v2.6.0
+ Target IP: 192.168.112.130
+ Server: Apache/2.2.8 (Ubuntu) DAV/2
+ [999986] /: Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10.
+ [750500] /icons/: Directory indexing found.
+ [600625] PHP/5.2.4-2ubuntu5.10 appears to be outdated (current is at least 8.5.1).
+ [600050] Apache/2.2.8 appears to be outdated (current is at least 2.4.66).
+ [000434] /: HTTP TRACE method is active — vulnerable to XST. CVE-2004-2320.
+ [750510] /phpinfo.php: Output from the phpinfo() function was found.
+ [001795] /phpMyAdmin/changelog.php: phpMyAdmin is for managing MySQL databases.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [001384] /?=PHPB8B5F2A0: PHP Easter Eggs reveals sensitive information.
+ 8242 requests: 16 errors and 30 items reported
+ 1 host(s) tested"""

    findings = parse_nikto(2, raw, '192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title'][:65]}")
