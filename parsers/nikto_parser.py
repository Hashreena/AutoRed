import re
from backend.db import insert_finding, insert_audit_log

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
    message_lower = message.lower()
    for keyword in SEVERITY_KEYWORDS['Critical']:
        if keyword in message_lower:
            return 'Critical'
    for keyword in SEVERITY_KEYWORDS['High']:
        if keyword in message_lower:
            return 'High'
    for keyword in SEVERITY_KEYWORDS['Medium']:
        if keyword in message_lower:
            return 'Medium'
    for keyword in SEVERITY_KEYWORDS['Low']:
        if keyword in message_lower:
            return 'Low'
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

        osvdb_match = re.match(r'^\[(\d+)\]\s*(.*)', line)
        if osvdb_match:
            osvdb_id = osvdb_match.group(1)
            message = osvdb_match.group(2).strip()
        else:
            osvdb_id = ''
            message = line

        if not message or len(message) < 10:
            continue

        url_part = ''
        if ': ' in message:
            parts = message.split(': ', 1)
            url_part = parts[0].strip()
            description_text = parts[1].strip() if len(parts) > 1 else message
        else:
            url_part = '/'
            description_text = message

        asset = f"http://{target}{url_part}" if url_part.startswith('/') else f"http://{target}"

        severity = get_severity(message)

        title = f"Nikto: {message[:80]}"
        if len(message) > 80:
            title += "..."

        description = (
            f"Nikto web scanner detected an issue on {asset}. "
            f"Finding: {message}"
        )

        evidence = f"Nikto scan result: {message}"
        if osvdb_id:
            evidence += f" (ID: {osvdb_id})"

        if severity == 'Critical':
            recommendation = (
                f"Critical issue detected: {message[:60]}. "
                "Investigate immediately and remediate."
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
                "Review this finding as part of your security "
                "hardening process."
            )

        finding = {
            'scan_id': scan_id,
            'tool': 'nikto',
            'asset': asset,
            'category': 'web_vulnerability',
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='nikto',
            asset=asset,
            category='web_vulnerability',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
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
+ [000434] /: HTTP TRACE method is active and replies which suggests the host is vulnerable to XST.
+ [750510] /phpinfo.php: Output from the phpinfo() function was found.
+ [001795] /phpMyAdmin/changelog.php: phpMyAdmin is for managing MySQL databases.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [001384] /?=PHPB8B5F2A0: PHP Easter Eggs reveals potentially sensitive information.
+ 8242 requests: 16 errors and 30 items reported on the remote host
+ End Time: 2026-05-15 08:15:10 (GMT-4) (347 seconds)
+ 1 host(s) tested"""

    findings = parse_nikto(
        scan_id=2,
        raw_output=raw,
        target='192.168.112.130'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title'][:60]}")
