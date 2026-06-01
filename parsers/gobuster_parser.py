import re
from backend.db import insert_finding, insert_audit_log

HIGH_INTEREST = [
    'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
    'dashboard', 'config', 'backup', 'secret', 'private',
    'uploads', 'shell', 'cmd', 'console', 'manage', 'phpinfo',
    'setup', 'install', 'database', 'db', 'passwd', 'password',
    'credentials', 'twiki', 'dav'
]

def get_severity(path, status_code):
    path_lower = path.lower()
    for keyword in HIGH_INTEREST:
        if keyword in path_lower:
            return 'High'
    if status_code in [401, 403]:
        return 'Medium'
    if status_code == 200:
        return 'Low'
    if status_code in [301, 302]:
        return 'Low'
    return 'Info'

def parse_gobuster(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] Gobuster: no output to parse")
        insert_audit_log(scan_id, 'gobuster_parsed', '0 findings')
        return findings

    lines = raw_output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith('Error') or line.startswith('[!]'):
            continue

        match = re.match(
            r'^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]',
            line
        )
        if not match:
            continue

        path = match.group(1).strip()
        status_code = int(match.group(2))
        size = int(match.group(3))

        prefix = 'http' if any(
            c.isdigit() for c in target.split('.')[0]
        ) else 'https'

        full_url = f"{prefix}://{target}/{path.lstrip('/')}"

        severity = get_severity(path, status_code)

        title = f"Directory found: /{path.lstrip('/')} [{status_code}]"
        description = (
            f"Gobuster discovered path '/{path.lstrip('/')}' "
            f"on {target} returning HTTP {status_code}. "
            f"Response size: {size} bytes."
        )
        evidence = (
            f"Gobuster found: {full_url} "
            f"— status {status_code}, size {size} bytes"
        )

        if severity == 'High':
            recommendation = (
                f"Sensitive path '/{path.lstrip('/')}' is accessible. "
                "Restrict access immediately and review "
                "authentication controls."
            )
        elif severity == 'Medium':
            recommendation = (
                f"Path returns {status_code}. Review access controls "
                "and ensure proper authentication is enforced."
            )
        else:
            recommendation = (
                f"Review path '/{path.lstrip('/')}' to confirm "
                "it should be publicly accessible."
            )

        finding = {
            'scan_id': scan_id,
            'tool': 'gobuster',
            'asset': full_url,
            'category': 'directory',
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='gobuster',
            asset=full_url,
            category='directory',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'gobuster_parsed',
        f"{len(findings)} directories found"
    )
    print(f"[+] Gobuster parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """.hta                 (Status: 403) [Size: 292]
.htaccess            (Status: 403) [Size: 297]
.htpasswd            (Status: 403) [Size: 297]
cgi-bin/             (Status: 403) [Size: 296]
dav                  (Status: 301) [Size: 321] [--> http://192.168.112.130/dav/]
index.php            (Status: 200) [Size: 891]
phpMyAdmin           (Status: 301) [Size: 328] [--> http://192.168.112.130/phpMyAdmin/]
phpinfo              (Status: 200) [Size: 48029]
phpinfo.php          (Status: 200) [Size: 48041]
server-status        (Status: 403) [Size: 301]
test                 (Status: 301) [Size: 322] [--> http://192.168.112.130/test/]
twiki                (Status: 301) [Size: 323] [--> http://192.168.112.130/twiki/]"""

    findings = parse_gobuster(
        scan_id=2,
        raw_output=raw,
        target='192.168.112.130'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
