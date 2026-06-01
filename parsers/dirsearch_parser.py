import re
from backend.db import insert_finding, insert_audit_log

HIGH_INTEREST = [
    'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
    'dashboard', 'config', 'backup', 'secret', 'private',
    'uploads', 'shell', 'cmd', 'console', 'manage', 'phpinfo',
    'setup', 'install', 'database', 'db', 'passwd', 'password',
    'credentials', 'dvwa', 'mutillidae', 'twiki', 'tikiwiki',
    'dav', 'webdav', 'phpMyAdmin', 'doc', 'docs'
]

def get_severity(url, status_code):
    url_lower = url.lower()
    for keyword in HIGH_INTEREST:
        if keyword in url_lower:
            return 'High'
    if status_code in [401, 403]:
        return 'Medium'
    if status_code == 200:
        return 'Low'
    if status_code in [301, 302]:
        return 'Low'
    return 'Info'

def parse_dirsearch(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] Dirsearch: no output to parse")
        insert_audit_log(scan_id, 'dirsearch_parsed', '0 findings')
        return findings

    lines = raw_output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith('#'):
            continue

        match = re.match(
            r'^(\d{3})\s+[\d.]+\w*\s+(https?://\S+)',
            line
        )
        if not match:
            continue

        status_code = int(match.group(1))
        url = match.group(2).strip()

        if '->' in url:
            url = url.split('->')[0].strip()

        severity = get_severity(url, status_code)

        path = url.replace(f'http://{target}', '').replace(
            f'https://{target}', ''
        )
        if not path:
            path = '/'

        title = f"Path discovered: {path} [{status_code}]"
        description = (
            f"Dirsearch discovered path '{path}' "
            f"on {target} returning HTTP {status_code}."
        )
        evidence = (
            f"Dirsearch found: {url} "
            f"— status {status_code}"
        )

        if severity == 'High':
            recommendation = (
                f"Sensitive path '{path}' is accessible. "
                "Restrict access immediately and review "
                "authentication controls."
            )
        elif severity == 'Medium':
            recommendation = (
                f"Path returns {status_code}. Review access "
                "controls and ensure proper authentication."
            )
        else:
            recommendation = (
                f"Review path '{path}' to confirm "
                "it should be publicly accessible."
            )

        finding = {
            'scan_id': scan_id,
            'tool': 'dirsearch',
            'asset': url,
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
            tool='dirsearch',
            asset=url,
            category='directory',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'dirsearch_parsed',
        f"{len(findings)} paths found"
    )
    print(f"[+] Dirsearch parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """# Dirsearch started Fri May 15 10:16:02 2026
403   299B   http://192.168.112.130/.ht_wsr.txt
403   302B   http://192.168.112.130/.htaccess.bak1
403   296B   http://192.168.112.130/cgi-bin/
200   111KB  http://192.168.112.130/doc/
302     0B   http://192.168.112.130/dvwa/  ->  login.php
200    24KB  http://192.168.112.130/mutillidae/
200    49KB  http://192.168.112.130/phpinfo
200    49KB  http://192.168.112.130/phpinfo.php
301   328B   http://192.168.112.130/phpMyAdmin
200     4KB  http://192.168.112.130/phpMyAdmin/
403   301B   http://192.168.112.130/server-status
301   322B   http://192.168.112.130/test
200   886B   http://192.168.112.130/test/
301   326B   http://192.168.112.130/tikiwiki"""

    findings = parse_dirsearch(
        scan_id=2,
        raw_output=raw,
        target='192.168.112.130'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
