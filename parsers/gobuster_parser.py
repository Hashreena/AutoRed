import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))
import re
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import enrich_path, best_severity, post_enrich_finding

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
        if not line or line.startswith('Error') or line.startswith('[!]'):
            continue

        match = re.match(
            r'^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]',
            line
        )
        if not match:
            continue

        path        = match.group(1).strip()
        status_code = int(match.group(2))
        size        = int(match.group(3))
        prefix      = 'http' if any(
            c.isdigit() for c in target.split('.')[0]
        ) else 'https'
        full_url    = f"{prefix}://{target}/{path.lstrip('/')}"
        base_sev    = get_severity(path, status_code)

        # ── Path enrichment ──────────────────────────────
        enrichment = enrich_path(full_url, status_code)

        if enrichment:
            severity       = best_severity(base_sev, enrichment['severity'])
            cwe_id         = enrichment['cwe_id']
            cvss_score     = enrichment['cvss_score']
            description    = (
                f"{enrichment['description']}\n\n"
                f"URL: {full_url}  |  HTTP {status_code}  |  "
                f"Size: {size} bytes.\n"
                f"CWE: {cwe_id}  |  CVSS: {cvss_score}"
            )
            recommendation = enrichment['recommendation']
            title          = (
                f"[{cwe_id}] Sensitive path: "
                f"/{path.lstrip('/')} [{status_code}]"
            )
        else:
            severity       = base_sev
            cwe_id         = None
            cvss_score     = None
            description    = (
                f"Gobuster discovered path "
                f"'/{path.lstrip('/')}' on {target} "
                f"returning HTTP {status_code}. "
                f"Response size: {size} bytes."
            )
            title          = (
                f"Directory found: "
                f"/{path.lstrip('/')} [{status_code}]"
            )
            if severity == 'High':
                recommendation = (
                    f"Sensitive path '/{path.lstrip('/')}' "
                    "is accessible. Restrict access immediately."
                )
            elif severity == 'Medium':
                recommendation = (
                    f"Path returns {status_code}. "
                    "Review access controls."
                )
            else:
                recommendation = (
                    f"Review '/{path.lstrip('/')}' to confirm "
                    "it should be publicly accessible."
                )

        evidence = (
            f"Gobuster found: {full_url} "
            f"— status {status_code}, size {size} bytes"
        )

        finding = {
            'scan_id':        scan_id,
            'tool':           'gobuster',
            'asset':          full_url,
            'category':       'directory',
            'severity':       severity,
            'title':          title,
            'description':    description,
            'evidence':       evidence,
            'recommendation': recommendation,
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id, tool='gobuster',
            asset=full_url, category='directory',
            severity=severity, title=title,
            description=description, evidence=evidence,
            recommendation=recommendation
        )

        if cwe_id:
            post_enrich_finding(
                scan_id, 'gobuster', full_url, cwe_id, cvss_score
            )

        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'gobuster_parsed',
        f"{len(findings)} directories found"
    )
    print(f"[+] Gobuster parser done — {len(findings)} findings saved")
    return findings


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    ))
    from backend.db import init_db
    init_db()

    raw = """.htpasswd            (Status: 403) [Size: 297]
dav                  (Status: 301) [Size: 321]
phpMyAdmin           (Status: 301) [Size: 328]
phpinfo              (Status: 200) [Size: 48029]
backup               (Status: 200) [Size: 1024]
server-status        (Status: 403) [Size: 301]
twiki                (Status: 301) [Size: 323]"""

    findings = parse_gobuster(2, raw, '192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
