import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))
import re
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import enrich_path, best_severity, post_enrich_cve

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
        if not line or line.startswith('#'):
            continue

        match = re.match(
            r'^(\d{3})\s+[\d.]+\w*\s+(https?://\S+)',
            line
        )
        if not match:
            continue

        status_code = int(match.group(1))
        url         = match.group(2).strip()
        if '->' in url:
            url = url.split('->')[0].strip()

        base_sev = get_severity(url, status_code)
        path     = url.replace(
            f'http://{target}', ''
        ).replace(f'https://{target}', '') or '/'

        # ── Path enrichment ──────────────────────────────
        enrichment = enrich_path(url, status_code)

        if enrichment:
            severity       = best_severity(base_sev, enrichment['severity'])
            cwe_id         = enrichment['cwe_id']
            cvss_score     = enrichment['cvss_score']
            description    = (
                f"{enrichment['description']}\n\n"
                f"URL: {url}  |  HTTP {status_code}\n"
                f"CWE: {cwe_id}  |  CVSS: {cvss_score}"
            )
            recommendation = enrichment['recommendation']
            title          = (
                f"[{cwe_id}] Sensitive path: "
                f"{path} [{status_code}]"
            )
        else:
            severity       = base_sev
            cwe_id         = None
            cvss_score     = None
            description    = (
                f"Dirsearch discovered path '{path}' "
                f"on {target} returning HTTP {status_code}."
            )
            title          = (
                f"Path discovered: {path} [{status_code}]"
            )
            if severity == 'High':
                recommendation = (
                    f"Sensitive path '{path}' is accessible. "
                    "Restrict access immediately."
                )
            elif severity == 'Medium':
                recommendation = (
                    f"Path returns {status_code}. "
                    "Review access controls."
                )
            else:
                recommendation = (
                    f"Review '{path}' to confirm "
                    "it should be publicly accessible."
                )

        evidence = f"Dirsearch found: {url} — status {status_code}"

        finding = {
            'scan_id':        scan_id,
            'tool':           'dirsearch',
            'asset':          url,
            'category':       'directory',
            'severity':       severity,
            'title':          title,
            'description':    description,
            'evidence':       evidence,
            'recommendation': recommendation,
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id, tool='dirsearch',
            asset=url, category='directory',
            severity=severity, title=title,
            description=description, evidence=evidence,
            recommendation=recommendation
        )

        if cwe_id:
            post_enrich_cve(
                scan_id, 'dirsearch', url, cwe_id, cvss_score
            )

        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'dirsearch_parsed',
        f"{len(findings)} paths found"
    )
    print(f"[+] Dirsearch parser done — {len(findings)} findings saved")
    return findings


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    ))
    from backend.db import init_db
    init_db()

    raw = """# Dirsearch started
403   299B   http://192.168.112.130/.htpasswd
403   296B   http://192.168.112.130/cgi-bin/
200   111KB  http://192.168.112.130/doc/
302     0B   http://192.168.112.130/dvwa/
200    24KB  http://192.168.112.130/mutillidae/
200    49KB  http://192.168.112.130/phpinfo.php
301   328B   http://192.168.112.130/phpMyAdmin
200     4KB  http://192.168.112.130/phpMyAdmin/
403   301B   http://192.168.112.130/server-status
200   886B   http://192.168.112.130/backup/"""

    findings = parse_dirsearch(2, raw, '192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
