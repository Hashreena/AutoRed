import json
from backend.db import insert_finding, insert_audit_log

HIGH_INTEREST = [
    'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
    'dashboard', 'config', 'backup', 'secret', 'private',
    'uploads', 'shell', 'cmd', 'console', 'manage'
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
    return 'Info'

def parse_ffuf(scan_id, raw_output, target):
    findings = []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse ffuf output: {e}")
        return findings

    results = data.get('results', [])

    if not results:
        print("[*] ffuf: no endpoints discovered")
        insert_audit_log(scan_id, 'ffuf_parsed', '0 endpoints found')
        return findings

    for result in results:
        url = result.get('url', '')
        status = result.get('status', 0)
        length = result.get('length', 0)
        words = result.get('words', 0)
        path = url.split('/')[-1] if '/' in url else url

        severity = get_severity(path, status)

        title = f"Endpoint discovered: {url} [{status}]"
        description = (
            f"ffuf discovered endpoint '{url}' returning HTTP {status}. "
            f"Response size: {length} bytes, {words} words."
        )
        evidence = f"ffuf found: {url} — status {status}, length {length}"

        if severity == 'High':
            recommendation = (
                f"This endpoint '{path}' appears to be a sensitive path. "
                f"Restrict access immediately and review authentication controls."
            )
        elif severity == 'Medium':
            recommendation = (
                f"Endpoint returns {status}. Review access controls and "
                f"ensure proper authentication is enforced."
            )
        else:
            recommendation = (
                f"Review endpoint '{url}' to confirm it should be publicly accessible."
            )

        finding = {
            'scan_id': scan_id,
            'tool': 'ffuf',
            'asset': url,
            'category': 'endpoint',
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }

        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='ffuf',
            asset=url,
            category='endpoint',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )

        print(f"[{severity.upper()}] {title}")

    insert_audit_log(scan_id, 'ffuf_parsed', f"{len(findings)} endpoints found")
    print(f"[+] ffuf parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = json.dumps({
        "results": [
            {
                "url": "http://scanme.nmap.org/index.html",
                "status": 200,
                "length": 1234,
                "words": 56
            },
            {
                "url": "http://scanme.nmap.org/admin",
                "status": 403,
                "length": 290,
                "words": 12
            },
            {
                "url": "http://scanme.nmap.org/images",
                "status": 200,
                "length": 890,
                "words": 34
            },
            {
                "url": "http://scanme.nmap.org/login",
                "status": 200,
                "length": 2100,
                "words": 98
            }
        ]
    })

    findings = parse_ffuf(scan_id=2, raw_output=raw, target='scanme.nmap.org')
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
