import json
from backend.db import insert_finding, insert_audit_log

def parse_httpx(scan_id, raw_output, target):
    findings = []

    lines = raw_output.strip().split('\n')
    lines = [line.strip() for line in lines if line.strip()]

    if not lines:
        print("[*] httpx: no output to parse")
        insert_audit_log(scan_id, 'httpx_parsed', '0 live hosts found')
        return findings

    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = data.get('url', '')
        status_code = data.get('status_code', 0)
        title = data.get('title', 'No title')
        tech = data.get('tech', [])
        content_length = data.get('content_length', 0)

        if status_code in [401, 403]:
            severity = 'Medium'
        elif status_code == 200:
            severity = 'Info'
        else:
            severity = 'Low'

        finding_title = f"Live host detected: {url} [{status_code}]"
        description = (
            f"Host {url} is live and returned HTTP {status_code}. "
            f"Page title: {title}. "
            f"Technologies detected: {', '.join(tech) if tech else 'none'}."
        )
        evidence = f"httpx detected live host at {url} with status {status_code} and content length {content_length}"
        recommendation = (
            "Review this host. Ensure it is intentional and properly secured. "
            "Check for sensitive information exposure and proper authentication."
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'httpx',
            'asset': url,
            'category': 'live_host',
            'severity': severity,
            'title': finding_title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }

        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='httpx',
            asset=url,
            category='live_host',
            severity=severity,
            title=finding_title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )

        print(f"[{severity.upper()}] {finding_title}")

    insert_audit_log(scan_id, 'httpx_parsed', f"{len(findings)} live hosts found")
    print(f"[+] httpx parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = '''{"url":"http://scanme.nmap.org","status_code":200,"title":"Go ahead and ScanMe!","tech":["Apache"]}
{"url":"https://scanme.nmap.org","status_code":200,"title":"Go ahead and ScanMe!","tech":["Apache"]}'''

    findings = parse_httpx(scan_id=2, raw_output=raw, target='scanme.nmap.org')
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
