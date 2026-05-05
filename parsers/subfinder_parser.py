from backend.db import insert_finding, insert_audit_log
from datetime import datetime

def parse_subfinder(scan_id, raw_output, target):
    findings = []

    lines = raw_output.strip().split('\n')
    subdomains = [line.strip() for line in lines if line.strip()]

    if not subdomains:
        print("[*] Subfinder: no subdomains found")
        insert_audit_log(scan_id, 'subfinder_parsed', '0 subdomains found')
        return findings

    for subdomain in subdomains:
        title = f"Subdomain discovered: {subdomain}"
        description = (
            f"Subdomain '{subdomain}' was discovered under the target domain '{target}'. "
            f"This expands the attack surface and may expose additional services."
        )
        evidence = f"Subfinder discovered subdomain: {subdomain}"
        recommendation = (
            "Review this subdomain. Ensure it is intentional and properly secured. "
            "Remove unused subdomains to reduce attack surface."
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'subfinder',
            'asset': subdomain,
            'category': 'subdomain',
            'severity': 'Info',
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }

        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='subfinder',
            asset=subdomain,
            category='subdomain',
            severity='Info',
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )

        print(f"[INFO] {title}")

    insert_audit_log(scan_id, 'subfinder_parsed', f"{len(findings)} subdomains found")
    print(f"[+] Subfinder parser done — {len(findings)} subdomains saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """sub1.scanme.nmap.org
sub2.scanme.nmap.org
test.scanme.nmap.org"""

    findings = parse_subfinder(scan_id=2, raw_output=raw, target='scanme.nmap.org')
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
