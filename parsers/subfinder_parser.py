import ipaddress
from backend.db import insert_finding, insert_audit_log

def parse_subfinder(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] Subfinder: no output to parse")
        insert_audit_log(scan_id, 'subfinder_parsed', '0 subdomains found')
        return findings

    lines = raw_output.strip().split('\n')
    subdomains = [line.strip() for line in lines if line.strip()]

    if not subdomains:
        print("[*] Subfinder: no subdomains found")
        insert_audit_log(scan_id, 'subfinder_parsed', '0 subdomains found')
        return findings

    for subdomain in subdomains:
        try:
            ipaddress.ip_address(subdomain)
            print(f"[*] Subfinder: skipping IP address {subdomain}")
            continue
        except ValueError:
            pass

        if not subdomain or len(subdomain) < 4:
            continue

        if '.' not in subdomain:
            continue

        title = f"Subdomain discovered: {subdomain}"
        description = (
            f"Subdomain '{subdomain}' was discovered under the "
            f"target domain '{target}'. This expands the attack "
            f"surface and may expose additional services."
        )
        evidence = f"Subfinder discovered subdomain: {subdomain}"
        recommendation = (
            "Review this subdomain. Ensure it is intentional and "
            "properly secured. Remove unused subdomains to reduce "
            "attack surface."
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

    insert_audit_log(
        scan_id, 'subfinder_parsed',
        f"{len(findings)} subdomains found"
    )
    print(f"[+] Subfinder parser done — {len(findings)} subdomains saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """sub1.scanme.nmap.org
sub2.scanme.nmap.org
test.scanme.nmap.org
192.168.112.130
10.0.0.1"""

    print("--- Testing with mix of subdomains and IPs ---")
    findings = parse_subfinder(
        scan_id=2,
        raw_output=raw,
        target='scanme.nmap.org'
    )
    print(f"\nTotal valid subdomains: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
