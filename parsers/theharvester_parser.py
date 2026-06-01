import json
from backend.db import insert_finding, insert_audit_log

def parse_theharvester(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] theHarvester: no output to parse")
        insert_audit_log(scan_id, 'theharvester_parsed', '0 findings')
        return findings

    if 'IP target - theHarvester skipped' in raw_output:
        print("[*] theHarvester: skipped for IP target")
        insert_audit_log(scan_id, 'theharvester_parsed', 'skipped for IP target')
        return findings

    json_file = '/tmp/harvester_out.json'
    import os
    if not os.path.exists(json_file):
        print("[-] theHarvester: output file not found")
        return findings

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] theHarvester parse error: {e}")
        return findings

    hosts = data.get('hosts', [])
    emails = data.get('emails', [])
    ips = data.get('ips', [])

    for host in hosts:
        if not host or not isinstance(host, str):
            continue

        title = f"Host discovered: {host}"
        description = (
            f"theHarvester discovered host '{host}' "
            f"associated with target domain '{target}' "
            f"via OSINT sources."
        )
        evidence = f"theHarvester found host: {host}"
        recommendation = (
            "Review this host. Ensure it is intentional "
            "and properly secured. Remove unused hosts "
            "to reduce attack surface."
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'theharvester',
            'asset': host,
            'category': 'osint_host',
            'severity': 'Info',
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='theharvester',
            asset=host,
            category='osint_host',
            severity='Info',
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[INFO] {title}")

    for email in emails:
        if not email or not isinstance(email, str):
            continue

        title = f"Email discovered: {email}"
        description = (
            f"theHarvester discovered email '{email}' "
            f"associated with target domain '{target}'. "
            f"This could be used for phishing or "
            f"social engineering attacks."
        )
        evidence = f"theHarvester found email: {email}"
        recommendation = (
            "Review exposed email addresses. Consider "
            "using email obfuscation on public pages. "
            "Train staff on phishing awareness."
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'theharvester',
            'asset': email,
            'category': 'osint_email',
            'severity': 'Low',
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='theharvester',
            asset=email,
            category='osint_email',
            severity='Low',
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[LOW] {title}")

    for ip in ips:
        if not ip or not isinstance(ip, str):
            continue

        title = f"IP discovered: {ip}"
        description = (
            f"theHarvester discovered IP address '{ip}' "
            f"associated with target domain '{target}'."
        )
        evidence = f"theHarvester found IP: {ip}"
        recommendation = (
            "Review this IP address. Ensure all exposed "
            "services are intentional and properly secured."
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'theharvester',
            'asset': ip,
            'category': 'osint_ip',
            'severity': 'Info',
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='theharvester',
            asset=ip,
            category='osint_ip',
            severity='Info',
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[INFO] {title}")

    insert_audit_log(
        scan_id, 'theharvester_parsed',
        f"{len(findings)} OSINT findings saved"
    )
    print(f"[+] theHarvester parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    import json
    test_data = {
        "hosts": [
            "mail.scanme.nmap.org",
            "www.scanme.nmap.org",
            "dev.scanme.nmap.org"
        ],
        "emails": [
            "admin@scanme.nmap.org",
            "info@scanme.nmap.org"
        ],
        "ips": [
            "45.33.32.156",
            "45.33.32.157"
        ]
    }

    with open('/tmp/harvester_out.json', 'w') as f:
        json.dump(test_data, f)

    findings = parse_theharvester(
        scan_id=2,
        raw_output='test',
        target='scanme.nmap.org'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
