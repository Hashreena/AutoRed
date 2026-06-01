import json
import os
from backend.db import insert_finding, insert_audit_log

RECORD_SEVERITY = {
    'A':     'Info',
    'AAAA':  'Info',
    'MX':    'Low',
    'NS':    'Low',
    'SOA':   'Info',
    'TXT':   'Low',
    'CNAME': 'Info',
    'PTR':   'Info',
    'SRV':   'Low',
    'AXFR':  'Critical',
}

RECORD_RECOMMENDATIONS = {
    'A':     'Ensure this IP is intentional and properly secured.',
    'AAAA':  'Ensure this IPv6 address is intentional and properly secured.',
    'MX':    'Review mail server configuration. Ensure SPF, DKIM and DMARC are configured.',
    'NS':    'Review nameserver configuration. Restrict zone transfers to authorized servers only.',
    'SOA':   'Review SOA record. Ensure zone transfer restrictions are in place.',
    'TXT':   'Review TXT records for sensitive information exposure.',
    'CNAME': 'Review CNAME records for subdomain takeover vulnerabilities.',
    'PTR':   'Review PTR records for information disclosure.',
    'SRV':   'Review SRV records. Ensure exposed services are intentional.',
    'AXFR':  'Critical: Zone transfer is enabled! Restrict AXFR to authorized servers immediately.',
}

def parse_dnsrecon(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        print("[*] DNSrecon: no output to parse")
        insert_audit_log(scan_id, 'dnsrecon_parsed', '0 findings')
        return findings

    if 'IP target - DNSrecon skipped' in raw_output:
        print("[*] DNSrecon: skipped for IP target")
        insert_audit_log(scan_id, 'dnsrecon_parsed', 'skipped for IP target')
        return findings

    json_file = '/tmp/dnsrecon_out.json'
    if not os.path.exists(json_file):
        print("[-] DNSrecon: output file not found")
        return findings

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] DNSrecon parse error: {e}")
        return findings

    if not isinstance(data, list):
        print("[-] DNSrecon: unexpected JSON format")
        return findings

    for record in data:
        if not isinstance(record, dict):
            continue

        record_type = record.get('type', '')

        if record_type == 'ScanInfo':
            continue

        if not record_type:
            continue

        name = record.get('name', '')
        address = record.get('address', '')
        domain = record.get('domain', target)
        exchange = record.get('exchange', '')
        target_val = record.get('target', '')
        strings = record.get('strings', '')

        asset = name or domain or target
        detail = address or exchange or target_val or strings or 'N/A'

        severity = RECORD_SEVERITY.get(record_type, 'Info')
        recommendation = RECORD_RECOMMENDATIONS.get(
            record_type,
            'Review this DNS record for security implications.'
        )

        title = f"DNS {record_type} record: {asset}"
        if detail and detail != 'N/A':
            title += f" → {detail}"

        description = (
            f"DNSrecon discovered a {record_type} DNS record "
            f"for '{asset}'. "
            f"Value: {detail}. "
            f"This record is publicly accessible and may "
            f"reveal infrastructure information."
        )

        evidence = (
            f"DNSrecon found {record_type} record: "
            f"{asset} → {detail}"
        )

        finding = {
            'scan_id': scan_id,
            'tool': 'dnsrecon',
            'asset': asset,
            'category': 'dns_record',
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='dnsrecon',
            asset=asset,
            category='dns_record',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'dnsrecon_parsed',
        f"{len(findings)} DNS records found"
    )
    print(f"[+] DNSrecon parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    test_data = [
        {
            "arguments": "dnsrecon -d scanme.nmap.org",
            "date": "2026-05-15",
            "type": "ScanInfo"
        },
        {
            "address": "45.33.32.156",
            "domain": "scanme.nmap.org",
            "name": "scanme.nmap.org",
            "type": "A"
        },
        {
            "address": "2600:3c01::f03c:91ff:fe18:bb2f",
            "domain": "scanme.nmap.org",
            "name": "scanme.nmap.org",
            "type": "AAAA"
        },
        {
            "exchange": "mail.scanme.nmap.org",
            "name": "scanme.nmap.org",
            "type": "MX"
        },
        {
            "name": "scanme.nmap.org",
            "target": "ns1.linode.com",
            "type": "NS"
        }
    ]

    with open('/tmp/dnsrecon_out.json', 'w') as f:
        json.dump(test_data, f)

    findings = parse_dnsrecon(
        scan_id=2,
        raw_output='test',
        target='scanme.nmap.org'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
