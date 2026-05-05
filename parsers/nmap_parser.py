import xml.etree.ElementTree as ET
from datetime import datetime
from backend.db import insert_finding, insert_audit_log

SEVERITY_MAP = {
    '22': 'Medium',
    '23': 'High',
    '21': 'High',
    '3389': 'High',
    '445': 'High',
    '139': 'Medium',
    '80': 'Info',
    '443': 'Info',
    '8080': 'Low',
    '8443': 'Low',
}

RECOMMENDATION_MAP = {
    '22': 'Restrict SSH access to trusted IPs only. Disable root login.',
    '23': 'Disable Telnet immediately. Use SSH instead.',
    '21': 'Disable FTP if not needed. Use SFTP instead.',
    '3389': 'Restrict RDP access. Enable Network Level Authentication.',
    '445': 'Disable SMB if not needed. Apply latest patches.',
    '139': 'Restrict NetBIOS access. Apply firewall rules.',
    '80': 'Ensure web server is patched and properly configured.',
    '443': 'Ensure SSL/TLS is up to date. Check certificate validity.',
    '8080': 'Restrict access to alternative HTTP port if not needed.',
    '8443': 'Ensure proper SSL/TLS configuration on alternative HTTPS port.',
}

def get_severity(port):
    return SEVERITY_MAP.get(str(port), 'Low')

def get_recommendation(port):
    return RECOMMENDATION_MAP.get(str(port), 'Review this service and restrict access if not needed.')

def parse_nmap(scan_id, xml_output, target):
    findings = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print(f"[-] Failed to parse Nmap XML: {e}")
        return findings

    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue

        address = host.find('address')
        ip = address.get('addr') if address is not None else target

        hostnames_el = host.find('hostnames')
        hostname = target
        if hostnames_el is not None:
            hn = hostnames_el.find('hostname')
            if hn is not None:
                hostname = hn.get('name', target)

        ports_el = host.find('ports')
        if ports_el is None:
            continue

        for port_el in ports_el.findall('port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue

            port_id = port_el.get('portid')
            protocol = port_el.get('protocol', 'tcp')

            service_el = port_el.find('service')
            service_name = 'unknown'
            service_version = ''
            if service_el is not None:
                service_name = service_el.get('name', 'unknown')
                service_version = service_el.get('version', '')

            severity = get_severity(port_id)
            recommendation = get_recommendation(port_id)

            title = f"Open port {port_id}/{protocol} — {service_name}"
            description = (
                f"Port {port_id} ({protocol}) is open on {hostname} ({ip}). "
                f"Service detected: {service_name} {service_version}.".strip()
            )
            evidence = f"Nmap scan detected open port {port_id}/{protocol} with service '{service_name}' on {ip}"

            finding = {
                'scan_id': scan_id,
                'tool': 'nmap',
                'asset': f"{hostname} ({ip})",
                'category': 'open_port',
                'severity': severity,
                'title': title,
                'description': description,
                'evidence': evidence,
                'recommendation': recommendation
            }

            findings.append(finding)

            insert_finding(
                scan_id=scan_id,
                tool='nmap',
                asset=f"{hostname} ({ip})",
                category='open_port',
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation
            )

            print(f"[{severity.upper()}] {title}")

    insert_audit_log(scan_id, 'nmap_parsed', f"{len(findings)} findings saved from Nmap")
    print(f"[+] Nmap parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    import os
    from backend.db import init_db

    init_db()

    xml_file = 'storage/2/nmap/nmap_raw.txt'
    if not os.path.exists(xml_file):
        print(f"[-] File not found: {xml_file}")
        exit(1)

    with open(xml_file, 'r') as f:
        xml_output = f.read()

    findings = parse_nmap(scan_id=2, xml_output=xml_output, target='scanme.nmap.org')

    print(f"\n--- SUMMARY ---")
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
