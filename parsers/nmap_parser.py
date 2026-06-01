import xml.etree.ElementTree as ET
from datetime import datetime
from backend.db import insert_finding, insert_audit_log

SEVERITY_MAP = {
    '21':   'High',
    '22':   'Medium',
    '23':   'Critical',
    '25':   'Medium',
    '53':   'Low',
    '80':   'Info',
    '110':  'Medium',
    '139':  'Medium',
    '143':  'Medium',
    '443':  'Info',
    '445':  'High',
    '1524': 'Critical',
    '3306': 'High',
    '3389': 'High',
    '5432': 'High',
    '5900': 'High',
    '6667': 'Medium',
    '8080': 'Low',
    '8443': 'Low',
    '8180': 'Low',
}

RECOMMENDATION_MAP = {
    '21':   'Disable FTP immediately. Use SFTP instead. FTP transmits credentials in plaintext.',
    '22':   'Restrict SSH access to trusted IPs only. Disable root login. Use key-based authentication.',
    '23':   'Disable Telnet immediately. It transmits all data including passwords in plaintext. Use SSH.',
    '25':   'Restrict SMTP relay. Ensure authentication is required to prevent spam relay.',
    '53':   'Restrict DNS zone transfers. Only allow trusted resolvers.',
    '80':   'Ensure web server is patched and properly configured. Consider redirecting to HTTPS.',
    '110':  'Disable POP3 if not needed. Use encrypted POP3S on port 995 instead.',
    '139':  'Restrict NetBIOS access using firewall rules. Apply latest SMB patches.',
    '143':  'Disable IMAP if not needed. Use encrypted IMAPS on port 993 instead.',
    '443':  'Ensure SSL/TLS is up to date. Check certificate validity and cipher suites.',
    '445':  'Disable SMB if not needed. Apply latest patches. Restrict access with firewall.',
    '1524': 'Critical backdoor port detected. Investigate immediately. This is a known Metasploitable backdoor.',
    '3306': 'Restrict MySQL access to localhost only. Never expose database ports publicly.',
    '3389': 'Restrict RDP access to trusted IPs. Enable Network Level Authentication.',
    '5432': 'Restrict PostgreSQL access to localhost only. Never expose database ports publicly.',
    '5900': 'Disable VNC if not needed. If required use strong passwords and restrict access.',
    '6667': 'Investigate IRC service. Commonly used by malware for command and control.',
    '8080': 'Restrict access to alternative HTTP port if not needed.',
    '8443': 'Ensure proper SSL/TLS configuration on alternative HTTPS port.',
    '8180': 'Restrict access to Tomcat HTTP port. Ensure default credentials are changed.',
}

def get_severity(port):
    return SEVERITY_MAP.get(str(port), 'Low')

def get_recommendation(port):
    return RECOMMENDATION_MAP.get(
        str(port),
        'Review this service and restrict access if not needed.'
    )

def parse_nmap(scan_id, xml_output, target):
    findings = []

    if not xml_output or not xml_output.strip():
        print("[-] Nmap: empty output")
        insert_audit_log(scan_id, 'nmap_parsed', '0 findings — empty output')
        return findings

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print(f"[-] Failed to parse Nmap XML: {e}")
        insert_audit_log(scan_id, 'nmap_parsed', f'Parse error: {e}')
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
            service_product = ''

            if service_el is not None:
                service_name = service_el.get('name', 'unknown')
                service_version = service_el.get('version', '')
                service_product = service_el.get('product', '')

            full_service = f"{service_product} {service_version}".strip()

            severity = get_severity(port_id)
            recommendation = get_recommendation(port_id)

            title = f"Open port {port_id}/{protocol} — {service_name}"

            description = (
                f"Port {port_id} ({protocol}) is open on "
                f"{hostname} ({ip}). "
                f"Service detected: {service_name} "
                f"{full_service}.".strip()
            )

            evidence = (
                f"Nmap scan detected open port {port_id}/{protocol} "
                f"with service '{service_name}' on {ip}"
            )

            if full_service:
                evidence += f" (version: {full_service})"

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

    insert_audit_log(
        scan_id, 'nmap_parsed',
        f"{len(findings)} findings saved from Nmap"
    )
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

    findings = parse_nmap(
        scan_id=2,
        xml_output=xml_output,
        target='scanme.nmap.org'
    )

    print(f"\n--- SUMMARY ---")
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
