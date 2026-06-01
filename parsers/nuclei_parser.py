import re
from backend.db import insert_finding, insert_audit_log

SEVERITY_MAP = {
    'critical': 'Critical',
    'high':     'High',
    'medium':   'Medium',
    'low':      'Low',
    'info':     'Info',
}

CATEGORY_MAP = {
    'http':       'web_vulnerability',
    'tcp':        'network_vulnerability',
    'javascript': 'service_vulnerability',
    'dns':        'dns_vulnerability',
    'ssl':        'ssl_vulnerability',
}

def get_recommendation(template_id, severity):
    if 'CVE' in template_id:
        return (
            f"This is a known CVE vulnerability ({template_id}). "
            f"Apply the vendor patch immediately. Check NVD for "
            f"patch details: https://nvd.nist.gov/vuln/detail/{template_id}"
        )
    elif 'default-login' in template_id or 'weak-credentials' in template_id:
        return (
            "Default or weak credentials detected. "
            "Change all default passwords immediately. "
            "Implement strong password policy and account lockout."
        )
    elif 'empty-password' in template_id:
        return (
            "Empty password detected on a service. "
            "Set a strong password immediately and restrict access."
        )
    elif 'default-db' in template_id:
        return (
            "Default database credentials detected. "
            "Change database passwords and restrict remote access."
        )
    elif severity == 'Critical':
        return (
            "Critical vulnerability detected. "
            "Patch or mitigate immediately. "
            "Consider taking the service offline until patched."
        )
    else:
        return (
            "Review and remediate this vulnerability. "
            "Apply vendor patches and restrict access where possible."
        )

def parse_nuclei(scan_id, raw_output, target):
    findings = []

    if not raw_output or not raw_output.strip():
        txt_file = '/tmp/nuclei_out.txt'
        import os
        if os.path.exists(txt_file):
            with open(txt_file, 'r') as f:
                raw_output = f.read().strip()

    if not raw_output or not raw_output.strip():
        print("[*] Nuclei: no output to parse")
        insert_audit_log(scan_id, 'nuclei_parsed', '0 findings')
        return findings

    lines = raw_output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(?:\s+\[([^\]]*)\])?'
        match = re.match(pattern, line)
        if not match:
            continue

        template_id = match.group(1).strip()
        protocol = match.group(2).strip()
        severity_raw = match.group(3).strip().lower()
        asset = match.group(4).strip()
        extra_info = match.group(5).strip() if match.group(5) else ''

        severity = SEVERITY_MAP.get(severity_raw, 'Info')
        category = CATEGORY_MAP.get(protocol, 'vulnerability')

        is_cve = template_id.upper().startswith('CVE')

        if is_cve:
            title = f"[{template_id}] Vulnerability detected on {asset}"
        else:
            title = f"{template_id.replace('-', ' ').title()} on {asset}"

        description = (
            f"Nuclei detected '{template_id}' on {asset}. "
            f"Protocol: {protocol}. Severity: {severity}."
        )
        if extra_info:
            description += f" Details: {extra_info}."

        evidence = f"Nuclei template [{template_id}] matched: {asset}"
        if extra_info:
            evidence += f" — {extra_info}"

        recommendation = get_recommendation(template_id, severity)

        finding = {
            'scan_id': scan_id,
            'tool': 'nuclei',
            'asset': asset,
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id,
            tool='nuclei',
            asset=asset,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        print(f"[{severity.upper()}] {title[:70]}")

    insert_audit_log(
        scan_id, 'nuclei_parsed',
        f"{len(findings)} vulnerabilities found"
    )
    print(f"[+] Nuclei parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = """[CVE-2012-1823] [http] [high] http://192.168.112.130/index.php
[vnc-default-login] [javascript] [high] 192.168.112.130:5900 [passwords="password"]
[pgsql-empty-password] [javascript] [critical] 192.168.112.130:5432
[ftp-weak-credentials] [tcp] [high] 192.168.112.130:21 [password="123456",username="ftp"]
[CVE-2020-1938] [tcp] [critical] 192.168.112.130:8009
[CVE-2004-2687] [tcp] [high] 192.168.112.130:3632"""

    findings = parse_nuclei(
        scan_id=2,
        raw_output=raw,
        target='192.168.112.130'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title'][:60]}")
