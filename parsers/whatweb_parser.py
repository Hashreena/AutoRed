import json
from backend.db import insert_finding, insert_audit_log

def parse_whatweb(scan_id, raw_output, target):
    findings = []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        try:
            lines = [l.strip() for l in raw_output.strip().split('\n') if l.strip()]
            data = [json.loads(l) for l in lines]
        except json.JSONDecodeError as e:
            print(f"[-] Failed to parse WhatWeb output: {e}")
            return findings

    if isinstance(data, dict):
        data = [data]

    for entry in data:
        target_url = entry.get('target', target)
        plugins = entry.get('plugins', {})

        for plugin_name, plugin_data in plugins.items():
            versions = plugin_data.get('version', [])
            strings = plugin_data.get('string', [])

            version_str = ', '.join(versions) if versions else ''
            string_str = ', '.join(strings[:3]) if strings else ''

            detail = version_str or string_str or 'detected'

            severity = 'Info'
            if versions:
                severity = 'Low'

            title = f"Technology detected: {plugin_name}"
            if version_str:
                title += f" {version_str}"

            description = (
                f"WhatWeb detected '{plugin_name}' on {target_url}. "
                f"Detail: {detail}."
            )
            evidence = f"WhatWeb plugin match: {plugin_name} — {detail} on {target_url}"
            recommendation = (
                f"Ensure {plugin_name} is up to date and properly configured. "
                f"Remove version information from HTTP headers if possible."
            )

            finding = {
                'scan_id': scan_id,
                'tool': 'whatweb',
                'asset': target_url,
                'category': 'tech_fingerprint',
                'severity': severity,
                'title': title,
                'description': description,
                'evidence': evidence,
                'recommendation': recommendation
            }

            findings.append(finding)

            insert_finding(
                scan_id=scan_id,
                tool='whatweb',
                asset=target_url,
                category='tech_fingerprint',
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation
            )

            print(f"[{severity.upper()}] {title}")

    insert_audit_log(scan_id, 'whatweb_parsed', f"{len(findings)} tech fingerprints found")
    print(f"[+] WhatWeb parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = json.dumps({
        "target": "http://scanme.nmap.org",
        "plugins": {
            "Apache": {
                "version": ["2.4.7"],
                "string": []
            },
            "Ubuntu": {
                "version": [],
                "string": ["Ubuntu"]
            },
            "HTML5": {
                "version": [],
                "string": []
            },
            "HTTPServer": {
                "version": [],
                "string": ["Apache/2.4.7 (Ubuntu)"]
            }
        }
    })

    findings = parse_whatweb(scan_id=2, raw_output=raw, target='scanme.nmap.org')
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
