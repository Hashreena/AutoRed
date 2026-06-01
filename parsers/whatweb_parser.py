import json
from backend.db import insert_finding, insert_audit_log

def parse_whatweb(scan_id, raw_output, target):
    findings = []

    try:
        raw_output = raw_output.strip()

        data = None
        lines = [l.strip() for l in raw_output.split('\n') if l.strip()]
        for line in lines:
            try:
                parsed = json.loads(line)
                if isinstance(parsed, list) and len(parsed) > 0:
                    data = parsed[0]
                    break
                elif isinstance(parsed, dict):
                    data = parsed
                    break
            except json.JSONDecodeError:
                continue

        if data is None:
            print("[-] WhatWeb: could not parse any valid JSON")
            return findings

        entries = [data] if isinstance(data, dict) else data

    except Exception as e:
        print(f"[-] WhatWeb parse error: {e}")
        return findings

    for entry in entries:
        target_url = entry.get('target', target)
        plugins = entry.get('plugins', {})

        for plugin_name, plugin_data in plugins.items():
            versions = plugin_data.get('version', [])
            strings = plugin_data.get('string', [])

            version_str = ', '.join(versions) if versions else ''
            string_str = ', '.join(strings[:3]) if strings else ''
            detail = version_str or string_str or 'detected'

            severity = 'Low' if versions else 'Info'

            title = f"Technology detected: {plugin_name}"
            if version_str:
                title += f" {version_str}"

            description = (
                f"WhatWeb detected '{plugin_name}' on {target_url}. "
                f"Detail: {detail}."
            )
            evidence = (
                f"WhatWeb plugin match: {plugin_name} "
                f"— {detail} on {target_url}"
            )
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

    insert_audit_log(
        scan_id, 'whatweb_parsed',
        f"{len(findings)} tech fingerprints found"
    )
    print(f"[+] WhatWeb parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    raw = json.dumps([{
        "target": "http://192.168.112.130",
        "plugins": {
            "Apache": {"version": ["2.2.8"], "string": []},
            "PHP":    {"version": ["5.2.4"], "string": []},
            "Ubuntu": {"version": [], "string": ["Ubuntu"]},
        }
    }])

    findings = parse_whatweb(scan_id=2, raw_output=raw, target='192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
