import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))

import json
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import post_enrich_cve

# ── Outdated version detection ────────────────────────────────
# (tech_name_lower): (min_safe_major, min_safe_minor, cwe, severity, note)
OUTDATED_DB = {
    'apache':    (2, 4,  'CWE-1104', 'High',   'Apache 2.2.x is EOL — upgrade to 2.4.x'),
    'php':       (7, 4,  'CWE-1104', 'High',   'PHP < 7.4 is EOL — upgrade immediately'),
    'nginx':     (1, 20, 'CWE-1104', 'Medium', 'nginx version is outdated'),
    'jquery':    (3, 0,  'CWE-79',   'Medium', 'jQuery < 3.x has known XSS vulnerabilities'),
    'bootstrap': (4, 0,  'CWE-1104', 'Low',    'Bootstrap version is outdated'),
    'wordpress': (6, 0,  'CWE-1104', 'High',   'WordPress version is outdated'),
    'joomla':    (4, 0,  'CWE-1104', 'High',   'Joomla version is outdated'),
    'drupal':    (9, 0,  'CWE-1104', 'High',   'Drupal version is outdated'),
    'openssl':   (1, 1,  'CWE-1104', 'High',   'OpenSSL version is outdated'),
}

def _check_outdated(tech_name, version_str):
    """
    Returns (cwe_id, severity, note) if version is outdated,
    else None.
    """
    entry = OUTDATED_DB.get(tech_name.lower())
    if not entry:
        return None
    min_maj, min_min, cwe, severity, note = entry
    try:
        parts = [int(x) for x in str(version_str).split('.')[:2]]
        if len(parts) == 1:
            parts.append(0)
        if parts[0] < min_maj or (parts[0] == min_maj and parts[1] < min_min):
            return cwe, severity, note
    except (ValueError, AttributeError):
        pass
    return None


def parse_whatweb(scan_id, raw_output, target):
    findings = []

    try:
        raw_output = raw_output.strip()
        data       = None
        for line in [l.strip() for l in raw_output.split('\n') if l.strip()]:
            try:
                parsed = json.loads(line)
                if isinstance(parsed, list) and parsed:
                    data = parsed[0]
                    break
                elif isinstance(parsed, dict):
                    data = parsed
                    break
            except json.JSONDecodeError:
                continue

        if data is None:
            print("[-] WhatWeb: could not parse valid JSON")
            return findings

        entries = [data] if isinstance(data, dict) else data

    except Exception as e:
        print(f"[-] WhatWeb parse error: {e}")
        return findings

    for entry in entries:
        target_url = entry.get('target', target)
        plugins    = entry.get('plugins', {})

        for tech_name, plugin_data in plugins.items():
            versions   = plugin_data.get('version', [])
            strings    = plugin_data.get('string', [])
            version_str = versions[0] if versions else ''
            detail      = version_str or (', '.join(strings[:3]) if strings else 'detected')

            # Check if version is outdated
            outdated = _check_outdated(tech_name, version_str) if version_str else None

            if outdated:
                cwe_id, severity, note = outdated
                title = (
                    f"[{cwe_id}] Outdated {tech_name} {version_str}"
                )
                description = (
                    f"{note}\n"
                    f"Detected: {tech_name} {version_str} "
                    f"on {target_url}.\n"
                    f"CWE: {cwe_id} — Use of Unmaintained "
                    f"Third Party Components."
                )
                recommendation = (
                    f"Upgrade {tech_name} to the latest stable "
                    f"version immediately. Outdated components "
                    f"may contain known exploitable vulnerabilities."
                )
            elif version_str:
                # Version detected but not in outdated DB
                cwe_id    = 'CWE-200'
                severity  = 'Low'
                title     = f"Technology detected: {tech_name} {version_str}"
                description = (
                    f"WhatWeb detected {tech_name} {version_str} "
                    f"on {target_url}. "
                    f"Version disclosure may assist attackers."
                )
                recommendation = (
                    f"Suppress version information from HTTP "
                    f"headers and responses for {tech_name}."
                )
            else:
                # No version — just tech detection
                cwe_id    = None
                severity  = 'Info'
                title     = f"Technology detected: {tech_name}"
                description = (
                    f"WhatWeb detected '{tech_name}' on {target_url}. "
                    f"Detail: {detail}."
                )
                recommendation = (
                    f"Ensure {tech_name} is up to date "
                    f"and properly configured."
                )

            evidence = (
                f"WhatWeb: {tech_name} {detail} "
                f"on {target_url}"
            )

            finding = {
                'scan_id':        scan_id,
                'tool':           'whatweb',
                'asset':          target_url,
                'category':       'tech_fingerprint',
                'severity':       severity,
                'title':          title,
                'description':    description,
                'evidence':       evidence,
                'recommendation': recommendation,
            }
            findings.append(finding)

            insert_finding(
                scan_id=scan_id, tool='whatweb',
                asset=target_url, category='tech_fingerprint',
                severity=severity, title=title,
                description=description, evidence=evidence,
                recommendation=recommendation
            )

            if cwe_id:
                post_enrich_cve(
                    scan_id, 'whatweb', target_url,
                    cwe_id=cwe_id
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
            "Apache":    {"version": ["2.2.8"],  "string": []},
            "PHP":       {"version": ["5.2.4"],  "string": []},
            "jQuery":    {"version": ["1.3.2"],  "string": []},
            "WordPress": {"version": ["5.8.1"],  "string": []},
            "Ubuntu":    {"version": [],         "string": ["Ubuntu"]},
            "Bootstrap": {"version": ["4.6.0"],  "string": []},
        }
    }])

    findings = parse_whatweb(2, raw, '192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
