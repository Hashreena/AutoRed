from datetime import datetime

SEVERITY_ORDER = {
    'Critical': 0,
    'High': 1,
    'Medium': 2,
    'Low': 3,
    'Info': 4
}

def normalize_finding(finding):
    normalized = {
        'scan_id': finding.get('scan_id', None),
        'tool': finding.get('tool', 'unknown').lower().strip(),
        'asset': finding.get('asset', 'unknown').strip(),
        'category': finding.get('category', 'general').lower().strip(),
        'severity': normalize_severity(finding.get('severity', 'Info')),
        'title': finding.get('title', 'Untitled Finding').strip(),
        'description': finding.get('description', 'No description provided.').strip(),
        'evidence': finding.get('evidence', 'No evidence provided.').strip(),
        'recommendation': finding.get('recommendation', 'Review and remediate.').strip(),
        'status': finding.get('status', 'Potential'),
        'created_at': datetime.now().isoformat()
    }
    return normalized

def normalize_severity(severity):
    severity = severity.strip().capitalize()
    if severity in SEVERITY_ORDER:
        return severity
    return 'Info'

def normalize_all(findings):
    normalized = []
    for f in findings:
        try:
            n = normalize_finding(f)
            normalized.append(n)
        except Exception as e:
            print(f"[-] Failed to normalize finding: {e}")
    return normalized

def sort_by_severity(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'Info'), 99))

if __name__ == '__main__':
    test_findings = [
        {
            'scan_id': 2,
            'tool': 'Nmap',
            'asset': 'scanme.nmap.org',
            'category': 'Open_Port',
            'severity': 'medium',
            'title': 'Open port 22/tcp',
            'description': 'SSH is open',
            'evidence': 'Port 22 detected',
            'recommendation': 'Restrict SSH access'
        },
        {
            'scan_id': 2,
            'tool': 'ffuf',
            'asset': 'http://scanme.nmap.org/admin',
            'category': 'endpoint',
            'severity': 'HIGH',
            'title': 'Admin panel found',
            'description': 'Admin panel is accessible',
            'evidence': 'ffuf found /admin returning 403',
            'recommendation': 'Restrict access to admin panel'
        },
        {
            'scan_id': 2,
            'tool': 'whatweb',
            'asset': 'http://scanme.nmap.org',
            'category': 'tech_fingerprint',
            'severity': 'info',
            'title': 'Apache detected',
            'description': 'Apache web server detected',
            'evidence': 'WhatWeb detected Apache',
            'recommendation': 'Keep Apache updated'
        }
    ]

    print("--- BEFORE NORMALIZATION ---")
    for f in test_findings:
        print(f"  tool={f['tool']}, severity={f['severity']}, category={f['category']}")

    normalized = normalize_all(test_findings)
    sorted_findings = sort_by_severity(normalized)

    print("\n--- AFTER NORMALIZATION (sorted by severity) ---")
    for f in sorted_findings:
        print(f"  [{f['severity']}] {f['tool']} — {f['title']}")
