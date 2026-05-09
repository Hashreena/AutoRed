SEVERITY_RULES = {
    'open_port': {
        '22': 'Medium',
        '23': 'High',
        '21': 'High',
        '3389': 'High',
        '445': 'High',
        '139': 'Medium',
        '80': 'Info',
        '443': 'Info',
        '8080': 'Low',
    },
    'endpoint': {
        'admin': 'High',
        'administrator': 'High',
        'login': 'High',
        'wp-admin': 'High',
        'phpmyadmin': 'High',
        'dashboard': 'High',
        'config': 'High',
        'backup': 'High',
        'shell': 'Critical',
        'cmd': 'Critical',
        'upload': 'High',
    },
    'tech_fingerprint': {
        'default': 'Info'
    },
    'subdomain': {
        'default': 'Info'
    },
    'live_host': {
        'default': 'Info'
    }
}

ENRICHMENT = {
    'open_port': 'Restrict access to this port using firewall rules. Only allow trusted IPs.',
    'endpoint': 'Review this endpoint. Ensure proper authentication and authorization controls.',
    'tech_fingerprint': 'Keep this technology updated. Remove version banners from HTTP headers.',
    'subdomain': 'Review this subdomain. Remove unused subdomains to reduce attack surface.',
    'live_host': 'Ensure this host is intentional and properly secured.',
}

def score_finding(finding):
    category = finding.get('category', '').lower()
    title = finding.get('title', '').lower()
    current_severity = finding.get('severity', 'Info')

    rules = SEVERITY_RULES.get(category, {})

    for keyword, severity in rules.items():
        if keyword == 'default':
            continue
        if keyword in title:
            finding['severity'] = severity
            return finding

    if 'default' in rules:
        finding['severity'] = rules['default']

    if not finding.get('recommendation') or finding.get('recommendation') == 'Review and remediate.':
        finding['recommendation'] = ENRICHMENT.get(category, 'Review and remediate.')

    return finding

def score_all(findings):
    scored = []
    for f in findings:
        scored.append(score_finding(f))
    return scored

if __name__ == '__main__':
    test_findings = [
        {
            'category': 'open_port',
            'title': 'open port 22/tcp ssh',
            'severity': 'Info',
            'recommendation': ''
        },
        {
            'category': 'endpoint',
            'title': 'endpoint discovered: /admin [403]',
            'severity': 'Low',
            'recommendation': ''
        },
        {
            'category': 'endpoint',
            'title': 'endpoint discovered: /shell',
            'severity': 'Low',
            'recommendation': ''
        },
        {
            'category': 'tech_fingerprint',
            'title': 'apache 2.4.7 detected',
            'severity': 'Info',
            'recommendation': ''
        }
    ]

    print("--- BEFORE SCORING ---")
    for f in test_findings:
        print(f"  [{f['severity']}] {f['title']}")

    scored = score_all(test_findings)

    print("\n--- AFTER SCORING ---")
    for f in scored:
        print(f"  [{f['severity']}] {f['title']}")
        print(f"    Recommendation: {f['recommendation']}")
