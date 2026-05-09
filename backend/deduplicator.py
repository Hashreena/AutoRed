def make_key(finding):
    asset = finding.get('asset', '').lower().strip()
    category = finding.get('category', '').lower().strip()
    title = finding.get('title', '').lower().strip()
    return f"{asset}::{category}::{title}"

def deduplicate(findings):
    seen = {}
    duplicates = 0

    for finding in findings:
        key = make_key(finding)

        if key in seen:
            existing = seen[key]
            existing_tool = existing.get('tool', '')
            new_tool = finding.get('tool', '')

            if new_tool not in existing_tool:
                existing['tool'] = f"{existing_tool} + {new_tool}"

            duplicates += 1
            print(f"[~] Duplicate merged: {finding.get('title', '')} ({new_tool} -> {existing_tool})")
        else:
            seen[key] = finding

    unique_findings = list(seen.values())
    print(f"[+] Deduplication done — {len(unique_findings)} unique, {duplicates} duplicates merged")
    return unique_findings

if __name__ == '__main__':
    test_findings = [
        {
            'scan_id': 2,
            'tool': 'nmap',
            'asset': 'scanme.nmap.org (45.33.32.156)',
            'category': 'open_port',
            'severity': 'Medium',
            'title': 'Open port 22/tcp — ssh',
            'description': 'SSH port is open',
            'evidence': 'Nmap found port 22',
            'recommendation': 'Restrict SSH access'
        },
        {
            'scan_id': 2,
            'tool': 'shodan',
            'asset': 'scanme.nmap.org (45.33.32.156)',
            'category': 'open_port',
            'severity': 'Medium',
            'title': 'Open port 22/tcp — ssh',
            'description': 'SSH port is open',
            'evidence': 'Shodan found port 22',
            'recommendation': 'Restrict SSH access'
        },
        {
            'scan_id': 2,
            'tool': 'ffuf',
            'asset': 'http://scanme.nmap.org/admin',
            'category': 'endpoint',
            'severity': 'High',
            'title': 'Endpoint discovered: http://scanme.nmap.org/admin [403]',
            'description': 'Admin panel found',
            'evidence': 'ffuf found /admin',
            'recommendation': 'Restrict admin access'
        },
        {
            'scan_id': 2,
            'tool': 'nmap',
            'asset': 'scanme.nmap.org (45.33.32.156)',
            'category': 'open_port',
            'severity': 'Info',
            'title': 'Open port 80/tcp — http',
            'description': 'HTTP port is open',
            'evidence': 'Nmap found port 80',
            'recommendation': 'Ensure web server is patched'
        }
    ]

    print(f"Before dedup: {len(test_findings)} findings")
    unique = deduplicate(test_findings)
    print(f"After dedup: {len(unique)} findings")
    print("\n--- UNIQUE FINDINGS ---")
    for f in unique:
        print(f"  [{f['severity']}] {f['tool']} — {f['title']}")
