import json
import os
from backend.db import insert_finding, insert_audit_log

def parse_wpscan(scan_id, raw_output, target):
    findings = []

    json_file = '/tmp/wpscan_out.json'
    if not os.path.exists(json_file):
        print("[-] WPScan: output file not found")
        insert_audit_log(scan_id, 'wpscan_parsed', '0 findings')
        return findings

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] WPScan parse error: {e}")
        return findings

    if 'scan_aborted' in data:
        msg = data['scan_aborted']
        print(f"[*] WPScan aborted: {msg}")
        insert_audit_log(scan_id, 'wpscan_parsed', f'Scan aborted: {msg}')
        return findings

    target_url = data.get('target_url', target)

    wp_version = data.get('version', {})
    if wp_version:
        version_num = wp_version.get('number', 'unknown')
        severity = 'High' if wp_version.get('vulnerabilities') else 'Low'
        title = f"WordPress version detected: {version_num}"
        description = (
            f"WPScan detected WordPress version {version_num} "
            f"on {target_url}."
        )
        evidence = f"WordPress version {version_num} found at {target_url}"
        recommendation = (
            "Update WordPress to the latest version immediately. "
            "Enable automatic updates for core, plugins and themes."
        )

        insert_finding(
            scan_id=scan_id,
            tool='wpscan',
            asset=target_url,
            category='cms_version',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        findings.append({'severity': severity, 'title': title})
        print(f"[{severity.upper()}] {title}")

        for vuln in wp_version.get('vulnerabilities', []):
            vuln_title = vuln.get('title', 'Unknown vulnerability')
            cvss = vuln.get('cvss', {})
            score = cvss.get('score', 0) if cvss else 0

            if score >= 9:
                sev = 'Critical'
            elif score >= 7:
                sev = 'High'
            elif score >= 4:
                sev = 'Medium'
            else:
                sev = 'Low'

            refs = vuln.get('references', {})
            cve_list = refs.get('cve', [])
            cve = f"CVE-{cve_list[0]}" if cve_list else 'N/A'

            t = f"WordPress vulnerability: {vuln_title[:60]}"
            d = (
                f"WPScan found vulnerability in WordPress core: "
                f"{vuln_title}. CVE: {cve}. CVSS Score: {score}."
            )
            e = f"WPScan detected: {vuln_title} ({cve})"
            r = (
                "Update WordPress immediately to patch this "
                "vulnerability. Check WPScan database for patches."
            )

            insert_finding(
                scan_id=scan_id,
                tool='wpscan',
                asset=target_url,
                category='cms_vulnerability',
                severity=sev,
                title=t,
                description=d,
                evidence=e,
                recommendation=r
            )
            findings.append({'severity': sev, 'title': t})
            print(f"[{sev.upper()}] {t}")

    plugins = data.get('plugins', {})
    for plugin_name, plugin_data in plugins.items():
        plugin_version = plugin_data.get('version', {})
        version_num = plugin_version.get('number', 'unknown') if plugin_version else 'unknown'
        vulns = plugin_data.get('vulnerabilities', [])

        severity = 'High' if vulns else 'Info'
        title = f"WordPress plugin: {plugin_name} {version_num}"
        description = (
            f"WPScan detected WordPress plugin '{plugin_name}' "
            f"version {version_num} on {target_url}."
        )
        evidence = f"Plugin '{plugin_name}' version {version_num} detected"
        recommendation = (
            f"Keep plugin '{plugin_name}' updated. "
            "Remove unused plugins to reduce attack surface."
        )

        insert_finding(
            scan_id=scan_id,
            tool='wpscan',
            asset=target_url,
            category='cms_plugin',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        findings.append({'severity': severity, 'title': title})
        print(f"[{severity.upper()}] {title}")

        for vuln in vulns:
            vuln_title = vuln.get('title', 'Unknown')
            t = f"Plugin vulnerability: {plugin_name} — {vuln_title[:50]}"
            d = (
                f"Vulnerable plugin '{plugin_name}': {vuln_title}. "
                f"Target: {target_url}."
            )
            e = f"WPScan found vulnerable plugin: {plugin_name} — {vuln_title}"
            r = (
                f"Update or remove plugin '{plugin_name}' immediately."
            )
            insert_finding(
                scan_id=scan_id,
                tool='wpscan',
                asset=target_url,
                category='cms_plugin_vulnerability',
                severity='High',
                title=t,
                description=d,
                evidence=e,
                recommendation=r
            )
            findings.append({'severity': 'High', 'title': t})
            print(f"[HIGH] {t}")

    themes = data.get('themes', {})
    for theme_name, theme_data in themes.items():
        vulns = theme_data.get('vulnerabilities', [])
        severity = 'Medium' if vulns else 'Info'
        title = f"WordPress theme: {theme_name}"
        description = (
            f"WPScan detected WordPress theme '{theme_name}' "
            f"on {target_url}."
        )
        evidence = f"Theme '{theme_name}' detected at {target_url}"
        recommendation = (
            f"Keep theme '{theme_name}' updated. "
            "Remove unused themes."
        )
        insert_finding(
            scan_id=scan_id,
            tool='wpscan',
            asset=target_url,
            category='cms_theme',
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        findings.append({'severity': severity, 'title': title})
        print(f"[{severity.upper()}] {title}")

    users = data.get('users', {})
    for username in users:
        title = f"WordPress user enumerated: {username}"
        description = (
            f"WPScan enumerated WordPress user '{username}' "
            f"on {target_url}. This could aid brute force attacks."
        )
        evidence = f"User '{username}' found via WPScan enumeration"
        recommendation = (
            "Disable user enumeration. Use security plugins "
            "to hide usernames. Enforce strong passwords."
        )
        insert_finding(
            scan_id=scan_id,
            tool='wpscan',
            asset=target_url,
            category='cms_user',
            severity='Medium',
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
        findings.append({'severity': 'Medium', 'title': title})
        print(f"[MEDIUM] {title}")

    insert_audit_log(
        scan_id, 'wpscan_parsed',
        f"{len(findings)} WordPress findings saved"
    )
    print(f"[+] WPScan parser done — {len(findings)} findings saved")
    return findings

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    test_data = {
        "target_url": "http://testwordpress.com/",
        "version": {
            "number": "6.2.1",
            "vulnerabilities": [
                {
                    "title": "WordPress 6.2 XSS vulnerability",
                    "cvss": {"score": 7.5},
                    "references": {"cve": ["2023-12345"]}
                }
            ]
        },
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.7.1"},
                "vulnerabilities": []
            },
            "woocommerce": {
                "version": {"number": "7.0.0"},
                "vulnerabilities": [
                    {"title": "WooCommerce SQL injection"}
                ]
            }
        },
        "themes": {
            "twentytwentythree": {
                "vulnerabilities": []
            }
        },
        "users": {
            "admin": {},
            "editor": {}
        }
    }

    with open('/tmp/wpscan_out.json', 'w') as f:
        json.dump(test_data, f)

    findings = parse_wpscan(
        scan_id=2,
        raw_output='',
        target='testwordpress.com'
    )
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
