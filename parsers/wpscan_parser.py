import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))

import json
import os as _os
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import post_enrich_cve

# ── CWE from vulnerability type keywords ─────────────────────
VULN_TYPE_CWE = [
    ('sql',         'CWE-89',  9.8),
    ('sqli',        'CWE-89',  9.8),
    ('xss',         'CWE-79',  7.2),
    ('cross-site',  'CWE-79',  7.2),
    ('csrf',        'CWE-352', 6.5),
    ('rce',         'CWE-78',  9.8),
    ('remote code', 'CWE-78',  9.8),
    ('traversal',   'CWE-22',  7.5),
    ('lfi',         'CWE-22',  8.6),
    ('rfi',         'CWE-22',  9.8),
    ('upload',      'CWE-434', 8.8),
    ('bypass',      'CWE-287', 7.5),
    ('auth',        'CWE-287', 7.5),
    ('xxe',         'CWE-611', 7.5),
    ('ssrf',        'CWE-918', 8.6),
    ('object inject','CWE-502',9.8),
    ('deserializ',  'CWE-502', 9.8),
    ('open redirect','CWE-601',6.1),
]

def _cwe_for_vuln(title):
    t = title.lower()
    for keyword, cwe, _ in VULN_TYPE_CWE:
        if keyword in t:
            return cwe
    return 'CWE-284'   # default: improper access control

def _score_to_severity(score):
    if score >= 9.0: return 'Critical'
    if score >= 7.0: return 'High'
    if score >= 4.0: return 'Medium'
    if score >= 0.1: return 'Low'
    return 'Info'

def _format_cve(raw):
    """raw may be '2023-12345' or 'CVE-2023-12345'."""
    raw = str(raw).strip().upper()
    return raw if raw.startswith('CVE-') else f"CVE-{raw}"


def parse_wpscan(scan_id, raw_output, target):
    findings = []

    json_file = '/tmp/wpscan_out.json'
    if not _os.path.exists(json_file):
        print("[-] WPScan: output file not found")
        insert_audit_log(scan_id, 'wpscan_parsed', '0 findings')
        return findings

    try:
        with open(json_file) as f:
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

    # ── WordPress core version ────────────────────────────
    wp_version = data.get('version', {})
    if wp_version:
        version_num = wp_version.get('number', 'unknown')
        core_vulns  = wp_version.get('vulnerabilities', [])
        severity    = 'High' if core_vulns else 'Low'
        title       = f"WordPress {version_num} detected"
        description = (
            f"WPScan detected WordPress {version_num} on {target_url}."
        )
        evidence    = f"WordPress version {version_num} at {target_url}"
        recommendation = (
            "Update WordPress to the latest version. "
            "Enable automatic core updates."
        )

        insert_finding(
            scan_id=scan_id, tool='wpscan',
            asset=target_url, category='cms_version',
            severity=severity, title=title,
            description=description, evidence=evidence,
            recommendation=recommendation
        )
        post_enrich_cve(scan_id, 'wpscan', target_url,
                        cwe_id='CWE-1104')
        findings.append({'severity': severity, 'title': title})
        print(f"[{severity.upper()}] {title}")

        # WordPress core vulnerabilities
        for vuln in core_vulns:
            v_title = vuln.get('title', 'Unknown vulnerability')
            cvss_d  = vuln.get('cvss', {}) or {}
            score   = float(cvss_d.get('score', 0))
            refs    = vuln.get('references', {}) or {}
            cve_list= refs.get('cve', [])
            cve_id  = _format_cve(cve_list[0]) if cve_list else None
            cwe_id  = _cwe_for_vuln(v_title)
            sev     = _score_to_severity(score) if score else 'High'

            t = (
                f"[{cwe_id}]"
                f"{f'[{cve_id}]' if cve_id else ''} "
                f"WordPress core: {v_title[:55]}"
            )
            d = (
                f"WPScan found WordPress core vulnerability: "
                f"{v_title}.\n"
                f"CVE: {cve_id or 'N/A'}  "
                f"CVSS: {score}  CWE: {cwe_id}"
            )
            e = f"WPScan: {v_title} ({cve_id or 'N/A'})"
            r = (
                "Update WordPress immediately. "
                "Check WPVulnDB for patch details."
            )

            insert_finding(
                scan_id=scan_id, tool='wpscan',
                asset=target_url, category='cms_vulnerability',
                severity=sev, title=t,
                description=d, evidence=e,
                recommendation=r
            )
            post_enrich_cve(
                scan_id, 'wpscan', target_url,
                cve_id=cve_id, cwe_id=cwe_id,
                cvss_score=score if score else None
            )
            findings.append({'severity': sev, 'title': t})
            print(f"[{sev.upper()}] {t[:70]}")

    # ── Plugins ───────────────────────────────────────────
    for plugin_name, plugin_data in data.get('plugins', {}).items():
        pv      = plugin_data.get('version', {}) or {}
        ver     = pv.get('number', 'unknown')
        vulns   = plugin_data.get('vulnerabilities', [])
        sev     = 'High' if vulns else 'Info'
        title   = f"WordPress plugin: {plugin_name} {ver}"
        desc    = (
            f"Plugin '{plugin_name}' v{ver} detected "
            f"on {target_url}."
        )
        evid    = f"Plugin '{plugin_name}' v{ver} at {target_url}"
        rec     = (
            f"Keep '{plugin_name}' updated. "
            "Remove unused plugins."
        )
        insert_finding(
            scan_id=scan_id, tool='wpscan',
            asset=target_url, category='cms_plugin',
            severity=sev, title=title,
            description=desc, evidence=evid,
            recommendation=rec
        )
        findings.append({'severity': sev, 'title': title})
        print(f"[{sev.upper()}] {title}")

        for vuln in vulns:
            v_title  = vuln.get('title', 'Unknown')
            cvss_d   = vuln.get('cvss', {}) or {}
            score    = float(cvss_d.get('score', 0))
            refs     = vuln.get('references', {}) or {}
            cve_list = refs.get('cve', [])
            cve_id   = _format_cve(cve_list[0]) if cve_list else None
            cwe_id   = _cwe_for_vuln(v_title)
            sev_v    = _score_to_severity(score) if score else 'High'

            t = (
                f"[{cwe_id}]"
                f"{f'[{cve_id}]' if cve_id else ''} "
                f"{plugin_name}: {v_title[:50]}"
            )
            d = (
                f"Vulnerable plugin '{plugin_name}': {v_title}.\n"
                f"CVE: {cve_id or 'N/A'}  "
                f"CVSS: {score}  CWE: {cwe_id}"
            )
            e = f"WPScan: {plugin_name} — {v_title} ({cve_id or 'N/A'})"
            r = f"Update or remove plugin '{plugin_name}' immediately."

            insert_finding(
                scan_id=scan_id, tool='wpscan',
                asset=target_url,
                category='cms_plugin_vulnerability',
                severity=sev_v, title=t,
                description=d, evidence=e,
                recommendation=r
            )
            post_enrich_cve(
                scan_id, 'wpscan', target_url,
                cve_id=cve_id, cwe_id=cwe_id,
                cvss_score=score if score else None
            )
            findings.append({'severity': sev_v, 'title': t})
            print(f"[{sev_v.upper()}] {t[:70]}")

    # ── Themes ────────────────────────────────────────────
    for theme_name, theme_data in data.get('themes', {}).items():
        vulns = theme_data.get('vulnerabilities', [])
        sev   = 'Medium' if vulns else 'Info'
        title = f"WordPress theme: {theme_name}"
        insert_finding(
            scan_id=scan_id, tool='wpscan',
            asset=target_url, category='cms_theme',
            severity=sev, title=title,
            description=f"Theme '{theme_name}' on {target_url}.",
            evidence=f"Theme '{theme_name}' at {target_url}",
            recommendation=f"Keep '{theme_name}' updated."
        )
        findings.append({'severity': sev, 'title': title})
        print(f"[{sev.upper()}] {title}")

    # ── Users ─────────────────────────────────────────────
    for username in data.get('users', {}):
        title = f"WordPress user enumerated: {username}"
        insert_finding(
            scan_id=scan_id, tool='wpscan',
            asset=target_url, category='cms_user',
            severity='Medium', title=title,
            description=(
                f"User '{username}' enumerated on {target_url}. "
                "Could aid brute-force attacks."
            ),
            evidence=f"User '{username}' found via WPScan",
            recommendation=(
                "Disable user enumeration. "
                "Enforce strong passwords and MFA."
            )
        )
        post_enrich_cve(scan_id, 'wpscan', target_url,
                        cwe_id='CWE-200')
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
            "vulnerabilities": [{
                "title": "WordPress 6.2 XSS in core editor",
                "cvss": {"score": 7.5},
                "references": {"cve": ["2023-12345"]}
            }]
        },
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.7.1"},
                "vulnerabilities": []
            },
            "woocommerce": {
                "version": {"number": "7.0.0"},
                "vulnerabilities": [{
                    "title": "WooCommerce SQL injection in order query",
                    "cvss": {"score": 9.8},
                    "references": {"cve": ["2023-56789"]}
                }]
            }
        },
        "themes":  {"twentytwentythree": {"vulnerabilities": []}},
        "users":   {"admin": {}, "editor": {}}
    }

    with open('/tmp/wpscan_out.json', 'w') as f:
        json.dump(test_data, f)

    findings = parse_wpscan(2, '', 'testwordpress.com')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title'][:65]}")
