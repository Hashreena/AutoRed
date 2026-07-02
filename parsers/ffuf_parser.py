import sys, os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))
import json
from backend.db import insert_finding, insert_audit_log
from backend.path_enricher import enrich_path, best_severity, post_enrich_finding

HIGH_INTEREST = [
    'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
    'dashboard', 'config', 'backup', 'secret', 'private',
    'uploads', 'shell', 'cmd', 'console', 'manage'
]

def get_severity(path, status_code):
    path_lower = path.lower()
    for keyword in HIGH_INTEREST:
        if keyword in path_lower:
            return 'High'
    if status_code in [401, 403]:
        return 'Medium'
    if status_code == 200:
        return 'Low'
    return 'Info'

def parse_ffuf(scan_id, raw_output, target):
    findings = []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse ffuf output: {e}")
        return findings

    results = data.get('results', [])

    if not results:
        print("[*] ffuf: no endpoints discovered")
        insert_audit_log(scan_id, 'ffuf_parsed', '0 endpoints found')
        return findings

    for result in results:
        url        = result.get('url', '')
        status     = result.get('status', 0)
        length     = result.get('length', 0)
        words      = result.get('words', 0)
        path       = url.split('/')[-1] if '/' in url else url
        base_sev   = get_severity(path, status)

        # ── Path enrichment ──────────────────────────────
        enrichment = enrich_path(url, status)

        if enrichment:
            severity        = best_severity(base_sev, enrichment['severity'])
            cwe_id          = enrichment['cwe_id']
            cvss_score      = enrichment['cvss_score']
            description     = (
                f"{enrichment['description']}\n\n"
                f"URL: {url}  |  HTTP {status}  |  "
                f"Response: {length} bytes, {words} words.\n"
                f"CWE: {cwe_id}  |  CVSS: {cvss_score}"
            )
            recommendation  = enrichment['recommendation']
            title           = (
                f"[{cwe_id}] Sensitive endpoint: "
                f"{url} [{status}]"
            )
        else:
            severity       = base_sev
            cwe_id         = None
            cvss_score     = None
            description    = (
                f"ffuf discovered endpoint '{url}' "
                f"returning HTTP {status}. "
                f"Response size: {length} bytes, {words} words."
            )
            title          = f"Endpoint discovered: {url} [{status}]"
            if severity == 'High':
                recommendation = (
                    f"'{path}' appears to be a sensitive path. "
                    "Restrict access immediately."
                )
            elif severity == 'Medium':
                recommendation = (
                    f"Endpoint returns {status}. "
                    "Review access controls."
                )
            else:
                recommendation = (
                    f"Review whether '{url}' "
                    "should be publicly accessible."
                )

        evidence = (
            f"ffuf found: {url} "
            f"— status {status}, length {length}"
        )

        finding = {
            'scan_id':        scan_id,
            'tool':           'ffuf',
            'asset':          url,
            'category':       'endpoint',
            'severity':       severity,
            'title':          title,
            'description':    description,
            'evidence':       evidence,
            'recommendation': recommendation,
        }
        findings.append(finding)

        insert_finding(
            scan_id=scan_id, tool='ffuf',
            asset=url, category='endpoint',
            severity=severity, title=title,
            description=description, evidence=evidence,
            recommendation=recommendation
        )

        # Write CWE + CVSS into DB if enriched
        if cwe_id:
            post_enrich_finding(
                scan_id, 'ffuf', url, cwe_id, cvss_score
            )

        print(f"[{severity.upper()}] {title}")

    insert_audit_log(
        scan_id, 'ffuf_parsed',
        f"{len(findings)} endpoints found"
    )
    print(f"[+] ffuf parser done — {len(findings)} findings saved")
    return findings


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    ))
    from backend.db import init_db

    raw = json.dumps({"results": [
        {"url": "http://192.168.112.130/admin",    "status": 403, "length": 290,   "words": 12},
        {"url": "http://192.168.112.130/phpMyAdmin","status": 200, "length": 4096, "words": 98},
        {"url": "http://192.168.112.130/.git",     "status": 200, "length": 1234,  "words": 56},
        {"url": "http://192.168.112.130/.env",     "status": 200, "length": 512,   "words": 24},
        {"url": "http://192.168.112.130/index.php","status": 200, "length": 891,   "words": 45},
    ]})

    findings = parse_ffuf(2, raw, '192.168.112.130')
    print(f"\nTotal: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
