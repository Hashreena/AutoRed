import json
import subprocess
import re
import os


# ── CWE Local Mapping ─────────────────────────────────────────
# Based on MITRE CWE definitions
# https://cwe.mitre.org
CWE_RULES = {
    'telnet': {
        'cwe_id': 'CWE-319',
        'name':   'Cleartext Transmission of Sensitive Information',
        'url':    'https://cwe.mitre.org/data/definitions/319.html',
        'risk':   'Protocol weakness — credentials transmitted in cleartext',
    },
    'ftp': {
        'cwe_id': 'CWE-319',
        'name':   'Cleartext Transmission of Sensitive Information',
        'url':    'https://cwe.mitre.org/data/definitions/319.html',
        'risk':   'Protocol weakness — credentials and data in cleartext',
    },
    'empty password': {
        'cwe_id': 'CWE-521',
        'name':   'Weak Password Requirements',
        'url':    'https://cwe.mitre.org/data/definitions/521.html',
        'risk':   'No password protection on service',
    },
    'default password': {
        'cwe_id': 'CWE-1392',
        'name':   'Use of Default Credentials',
        'url':    'https://cwe.mitre.org/data/definitions/1392.html',
        'risk':   'Default credentials not changed after deployment',
    },
    'anonymous login': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'Service accessible without any authentication',
    },
    'directory listing': {
        'cwe_id': 'CWE-548',
        'name':   'Exposure of Information Through Directory Listing',
        'url':    'https://cwe.mitre.org/data/definitions/548.html',
        'risk':   'Web server exposes file structure to attackers',
    },
    'phpinfo': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Server configuration and version information exposed',
    },
    'php easter': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'PHP version and configuration information exposed',
    },
    'information disclosure': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Sensitive information exposed to unauthorized parties',
    },
    'version disclosure': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Software version information aids attacker reconnaissance',
    },
    'server leaks': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Server header leaks version and technology information',
    },
    'http trace': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'HTTP TRACE enables Cross-Site Tracing (XST) attacks',
    },
    'trace method': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'HTTP TRACE enables XST bypassing HttpOnly cookies',
    },
    'clickjacking': {
        'cwe_id': 'CWE-1021',
        'name':   'Improper Restriction of Rendered UI Layers or Frames',
        'url':    'https://cwe.mitre.org/data/definitions/1021.html',
        'risk':   'Missing X-Frame-Options allows UI redressing attacks',
    },
    'x-frame': {
        'cwe_id': 'CWE-1021',
        'name':   'Improper Restriction of Rendered UI Layers or Frames',
        'url':    'https://cwe.mitre.org/data/definitions/1021.html',
        'risk':   'Missing X-Frame-Options header allows clickjacking',
    },
    'cors': {
        'cwe_id': 'CWE-942',
        'name':   'Permissive Cross-domain Policy with Untrusted Domains',
        'url':    'https://cwe.mitre.org/data/definitions/942.html',
        'risk':   'CORS misconfiguration allows cross-origin data theft',
    },
    'vnc': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'Remote desktop accessible without proper authentication',
    },
    'ssh': {
        'cwe_id': 'CWE-307',
        'name':   'Improper Restriction of Excessive Authentication Attempts',
        'url':    'https://cwe.mitre.org/data/definitions/307.html',
        'risk':   'SSH service may be vulnerable to brute force attacks',
    },
    'smtp': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'SMTP exposed allows user enumeration and relay abuse',
    },
    'mysql': {
        'cwe_id': 'CWE-284',
        'name':   'Improper Access Control',
        'url':    'https://cwe.mitre.org/data/definitions/284.html',
        'risk':   'Database exposed on network without access controls',
    },
    'postgresql': {
        'cwe_id': 'CWE-521',
        'name':   'Weak Password Requirements',
        'url':    'https://cwe.mitre.org/data/definitions/521.html',
        'risk':   'PostgreSQL accessible with empty or default password',
    },
    'mongodb': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'MongoDB accessible without authentication',
    },
    'redis': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'Redis accessible without authentication',
    },
    'smb': {
        'cwe_id': 'CWE-284',
        'name':   'Improper Access Control',
        'url':    'https://cwe.mitre.org/data/definitions/284.html',
        'risk':   'SMB exposed allows credential relay and file access',
    },
    'nfs': {
        'cwe_id': 'CWE-306',
        'name':   'Missing Authentication for Critical Function',
        'url':    'https://cwe.mitre.org/data/definitions/306.html',
        'risk':   'NFS share mountable without authentication',
    },
    'webdav': {
        'cwe_id': 'CWE-434',
        'name':   'Unrestricted Upload of File with Dangerous Type',
        'url':    'https://cwe.mitre.org/data/definitions/434.html',
        'risk':   'WebDAV misconfiguration allows malicious file upload',
    },
    'ssl': {
        'cwe_id': 'CWE-326',
        'name':   'Inadequate Encryption Strength',
        'url':    'https://cwe.mitre.org/data/definitions/326.html',
        'risk':   'Weak SSL/TLS configuration allows traffic decryption',
    },
    'tls': {
        'cwe_id': 'CWE-326',
        'name':   'Inadequate Encryption Strength',
        'url':    'https://cwe.mitre.org/data/definitions/326.html',
        'risk':   'Weak TLS configuration detected',
    },
    'rdp': {
        'cwe_id': 'CWE-307',
        'name':   'Improper Restriction of Excessive Authentication Attempts',
        'url':    'https://cwe.mitre.org/data/definitions/307.html',
        'risk':   'RDP exposed may allow brute force attacks',
    },
    'mod_negotiation': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Apache mod_negotiation allows filename enumeration',
    },
    'negotiation': {
        'cwe_id': 'CWE-200',
        'name':   'Exposure of Sensitive Information to Unauthorized Actor',
        'url':    'https://cwe.mitre.org/data/definitions/200.html',
        'risk':   'Apache mod_negotiation filename enumeration',
    },
    'backdoor': {
        'cwe_id': 'CWE-912',
        'name':   'Hidden Functionality',
        'url':    'https://cwe.mitre.org/data/definitions/912.html',
        'risk':   'Backdoor allows unauthorized remote access',
    },
    'bindshell': {
        'cwe_id': 'CWE-912',
        'name':   'Hidden Functionality',
        'url':    'https://cwe.mitre.org/data/definitions/912.html',
        'risk':   'Bind shell provides direct command execution',
    },
    'bind shell': {
        'cwe_id': 'CWE-912',
        'name':   'Hidden Functionality',
        'url':    'https://cwe.mitre.org/data/definitions/912.html',
        'risk':   'Bind shell provides direct command execution',
    },
    'sql injection': {
        'cwe_id': 'CWE-89',
        'name':   'Improper Neutralization of SQL Commands',
        'url':    'https://cwe.mitre.org/data/definitions/89.html',
        'risk':   'SQL injection allows database manipulation',
    },
    'xss': {
        'cwe_id': 'CWE-79',
        'name':   'Improper Neutralization of Input During Web Page Generation',
        'url':    'https://cwe.mitre.org/data/definitions/79.html',
        'risk':   'Cross-site scripting allows script injection',
    },
    'cross-site scripting': {
        'cwe_id': 'CWE-79',
        'name':   'Improper Neutralization of Input During Web Page Generation',
        'url':    'https://cwe.mitre.org/data/definitions/79.html',
        'risk':   'XSS allows attacker script execution in victim browser',
    },
    'file upload': {
        'cwe_id': 'CWE-434',
        'name':   'Unrestricted Upload of File with Dangerous Type',
        'url':    'https://cwe.mitre.org/data/definitions/434.html',
        'risk':   'Unrestricted file upload may lead to RCE',
    },
    'path traversal': {
        'cwe_id': 'CWE-22',
        'name':   'Improper Limitation of a Pathname to a Restricted Directory',
        'url':    'https://cwe.mitre.org/data/definitions/22.html',
        'risk':   'Path traversal allows access to restricted files',
    },
    'directory traversal': {
        'cwe_id': 'CWE-22',
        'name':   'Improper Limitation of a Pathname to a Restricted Directory',
        'url':    'https://cwe.mitre.org/data/definitions/22.html',
        'risk':   'Directory traversal allows access outside web root',
    },
    'command injection': {
        'cwe_id': 'CWE-78',
        'name':   'Improper Neutralization of Special Elements in OS Command',
        'url':    'https://cwe.mitre.org/data/definitions/78.html',
        'risk':   'OS command injection allows arbitrary command execution',
    },
    'buffer overflow': {
        'cwe_id': 'CWE-121',
        'name':   'Stack-based Buffer Overflow',
        'url':    'https://cwe.mitre.org/data/definitions/121.html',
        'risk':   'Buffer overflow may allow code execution',
    },
    'csrf': {
        'cwe_id': 'CWE-352',
        'name':   'Cross-Site Request Forgery',
        'url':    'https://cwe.mitre.org/data/definitions/352.html',
        'risk':   'CSRF allows unauthorized actions on behalf of users',
    },
    'ssrf': {
        'cwe_id': 'CWE-918',
        'name':   'Server-Side Request Forgery',
        'url':    'https://cwe.mitre.org/data/definitions/918.html',
        'risk':   'SSRF allows server to make unintended requests',
    },
    'xxe': {
        'cwe_id': 'CWE-611',
        'name':   'Improper Restriction of XML External Entity Reference',
        'url':    'https://cwe.mitre.org/data/definitions/611.html',
        'risk':   'XXE allows reading internal files via XML parsing',
    },
    'deserialization': {
        'cwe_id': 'CWE-502',
        'name':   'Deserialization of Untrusted Data',
        'url':    'https://cwe.mitre.org/data/definitions/502.html',
        'risk':   'Unsafe deserialization may lead to RCE',
    },
    'open redirect': {
        'cwe_id': 'CWE-601',
        'name':   'URL Redirection to Untrusted Site',
        'url':    'https://cwe.mitre.org/data/definitions/601.html',
        'risk':   'Open redirect used for phishing attacks',
    },
    'weak cipher': {
        'cwe_id': 'CWE-326',
        'name':   'Inadequate Encryption Strength',
        'url':    'https://cwe.mitre.org/data/definitions/326.html',
        'risk':   'Weak encryption cipher allows traffic decryption',
    },
    'heartbleed': {
        'cwe_id': 'CWE-125',
        'name':   'Out-of-bounds Read',
        'url':    'https://cwe.mitre.org/data/definitions/125.html',
        'risk':   'Heartbleed leaks server memory including private keys',
    },
    'shellshock': {
        'cwe_id': 'CWE-78',
        'name':   'OS Command Injection',
        'url':    'https://cwe.mitre.org/data/definitions/78.html',
        'risk':   'Shellshock allows arbitrary command execution via bash',
    },
}


def get_cwe_for_finding(finding):
    title       = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    combined    = f"{title} {description}"

    for keyword, cwe_data in CWE_RULES.items():
        if keyword in combined:
            return cwe_data

    return None


def extract_version_from_finding(finding):
    title       = finding.get('title', '')
    description = finding.get('description', '')
    evidence    = finding.get('evidence', '')
    combined    = f"{title} {description} {evidence}"

    version_patterns = [
        (r'vsftpd[\s_]?(\d+[\.\d]+)',      'vsftpd'),
        (r'openssh[\s_]?(\d+[\.\dp]+)',    'openssh'),
        (r'apache[\s_/]?(\d+[\.\d]+)',     'apache'),
        (r'samba[\s_]?(\d+[\.\d]+)',       'samba'),
        (r'proftpd[\s_]?(\d+[\.\d]+)',     'proftpd'),
        (r'nginx[\s_/]?(\d+[\.\d]+)',      'nginx'),
        (r'mysql[\s_]?(\d+[\.\d]+)',       'mysql'),
        (r'php[\s_/]?(\d+[\.\d]+)',        'php'),
        (r'tomcat[\s_]?(\d+[\.\d]+)',      'tomcat'),
        (r'openssl[\s_]?(\d+[\.\d]+)',     'openssl'),
        (r'wordpress[\s_]?(\d+[\.\d]+)',   'wordpress'),
        (r'drupal[\s_]?(\d+[\.\d]+)',      'drupal'),
        (r'unrealircd[\s_]?(\d+[\.\d]+)', 'unrealircd'),
        (r'unreal[\s_]?(\d+[\.\d]+)',     'unrealircd'),
        (r'webmin[\s_]?(\d+[\.\d]+)',      'webmin'),
        (r'distcc[\s_]?(\d+[\.\d]+)',      'distcc'),
        (r'postgresql[\s_]?(\d+[\.\d]+)',  'postgresql'),
        (r'postgres[\s_]?(\d+[\.\d]+)',   'postgresql'),
        (r'joomla[\s_]?(\d+[\.\d]+)',      'joomla'),
        (r'spring[\s_]?(\d+[\.\d]+)',      'spring'),
        (r'log4j[\s_]?(\d+[\.\d]+)',       'log4j'),
    ]

    for pattern, service in version_patterns:
        matches = re.findall(
            pattern, combined, re.IGNORECASE
        )
        if matches:
            return service, matches[0]

    return None, None


def lookup_known_vuln_db(finding):
    db_path = os.path.join(
        os.path.dirname(__file__),
        'known_vulnerabilities.json'
    )

    if not os.path.exists(db_path):
        print(
            f"[!] known_vulnerabilities.json not found "
            f"at {db_path}"
        )
        return None

    try:
        with open(db_path, 'r') as f:
            db = json.load(f)
    except Exception as e:
        print(f"[!] Error loading known_vulnerabilities.json: {e}")
        return None

    title       = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    evidence    = finding.get('evidence', '').lower()
    combined    = f"{title} {description} {evidence}"

    service, version = extract_version_from_finding(finding)

    for entry in db:
        product = entry.get('product', '').lower()
        ver     = entry.get('version', '').lower()

        if product not in combined:
            continue

        if not ver:
            print(
                f"[*] Known vuln DB match: "
                f"{entry['name']} → {entry['cve']}"
            )
            return entry

        if version and version.startswith(ver):
            print(
                f"[*] Known vuln DB version match: "
                f"{entry['name']} → {entry['cve']}"
            )
            return entry

        if ver and ver in combined:
            print(
                f"[*] Known vuln DB keyword match: "
                f"{entry['name']} → {entry['cve']}"
            )
            return entry

    return None


def fetch_cve_from_nvd(cve_id):
    try:
        url    = (
            f"https://services.nvd.nist.gov/rest/json/"
            f"cves/2.0?cveId={cve_id}"
        )
        result = subprocess.run(
            [
                'curl', '-s', '--max-time', '20',
                '--retry', '2',
                '--retry-delay', '1',
                '-H', 'User-Agent: AutoRed/1.0',
                '-H', 'Accept: application/json',
                url
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0 or not result.stdout.strip():
            print(f"[!] curl failed for {cve_id}")
            return None

        if result.stdout.strip().startswith('<'):
            print(f"[!] NVD returned HTML for {cve_id}")
            return None

        data  = json.loads(result.stdout)
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return None

        cve_data = vulns[0].get('cve', {})
        metrics  = cve_data.get('metrics', {})
        cvss_v3  = metrics.get('cvssMetricV31', [])
        cvss_v2  = metrics.get('cvssMetricV2', [])

        cvss_score        = None
        cvss_severity     = None
        cvss_version      = None
        cvss_vector       = None
        exploitability    = None
        attack_vector     = None
        attack_complexity = None
        privileges_req    = None
        user_interaction  = None

        if cvss_v3:
            d                 = cvss_v3[0].get('cvssData', {})
            cvss_score        = d.get('baseScore')
            cvss_severity     = d.get('baseSeverity')
            cvss_version      = '3.1'
            cvss_vector       = d.get('vectorString')
            exploitability    = cvss_v3[0].get(
                'exploitabilityScore'
            )
            attack_vector     = d.get('attackVector')
            attack_complexity = d.get('attackComplexity')
            privileges_req    = d.get('privilegesRequired')
            user_interaction  = d.get('userInteraction')
        elif cvss_v2:
            d                 = cvss_v2[0].get('cvssData', {})
            cvss_score        = d.get('baseScore')
            cvss_severity     = cvss_v2[0].get('baseSeverity')
            cvss_version      = '2.0'
            cvss_vector       = d.get('vectorString')
            exploitability    = cvss_v2[0].get(
                'exploitabilityScore'
            )
            attack_vector     = d.get('accessVector')
            attack_complexity = d.get('accessComplexity')
            privileges_req    = d.get('authentication')
            user_interaction  = 'NONE'

        descriptions = cve_data.get('descriptions', [])
        description  = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        weaknesses = []
        for w in cve_data.get('weaknesses', []):
            for desc in w.get('description', []):
                if desc.get('lang') == 'en':
                    weaknesses.append(desc.get('value', ''))

        exploit_level = 'Unknown'
        if exploitability is not None:
            if exploitability >= 3.5:
                exploit_level = 'Easy'
            elif exploitability >= 2.0:
                exploit_level = 'Moderate'
            else:
                exploit_level = 'Difficult'

        return {
            'cve_id':            cve_id,
            'description':       description,
            'cvss_score':        cvss_score,
            'cvss_severity':     cvss_severity,
            'cvss_version':      cvss_version,
            'cvss_vector':       cvss_vector,
            'exploitability':    exploitability,
            'exploit_level':     exploit_level,
            'attack_vector':     attack_vector,
            'attack_complexity': attack_complexity,
            'privileges_req':    privileges_req,
            'user_interaction':  user_interaction,
            'weaknesses':        weaknesses,
            'published':         cve_data.get(
                'published', ''
            )[:10],
            'last_modified':     cve_data.get(
                'lastModified', ''
            )[:10],
            'nvd_url': (
                f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            ),
        }

    except Exception as e:
        print(f"[!] NVD fetch error for {cve_id}: {e}")
        return None


def enrich_with_weakness(finding):
    result = {
        'cve_id':      None,
        'cvss_score':  None,
        'cve_data':    None,
        'cwe_data':    None,
        'source':      None,
        'is_fallback': False,
    }

    # Step 1 — Check known vulnerability DB
    known = lookup_known_vuln_db(finding)
    if known:
        cve_id   = known.get('cve', '')
        nvd_data = fetch_cve_from_nvd(cve_id)
        if nvd_data:
            result['cve_id']     = cve_id
            result['cvss_score'] = nvd_data.get('cvss_score')
            result['cve_data']   = nvd_data
            result['source']     = 'Known Vulnerability DB + NVD API'
            # Also get CWE
            cwe = get_cwe_for_finding(finding)
            if cwe:
                result['cwe_data'] = cwe
            return result

    # Step 2 — Get CWE mapping
    cwe = get_cwe_for_finding(finding)
    if cwe:
        result['cwe_data']    = cwe
        result['source']      = 'CWE Reference (MITRE)'
        result['is_fallback'] = True
        print(
            f"[*] CWE mapped: "
            f"{cwe['cwe_id']} — {cwe['name']}"
        )

    return result


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — Weakness Enrichment Module Test")
    print("=" * 60)

    tests = [
        {
            'title':       'vsftpd 2.3.4 Backdoor',
            'description': 'vsftpd 2.3.4 detected',
            'evidence':    '',
            'asset':       '192.168.112.130:21',
        },
        {
            'title':       'Telnet Service on Port 23',
            'description': 'Telnet cleartext protocol',
            'evidence':    '',
            'asset':       '192.168.112.130:23',
        },
        {
            'title':       'PostgreSQL Empty Password',
            'description': 'PostgreSQL empty password',
            'evidence':    '',
            'asset':       '192.168.112.130:5432',
        },
        {
            'title':       'PHP Easter Egg Information Disclosure',
            'description': 'PHP easter egg disclosure',
            'evidence':    '',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'Directory Listing Enabled',
            'description': 'Web server directory listing',
            'evidence':    '',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'HTTP TRACE Method Enabled',
            'description': 'HTTP TRACE XST attack possible',
            'evidence':    '',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'UnrealIRCd Backdoor Detection',
            'description': 'Unreal IRCd backdoor detected',
            'evidence':    '',
            'asset':       '192.168.112.130:6667',
        },
        {
            'title':       'Samba Usermap Script RCE',
            'description': 'Samba username map script RCE',
            'evidence':    '',
            'asset':       '192.168.112.130:445',
        },
        {
            'title':       'DistCC Remote Code Execution',
            'description': 'DistCC daemon allows RCE',
            'evidence':    '',
            'asset':       '192.168.112.130:3632',
        },
        {
            'title':       'PHP CGI Argument Injection',
            'description': 'PHP CGI argument injection',
            'evidence':    '',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'Apache mod_negotiation Filename Enumeration',
            'description': 'mod_negotiation enabled',
            'evidence':    '',
            'asset':       '192.168.112.130:80',
        },
    ]

    for t in tests:
        print(f"\n{'─' * 50}")
        print(f"Finding: {t['title']}")
        result = enrich_with_weakness(t)
        cve    = result.get('cve_id')
        cve_d  = result.get('cve_data') or {}
        cwe    = result.get('cwe_data')
        print(f"  CVE:    {cve or 'None — no direct CVE'}")
        print(f"  CVSS:   {cve_d.get('cvss_score', 'N/A')}")
        if cwe:
            print(
                f"  CWE:    {cwe['cwe_id']} "
                f"— {cwe['name']}"
            )
            print(f"  Risk:   {cwe['risk']}")
        print(f"  Source: {result.get('source', 'None')}")

    print(f"\n{'=' * 60}")
    print("[+] Test complete!")
