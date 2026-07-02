import json
import subprocess
import re
import os
import time
import urllib.parse
from datetime import datetime


# ── NVD API key (optional but strongly recommended) ──────────
# Without a key NVD throttles to ~5 requests / 30s, which makes the
# CVE lookups time out and silently return nothing. Get a free key at
# https://nvd.nist.gov/developers/request-an-api-key and add it to .env:
#     NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
def load_nvd_key():
    key = os.environ.get('NVD_API_KEY', '')
    if key:
        return key.strip()
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('NVD_API_KEY='):
                        return line.split('=', 1)[1].strip()
        except Exception:
            pass
    return ''


_NVD_KEY  = load_nvd_key()
_NVD_LAST = [0.0]   # timestamp of last request, for rate spacing


# ── Configuration Weakness Keywords ──────────────────────────
# These findings should use CWE fallback — NOT NVD keyword search
CONFIG_WEAKNESS_KEYWORDS = [
    'telnet', 'ftp', 'ssh', 'smtp', 'mysql', 'postgresql',
    'mongodb', 'redis', 'smb', 'nfs', 'vnc', 'rdp',
    'directory listing', 'phpinfo', 'http trace',
    'trace method', 'clickjacking', 'x-frame', 'cors',
    'ssl', 'tls', 'empty password', 'default password',
    'anonymous login', 'webdav', 'information disclosure',
    'php easter', 'version disclosure', 'server leaks',
    'mod_negotiation', 'negotiation',
]

# ── Known CVE Signatures ──────────────────────────────────────
# These findings have specific CVEs — search NVD
KNOWN_CVE_SIGNATURES = [
    'vsftpd 2.3.4', 'vsftpd 2.3',
    'unrealircd', 'unreal ircd',
    'samba usermap', 'username map', 'usermap',
    'php cgi', 'cgi argument', 'argument injection',
    'shellshock', 'heartbleed', 'eternalblue',
    'log4shell', 'spring4shell',
    'ms17-010', 'ms08-067',
    'distcc', 'proftpd', 'twiki', 'tikiwiki',
    'webmin', 'phpmyadmin',
    'apache struts', 'jenkins', 'jboss',
    'weblogic', 'coldfusion',
    'drupal', 'joomla', 'wordpress plugin',
    'openssl', 'java rmi', 'java-rmi', 'rmi registry',
    'ingreslock', 'tomcat', 'bindshell', 'bind shell',
    # Nikto/whatweb version-disclosure patterns
    'appears to be outdated',
    'technology detected: apache',
    'technology detected: php',
    'technology detected: nginx',
    'technology detected: mysql',
    'technology detected: openssl',
    'apache/', 'php/', 'nginx/',
]


def is_configuration_weakness(finding):
    combined = (
        f"{finding.get('title', '')} "
        f"{finding.get('description', '')} "
        f"{finding.get('evidence', '')} "
        f"{finding.get('asset', '')}"
    ).lower()
    return any(
        kw in combined
        for kw in CONFIG_WEAKNESS_KEYWORDS
    )


def has_known_cve_signature(finding):
    combined = (
        f"{finding.get('title', '')} "
        f"{finding.get('description', '')} "
        f"{finding.get('evidence', '')}"
    ).lower()
    return any(
        kw in combined
        for kw in KNOWN_CVE_SIGNATURES
    )




def extract_cve_from_text(text):
    if not text:
        return []
    pattern = r'CVE-\d{4}-\d{4,7}'
    cves    = re.findall(pattern, str(text).upper())
    return list(set(cves))


def parse_nvd_response(data):
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        return None

    cve_data   = vulns[0].get('cve', {})
    cve_id_out = cve_data.get('id', '')

    descriptions = cve_data.get('descriptions', [])
    description  = ''
    for d in descriptions:
        if d.get('lang') == 'en':
            description = d.get('value', '')
            break

    published     = cve_data.get('published', '')[:10]
    last_modified = cve_data.get('lastModified', '')[:10]

    metrics  = cve_data.get('metrics', {})
    cvss_v3  = metrics.get('cvssMetricV31', [])
    cvss_v2  = metrics.get('cvssMetricV2', [])

    cvss_score        = None
    cvss_vector       = None
    cvss_severity     = None
    cvss_version      = None
    exploitability    = None
    impact_score      = None
    attack_vector     = None
    attack_complexity = None
    privileges_req    = None
    user_interaction  = None

    if cvss_v3:
        cvss_data         = cvss_v3[0].get('cvssData', {})
        cvss_score        = cvss_data.get('baseScore')
        cvss_vector       = cvss_data.get('vectorString')
        cvss_severity     = cvss_data.get('baseSeverity')
        cvss_version      = '3.1'
        exploitability    = cvss_v3[0].get('exploitabilityScore')
        impact_score      = cvss_v3[0].get('impactScore')
        attack_vector     = cvss_data.get('attackVector')
        attack_complexity = cvss_data.get('attackComplexity')
        privileges_req    = cvss_data.get('privilegesRequired')
        user_interaction  = cvss_data.get('userInteraction')
    elif cvss_v2:
        cvss_data         = cvss_v2[0].get('cvssData', {})
        cvss_score        = cvss_data.get('baseScore')
        cvss_vector       = cvss_data.get('vectorString')
        cvss_severity     = cvss_v2[0].get('baseSeverity')
        cvss_version      = '2.0'
        exploitability    = cvss_v2[0].get('exploitabilityScore')
        impact_score      = cvss_v2[0].get('impactScore')
        attack_vector     = cvss_data.get('accessVector')
        attack_complexity = cvss_data.get('accessComplexity')
        privileges_req    = cvss_data.get('authentication')
        user_interaction  = 'NONE'

    weaknesses = []
    for w in cve_data.get('weaknesses', []):
        for desc in w.get('description', []):
            if desc.get('lang') == 'en':
                weaknesses.append(desc.get('value', ''))

    references = []
    for ref in cve_data.get('references', [])[:5]:
        url_ref = ref.get('url', '')
        tags    = ref.get('tags', [])
        if url_ref:
            references.append({'url': url_ref, 'tags': tags})

    exploit_level = 'Unknown'
    if exploitability is not None:
        if exploitability >= 3.5:
            exploit_level = 'Easy'
        elif exploitability >= 2.0:
            exploit_level = 'Moderate'
        else:
            exploit_level = 'Difficult'

    return {
        'cve_id':            cve_id_out,
        'description':       description,
        'published':         published,
        'last_modified':     last_modified,
        'cvss_score':        cvss_score,
        'cvss_vector':       cvss_vector,
        'cvss_severity':     cvss_severity,
        'cvss_version':      cvss_version,
        'exploitability':    exploitability,
        'exploit_level':     exploit_level,
        'impact_score':      impact_score,
        'attack_vector':     attack_vector,
        'attack_complexity': attack_complexity,
        'privileges_req':    privileges_req,
        'user_interaction':  user_interaction,
        'weaknesses':        weaknesses,
        'references':        references,
        'nvd_url': (
            f"https://nvd.nist.gov/vuln/detail/{cve_id_out}"
        ),
    }


def nvd_curl(url):
    """Robust NVD API GET.

    Adds the API key (if configured), spaces requests to respect NVD
    rate limits, retries with backoff on throttling/timeouts, and prints
    a clear reason on failure instead of silently returning None.
    """
    cmd = [
        'curl', '-s', '--max-time', '40',
        '-H', 'User-Agent: AutoRed/1.0',
        '-H', 'Accept: application/json',
    ]
    if _NVD_KEY:
        cmd += ['-H', f'apiKey: {_NVD_KEY}']
    cmd.append(url)

    # Space out requests: NVD allows ~5/30s without a key, ~50/30s with.
    min_gap = 0.8 if _NVD_KEY else 6.5
    elapsed = time.time() - _NVD_LAST[0]
    if elapsed < min_gap:
        time.sleep(min_gap - elapsed)

    for attempt in range(4):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=50
            )
            _NVD_LAST[0] = time.time()
            out = (result.stdout or '').strip()

            if result.returncode != 0:
                print(f"[!] NVD curl rc={result.returncode} "
                      f"(attempt {attempt + 1}/4)")
            elif not out:
                hint = ("  → add NVD_API_KEY to .env to stop throttling"
                        if not _NVD_KEY else "")
                print(f"[!] NVD empty response — likely rate limit "
                      f"(attempt {attempt + 1}/4){hint}")
            elif out.startswith('<'):
                print(f"[!] NVD returned HTML, not JSON "
                      f"(attempt {attempt + 1}/4)")
            else:
                return json.loads(out)
        except subprocess.TimeoutExpired:
            print(f"[!] NVD curl timed out (attempt {attempt + 1}/4)")
        except json.JSONDecodeError:
            print(f"[!] NVD JSON parse failed (attempt {attempt + 1}/4)")
        except Exception as e:
            print(f"[!] NVD curl error: {e} (attempt {attempt + 1}/4)")

        time.sleep(2 if _NVD_KEY else 7)   # back off before retrying
        _NVD_LAST[0] = time.time()

    print("[!] NVD fetch failed after 4 attempts.")
    return None


def lookup_nvd(cve_id):
    """Step 2 — Verify CVE from Nuclei against NVD API."""
    try:
        url  = (
            f"https://services.nvd.nist.gov/rest/json/"
            f"cves/2.0?cveId={cve_id}"
        )
        print(f"[*] NVD lookup: {cve_id}")
        data = nvd_curl(url)
        if not data:
            return None
        return parse_nvd_response(data)
    except Exception as e:
        print(f"[!] NVD lookup error for {cve_id}: {e}")
        return None


def extract_search_keywords(title, description, asset):
    combined = f"{title} {description}".lower()
    keywords = []

    version_patterns = [
        (r'vsftpd[\s_]?(\d+[\.\d]+)',     'vsftpd'),
        (r'openssh[\s_]?(\d+[\.\dp]+)',   'openssh'),
        (r'apache[\s/]?(\d+[\.\d]+)',     'apache httpd'),
        (r'samba[\s_]?(\d+[\.\d]+)',      'samba'),
        (r'proftpd[\s_]?(\d+[\.\d]+)',    'proftpd'),
        (r'nginx[\s/]?(\d+[\.\d]+)',      'nginx'),
        (r'mysql[\s_]?(\d+[\.\d]+)',      'mysql'),
        (r'postgresql[\s_]?(\d+[\.\d]+)', 'postgresql'),
        (r'php[\s/]?(\d+[\.\d]+)',        'php'),
        (r'tomcat[\s_]?(\d+[\.\d]+)',     'apache tomcat'),
        (r'distcc[\s_]?(\d+[\.\d]+)',     'distcc'),
        (r'openssl[\s_]?(\d+[\.\d]+)',    'openssl'),
        (r'wordpress[\s_]?(\d+[\.\d]+)',  'wordpress'),
        (r'unrealirc[\s_]?(\d+[\.\d]+)', 'unrealircd'),
        (r'unreal[\s_]?(\d+[\.\d]+)',    'unrealircd'),
        (r'drupal[\s_]?(\d+[\.\d]+)',     'drupal'),
        (r'joomla[\s_]?(\d+[\.\d]+)',     'joomla'),
    ]

    for pattern, service in version_patterns:
        matches = re.findall(pattern, combined)
        if matches:
            kw = f"{service} {matches[0]}".strip()
            keywords.append(kw)

    KNOWN_SEARCHES = [
        ('php cgi',              'PHP CGI CVE-2012-1823'),
        ('cgi argument',         'PHP CGI CVE-2012-1823'),
        ('argument injection',   'PHP CGI CVE-2012-1823'),
        ('usermap',              'samba username map'),
        ('username map',         'samba username map'),
        ('unrealircd',           'UnrealIRCd'),
        ('unreal ircd',          'UnrealIRCd'),
        ('distcc',               'distcc'),
        ('java rmi',             'java rmi remote code execution'),
        ('rmi registry',         'java rmi registry'),
        ('ingreslock',           'ingreslock backdoor'),
        ('bindshell',            'remote access backdoor'),
        ('bind shell',           'remote access backdoor'),
        ('twiki',                'twiki remote code execution'),
        ('webmin',               'webmin remote code execution'),
        ('shellshock',           'bash shellshock CVE-2014-6271'),
        ('heartbleed',           'openssl heartbleed CVE-2014-0160'),
        ('eternalblue',          'SMB eternalblue CVE-2017-0144'),
        ('log4shell',            'log4j CVE-2021-44228'),
        ('spring4shell',         'spring framework CVE-2022-22965'),
        ('apache struts',        'apache struts remote code execution'),
        ('jenkins',              'jenkins remote code execution'),
        ('jboss',                'jboss remote code execution'),
        ('weblogic',             'weblogic remote code execution'),
        ('ms08-067',             'windows ms08-067 netapi'),
        ('ms17-010',             'windows ms17-010 eternalblue'),
    ]

    lower_combined = f"{title} {description}".lower()
    for trigger, search_term in KNOWN_SEARCHES:
        if trigger in lower_combined:
            if search_term not in keywords:
                keywords.append(search_term)
            break

    if not keywords:
        security_terms = {
            'injection', 'execution', 'overflow', 'traversal',
            'bypass', 'escalation', 'backdoor', 'exploit',
            'arbitrary', 'command', 'code', 'buffer', 'heap',
            'deserialization', 'xxe', 'ssrf', 'rce', 'lfi',
        }
        stop = {
            'a','an','the','on','in','at','is','are','was',
            'were','be','been','have','has','had','do','does',
            'did','will','would','could','should','may','might',
            'to','of','for','with','from','by','and','or','but',
            'port','service','open','running','detected','found',
            'enabled','exposed','version','server','web','host',
            'network','system','file','data','http','tcp','udp',
            'ssl','tls','this','that','method','allow','using',
            'via','through','over',
        }
        words     = re.sub(r'[^\w\s]', ' ', title).split()
        key_words = []
        for w in words:
            wl = w.lower()
            if (
                len(w) > 3
                and wl not in stop
                and not w.isdigit()
            ):
                if wl in security_terms:
                    key_words.insert(0, w)
                else:
                    key_words.append(w)

        if len(key_words) >= 2:
            keywords.append(' '.join(key_words[:5]))
        if len(key_words) >= 1:
            keywords.append(' '.join(key_words[:3]))

    seen = []
    for k in keywords:
        k = k.strip()
        if k and k not in seen:
            seen.append(k)
    return seen[:4]


def search_nvd_by_keyword(finding):
    title       = finding.get('title', '')
    description = finding.get('description', '')
    asset       = finding.get('asset', '')

    keywords = extract_search_keywords(
        title, description, asset
    )

    if not keywords:
        return None

    for keyword in keywords:
        print(f"[*] NVD keyword search: '{keyword}'")
        encoded = urllib.parse.quote(keyword)

        for url_suffix in [
            '&resultsPerPage=5&cvssV3Severity=CRITICAL',
            '&resultsPerPage=5&cvssV3Severity=HIGH',
            '&resultsPerPage=5',
        ]:
            url  = (
                f"https://services.nvd.nist.gov/rest/json/"
                f"cves/2.0?keywordSearch={encoded}{url_suffix}"
            )
            data = nvd_curl(url)
            if not data:
                continue

            vulns = data.get('vulnerabilities', [])
            if not vulns:
                continue

            best       = None
            best_score = -1

            for vuln in vulns:
                cve_data = vuln.get('cve', {})
                metrics  = cve_data.get('metrics', {})
                cvss_v3  = metrics.get('cvssMetricV31', [])
                cvss_v2  = metrics.get('cvssMetricV2', [])

                score = 0
                if cvss_v3:
                    score = cvss_v3[0].get(
                        'cvssData', {}
                    ).get('baseScore', 0)
                elif cvss_v2:
                    score = cvss_v2[0].get(
                        'cvssData', {}
                    ).get('baseScore', 0)

                if score > best_score:
                    best_score = score
                    best       = vuln

            if best:
                result = parse_nvd_response(
                    {'vulnerabilities': [best]}
                )
                if result and result.get('cvss_score'):
                    result['found_by'] = 'keyword_search'
                    print(
                        f"[+] NVD keyword found: "
                        f"{result.get('cve_id')} "
                        f"CVSS: {result.get('cvss_score')}"
                    )
                    return result

    return None


# get_fallback_data() and PROTOCOL_WEAKNESS_DB were removed: CVSS for
# CWE-classified findings with no CVE is now computed from the CWE via
# backend.cvss_predictor (ML model if trained, else the baseline vector),
# rather than looked up in a hand-typed table.


def get_no_cve_reason(finding):
    """
    Generate a specific, human-readable explanation for why a finding
    has no CVE, based on its type, tool, category, and title.
    Displayed in the UI so analysts understand it is intentional,
    not a pipeline failure.
    """
    title    = (finding.get('title',    '') or '').lower()
    desc     = (finding.get('description', '') or '').lower()
    category = (finding.get('category', '') or '').lower()
    tool     = (finding.get('tool',     '') or '').lower()
    combined = f"{title} {desc} {category}"

    # ── Discovery / recon findings ────────────────────────────
    if tool in ('gobuster', 'ffuf') or \
       'directory found' in combined or \
       'endpoint discovered' in combined:
        if 'htpasswd' in combined or 'htaccess' in combined:
            return (
                "The presence of a sensitive file (e.g. .htpasswd) "
                "is a configuration exposure. CVEs are assigned to "
                "exploitable software bugs, not to files existing at "
                "predictable paths."
            )
        return (
            "This is a directory or endpoint discovery result. "
            "CVEs are assigned to software vulnerabilities, not to "
            "paths or directories being present on a server."
        )

    # ── Live host / HTTP probe ────────────────────────────────
    if tool in ('httpx', 'httprobe') or 'live host' in combined:
        return (
            "This is a host-reachability finding — informational "
            "only. No vulnerability is present, so no CVE applies."
        )

    # ── Technology detection (whatweb) ────────────────────────
    if tool == 'whatweb' or 'technology detected' in combined:
        if 'outdated' in combined or 'appears to be' in combined:
            return (
                "An outdated software version was detected but no "
                "matching CVE was found in NVD, CIRCL, or MITRE. "
                "The risk is represented by the CWE and computed "
                "CVSS score above."
            )
        return (
            "Technology fingerprinting identifies what software is "
            "running — informational only. No specific vulnerability "
            "was detected, so no CVE is assigned."
        )

    # ── Missing / deprecated HTTP security headers ────────────
    if 'header' in combined and any(
        kw in combined for kw in
        ('missing', 'not set', 'deprecated', 'suggested security')
    ):
        return (
            "Missing or deprecated HTTP security headers are a "
            "server misconfiguration. CVEs are assigned to "
            "exploitable software defects, not to absent header "
            "settings."
        )

    # ── Open port — protocol weakness ─────────────────────────
    if 'open port' in combined or category == 'open_port':
        proto_map = {
            'telnet':     'Telnet transmits data in cleartext by design — '
                          'this is a protocol choice, not a software bug.',
            'ftp':        'FTP transmits credentials in cleartext by design — '
                          'this is a protocol choice, not a software bug.',
            'ssh':        'SSH being open is not itself a vulnerability. '
                          'CVEs apply to specific SSH implementation bugs, '
                          'not to the port being open.',
            'smtp':       'SMTP being exposed is a configuration choice. '
                          'No CVE is assigned for the service being open.',
            'nfs':        'An NFS share being accessible is a configuration '
                          'exposure, not a software bug with a CVE.',
            'vnc':        'VNC being open is a configuration exposure. '
                          'CVEs exist for specific VNC implementation bugs, '
                          'not for the service being enabled.',
            'rdp':        'RDP being open is a configuration exposure. '
                          'CVEs apply to specific RDP implementation bugs.',
            'java-rmi':   'Java RMI being open is a configuration exposure. '
                          'CVEs apply to specific RMI exploit payloads, '
                          'not to the port being open.',
            'irc':        'IRC being open is a configuration choice. '
                          'CVEs apply to specific IRC daemon exploits.',
            'mysql':      'MySQL being network-accessible is a configuration '
                          'exposure. CVEs apply to specific database bugs.',
            'rpcbind':    'RPC/portmapper being open is a configuration '
                          'exposure, not a specific software vulnerability.',
            'netbios':    'NetBIOS/SMB exposure is a configuration choice. '
                          'CVEs apply to specific SMB implementation bugs.',
            'exec':       'Remote exec service (rsh) being open is a '
                          'serious configuration exposure with no single CVE.',
            'tcpwrapped': 'Port is TCP-wrapped — service details are '
                          'unavailable for CVE matching.',
        }
        for proto, reason in proto_map.items():
            if proto in combined:
                return reason
        return (
            "An open port indicates a service is running. CVEs are "
            "assigned to specific exploitable bugs in software, not "
            "to ports being open."
        )

    # ── Default / weak credentials ────────────────────────────
    if any(kw in combined for kw in
           ('default login', 'default credential', 'weak credential',
            'ftp weak', 'vnc default')):
        return (
            "Default or weak credentials are a configuration "
            "weakness (CWE-1392 / CWE-521). A CVE is only assigned "
            "when a specific software version ships with documented "
            "hardcoded credentials."
        )

    # ── Empty password ────────────────────────────────────────
    if 'empty password' in combined or 'pgsql empty' in combined:
        return (
            "An empty password is a configuration weakness "
            "(CWE-521). No CVE is assigned for a service being "
            "configured without a password — that is an "
            "administrative decision, not a software bug."
        )

    # ── PHP information disclosure ────────────────────────────
    if any(kw in combined for kw in
           ('phpinfo', 'php easter', 'easter egg')):
        return (
            "PHP's phpinfo() and Easter Egg features are built-in "
            "functionality that expose version and configuration "
            "details. No CVE is assigned for these features being "
            "enabled — it is a deployment configuration choice."
        )

    # ── Directory listing ─────────────────────────────────────
    if 'directory listing' in combined or \
       'directory indexing' in combined or \
       'icons/' in combined:
        return (
            "Directory listing / indexing is a web server "
            "configuration setting. No CVE is assigned for "
            "misconfigured directory browsing."
        )

    # ── HTTP TRACE ────────────────────────────────────────────
    if 'http trace' in combined or 'trace method' in combined:
        return (
            "HTTP TRACE is a protocol method that server "
            "administrators can enable or disable. No CVE is "
            "assigned for the method being active — it is a "
            "configuration choice."
        )

    # ── Clickjacking / X-Frame ────────────────────────────────
    if 'clickjacking' in combined or 'x-frame' in combined:
        return (
            "Missing X-Frame-Options is a security header "
            "configuration issue, not a software bug. No CVE is "
            "assigned for absent HTTP security headers."
        )

    # ── Outdated software (generic) ───────────────────────────
    if 'outdated' in combined or 'appears to be' in combined:
        return (
            "An outdated software version was detected. A CVE "
            "lookup was attempted across NVD, CIRCL, and MITRE "
            "but no matching entry was returned. The risk is "
            "represented by the CWE and computed CVSS score."
        )

    # ── Fallback ──────────────────────────────────────────────
    return (
        "No specific software vulnerability with an assigned CVE "
        "number was identified. This finding represents a "
        "configuration, protocol, or exposure weakness — the risk "
        "is captured by the CWE classification and computed CVSS "
        "score above."
    )


def enrich_finding(finding):
    from backend.mitre_mapper import (
        get_mitre_mapping,
        get_attack_surface_tags,
        get_exploitability_from_nvd,
    )

    title       = finding.get('title', '')
    description = finding.get('description', '')
    evidence    = finding.get('evidence', '')
    combined    = f"{title} {description} {evidence}"

    # ── Step 1: Extract CVE from Nuclei output ───────────────
    cves = extract_cve_from_text(combined)
    print(f"[*] CVEs from Nuclei: {cves if cves else 'none'}")

    # ── Step 2: Multi-source CVE lookup ──────────────────────
    # Queries NVD + CIRCL + MITRE, cross-checks scores, and
    # falls back to Claude API if all sources return nothing.
    nvd_results = {}
    best_cve    = None
    best_score  = -1

    for cve in cves:
        try:
            from backend.cve_multi_source import lookup_cve_multi
            cve_data = lookup_cve_multi(cve, finding)
        except Exception:
            # Graceful fallback to single-source NVD if module missing
            cve_data = lookup_nvd(cve)

        if cve_data and cve_data.get('cvss_score'):
            nvd_results[cve] = cve_data
            score = cve_data.get('cvss_score') or 0
            if score > best_score:
                best_score = score
                best_cve   = cve
                conf = cve_data.get('data_confidence', '')
                print(
                    f"[+] Multi-source: {cve} CVSS: {score} "
                    f"| Confidence: {conf}"
                )

    nvd_best = nvd_results.get(best_cve) if best_cve else None

    # ── Step 3: Known Vulnerability DB + NVD ─────────────────
    if not nvd_best:
        try:
            from backend.weakness_enrichment import (
                enrich_with_weakness,
            )
            weakness_result = enrich_with_weakness(finding)

            if weakness_result.get('cve_data'):
                nvd_best = weakness_result['cve_data']
                best_cve = weakness_result.get('cve_id')
                print(
                    f"[+] Known vuln DB + NVD: "
                    f"{best_cve} CVSS: "
                    f"{nvd_best.get('cvss_score')}"
                )
        except Exception as e:
            print(f"[!] Weakness enrichment error: {e}")

    # ── Step 4: NVD keyword search ────────────────────────────
    if not nvd_best:
        if has_known_cve_signature(finding):
            print(
                "[*] Known CVE signature — "
                "searching NVD by keyword..."
            )
            nvd_best = search_nvd_by_keyword(finding)
            if nvd_best:
                best_cve = nvd_best.get('cve_id')
        elif is_configuration_weakness(finding):
            print(
                "[*] Configuration weakness — "
                "skipping NVD keyword search."
            )
        else:
            # Last chance: if extract_search_keywords pulled a
            # version string (e.g. "apache httpd 2.2.8"), search
            # NVD for it — covers Nikto/whatweb version disclosures.
            title       = finding.get('title', '')
            description = finding.get('description', '')
            asset       = finding.get('asset', '')
            kws = extract_search_keywords(title, description, asset)
            if kws:
                print(
                    f"[*] Version-based NVD search: "
                    f"'{kws[0]}'..."
                )
                nvd_best = search_nvd_by_keyword(finding)
                if nvd_best:
                    best_cve = nvd_best.get('cve_id')
            else:
                print(
                    "[*] Generic recon finding — "
                    "skipping broad NVD search."
                )

    # ── Step 4.5: Claude CVE suggestion → multi-source verify ──
    # If all keyword/version searches still found nothing AND this is
    # not a pure configuration weakness (telnet, FTP, missing headers),
    # ask Claude to suggest the most relevant CVE, then immediately
    # verify that suggestion against NVD + CIRCL + MITRE.
    if not nvd_best and not is_configuration_weakness(finding):
        try:
            from backend.cve_multi_source import (
                claude_suggest_cve,
                lookup_cve_multi,
            )
            suggested = claude_suggest_cve(finding)
            if suggested:
                print(
                    f"[*] Verifying Claude suggestion "
                    f"{suggested} against sources..."
                )
                verified = lookup_cve_multi(suggested, finding)
                if verified and verified.get('cvss_score'):
                    verified['is_ai_suggested'] = True
                    verified['ai_suggested_cve'] = suggested
                    nvd_best = verified
                    best_cve = suggested
                    print(
                        f"[+] AI-suggested CVE verified: "
                        f"{suggested} CVSS "
                        f"{verified.get('cvss_score')} "
                        f"{verified.get('cvss_severity')} "
                        f"| Confidence: "
                        f"{verified.get('data_confidence')}"
                    )
                else:
                    print(
                        f"[!] Claude suggested {suggested} "
                        f"but sources could not verify it — discarding."
                    )
        except Exception as e:
            print(f"[!] Step 4.5 error: {e}")

    # ── Step 5: CWE → CVSS prediction (replaces manual table) ─
    exploit_level  = None
    exploit_reason = None

    # Resolve the CWE first so we can both derive a score from it and
    # gate the GPT phase correctly.
    cwe_data = None
    try:
        from backend.weakness_enrichment import get_cwe_for_finding
        cwe_data = get_cwe_for_finding(finding)
    except Exception:
        pass

    # Compute a CVSS from the CWE (ML model if trained, else the
    # baseline vector) via the official CVSS 3.1 formula — instead of
    # looking the score up in a hand-typed table.
    if not nvd_best and cwe_data and cwe_data.get('cwe_id'):
        try:
            from backend.cvss_predictor import derive_cvss_from_cwe
            nvd_best = derive_cvss_from_cwe(
                cwe_data['cwe_id'], finding
            )
            if nvd_best:
                exploit_level  = nvd_best.get('exploit_level')
                exploit_reason = nvd_best.get('exploit_reason')
                print(
                    f"[+] CVSS derived from {cwe_data['cwe_id']}: "
                    f"{nvd_best.get('cvss_score')} "
                    f"({nvd_best.get('cvss_severity')})"
                )
        except Exception as e:
            print(f"[!] CVSS derivation error: {e}")

    # ── Exploitability from NVD (real-CVE findings) ──────────
    if nvd_best and not exploit_level:
        exploit_level, exploit_reason = \
            get_exploitability_from_nvd(nvd_best)

    # ── Phase 2: GPT Reasoning Layer ─────────────────────────
    # Called ONLY when deterministic enrichment is incomplete
    gpt_result = None
    if not cwe_data or not exploit_level:
        try:
            from backend.gpt_enricher import gpt_classify_finding
            print(
                "[*] Phase 2 — GPT contextual "
                "classification..."
            )
            gpt_result = gpt_classify_finding(
                finding,
                nvd_best or {}
            )
        except Exception as e:
            print(f"[!] GPT phase 2 error: {e}")

    # ── Merge GPT results ─────────────────────────────────────
    if gpt_result:
        if not cwe_data and gpt_result.get('cwe_id'):
            cwe_data = {
                'cwe_id': gpt_result.get('cwe_id', ''),
                'name':   gpt_result.get('cwe_name', ''),
                'url':    gpt_result.get('cwe_url', ''),
                'risk':   gpt_result.get('ai_explanation', ''),
                'source': 'GPT-4o-mini Classification',
            }
            print(
                f"[+] GPT CWE: {cwe_data['cwe_id']} — "
                f"{cwe_data['name']}"
            )

        if not exploit_level and gpt_result.get('exploitability'):
            exploit_level  = gpt_result.get('exploitability')
            exploit_reason = gpt_result.get('ai_explanation', '')

    # ── MITRE ATT&CK + Attack Surface ────────────────────────
    mitre = get_mitre_mapping(finding)
    tags  = get_attack_surface_tags(finding)

    if gpt_result and not mitre and gpt_result.get('mitre_technique'):
        mitre = {
            'tactic':    gpt_result.get('mitre_tactic', ''),
            'tactic_id': '',
            'technique': gpt_result.get('mitre_technique', ''),
            'tech_id':   gpt_result.get('mitre_technique', ''),
            'url':       gpt_result.get('mitre_url', ''),
            'source':    'GPT-4o-mini Classification',
        }

    if gpt_result and gpt_result.get('attack_surface'):
        for tag in gpt_result['attack_surface']:
            if tag not in tags:
                tags.append(tag)

    # ── AI Explanation from GPT ───────────────────────────────
    ai_explanation = None
    if gpt_result and gpt_result.get('ai_explanation'):
        ai_explanation = gpt_result.get('ai_explanation')

    # ── Step 6: Derive CVSS from CWE when no CVE was found ───
    # Most recon findings have no CVE but do get a CWE. Rather than a
    # hand-typed score, compute one from the CWE (ML model if trained,
    # else the baseline table) via the official CVSS 3.1 formula.
    if not nvd_best and cwe_data and cwe_data.get('cwe_id'):
        try:
            from backend.cvss_predictor import derive_cvss_from_cwe
            nvd_best = derive_cvss_from_cwe(
                cwe_data['cwe_id'], finding
            )
            if nvd_best:
                exploit_level  = exploit_level or nvd_best.get('exploit_level')
                exploit_reason = exploit_reason or nvd_best.get('exploit_reason')
                print(
                    f"[+] CVSS derived from {cwe_data['cwe_id']}: "
                    f"{nvd_best.get('cvss_score')} "
                    f"({nvd_best.get('cvss_severity')})"
                )
        except Exception as e:
            print(f"[!] CVSS derivation error: {e}")

    return {
        'cves':           cves,
        'nvd_data':       nvd_results,
        'nvd_best':       nvd_best,
        'best_cvss':      best_score if best_score > 0 else None,
        'best_cve':       best_cve,
        'enriched':       bool(nvd_best),
        'mitre':          mitre,
        'attack_surface': tags,
        'exploit_level':  exploit_level,
        'exploit_reason': exploit_reason,
        'cwe_data':       cwe_data,
        'ai_explanation': ai_explanation,
        'gpt_result':     gpt_result,
        'no_cve_reason':  (
            None if best_cve else (
                # Prefer Claude's contextual explanation (from phase 2)
                # Fall back to the static function for findings where
                # phase 2 didn't fire (e.g. telnet — already has CWE+level)
                (gpt_result.get('no_cve_reason') if gpt_result else None)
                or get_no_cve_reason(finding)
            )
        ),
    }


def get_attack_path_ai(finding, nvd_data=None):
    # ── Try Claude API first ──────────────────────────────────
    try:
        from gui.ai_chat import load_api_key, clean_markdown
        import urllib.request

        api_key = load_api_key()
        if not api_key:
            raise Exception("No Claude API key")

        title       = finding.get('title', '')
        severity    = finding.get('severity', '')
        asset       = finding.get('asset', '')
        description = finding.get('description', '')
        cve_info    = ''

        if nvd_data:
            cve_id   = nvd_data.get('cve_id', '')
            cvss     = nvd_data.get('cvss_score', '')
            cve_desc = nvd_data.get('description', '')[:200]
            if not nvd_data.get('is_fallback'):
                cve_info = (
                    f"CVE: {cve_id}\n"
                    f"CVSS: {cvss}\n"
                    f"Description: {cve_desc}\n"
                )
            else:
                cve_info = (
                    f"Weakness: {cve_id}\n"
                    f"CVSS: {cvss}\n"
                )

        prompt_attack = (
            f"You are an expert penetration tester. "
            f"A recon scan found this vulnerability.\n\n"
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"Asset: {asset}\n"
            f"Description: {description[:300]}\n"
            f"{cve_info}\n"
            f"Give exactly 5 specific next steps for "
            f"exploitation planning. "
            f"Use • bullet points. "
            f"Include specific tool commands. "
            f"No markdown, no bold, no headers."
        )

        prompt_verify = (
            f"You are an expert penetration tester helping "
            f"a student verify a finding.\n\n"
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"Asset: {asset}\n"
            f"Description: {description[:300]}\n"
            f"{cve_info}\n"
            f"Give exactly 5 specific steps to VERIFY and "
            f"CONFIRM this finding is real. "
            f"Use • bullet points. "
            f"Include specific commands. "
            f"No markdown, no bold, no headers."
        )

        def call_claude(prompt):
            payload = json.dumps({
                "model":      "claude-sonnet-4-5-20250929",
                "max_tokens": 600,
                "messages":   [
                    {"role": "user", "content": prompt}
                ],
            }).encode('utf-8')

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type":      "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key":         api_key,
                },
                method="POST"
            )
            with urllib.request.urlopen(
                req, timeout=30
            ) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return clean_markdown(data['content'][0]['text'])

        attack_path  = call_claude(prompt_attack)
        verify_steps = call_claude(prompt_verify)
        return attack_path, verify_steps

    except Exception as claude_err:
        print(
            f"[!] Claude error: {claude_err} — "
            f"trying GPT fallback..."
        )

    # ── Fallback to GPT ───────────────────────────────────────
    try:
        from backend.gpt_enricher import gpt_attack_path
        print("[*] Using GPT for attack path...")
        intel = {}
        if nvd_data:
            intel['cve_id']     = nvd_data.get('cve_id', '')
            intel['cvss_score'] = nvd_data.get('cvss_score', '')
        return gpt_attack_path(finding, intel)
    except Exception as gpt_err:
        print(f"[!] GPT error: {gpt_err}")
        return None, None


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — CVE Enricher Full Pipeline Test")
    print("=" * 60)

    tests = [
        {
            'title':       'HTTP TRACE method enabled',
            'severity':    'Medium',
            'asset':       '192.168.112.130:80',
            'description': 'HTTP TRACE XST attack possible',
            'evidence':    '',
        },
        {
            'title':       'Unreal IRCd Backdoor Detection',
            'severity':    'Critical',
            'asset':       '192.168.112.130:6667',
            'description': 'Unreal IRCd backdoor detected',
            'evidence':    '',
        },
        {
            'title':       'DistCC Remote Code Execution',
            'severity':    'High',
            'asset':       '192.168.112.130:3632',
            'description': 'DistCC daemon RCE',
            'evidence':    '',
        },
        {
            'title':       'PHP CGI Argument Injection',
            'severity':    'High',
            'asset':       '192.168.112.130:80',
            'description': 'PHP CGI argument injection',
            'evidence':    '',
        },
        {
            'title':       'Samba Usermap Script',
            'severity':    'Critical',
            'asset':       '192.168.112.130:445',
            'description': 'Samba username map script RCE',
            'evidence':    '',
        },
        {
            'title':       'vsftpd 2.3.4 Backdoor CVE-2011-2523',
            'severity':    'Critical',
            'asset':       '192.168.112.130:21',
            'description': 'vsftpd backdoor detected',
            'evidence':    '',
        },
        {
            'title':       'Telnet Service Open on Port 23',
            'severity':    'High',
            'asset':       '192.168.112.130:23',
            'description': 'Telnet cleartext protocol',
            'evidence':    '',
        },
        {
            'title':       'PostgreSQL Empty Password',
            'severity':    'Critical',
            'asset':       '192.168.112.130:5432',
            'description': 'PostgreSQL empty password detected',
            'evidence':    '',
        },
    ]

    for t in tests:
        print(f"\n{'─' * 50}")
        print(f"Finding: {t['title']}")
        result = enrich_finding(t)
        nvd    = result.get('nvd_best') or {}
        fb     = nvd.get('is_fallback', False)
        found  = nvd.get('found_by', '')
        source = (
            'CWE Fallback'        if fb   else
            'NVD Keyword Search'  if found else
            'NVD Direct'          if nvd  else
            'No data found'
        )
        cwe = result.get('cwe_data')
        gpt = result.get('gpt_result')
        print(f"  CVE:    {nvd.get('cve_id', 'N/A')}")
        print(f"  CVSS:   {nvd.get('cvss_score', 'N/A')}")
        print(f"  Level:  {result.get('exploit_level', 'N/A')}")
        print(f"  Source: {source}")
        if cwe:
            print(
                f"  CWE:    {cwe['cwe_id']} — {cwe['name']}"
            )
        if gpt:
            print(
                f"  GPT:    {gpt.get('exposure_type', 'N/A')} "
                f"(confidence: {gpt.get('confidence', 'N/A')})"
            )

    print(f"\n{'=' * 60}")
    print("[+] Test complete!")
