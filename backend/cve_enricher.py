import json
import subprocess
import re
import os
import urllib.parse
from datetime import datetime


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
    'openssl', 'java rmi', 'rmi registry',
    'ingreslock', 'tomcat', 'bindshell', 'bind shell',
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


# ── CWE/Protocol Fallback DB ──────────────────────────────────
PROTOCOL_WEAKNESS_DB = {
    'telnet': {
        'cve_id':           'No CVE — Protocol Weakness',
        'description':      'Telnet transmits all data in cleartext.',
        'cvss_score':        7.5,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'Cleartext protocol, remotely exploitable',
        'weaknesses':  ['CWE-319 — Cleartext Transmission'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/319.html',
        'is_fallback': True,
    },
    'ftp': {
        'cve_id':           'No CVE — Protocol Weakness',
        'description':      'FTP transmits credentials in cleartext.',
        'cvss_score':        7.5,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'Cleartext credentials, potential anonymous access',
        'weaknesses':  ['CWE-319 — Cleartext Transmission'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/319.html',
        'is_fallback': True,
    },
    'vnc': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'VNC exposed without authentication.',
        'cvss_score':        9.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'CRITICAL',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication, full desktop access',
        'weaknesses':  ['CWE-306 — Missing Authentication'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/306.html',
        'is_fallback': True,
    },
    'smtp': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'SMTP exposed without authentication.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Moderate',
        'exploit_reason':    'User enumeration and open relay possible',
        'weaknesses':  ['CWE-306 — Missing Authentication'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/306.html',
        'is_fallback': True,
    },
    'mysql': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'MySQL exposed on network.',
        'cvss_score':        8.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'LOW',
        'user_interaction':  'NONE',
        'exploitability':    3.1,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Remotely exploitable, brute force possible',
        'weaknesses':  ['CWE-284 — Improper Access Control'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/284.html',
        'is_fallback': True,
    },
    'postgresql': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'PostgreSQL with empty or default password.',
        'cvss_score':        9.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'CRITICAL',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'Default empty password, no auth needed',
        'weaknesses':  ['CWE-521 — Weak Password Requirements'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/521.html',
        'is_fallback': True,
    },
    'smb': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'SMB exposed, relay attacks possible.',
        'cvss_score':        8.1,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'HIGH',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    2.2,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Multiple attack vectors including relay',
        'weaknesses':  ['CWE-284 — Improper Access Control'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/284.html',
        'is_fallback': True,
    },
    'nfs': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'NFS share mountable without auth.',
        'cvss_score':        7.5,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication required',
        'weaknesses':  ['CWE-306 — Missing Authentication'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/306.html',
        'is_fallback': True,
    },
    'directory listing': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Web server directory listing enabled.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication, browser accessible',
        'weaknesses':  ['CWE-548 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/548.html',
        'is_fallback': True,
    },
    'phpinfo': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'phpinfo() page publicly accessible.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication, directly accessible',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
    'ssh': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'SSH service exposed.',
        'cvss_score':        5.9,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'HIGH',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    2.2,
        'exploit_level':     'Difficult',
        'exploit_reason':    'Requires credentials or known exploit',
        'weaknesses':  ['CWE-307 — Brute Force'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/307.html',
        'is_fallback': True,
    },
    'webdav': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'WebDAV enabled, file upload possible.',
        'cvss_score':        9.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'CRITICAL',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'File upload possible, potential RCE',
        'weaknesses':  ['CWE-434 — Unrestricted File Upload'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/434.html',
        'is_fallback': True,
    },
    'http trace': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'HTTP TRACE enabled — XST possible.',
        'cvss_score':        5.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'REQUIRED',
        'exploitability':    2.8,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Requires user interaction, bypasses HttpOnly',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
    'trace': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'HTTP TRACE method enabled.',
        'cvss_score':        5.8,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'REQUIRED',
        'exploitability':    2.8,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Bypasses HttpOnly cookie protection',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
    'mod_negotiation': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Apache mod_negotiation filename enumeration.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication, information disclosure',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
    'negotiation': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Apache mod_negotiation filename enumeration.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'No authentication, information disclosure',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
    'clickjacking': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Missing X-Frame-Options allows clickjacking.',
        'cvss_score':        6.1,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'REQUIRED',
        'exploitability':    2.8,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Requires user interaction, UI redressing',
        'weaknesses':  ['CWE-1021 — UI Redressing'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/1021.html',
        'is_fallback': True,
    },
    'x-frame': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Missing X-Frame-Options allows clickjacking.',
        'cvss_score':        6.1,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'REQUIRED',
        'exploitability':    2.8,
        'exploit_level':     'Moderate',
        'exploit_reason':    'Requires user interaction, UI redressing',
        'weaknesses':  ['CWE-1021 — UI Redressing'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/1021.html',
        'is_fallback': True,
    },
    'cors': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'CORS misconfiguration detected.',
        'cvss_score':        7.5,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'Cross-origin data theft possible',
        'weaknesses':  ['CWE-942 — Permissive CORS Policy'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/942.html',
        'is_fallback': True,
    },
    'ssl': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'SSL/TLS misconfiguration detected.',
        'cvss_score':        7.4,
        'cvss_version':      '3.1',
        'cvss_severity':     'HIGH',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'HIGH',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    2.2,
        'exploit_level':     'Difficult',
        'exploit_reason':    'Requires MITM, traffic decryption',
        'weaknesses':  ['CWE-326 — Weak Encryption'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/326.html',
        'is_fallback': True,
    },
    'information disclosure': {
        'cve_id':           'No CVE — Configuration Weakness',
        'description':      'Sensitive information disclosed.',
        'cvss_score':        5.3,
        'cvss_version':      '3.1',
        'cvss_severity':     'MEDIUM',
        'cvss_vector':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'published':         'N/A',
        'last_modified':     'N/A',
        'attack_vector':     'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_req':    'NONE',
        'user_interaction':  'NONE',
        'exploitability':    3.9,
        'exploit_level':     'Easy',
        'exploit_reason':    'Passive gathering, no auth needed',
        'weaknesses':  ['CWE-200 — Information Exposure'],
        'references':  [],
        'nvd_url':     'https://cwe.mitre.org/data/definitions/200.html',
        'is_fallback': True,
    },
}


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
    try:
        result = subprocess.run(
            [
                'curl', '-s', '--max-time', '15',
                '-H', 'User-Agent: AutoRed/1.0',
                url
            ],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        if result.stdout.strip().startswith('<'):
            return None
        return json.loads(result.stdout)
    except Exception:
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


def get_fallback_data(finding):
    title       = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    asset       = finding.get('asset', '').lower()
    combined    = f"{title} {description} {asset}"

    for keyword, data in PROTOCOL_WEAKNESS_DB.items():
        if keyword in combined:
            exploit_level  = data.get('exploit_level', 'Unknown')
            exploit_reason = data.get('exploit_reason', '')
            cve            = data.get('cve_id', 'N/A')
            print(
                f"[*] Protocol fallback '{keyword}': "
                f"CVE={cve} Level={exploit_level}"
            )
            return data, exploit_level, exploit_reason

    return None, None, None


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

    # ── Step 2: Verify with NVD API ──────────────────────────
    nvd_results = {}
    best_cve    = None
    best_score  = -1

    for cve in cves:
        nvd_data = lookup_nvd(cve)
        if nvd_data and nvd_data.get('cvss_score'):
            nvd_results[cve] = nvd_data
            score = nvd_data.get('cvss_score') or 0
            if score > best_score:
                best_score = score
                best_cve   = cve
                print(
                    f"[+] NVD direct: {cve} "
                    f"CVSS: {score}"
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

    # ── Step 4: NVD keyword (known signatures only) ───────────
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
            print(
                "[*] Generic recon finding — "
                "skipping broad NVD search."
            )

    # ── Step 5: Protocol/CWE fallback ────────────────────────
    exploit_level  = None
    exploit_reason = None

    if not nvd_best:
        print("[*] Using protocol/CWE fallback...")
        nvd_best, exploit_level, exploit_reason = \
            get_fallback_data(finding)

    # ── Exploitability from NVD ───────────────────────────────
    if nvd_best and not exploit_level:
        exploit_level, exploit_reason = \
            get_exploitability_from_nvd(nvd_best)

    # ── CWE data ──────────────────────────────────────────────
    cwe_data = None
    try:
        from backend.weakness_enrichment import get_cwe_for_finding
        cwe_data = get_cwe_for_finding(finding)
    except Exception:
        pass

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
