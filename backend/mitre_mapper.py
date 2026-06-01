import json
import subprocess
import re
import os

MITRE_CACHE_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'storage',
    'mitre_attack_cache.json'
)
MITRE_GITHUB_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_mitre_cache = None


def download_mitre_data():
    print("[*] Downloading MITRE ATT&CK dataset from GitHub...")
    result = subprocess.run(
        [
            'curl', '-s', '--max-time', '30',
            '-H', 'User-Agent: AutoRed/1.0',
            MITRE_GITHUB_URL
        ],
        capture_output=True,
        text=True,
        timeout=35
    )
    if result.returncode != 0 or not result.stdout.strip():
        print("[!] Failed to download MITRE ATT&CK data")
        return None
    try:
        data = json.loads(result.stdout)
        os.makedirs(
            os.path.dirname(MITRE_CACHE_FILE), exist_ok=True
        )
        with open(MITRE_CACHE_FILE, 'w') as f:
            json.dump(data, f)
        print("[+] MITRE ATT&CK dataset downloaded and cached!")
        return data
    except Exception as e:
        print(f"[!] Failed to parse MITRE data: {e}")
        return None


def load_mitre_data():
    global _mitre_cache
    if _mitre_cache:
        return _mitre_cache

    if os.path.exists(MITRE_CACHE_FILE):
        try:
            with open(MITRE_CACHE_FILE, 'r') as f:
                _mitre_cache = json.load(f)
            print("[*] MITRE ATT&CK loaded from cache")
            return _mitre_cache
        except Exception:
            pass

    data = download_mitre_data()
    if data:
        _mitre_cache = data
    return _mitre_cache


def get_all_techniques():
    data = load_mitre_data()
    if not data:
        return []

    techniques = []
    for obj in data.get('objects', []):
        if (
            obj.get('type') == 'attack-pattern'
            and not obj.get('revoked', False)
            and not obj.get('x_mitre_deprecated', False)
        ):
            tech_id  = ''
            tech_url = ''
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tech_id  = ref.get('external_id', '')
                    tech_url = ref.get('url', '')
                    break

            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(
                        phase.get('phase_name', '')
                        .replace('-', ' ').title()
                    )

            description = obj.get('description', '')[:300]
            name        = obj.get('name', '')
            platforms   = obj.get('x_mitre_platforms', [])

            techniques.append({
                'id':          tech_id,
                'name':        name,
                'tactics':     tactics,
                'tactic':      tactics[0] if tactics else '',
                'description': description,
                'url':         tech_url,
                'platforms':   platforms,
            })

    return techniques


def search_mitre_by_keyword(finding):
    title       = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    asset       = finding.get('asset', '').lower()
    combined    = f"{title} {description} {asset}"

    # ── Priority mappings — specific findings first ───────────
    # Order matters: specific matches must come before generic
    PRIORITY_MAPPINGS = [

        # Credential weaknesses
        ('empty password',       'Valid Accounts'),
        ('default password',     'Valid Accounts'),
        ('default credentials',  'Valid Accounts'),
        ('anonymous login',      'Valid Accounts'),
        ('blank password',       'Valid Accounts'),
        ('weak password',        'Valid Accounts'),

        # Information disclosure
        ('php easter',           'System Information Discovery'),
        ('phpbb',                'System Information Discovery'),
        ('phpinfo',              'System Information Discovery'),
        ('version disclosure',   'Software Discovery'),
        ('information disclosure','System Information Discovery'),
        ('server leaks',         'System Information Discovery'),
        ('server version',       'Software Discovery'),
        ('software version',     'Software Discovery'),

        # Directory and file discovery
        ('directory listing',    'File and Directory Discovery'),
        ('directory indexing',   'File and Directory Discovery'),
        ('directory traversal',  'File and Directory Discovery'),
        ('admin page',           'File and Directory Discovery'),
        ('admin portal',         'File and Directory Discovery'),

        # Backdoors and shells
        ('bindshell',            'Command and Scripting Interpreter'),
        ('bind shell',           'Command and Scripting Interpreter'),
        ('backdoor',             'Exploit Public-Facing Application'),
        ('ingreslock',           'Command and Scripting Interpreter'),

        # Remote access services
        ('telnet',               'Remote Services'),
        ('vnc',                  'Remote Services'),
        ('rdp',                  'Remote Desktop Protocol'),
        ('ftp',                  'Remote Services'),
        ('ssh',                  'Remote Services'),

        # Database services
        ('postgresql',           'Valid Accounts'),
        ('pgsql',                'Valid Accounts'),
        ('mysql',                'Valid Accounts'),
        ('mongodb',              'Valid Accounts'),
        ('redis',                'Valid Accounts'),

        # Brute force — only if explicitly mentioned
        ('brute force',          'Brute Force'),
        ('hydra',                'Brute Force'),
        ('password spraying',    'Brute Force'),
        ('dictionary attack',    'Brute Force'),
        ('credential stuffing',  'Brute Force'),

        # HTTP methods and headers
        ('http trace',           'System Information Discovery'),
        ('trace method',         'System Information Discovery'),
        ('xst',                  'System Information Discovery'),
        ('clickjacking',         'System Information Discovery'),
        ('x-frame',              'System Information Discovery'),
        ('cors',                 'System Information Discovery'),

        # Known exploits
        ('samba usermap',        'Exploit Public-Facing Application'),
        ('username map',         'Exploit Public-Facing Application'),
        ('usermap',              'Exploit Public-Facing Application'),
        ('php cgi',              'Exploit Public-Facing Application'),
        ('cgi argument',         'Exploit Public-Facing Application'),
        ('argument injection',   'Exploit Public-Facing Application'),
        ('distcc',               'Exploit Public-Facing Application'),
        ('unrealircd',           'Exploit Public-Facing Application'),
        ('unreal ircd',          'Exploit Public-Facing Application'),
        ('shellshock',           'Exploit Public-Facing Application'),
        ('heartbleed',           'Exploit Public-Facing Application'),
        ('eternalblue',          'Exploit Public-Facing Application'),
        ('log4shell',            'Exploit Public-Facing Application'),
        ('vsftpd',               'Exploit Public-Facing Application'),
        ('proftpd',              'Exploit Public-Facing Application'),

        # Web application attacks
        ('sql injection',        'Exploit Public-Facing Application'),
        ('sqli',                 'Exploit Public-Facing Application'),
        ('xss',                  'Exploit Public-Facing Application'),
        ('cross-site scripting', 'Exploit Public-Facing Application'),
        ('lfi',                  'Exploit Public-Facing Application'),
        ('rfi',                  'Exploit Public-Facing Application'),
        ('ssrf',                 'Exploit Public-Facing Application'),
        ('xxe',                  'Exploit Public-Facing Application'),
        ('deserialization',      'Exploit Public-Facing Application'),
        ('file upload',          'Server Software Component'),
        ('webdav',               'Server Software Component'),

        # Web technology detection
        ('apache',               'Exploit Public-Facing Application'),
        ('nginx',                'Exploit Public-Facing Application'),
        ('iis',                  'Exploit Public-Facing Application'),
        ('tomcat',               'Exploit Public-Facing Application'),
        ('wordpress',            'Exploit Public-Facing Application'),
        ('drupal',               'Exploit Public-Facing Application'),
        ('joomla',               'Exploit Public-Facing Application'),
        ('phpmyadmin',           'Exploit Public-Facing Application'),
        ('webmin',               'Exploit Public-Facing Application'),

        # Network services
        ('smb',                  'SMB/Windows Admin Shares'),
        ('samba',                'Exploit Public-Facing Application'),
        ('nfs',                  'Network Share Discovery'),
        ('rpc',                  'Remote Procedure Calls'),
        ('snmp',                 'Network Sniffing'),
        ('smtp',                 'Email Collection'),
        ('irc',                  'Application Layer Protocol'),

        # Email and collection
        ('email',                'Email Collection'),
        ('harvester',            'Gather Victim Identity Information'),

        # Recon and scanning — generic, goes LAST
        ('subdomain',            'Active Scanning'),
        ('dns',                  'Active Scanning'),
        ('port scan',            'Active Scanning'),
        ('open port',            'Active Scanning'),
        ('service detection',    'Software Discovery'),
    ]

    search_term = None
    for keyword, technique_name in PRIORITY_MAPPINGS:
        if keyword in combined:
            search_term = technique_name
            break

    if not search_term:
        stop = {
            'a','an','the','on','in','at','is','are','was',
            'detected','found','enabled','open','service',
            'port','running','version','server','web','http',
        }
        words = re.sub(r'[^\w\s]', ' ', title).split()
        key_words = [
            w for w in words
            if len(w) > 4 and w.lower() not in stop
        ]
        search_term = (
            ' '.join(key_words[:3]) if key_words else title
        )

    print(f"[*] MITRE ATT&CK search: '{search_term}'")

    techniques = get_all_techniques()
    if not techniques:
        print("[!] MITRE data not available")
        return None

    search_lower  = search_term.lower()
    exact_matches = []
    partial_matches = []

    for tech in techniques:
        name_lower = tech['name'].lower()
        desc_lower = tech['description'].lower()

        if search_lower in name_lower:
            exact_matches.append(tech)
        elif any(
            word in name_lower or word in desc_lower
            for word in search_lower.split()
            if len(word) > 3
        ):
            partial_matches.append(tech)

    matches = exact_matches or partial_matches
    if not matches:
        return None

    best = matches[0]

    TACTIC_ID_MAP = {
        'Reconnaissance':        'TA0043',
        'Resource Development':  'TA0042',
        'Initial Access':        'TA0001',
        'Execution':             'TA0002',
        'Persistence':           'TA0003',
        'Privilege Escalation':  'TA0004',
        'Defense Evasion':       'TA0005',
        'Credential Access':     'TA0006',
        'Discovery':             'TA0007',
        'Lateral Movement':      'TA0008',
        'Collection':            'TA0009',
        'Command And Control':   'TA0011',
        'Exfiltration':          'TA0010',
        'Impact':                'TA0040',
    }

    tactic      = best.get('tactic', '')
    tactic_id   = TACTIC_ID_MAP.get(tactic, 'TA0000')
    tech_id     = best.get('id', '')
    subtechnique = tech_id if '.' in tech_id else None

    print(
        f"[+] MITRE match: {tech_id} — "
        f"{best['name']} ({tactic})"
    )

    return {
        'tactic':       tactic,
        'tactic_id':    tactic_id,
        'technique':    best['name'],
        'tech_id':      tech_id,
        'subtechnique': subtechnique,
        'description':  best.get('description', '')[:200],
        'url':          best.get('url', ''),
        'source':       'MITRE ATT&CK GitHub (Live)',
    }


def get_mitre_mapping(finding):
    return search_mitre_by_keyword(finding)


def get_attack_surface_tags(finding):
    title       = finding.get('title', '').lower()
    description = finding.get('description', '').lower()
    asset       = finding.get('asset', '').lower()
    combined    = f"{title} {description} {asset}"

    TAG_RULES = {
        'Internet Facing': [
            'http', 'https', 'web', 'apache', 'nginx',
            'port 80', 'port 443', 'wordpress', 'phpmyadmin',
            'subdomain', 'domain', 'tomcat', 'iis',
        ],
        'Internal Service': [
            'mysql', 'postgresql', 'mongodb', 'redis',
            'smb', 'nfs', 'rmi', 'port 3306', 'port 5432',
            'port 27017', 'port 6379', 'internal',
        ],
        'Authentication Portal': [
            'login', 'auth', 'password', 'credential',
            'htpasswd', 'phpmyadmin', 'admin', 'ssh',
            'telnet', 'vnc', 'ftp', 'rdp',
        ],
        'Admin Interface': [
            'phpmyadmin', 'admin', 'webmin', 'cpanel',
            'management', 'console', 'dashboard', 'panel',
            'control',
        ],
        'Exposed Service': [
            'telnet', 'ftp', 'vnc', 'rdp', 'bindshell',
            'shell', 'backdoor', 'port 23', 'port 21',
            'port 5900', 'port 3389', 'port 1524',
            'distcc', 'irc', 'port 6667',
        ],
        'Database': [
            'mysql', 'postgresql', 'pgsql', 'postgres',
            'mssql', 'oracle', 'mongodb', 'redis',
            'database', 'db', 'port 3306', 'port 5432',
            'port 1433',
        ],
        'Remote Access': [
            'ssh', 'telnet', 'vnc', 'rdp', 'ftp',
            'bindshell', 'shell', 'remote', 'port 22',
            'port 23', 'port 3389', 'port 5900',
        ],
        'Credential Weakness': [
            'empty password', 'default password',
            'default credentials', 'anonymous login',
            'blank password', 'weak password',
            'no password',
        ],
        'Information Disclosure': [
            'php easter', 'phpbb', 'phpinfo',
            'information disclosure', 'version disclosure',
            'server leaks', 'server version',
            'directory listing', 'directory indexing',
        ],
    }

    tags = []
    for tag, keywords in TAG_RULES.items():
        for kw in keywords:
            if kw in combined:
                tags.append(tag)
                break

    return tags if tags else ['Exposed Service']


def get_exploitability_from_nvd(nvd_data):
    if not nvd_data:
        return None, None

    exploit_level = nvd_data.get('exploit_level', 'Unknown')
    details       = []

    av = nvd_data.get('attack_vector', '')
    ac = nvd_data.get('attack_complexity', '')
    pr = nvd_data.get('privileges_req', '')
    ui = nvd_data.get('user_interaction', '')

    if av == 'NETWORK':
        details.append('Remotely exploitable')
    elif av == 'ADJACENT_NETWORK':
        details.append('Adjacent network required')
    elif av == 'LOCAL':
        details.append('Local access required')

    if ac == 'LOW':
        details.append('low complexity')
    elif ac == 'HIGH':
        details.append('high complexity')

    if pr == 'NONE':
        details.append('no privileges needed')
    elif pr == 'LOW':
        details.append('low privileges needed')
    elif pr == 'HIGH':
        details.append('admin privileges needed')

    if ui == 'NONE':
        details.append('no user interaction')
    elif ui == 'REQUIRED':
        details.append('user interaction required')

    reason = ', '.join(details) if details else ''
    return exploit_level, reason


def refresh_mitre_cache():
    global _mitre_cache
    _mitre_cache = None
    if os.path.exists(MITRE_CACHE_FILE):
        os.remove(MITRE_CACHE_FILE)
    return download_mitre_data()


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — Live MITRE ATT&CK Lookup Test")
    print("=" * 60)

    print("\n[*] Loading MITRE ATT&CK dataset...")
    techniques = get_all_techniques()
    print(f"[+] Loaded {len(techniques)} techniques")

    tests = [
        {
            'title':       'Telnet Service Open on Port 23',
            'description': 'Telnet cleartext protocol',
            'asset':       '192.168.112.130:23',
        },
        {
            'title':       'vsftpd 2.3.4 Backdoor CVE-2011-2523',
            'description': 'FTP backdoor detected',
            'asset':       '192.168.112.130:21',
        },
        {
            'title':       'Bind Shell on Port 1524',
            'description': 'Metasploit bindshell',
            'asset':       '192.168.112.130:1524',
        },
        {
            'title':       'HTTP TRACE method enabled',
            'description': 'HTTP TRACE XST attack',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'PHP CGI Argument Injection',
            'description': 'PHP CGI argument injection',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'Samba Usermap Script',
            'description': 'Samba username map script RCE',
            'asset':       '192.168.112.130:445',
        },
        {
            'title':       'MySQL Exposed on Port 3306',
            'description': 'MySQL database exposed',
            'asset':       '192.168.112.130:3306',
        },
        {
            'title':       'PostgreSQL Empty Password',
            'description': 'PostgreSQL empty password detected',
            'asset':       '192.168.112.130:5432',
        },
        {
            'title':       'PHP Easter Egg Information Disclosure',
            'description': 'PHP easter egg found via ?=PHPB8B5F2A0',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'Directory Listing Enabled',
            'description': 'Web server directory listing',
            'asset':       '192.168.112.130:80',
        },
        {
            'title':       'Unreal IRCd Backdoor',
            'description': 'Unreal IRCd backdoor detection',
            'asset':       '192.168.112.130:6667',
        },
    ]

    for t in tests:
        print(f"\n{'─' * 50}")
        print(f"Finding: {t['title']}")
        result = get_mitre_mapping(t)
        tags   = get_attack_surface_tags(t)
        if result:
            print(
                f"  Tactic:    "
                f"{result['tactic']} ({result['tactic_id']})"
            )
            print(
                f"  Technique: "
                f"{result['technique']} ({result['tech_id']})"
            )
            print(f"  Source:    {result['source']}")
        else:
            print("  No MITRE mapping found")
        print(f"  Tags:      {tags}")

    print(f"\n{'=' * 60}")
    print("[+] Test complete!")
