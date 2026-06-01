import re
import os
import json
import ipaddress
from datetime import datetime


# ============================================================
# AutoRed Scope Validation Policy
# Based on official Malaysian and international sources:
#
# 1. NACSA Malaysia — Critical National Information
#    Infrastructure (CNII) Sector Classification
#    https://www.nacsa.gov.my/cni.php
#
# 2. Bank Negara Malaysia (BNM) — Licensed Financial
#    Institutions List
#    https://www.bnm.gov.my
#
# 3. MAMPU — Malaysian Government Portal Directory
#    https://www.malaysia.gov.my
#
# 4. MYNIC — Malaysian Domain Registry
#    https://www.mynic.my
#
# 5. IANA Root Zone Database — TLD Registry
#    https://www.iana.org/domains/root/db
#
# 6. NIST SP 800-82 — ICS Security Guidelines
#    https://csrc.nist.gov/publications/detail/sp/800-82
# ============================================================


# ── Authorized Targets Whitelist ──────────────────────────────
# Targets explicitly authorized by the operator
# Stored in storage/authorized_targets.json
AUTHORIZED_TARGETS_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'storage',
    'authorized_targets.json'
)


def load_authorized_targets():
    if not os.path.exists(AUTHORIZED_TARGETS_FILE):
        return []
    try:
        with open(AUTHORIZED_TARGETS_FILE, 'r') as f:
            data = json.load(f)
            return [
                t.lower().strip()
                for t in data.get('targets', [])
            ]
    except Exception:
        return []


def save_authorized_target(
    target, authorized_by, engagement, notes=''
):
    os.makedirs(
        os.path.dirname(AUTHORIZED_TARGETS_FILE),
        exist_ok=True
    )

    data = {}
    if os.path.exists(AUTHORIZED_TARGETS_FILE):
        try:
            with open(AUTHORIZED_TARGETS_FILE, 'r') as f:
                data = json.load(f)
        except Exception:
            data = {}

    if 'targets' not in data:
        data['targets']        = []
    if 'authorizations' not in data:
        data['authorizations'] = []

    target = target.lower().strip()
    if target not in data['targets']:
        data['targets'].append(target)

    data['authorizations'].append({
        'target':        target,
        'authorized_by': authorized_by,
        'engagement':    engagement,
        'notes':         notes,
        'authorized_on': datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S'
        ),
    })

    with open(AUTHORIZED_TARGETS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

    print(
        f"[+] Target '{target}' authorized "
        f"by {authorized_by} for {engagement}"
    )
    return True


def is_authorized_target(target):
    authorized = load_authorized_targets()
    target     = target.lower().strip()
    for auth in authorized:
        if target == auth or target.endswith('.' + auth):
            return True
    return False


def remove_authorized_target(target):
    if not os.path.exists(AUTHORIZED_TARGETS_FILE):
        return False
    try:
        with open(AUTHORIZED_TARGETS_FILE, 'r') as f:
            data = json.load(f)
        target = target.lower().strip()
        if target in data.get('targets', []):
            data['targets'].remove(target)
            with open(AUTHORIZED_TARGETS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            print(
                f"[+] '{target}' removed from whitelist"
            )
            return True
    except Exception as e:
        print(f"[!] Error removing target: {e}")
    return False


def get_all_authorizations():
    if not os.path.exists(AUTHORIZED_TARGETS_FILE):
        return []
    try:
        with open(AUTHORIZED_TARGETS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('authorizations', [])
    except Exception:
        return []


# ── Exact Blocklist ──────────────────────────────────────────
BLOCKLIST = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
]


# ── Blocked Domains ──────────────────────────────────────────
BLOCKED_DOMAINS = [

    # ── Major Public Services ─────────────────────────────
    'google.com',       'gmail.com',
    'youtube.com',      'googleapis.com',
    'facebook.com',     'instagram.com',
    'whatsapp.com',     'meta.com',
    'microsoft.com',    'azure.com',
    'office.com',       'outlook.com',
    'live.com',         'hotmail.com',
    'bing.com',
    'amazon.com',       'amazonaws.com',
    'apple.com',        'icloud.com',
    'twitter.com',      'x.com',
    'linkedin.com',     'tiktok.com',
    'snapchat.com',     'reddit.com',
    'netflix.com',      'spotify.com',
    'wikipedia.org',    'wikimedia.org',
    'openai.com',       'anthropic.com',
    'cloudflare.com',   'github.com',
    'gitlab.com',

    # ── Malaysian Banking & Finance ───────────────────────
    # Source: BNM Licensed Financial Institutions
    # https://www.bnm.gov.my/licensed-institutions
    'maybank.com',          'maybank2u.com',
    'cimb.com',             'cimbclicks.com',
    'publicbank.com.my',    'pbebank.com',
    'rhbbank.com',          'rhbgroup.com',
    'hongleongbank.com',    'hlb.com.my',
    'affinbank.com',        'affinislamic.com',
    'alliancebank.com.my',  'allianceonline.com.my',
    'ambankgroup.com',      'ambank.com.my',
    'bankislam.com',        'bankislam.com.my',
    'bsn.com.my',
    'muamalat.com.my',
    'hsbc.com.my',
    'ocbc.com.my',
    'standardchartered.com.my',
    'uob.com.my',
    'citibank.com.my',
    'bankrakyat.com.my',
    'agro.bank',
    'smebank.com.my',
    'exim.com.my',
    'sc.com.my',
    'bursamalaysia.com',

    # International banks
    'bankofamerica.com',    'chase.com',
    'wellsfargo.com',       'barclays.com',
    'lloydsbankinggroup.com',
    'paypal.com',           'stripe.com',
    'visa.com',             'mastercard.com',

    # ── Malaysian Government Portals ──────────────────────
    # Source: MAMPU Government Portal Directory
    # https://www.malaysia.gov.my
    'malaysia.gov.my',      'mygov.my',
    'myeg.com.my',          'eperolehan.gov.my',
    'spr.gov.my',           'lhdn.gov.my',
    'hasil.gov.my',         'bnm.gov.my',
    'pdrm.gov.my',          'kpn.gov.my',
    'jpn.gov.my',           'jpa.gov.my',
    'mkn.gov.my',           'kdn.gov.my',
    'mot.gov.my',           'moh.gov.my',
    'moe.gov.my',           'mohe.gov.my',
    'kkmm.gov.my',          'mosti.gov.my',
    'miti.gov.my',          'treasury.gov.my',
    'agc.gov.my',           'pmo.gov.my',
    'parlimen.gov.my',      'sprm.gov.my',
    'mampu.gov.my',         'nacsa.gov.my',
    'cybersecurity.my',

    # ── Malaysian Critical Infrastructure ─────────────────
    # Source: NACSA CNII Sector Classification
    # https://www.nacsa.gov.my/cni.php

    # Energy
    'tnb.com.my',           'petronas.com.my',
    'petronasgas.com',      'sapuraenergy.com',
    'dialog.com.my',

    # Telecommunications
    'telekom.com.my',       'tm.com.my',
    'maxis.com.my',         'celcom.com.my',
    'digi.com.my',          'u.com.my',
    'yes.my',               'unifi.com.my',

    # Water
    'airselangor.com.my',   'syabas.com.my',
    'pbapp.com.my',         'sajh.com.my',

    # Transportation
    'airasia.com',          'malaysiaairlines.com',
    'mas.com.my',           'ktmb.com.my',
    'prasarana.com.my',     'myrapid.com.my',

    # Health
    'kpj.com.my',           'ihh.com.my',
    'pantai.com.my',        'sunwaymedical.com',
    'columbia-asia.com',

    # Emergency & Defence
    'bomba.gov.my',         'rela.gov.my',
    'mod.gov.my',           'mindef.gov.my',
    'atm.mil.my',
]


# ── Blocked TLDs ─────────────────────────────────────────────
# Source: MYNIC + IANA Root Zone Database
BLOCKED_TLDS = [
    # Malaysian Government & Military
    '.gov.my',      '.mil.my',
    '.edu.my',      '.police.gov.my',
    '.army.mil.my', '.navy.mil.my',
    '.airforce.mil.my',

    # International Government
    '.gov',         '.mil',
    '.govt.nz',     '.gov.uk',
    '.gov.au',      '.gov.sg',
    '.gov.in',      '.gov.ph',
    '.gov.id',      '.gov.th',
    '.gov.bn',      '.gov.us',
    '.gc.ca',       '.gov.vn',
    '.gov.kh',      '.gov.la',
    '.gov.mm',

    # Military subdomains
    '.army.mil',    '.navy.mil',
    '.af.mil',      '.mod.uk',
    '.defence.gov.au',

    # Education
    '.edu',         '.ac.my',
    '.ac.uk',       '.edu.sg',
    '.edu.au',      '.edu.ph',
    '.ac.id',
]


# ── Blocked Keywords ─────────────────────────────────────────
# Source: NACSA Malaysia CNII Sector Definition
BLOCKED_KEYWORDS = [

    # Defence & Security (CNII Sector 4)
    'police', 'pdrm', 'army', 'navy', 'airforce',
    'military', 'defense', 'defence', 'mindef',
    'armed.forces', 'interpol', 'fbi', 'cia', 'nsa',
    'dea', 'atf', 'homeland', 'pentagon', 'nato',
    'bomba', 'coastguard',

    # Government (CNII Sector 1)
    'parliament', 'parlimen', 'congress', 'senate',
    'whitehouse', 'kremlin', 'judiciary', 'mahkamah',
    'sprm', 'macc', 'suruhanjaya', 'jabatan',
    'kementerian', 'perkeso', 'kwsp', 'epf',
    'lhdn', 'hasil',

    # Health (CNII Sector 7)
    'hospital', 'klinik', 'clinic', 'healthcare',
    'medical', 'pharmacy', 'farmasi', 'ambulance',

    # Energy (CNII Sector 5)
    'nuclear', 'powerplant', 'power.plant',
    'electric.grid', 'tenaga', 'petroleum',
    'pipeline', 'refinery',

    # Water (CNII Sector 6)
    'waterworks', 'water.treatment', 'rawatan.air',
    'sewage', 'pembetungan', 'reservoir',

    # Emergency Services (CNII Sector 10)
    'rescue', 'penyelamat',

    # Banking & Finance (CNII Sector 2)
    'centralbank', 'bank.negara', 'bursa',
    'federalreserve',

    # Transport (CNII Sector 3)
    'airport', 'lapangan.terbang', 'seaport',
    'pelabuhan', 'railway', 'keretapi',

    # Other critical
    'prison', 'jail', 'correctional',
]


def is_private_ip(target):
    try:
        ip = ipaddress.ip_address(target.split('/')[0])
        return ip.is_private
    except ValueError:
        return False


def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_cidr(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(target):
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(target))


def validate_target(target):
    if not target:
        return {
            'allowed':    False,
            'authorized': False,
            'reason':     'Target cannot be empty.',
        }

    target = (
        target.strip().lower()
        .replace('https://', '')
        .replace('http://', '')
        .split('/')[0]
        .split(':')[0]
    )

    # ── Check authorized whitelist FIRST ─────────────────
    # Companies with authorization can override blocklist
    if is_authorized_target(target):
        return {
            'allowed':    True,
            'authorized': True,
            'reason': (
                f'"{target}" is explicitly authorized '
                f'for this engagement. '
                f'See Authorized Targets Manager.'
            ),
        }

    # ── Check exact blocklist ────────────────────────────
    if target in BLOCKLIST:
        return {
            'allowed':    False,
            'authorized': False,
            'reason': (
                f'"{target}" is blocked. '
                f'Scanning localhost or loopback '
                f'is not permitted.'
            ),
        }

    # ── Allow private IPs ────────────────────────────────
    if is_valid_ip(target):
        if is_private_ip(target):
            return {
                'allowed':    True,
                'authorized': False,
                'reason': (
                    f'Private IP {target} allowed '
                    f'for internal/lab pentesting.'
                ),
            }
        else:
            return {
                'allowed':    True,
                'authorized': False,
                'reason': (
                    f'Public IP {target} — ensure '
                    f'you have written authorization.'
                ),
            }

    if is_valid_cidr(target):
        return {
            'allowed':    True,
            'authorized': False,
            'reason':     f'Valid CIDR range: {target}',
        }

    # ── Check blocked TLDs ───────────────────────────────
    for tld in BLOCKED_TLDS:
        if target.endswith(tld):
            return {
                'allowed':    False,
                'authorized': False,
                'reason': (
                    f'"{target}" is blocked. '
                    f'"{tld}" domains are protected '
                    f'under MYNIC/IANA policy. '
                    f'Use the Authorized Targets Manager '
                    f'to override with written authorization.'
                ),
            }

    # ── Check blocked domains ────────────────────────────
    for domain in BLOCKED_DOMAINS:
        if target == domain or target.endswith('.' + domain):
            return {
                'allowed':    False,
                'authorized': False,
                'reason': (
                    f'"{target}" is a protected domain '
                    f'under NACSA CNII or BNM policy. '
                    f'Use the Authorized Targets Manager '
                    f'to override with written authorization.'
                ),
            }

    # ── Check blocked keywords ───────────────────────────
    for keyword in BLOCKED_KEYWORDS:
        if keyword in target:
            return {
                'allowed':    False,
                'authorized': False,
                'reason': (
                    f'"{target}" contains restricted '
                    f'keyword "{keyword}" (NACSA CNII). '
                    f'Use the Authorized Targets Manager '
                    f'to override with written authorization.'
                ),
            }

    # ── Validate domain format ───────────────────────────
    if is_valid_domain(target):
        return {
            'allowed':    True,
            'authorized': False,
            'reason': (
                f'Domain "{target}" is valid. '
                f'Ensure you have written authorization.'
            ),
        }

    return {
        'allowed':    False,
        'authorized': False,
        'reason': (
            f'"{target}" is not a valid IP, '
            f'CIDR, or domain format.'
        ),
    }


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — Scope Validation Test")
    print("=" * 60)

    # Test adding authorization
    print("\n[*] Testing authorization whitelist...")
    save_authorized_target(
        'maybank.com',
        'Ahmad Fauzi — CISO CyberShield Sdn Bhd',
        'Q3 2025 External Pentest — Ref SOW-2025-001',
        'Authorized for web application testing only'
    )

    tests = [
        # Should be ALLOWED
        ('192.168.112.130',     'Private IP — pentest lab'),
        ('192.168.1.1',         'Private IP — corporate'),
        ('10.0.0.1',            'Private IP — internal'),
        ('10.0.0.0/24',         'Private CIDR range'),
        ('45.33.32.156',        'Public IP — nmap scanme'),
        ('scanme.nmap.org',     'Nmap official test site'),
        ('testphp.vulnweb.com', 'Acunetix test site'),
        ('example.com',         'Generic test domain'),
        # Authorized override
        ('maybank.com',         'Malaysian bank — AUTHORIZED'),
        ('online.maybank.com',  'Maybank subdomain — AUTHORIZED'),

        # Should be BLOCKED
        ('localhost',           'Loopback'),
        ('127.0.0.1',           'Loopback IP'),
        ('0.0.0.0',             'Null IP'),
        ('google.com',          'Major public service'),
        ('cimb.com',            'Malaysian bank — BNM'),
        ('pdrm.gov.my',         'Malaysian police — CNII'),
        ('parliament.gov.my',   'Government — CNII'),
        ('tnb.com.my',          'Energy — CNII'),
        ('hospital.com.my',     'Health keyword — CNII'),
        ('nuclear.com',         'Energy keyword — CNII'),
        ('mod.gov.my',          'Defence — CNII'),
        ('airasia.com',         'Transport — CNII'),
        ('army.mil.my',         'Military TLD'),
        ('utm.edu.my',          'Education TLD'),
        ('cia.gov',             'US Government TLD'),
        ('',                    'Empty target'),
    ]

    allowed_count = 0
    blocked_count = 0

    for target, description in tests:
        result = validate_target(target)
        ok     = result['allowed']
        auth   = result.get('authorized', False)

        if ok:
            allowed_count += 1
            tag = '✅ AUTHORIZED' if auth else '✅ ALLOWED'
        else:
            blocked_count += 1
            tag = '❌ BLOCKED'

        print(f"\n[{tag}] {target or 'empty'}")
        print(f"  Desc:   {description}")
        print(f"  Reason: {result['reason']}")

    # Clean up test authorization
    remove_authorized_target('maybank.com')

    print(f"\n{'=' * 60}")
    print(
        f"Results: {allowed_count} allowed, "
        f"{blocked_count} blocked"
    )
    print("[+] Test complete!")
