import re
import ipaddress

BLOCKLIST = [
    'localhost',
    '127.0.0.1',
]

BLOCKED_DOMAINS = [
    # Big tech
    'google.com', 'gmail.com', 'youtube.com', 'googleapis.com',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
    'microsoft.com', 'azure.com', 'office.com', 'live.com',
    'outlook.com', 'hotmail.com', 'bing.com',
    'amazon.com', 'amazonaws.com', 'aws.amazon.com',
    'apple.com', 'icloud.com',
    'twitter.com', 'x.com',
    'linkedin.com', 'tiktok.com', 'snapchat.com',
    'netflix.com', 'spotify.com', 'reddit.com',
    'wikipedia.org', 'wikimedia.org',
    'openai.com', 'anthropic.com', 'cloudflare.com',
    'github.com', 'gitlab.com',
    # Banks
    'maybank.com', 'cimbclicks.com', 'cimb.com',
    'publicbank.com.my', 'rhbbank.com', 'hongleongbank.com',
    'ocbc.com', 'hsbc.com', 'citibank.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'barclays.com', 'lloydsbankinggroup.com',
    # Payment
    'paypal.com', 'stripe.com', 'visa.com', 'mastercard.com',
    # Malaysian government portals
    'malaysia.gov.my', 'mygov.my', 'hasil.gov.my',
    'lhdn.gov.my', 'eperolehan.gov.my', 'spr.gov.my',
    'pdrm.gov.my', 'kpn.gov.my', 'bnm.gov.my',
    'sc.com.my', 'bsn.com.my',
]

BLOCKED_TLDS = [
    # Government
    '.gov', '.gov.my', '.gov.uk', '.gov.au', '.gov.sg',
    '.gov.in', '.gov.us', '.gov.ph', '.gov.id', '.gov.th',
    '.gov.vn', '.gov.bn', '.gov.kh', '.gov.la', '.gov.mm',
    # Military
    '.mil', '.mil.my', '.army.mil', '.navy.mil', '.af.mil',
    '.mod.uk', '.defence.gov.au', '.dod.gov',
    # Police
    '.police.gov.my', '.police.uk',
    # Education (optional — comment out if you want to allow)
    '.edu', '.edu.my', '.ac.uk', '.ac.my', '.ac.id',
    '.edu.sg', '.edu.au', '.edu.ph',
]

BLOCKED_KEYWORDS = [
    # Law enforcement
    'police', 'pdrm', 'interpol', 'fbi', 'cia', 'nsa',
    'dea', 'atf', 'homeland', 'secret.service',
    # Military
    'army', 'navy', 'airforce', 'airforc', 'military',
    'defense', 'defence', 'pentagon', 'nato',
    'marines', 'coastguard',
    # Government
    'parliament', 'congress', 'senate', 'whitehouse',
    'kremlin', 'judiciary', 'court', 'suruhanjaya',
    'jabatan', 'kementerian',
    # Critical infrastructure
    'hospital', 'clinic', 'healthcare', 'medical',
    'prison', 'jail', 'correctional',
    'nuclear', 'powerplant', 'electric.grid',
    'waterworks', 'sewage',
    # Financial regulators
    'centralbank', 'federalreserve', 'bnm',
]


def is_valid_domain(target):
    pattern = (
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return re.match(pattern, target) is not None


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


def validate_target(target):
    target = target.strip().lower()

    if not target:
        return {
            'allowed': False,
            'reason':  'Target cannot be empty.'
        }

    if target in BLOCKLIST:
        return {
            'allowed': False,
            'reason':  (
                f'Target "{target}" is blocked. '
                f'AutoRed is for authorized testing only.'
            )
        }

    for domain in BLOCKED_DOMAINS:
        if target == domain or target.endswith('.' + domain):
            return {
                'allowed': False,
                'reason':  (
                    f'"{target}" is a restricted domain. '
                    f'Only scan targets you are authorized to test.'
                )
            }

    for tld in BLOCKED_TLDS:
        if target.endswith(tld):
            return {
                'allowed': False,
                'reason':  (
                    f'Government, military and education domains '
                    f'are not permitted: {target}'
                )
            }

    for keyword in BLOCKED_KEYWORDS:
        if keyword in target:
            return {
                'allowed': False,
                'reason':  (
                    f'Target "{target}" contains a restricted '
                    f'keyword ({keyword}). '
                    f'Scanning this target is not permitted.'
                )
            }

    if is_valid_ip(target):
        return {
            'allowed': True,
            'reason':  f'Valid IP address: {target}'
        }

    if is_valid_cidr(target):
        return {
            'allowed': True,
            'reason':  f'Valid CIDR range: {target}'
        }

    if is_valid_domain(target):
        return {
            'allowed': True,
            'reason':  f'Valid domain: {target}'
        }

    return {
        'allowed': False,
        'reason':  (
            f'Invalid target format: {target}. '
            f'Use a domain, IP address or CIDR range.'
        )
    }


if __name__ == '__main__':
    test_targets = [
        # Should be ALLOWED
        'scanme.nmap.org',
        '192.168.112.130',
        '10.0.0.1',
        '172.16.0.1',
        '45.33.32.156',
        'internal.company.com',
        'target.example.com',
        '10.0.0.0/24',
        '192.168.0.0/16',
        # Should be BLOCKED
        'localhost',
        '127.0.0.1',
        'google.com',
        'mail.google.com',
        'facebook.com',
        'microsoft.com',
        'maybank.com',
        'police.gov.my',
        'army.mil',
        'pdrm.gov.my',
        'moe.gov.my',
        'utm.edu.my',
        'cia.gov',
        'fbi.gov',
        'parliament.gov.my',
        'hospital.com',
        '',
    ]
    print("=" * 60)
    print("AutoRed — Scope Validation Test")
    print("=" * 60)
    allowed_count = 0
    blocked_count = 0
    for t in test_targets:
        result = validate_target(t)
        status = 'ALLOWED' if result['allowed'] else 'BLOCKED'
        if result['allowed']:
            allowed_count += 1
        else:
            blocked_count += 1
        print(f'[{status}] {t or "empty"}')
        if not result['allowed']:
            print(f'         → {result["reason"]}')
    print("=" * 60)
    print(f'Allowed: {allowed_count}  |  Blocked: {blocked_count}')
    print("=" * 60)
