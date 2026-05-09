import re
import ipaddress

BLOCKLIST = [
    'localhost',
    '127.0.0.1',
    'google.com',
    'facebook.com',
    'microsoft.com',
]

ALLOWLIST = [
    'scanme.nmap.org',
    '192.168.112.130',
]

def is_valid_domain(target):
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, target) is not None

def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_private_ip(target):
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private
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
            'reason': 'Target cannot be empty.'
        }

    if target in BLOCKLIST:
        return {
            'allowed': False,
            'reason': f'Target "{target}" is in the blocklist.'
        }

    if is_valid_ip(target):
        if is_private_ip(target) and target not in ALLOWLIST:
            return {
                'allowed': False,
                'reason': f'Private IP addresses are not allowed: {target}'
            }
        return {
            'allowed': True,
            'reason': f'Valid IP address: {target}'
        }

    if is_valid_cidr(target):
        return {
            'allowed': True,
            'reason': f'Valid CIDR range: {target}'
        }

    if is_valid_domain(target):
        return {
            'allowed': True,
            'reason': f'Valid domain: {target}'
        }

    return {
        'allowed': False,
        'reason': f'Invalid target format: {target}'
    }

if __name__ == '__main__':
    test_targets = [
        'scanme.nmap.org',
        'google.com',
        '192.168.1.1',
        '45.33.32.156',
        'localhost',
        'notavaliddomain',
        '',
        '10.0.0.0/24',
    ]

    for target in test_targets:
        result = validate_target(target)
        status = 'ALLOWED' if result['allowed'] else 'BLOCKED'
        print(f'[{status}] {target or "empty"} — {result["reason"]}')
