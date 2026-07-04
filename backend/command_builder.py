import os
import ipaddress
PROFILES = {
    'Production': {
        'rate_limit':   10,
        'timeout':      30,
        'threads':      10,
        'nmap_timing': 'T2',
    },
    'Standard': {
        'rate_limit':   50,
        'timeout':      20,
        'threads':      25,
        'nmap_timing': 'T3',
    },
    'Deep': {
        'rate_limit':  100,
        'timeout':      10,
        'threads':      40,
        'nmap_timing': 'T4',
    },
}
def is_ip(target):
    """
    Returns True if target is an IP address (with or without port).
    e.g. 192.168.1.1 → True
         192.168.1.1:5001 → True
         scanme.nmap.org → False
    """
    try:
        host = target.split(':')[0]
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
def _host(target):
    """
    Strip port from target — returns just the hostname or IP.
    e.g. 192.168.179.128:5001 → 192.168.179.128
         scanme.nmap.org → scanme.nmap.org
    """
    return target.split(':')[0]
def _prefix(target):
    """
    Return correct URL scheme for target.
    IP addresses (with or without port) → http
    Domain names → https
    """
    return 'http' if is_ip(target) else 'https'
# ── Nmap (+ vulners script for CVE detection) ─────────────────
def build_nmap_command(target, profile, preset='quick'):
    p      = PROFILES[profile]
    timing = p['nmap_timing']
    out    = '-oX -'
    mincvss = {
        'Production': '9.0',
        'Standard':   '7.0',
        'Deep':       '4.0',
    }.get(profile, '7.0')
    vulners = (
        f"--script vulners "
        f"--script-args mincvss={mincvss}"
    )
    if preset == 'quick':
        return (
            f"nmap -{timing} -sV {vulners} "
            f"--open {out} {target}"
        )
    elif preset == 'full':
        return (
            f"nmap -{timing} -sV -sC {vulners} "
            f"--open -p- {out} {target}"
        )
    elif preset == 'stealth':
        return f"nmap -T1 -sS --open {out} {target}"
    else:
        return (
            f"nmap -{timing} -sV {vulners} "
            f"--open {out} {target}"
        )
# ── Subfinder ─────────────────────────────────────────────────
def build_subfinder_command(target, profile, preset='quick'):
    host = _host(target)
    if is_ip(target):
        return f"echo '{target}'"
    if preset == 'full':
        return f"subfinder -d {host} -silent -all"
    return f"subfinder -d {host} -silent"
# ── httpx ─────────────────────────────────────────────────────
def build_httpx_command(target, profile, preset='quick'):
    prefix = _prefix(target)
    return (
        f"curl -s -o /dev/null -w "
        f"'{{\"url\":\"{prefix}://{target}\","
        f"\"status_code\":%{{http_code}},"
        f"\"title\":\"unknown\"}}' "
        f"{prefix}://{target}"
    )
# ── WhatWeb ───────────────────────────────────────────────────
def build_whatweb_command(target, profile, preset='quick'):
    prefix     = _prefix(target)
    aggression = '-a 3' if preset == 'full' else ''
    return (
        f"whatweb {prefix}://{target} "
        f"--log-json=/tmp/whatweb_out.json "
        f"{aggression} -q".strip()
    )
# ── ffuf ──────────────────────────────────────────────────────
def build_ffuf_command(target, profile, preset='quick'):
    p        = PROFILES[profile]
    rate     = p['rate_limit']
    prefix   = _prefix(target)
    wordlist = '/usr/share/wordlists/dirb/common.txt'
    big_wl   = (
        '/usr/share/wordlists/dirbuster/'
        'directory-list-2.3-medium.txt'
    )
    if preset == 'stealth':
        return (
            f"ffuf -u {prefix}://{target}/FUZZ "
            f"-w {wordlist} -rate 5 "
            f"-o /tmp/ffuf_out.json -of json -s"
        )
    wl = big_wl if preset == 'full' else wordlist
    return (
        f"ffuf -u {prefix}://{target}/FUZZ "
        f"-w {wl} -rate {rate} "
        f"-o /tmp/ffuf_out.json -of json -s"
    )
# ── Nikto ─────────────────────────────────────────────────────
def build_nikto_command(target, profile, preset='quick'):
    prefix = _prefix(target)
    tuning = '-Tuning 123bde ' if preset == 'full' else ''
    return (
        f"nikto -h {prefix}://{target} "
        f"{tuning}-nointeractive 2>/dev/null".strip()
    )
# ── theHarvester ──────────────────────────────────────────────
def build_theharvester_command(target, profile, preset='quick'):
    host = _host(target)
    if is_ip(target):
        return "echo 'IP target - theHarvester skipped'"
    sources = (
        'crtsh,dnsdumpster,rapiddns,urlscan,waybackarchive'
        if preset == 'full'
        else 'crtsh,dnsdumpster,rapiddns'
    )
    return (
        f"theHarvester -d {host} -b {sources} "
        f"-f /tmp/harvester_out -q"
    )
# ── DNSrecon ──────────────────────────────────────────────────
def build_dnsrecon_command(target, profile, preset='quick'):
    host = _host(target)
    if is_ip(target):
        return "echo 'IP target - DNSrecon skipped'"
    extra = '-a ' if preset == 'full' else ''
    return (
        f"dnsrecon -d {host} {extra}"
        f"-j /tmp/dnsrecon_out.json".strip()
    )
# ── Gobuster ──────────────────────────────────────────────────
def build_gobuster_command(target, profile, preset='quick'):
    p       = PROFILES[profile]
    threads = p['threads']
    prefix  = _prefix(target)
    wl      = '/usr/share/wordlists/dirb/common.txt'
    big_wl  = (
        '/usr/share/wordlists/dirbuster/'
        'directory-list-2.3-medium.txt'
    )
    wordlist = big_wl if preset == 'full' else wl
    return (
        f"gobuster dir -u {prefix}://{target} "
        f"-w {wordlist} -t {threads} "
        f"-o /tmp/gobuster_out.txt -q --no-progress"
    )
# ── Dirsearch ─────────────────────────────────────────────────
def build_dirsearch_command(target, profile, preset='quick'):
    prefix = _prefix(target)
    exts   = (
        '-e php,html,js,txt,bak,old,zip '
        if preset == 'full' else ''
    )
    return (
        f"dirsearch -u {prefix}://{target} {exts}"
        f"-o /tmp/dirsearch_out.txt "
        f"--format=plain -q 2>/dev/null".strip()
    )
# ── WPScan ────────────────────────────────────────────────────
def build_wpscan_command(target, profile, preset='quick'):
    prefix = _prefix(target)
    enum   = '--enumerate vp,vt,u ' if preset == 'full' else ''
    return (
        f"wpscan --url {prefix}://{target} "
        f"--no-update --format json {enum}"
        f"-o /tmp/wpscan_out.json 2>/dev/null".strip()
    )
# ── Nuclei (profile-driven plugin manager) ────────────────────
def build_nuclei_command(target, profile, preset='quick'):
    """
    Uses nuclei_plugin_manager to select templates based on profile:
      Production  → critical severity only
      Standard    → critical + high
      Deep        → critical + high + medium
    Custom templates in AutoRed/custom_templates/ always included.
    """
    from backend.nuclei_plugin_manager import get_nuclei_flags
    prefix = _prefix(target)
    flags  = get_nuclei_flags(profile)
    return (
        f"nuclei -u {prefix}://{target} "
        f"{flags} "
        f"-o /tmp/nuclei_out.txt "
        f"-stats -silent 2>/dev/null"
    )
# ── Dispatcher ────────────────────────────────────────────────
def build_command(tool, target, profile, preset='quick'):
    tool = tool.lower()
    dispatch = {
        'nmap':         build_nmap_command,
        'subfinder':    build_subfinder_command,
        'httpx':        build_httpx_command,
        'whatweb':      build_whatweb_command,
        'ffuf':         build_ffuf_command,
        'nikto':        build_nikto_command,
        'theharvester': build_theharvester_command,
        'dnsrecon':     build_dnsrecon_command,
        'gobuster':     build_gobuster_command,
        'dirsearch':    build_dirsearch_command,
        'wpscan':       build_wpscan_command,
        'nuclei':       build_nuclei_command,
    }
    fn = dispatch.get(tool)
    return fn(target, profile, preset) if fn else None
if __name__ == '__main__':
    import sys
    sys.path.insert(
        0, os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..')
        )
    )
    # Test with plain IP, IP:port, and domain
    targets = [
        'scanme.nmap.org',
        '192.168.112.130',
        '192.168.179.128:5001',
    ]
    tools = [
        'nmap', 'gobuster', 'dirsearch',
        'wpscan', 'nuclei', 'ffuf'
    ]
    for target in targets:
        print(f"\n===== TARGET: {target} =====")
        for tool in tools:
            cmd = build_command(tool, target, 'Standard', 'quick')
            print(f"[{tool}] {cmd}")
