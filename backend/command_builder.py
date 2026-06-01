import os
import ipaddress

PROFILES = {
    'Production': {
        'rate_limit': 10,
        'timeout': 30,
        'threads': 10,
        'nmap_timing': 'T2',
    },
    'Standard': {
        'rate_limit': 50,
        'timeout': 20,
        'threads': 25,
        'nmap_timing': 'T3',
    },
    'Deep': {
        'rate_limit': 100,
        'timeout': 10,
        'threads': 40,
        'nmap_timing': 'T4',
    },
}

def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def build_nmap_command(target, profile, preset='quick'):
    p = PROFILES[profile]
    timing = p['nmap_timing']
    output_flag = '-oX -'

    if preset == 'quick':
        return f"nmap -{timing} -sV --open {output_flag} {target}"
    elif preset == 'full':
        return f"nmap -{timing} -sV -sC --open -p- {output_flag} {target}"
    elif preset == 'stealth':
        return f"nmap -T1 -sS --open {output_flag} {target}"
    else:
        return f"nmap -{timing} -sV --open {output_flag} {target}"

def build_subfinder_command(target, profile, preset='quick'):
    if is_ip(target):
        return f"echo '{target}'"
    if preset == 'quick':
        return f"subfinder -d {target} -silent"
    elif preset == 'full':
        return f"subfinder -d {target} -silent -all"
    else:
        return f"subfinder -d {target} -silent"

def build_httpx_command(target, profile, preset='quick'):
    prefix = 'http' if is_ip(target) else 'https'
    return (
        f"curl -s -o /dev/null -w "
        f"'{{\"url\":\"{prefix}://{target}\","
        f"\"status_code\":%{{http_code}},"
        f"\"title\":\"unknown\"}}' "
        f"{prefix}://{target}"
    )

def build_whatweb_command(target, profile, preset='quick'):
    if preset == 'quick':
        return (
            f"whatweb http://{target} "
            f"--log-json=/tmp/whatweb_out.json -q"
        )
    elif preset == 'full':
        return (
            f"whatweb http://{target} "
            f"--log-json=/tmp/whatweb_out.json -a 3 -q"
        )
    else:
        return (
            f"whatweb http://{target} "
            f"--log-json=/tmp/whatweb_out.json -q"
        )

def build_ffuf_command(target, profile, preset='quick'):
    p = PROFILES[profile]
    rate = p['rate_limit']
    wordlist = '/usr/share/wordlists/dirb/common.txt'
    full_wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

    prefix = 'http' if is_ip(target) else 'https'

    if preset == 'quick':
        return (
            f"ffuf -u {prefix}://{target}/FUZZ "
            f"-w {wordlist} -rate {rate} "
            f"-o /tmp/ffuf_out.json -of json -s"
        )
    elif preset == 'full':
        return (
            f"ffuf -u {prefix}://{target}/FUZZ "
            f"-w {full_wordlist} -rate {rate} "
            f"-o /tmp/ffuf_out.json -of json -s"
        )
    elif preset == 'stealth':
        return (
            f"ffuf -u {prefix}://{target}/FUZZ "
            f"-w {wordlist} -rate 5 "
            f"-o /tmp/ffuf_out.json -of json -s"
        )
    else:
        return (
            f"ffuf -u {prefix}://{target}/FUZZ "
            f"-w {wordlist} -rate {rate} "
            f"-o /tmp/ffuf_out.json -of json -s"
        )

def build_nikto_command(target, profile, preset='quick'):
    prefix = 'http' if is_ip(target) else 'https'

    if preset == 'quick':
        return (
            f"nikto -h {prefix}://{target} "
            f"-nointeractive 2>/dev/null"
        )
    elif preset == 'full':
        return (
            f"nikto -h {prefix}://{target} "
            f"-nointeractive -Tuning 123bde 2>/dev/null"
        )
    else:
        return (
            f"nikto -h {prefix}://{target} "
            f"-nointeractive 2>/dev/null"
        )

def build_theharvester_command(target, profile, preset='quick'):
    if is_ip(target):
        return f"echo 'IP target - theHarvester skipped'"

    if preset == 'quick':
        return (
            f"theHarvester -d {target} "
            f"-b crtsh,dnsdumpster,rapiddns "
            f"-f /tmp/harvester_out -q"
        )
    elif preset == 'full':
        return (
            f"theHarvester -d {target} "
            f"-b crtsh,dnsdumpster,rapiddns,urlscan,waybackarchive "
            f"-f /tmp/harvester_out -q"
        )
    else:
        return (
            f"theHarvester -d {target} "
            f"-b crtsh,dnsdumpster -f /tmp/harvester_out -q"
        )

def build_dnsrecon_command(target, profile, preset='quick'):
    if is_ip(target):
        return f"echo 'IP target - DNSrecon skipped'"

    if preset == 'quick':
        return (
            f"dnsrecon -d {target} "
            f"-j /tmp/dnsrecon_out.json"
        )
    elif preset == 'full':
        return (
            f"dnsrecon -d {target} -a "
            f"-j /tmp/dnsrecon_out.json"
        )
    else:
        return (
            f"dnsrecon -d {target} "
            f"-j /tmp/dnsrecon_out.json"
        )

def build_gobuster_command(target, profile, preset='quick'):
    p = PROFILES[profile]
    threads = p['threads']
    prefix = 'http' if is_ip(target) else 'https'
    wordlist = '/usr/share/wordlists/dirb/common.txt'
    full_wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

    if preset == 'quick':
        return (
            f"gobuster dir -u {prefix}://{target} "
            f"-w {wordlist} -t {threads} "
            f"-o /tmp/gobuster_out.txt -q --no-progress"
        )
    elif preset == 'full':
        return (
            f"gobuster dir -u {prefix}://{target} "
            f"-w {full_wordlist} -t {threads} "
            f"-o /tmp/gobuster_out.txt -q --no-progress"
        )
    else:
        return (
            f"gobuster dir -u {prefix}://{target} "
            f"-w {wordlist} -t {threads} "
            f"-o /tmp/gobuster_out.txt -q --no-progress"
        )

def build_dirsearch_command(target, profile, preset='quick'):
    prefix = 'http' if is_ip(target) else 'https'

    if preset == 'quick':
        return (
            f"dirsearch -u {prefix}://{target} "
            f"-o /tmp/dirsearch_out.txt "
            f"--format=plain -q 2>/dev/null"
        )
    elif preset == 'full':
        return (
            f"dirsearch -u {prefix}://{target} "
            f"-e php,html,js,txt,bak,old,zip "
            f"-o /tmp/dirsearch_out.txt "
            f"--format=plain -q 2>/dev/null"
        )
    else:
        return (
            f"dirsearch -u {prefix}://{target} "
            f"-o /tmp/dirsearch_out.txt "
            f"--format=plain -q 2>/dev/null"
        )

def build_wpscan_command(target, profile, preset='quick'):
    prefix = 'http' if is_ip(target) else 'https'

    if preset == 'quick':
        return (
            f"wpscan --url {prefix}://{target} "
            f"--no-update --format json "
            f"-o /tmp/wpscan_out.json 2>/dev/null"
        )
    elif preset == 'full':
        return (
            f"wpscan --url {prefix}://{target} "
            f"--no-update --format json "
            f"--enumerate vp,vt,u "
            f"-o /tmp/wpscan_out.json 2>/dev/null"
        )
    else:
        return (
            f"wpscan --url {prefix}://{target} "
            f"--no-update --format json "
            f"-o /tmp/wpscan_out.json 2>/dev/null"
        )

def build_nuclei_command(target, profile, preset='quick'):
    prefix = 'http' if is_ip(target) else 'https'

    if preset == 'quick':
        return (
            f"nuclei -u {prefix}://{target} "
            f"-severity critical,high "
            f"-o /tmp/nuclei_out.txt "
            f"-stats -silent 2>/dev/null"
        )
    elif preset == 'full':
        return (
            f"nuclei -u {prefix}://{target} "
            f"-severity critical,high,medium "
            f"-o /tmp/nuclei_out.txt "
            f"-stats -silent 2>/dev/null"
        )
    else:
        return (
            f"nuclei -u {prefix}://{target} "
            f"-severity critical,high "
            f"-o /tmp/nuclei_out.txt "
            f"-stats -silent 2>/dev/null"
        )

def build_command(tool, target, profile, preset='quick'):
    tool = tool.lower()
    if tool == 'nmap':
        return build_nmap_command(target, profile, preset)
    elif tool == 'subfinder':
        return build_subfinder_command(target, profile, preset)
    elif tool == 'httpx':
        return build_httpx_command(target, profile, preset)
    elif tool == 'whatweb':
        return build_whatweb_command(target, profile, preset)
    elif tool == 'ffuf':
        return build_ffuf_command(target, profile, preset)
    elif tool == 'nikto':
        return build_nikto_command(target, profile, preset)
    elif tool == 'theharvester':
        return build_theharvester_command(target, profile, preset)
    elif tool == 'dnsrecon':
        return build_dnsrecon_command(target, profile, preset)
    elif tool == 'gobuster':
        return build_gobuster_command(target, profile, preset)
    elif tool == 'dirsearch':
        return build_dirsearch_command(target, profile, preset)
    elif tool == 'wpscan':
        return build_wpscan_command(target, profile, preset)
    elif tool == 'nuclei':
        return build_nuclei_command(target, profile, preset)
    else:
        return None

if __name__ == '__main__':
    targets = ['scanme.nmap.org', '192.168.112.130']
    tools = ['nmap', 'subfinder', 'httpx', 'whatweb', 'ffuf']

    for target in targets:
        print(f"\n===== TARGET: {target} =====")
        for tool in tools:
            cmd = build_command(tool, target, 'Standard', 'quick')
            print(f"[{tool}] {cmd}")
