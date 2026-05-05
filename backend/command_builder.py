import os

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
    p = PROFILES[profile]
    if preset == 'quick':
        return f"subfinder -d {target} -silent"
    elif preset == 'full':
        return f"subfinder -d {target} -silent -all"
    else:
        return f"subfinder -d {target} -silent"

def build_httpx_command(target, profile, preset='quick'):
    p = PROFILES[profile]
    threads = p['threads']
    if preset == 'quick':
        return f"httpx -l {target} -silent -json -threads {threads}"
    elif preset == 'full':
        return f"httpx -l {target} -silent -json -threads {threads} -title -tech-detect -status-code"
    else:
        return f"httpx -l {target} -silent -json -threads {threads}"

def build_whatweb_command(target, profile, preset='quick'):
    if preset == 'quick':
        return f"whatweb {target} --log-json=/tmp/whatweb_out.json -q"
    elif preset == 'full':
        return f"whatweb {target} --log-json=/tmp/whatweb_out.json -a 3 -q"
    else:
        return f"whatweb {target} --log-json=/tmp/whatweb_out.json -q"

def build_ffuf_command(target, profile, preset='quick'):
    p = PROFILES[profile]
    rate = p['rate_limit']
    wordlist = '/usr/share/wordlists/dirb/common.txt'

    if preset == 'quick':
        return f"ffuf -u https://{target}/FUZZ -w {wordlist} -rate {rate} -o /tmp/ffuf_out.json -of json -s"
    elif preset == 'full':
        return f"ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -rate {rate} -o /tmp/ffuf_out.json -of json -s"
    elif preset == 'stealth':
        return f"ffuf -u https://{target}/FUZZ -w {wordlist} -rate 5 -o /tmp/ffuf_out.json -of json -s"
    else:
        return f"ffuf -u https://{target}/FUZZ -w {wordlist} -rate {rate} -o /tmp/ffuf_out.json -of json -s"

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
    else:
        return None

if __name__ == '__main__':
    target = 'scanme.nmap.org'
    tools = ['nmap', 'subfinder', 'httpx', 'whatweb', 'ffuf']
    profiles = ['Production', 'Standard', 'Deep']
    presets = ['quick', 'full', 'stealth']

    for tool in tools:
        print(f"\n--- {tool.upper()} ---")
        for profile in profiles:
            cmd = build_command(tool, target, profile, 'quick')
            print(f"[{profile}] {cmd}")
