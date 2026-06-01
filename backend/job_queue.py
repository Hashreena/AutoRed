import os
from backend.runner import run_tool
from backend.db import insert_audit_log, get_connection

def clear_temp_files():
    for f in [
        '/tmp/whatweb_out.json',
        '/tmp/ffuf_out.json',
        '/tmp/harvester_out.json',
        '/tmp/dnsrecon_out.json',
        '/tmp/gobuster_out.txt',
        '/tmp/dirsearch_out.txt',
        '/tmp/wpscan_out.json',
        '/tmp/nuclei_out.txt',
    ]:
        if os.path.exists(f):
            os.remove(f)
            print(f"[*] Cleared temp file: {f}")

def parse_tool_output(scan_id, tool, output, target):
    try:
        if tool == 'nmap':
            from parsers.nmap_parser import parse_nmap
            parse_nmap(scan_id, output, target)

        elif tool == 'subfinder':
            from parsers.subfinder_parser import parse_subfinder
            parse_subfinder(scan_id, output, target)

        elif tool == 'httpx':
            from parsers.httpx_parser import parse_httpx
            parse_httpx(scan_id, output, target)

        elif tool == 'whatweb':
            from parsers.whatweb_parser import parse_whatweb
            json_file = '/tmp/whatweb_out.json'
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parse_whatweb(scan_id, content, target)
                else:
                    print(f"[-] WhatWeb output file is empty")
            else:
                print(f"[-] WhatWeb output file not found: {json_file}")

        elif tool == 'ffuf':
            from parsers.ffuf_parser import parse_ffuf
            json_file = '/tmp/ffuf_out.json'
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parse_ffuf(scan_id, content, target)
                else:
                    print(f"[-] ffuf output file is empty")
            else:
                print(f"[-] ffuf output file not found: {json_file}")

        elif tool == 'nikto':
            from parsers.nikto_parser import parse_nikto
            if output and output.strip():
                parse_nikto(scan_id, output, target)
            else:
                print(f"[-] Nikto: no output to parse")

        elif tool == 'theharvester':
            from parsers.theharvester_parser import parse_theharvester
            parse_theharvester(scan_id, output, target)

        elif tool == 'dnsrecon':
            from parsers.dnsrecon_parser import parse_dnsrecon
            parse_dnsrecon(scan_id, output, target)

        elif tool == 'gobuster':
            from parsers.gobuster_parser import parse_gobuster
            txt_file = '/tmp/gobuster_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parse_gobuster(scan_id, content, target)
                else:
                    print(f"[-] Gobuster output file is empty")
            else:
                print(f"[-] Gobuster output file not found: {txt_file}")

        elif tool == 'dirsearch':
            from parsers.dirsearch_parser import parse_dirsearch
            txt_file = '/tmp/dirsearch_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parse_dirsearch(scan_id, content, target)
                else:
                    print(f"[-] Dirsearch output file is empty")
            else:
                print(f"[-] Dirsearch output file not found: {txt_file}")

        elif tool == 'wpscan':
            from parsers.wpscan_parser import parse_wpscan
            parse_wpscan(scan_id, output, target)

        elif tool == 'nuclei':
            from parsers.nuclei_parser import parse_nuclei
            txt_file = '/tmp/nuclei_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parse_nuclei(scan_id, content, target)
                else:
                    print(f"[-] Nuclei output file is empty")
            else:
                parse_nuclei(scan_id, output, target)

    except Exception as e:
        print(f"[-] Parser error for {tool}: {e}")

def run_scan(scan_id, target, profile, selected_tools, presets):
    from backend.command_builder import build_command

    output_base = os.path.join('storage', str(scan_id))
    os.makedirs(output_base, exist_ok=True)

    insert_audit_log(
        scan_id, 'scan_started',
        f"Scan started for target: {target} with profile: {profile}"
    )

    clear_temp_files()

    results = []
    for tool in selected_tools:
        preset = presets.get(tool, 'quick')
        command = build_command(tool, target, profile, preset)

        if not command:
            print(f"[-] Unknown tool: {tool}, skipping.")
            continue

        output_dir = os.path.join(output_base, tool)
        result = run_tool(scan_id, tool, command, output_dir)
        results.append(result)

        if result['status'] == 'completed':
            parse_tool_output(scan_id, tool, result['stdout'], target)

    insert_audit_log(
        scan_id, 'scan_completed',
        f"Scan completed. {len(results)} tools ran."
    )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='completed' WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()

    print(f"\n[+] Scan complete. Results saved to: {output_base}")
    return results

if __name__ == '__main__':
    from backend.db import init_db, insert_scan
    init_db()

    scan_id = insert_scan('Nuclei Test', '192.168.112.130', 'Standard')
    print(f"[*] Created scan ID: {scan_id}")

    results = run_scan(
        scan_id=scan_id,
        target='192.168.112.130',
        profile='Standard',
        selected_tools=['nuclei'],
        presets={'nuclei': 'quick'}
    )

    print("\n--- RESULTS SUMMARY ---")
    for r in results:
        print(f"[{r['status'].upper()}] {r['tool']} — output: {r['output_file']}")
