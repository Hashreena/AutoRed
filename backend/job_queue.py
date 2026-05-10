import os
from backend.runner import run_tool
from backend.db import insert_audit_log

def parse_tool_output(scan_id, tool, output, target):
    try:
        if tool == 'nmap':
            from parsers.nmap_parser import parse_nmap
            parse_nmap(scan_id, output, target)
        elif tool == 'subfinder':
            from parsers.subfinder_parser import parse_subfinder
            parse_subfinder(scan_id, output, target)
        elif tool == 'whatweb':
            from parsers.whatweb_parser import parse_whatweb
            import os
            json_file = '/tmp/whatweb_out.json'
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    parse_whatweb(scan_id, f.read(), target)
        elif tool == 'ffuf':
            from parsers.ffuf_parser import parse_ffuf
            import os
            json_file = '/tmp/ffuf_out.json'
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    parse_ffuf(scan_id, f.read(), target)
        elif tool == 'httpx':
            from parsers.httpx_parser import parse_httpx
            parse_httpx(scan_id, output, target)
    except Exception as e:
        print(f"[-] Parser error for {tool}: {e}")

def run_scan(scan_id, target, profile, selected_tools, presets):
    from backend.command_builder import build_command

    output_base = os.path.join('storage', str(scan_id))
    os.makedirs(output_base, exist_ok=True)

    insert_audit_log(scan_id, 'scan_started', f"Scan started for target: {target} with profile: {profile}")

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

    insert_audit_log(scan_id, 'scan_completed', f"Scan completed. {len(results)} tools ran.")
    print(f"\n[+] Scan complete. Results saved to: {output_base}")
    return results

if __name__ == '__main__':
    from backend.db import init_db, insert_scan
    init_db()

    scan_id = insert_scan('Day 5 Test', 'scanme.nmap.org', 'Standard')
    print(f"[*] Created scan ID: {scan_id}")

    results = run_scan(
        scan_id=scan_id,
        target='scanme.nmap.org',
        profile='Standard',
        selected_tools=['nmap', 'subfinder'],
        presets={'nmap': 'quick', 'subfinder': 'quick'}
    )

    print("\n--- RESULTS SUMMARY ---")
    for r in results:
        print(f"[{r['status'].upper()}] {r['tool']} — output: {r['output_file']}")
