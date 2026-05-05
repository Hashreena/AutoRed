import os
from backend.runner import run_tool
from backend.db import insert_audit_log

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
