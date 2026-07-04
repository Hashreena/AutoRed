import os
import re
import xml.etree.ElementTree as ET
from backend.runner import run_tool
from backend.db     import insert_audit_log, get_connection


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


# ── Vulners CVE extractor ─────────────────────────────────────
def _cvss_to_severity(score):
    if score >= 9.0: return 'Critical'
    if score >= 7.0: return 'High'
    if score >= 4.0: return 'Medium'
    if score >= 0.1: return 'Low'
    return 'Info'


def _extract_vulners_findings(scan_id, nmap_xml, target):
    """
    Parse nmap --script vulners XML output and insert CVE findings.
    Deduplication rules:
      1. Same CVE on multiple ports → one finding, list all ports
      2. CVE already inserted by another tool → skip (no duplicate)
    """
    if not nmap_xml or 'vulners' not in nmap_xml:
        return
    try:
        xml_clean = re.sub(
            r'<!DOCTYPE[^>]*?>', '', nmap_xml,
            flags=re.DOTALL
        ).strip()
        root = ET.fromstring(xml_clean)
    except ET.ParseError as e:
        print(f"[!] vulners: XML parse error: {e}")
        return

    CVE_RE = re.compile(
        r'(CVE-\d{4}-\d{4,7})\s+([\d.]+)\s+https?://\S+',
        re.IGNORECASE
    )

    cve_map = {}
    for host in root.findall('.//host'):
        for port_el in host.findall('.//port'):
            portid   = port_el.get('portid', '?')
            protocol = port_el.get('protocol', 'tcp')
            svc      = port_el.find('service')
            product  = svc.get('product', '') if svc is not None else ''
            version  = svc.get('version', '') if svc is not None else ''
            svc_str  = f"{product} {version}".strip()
            for script in port_el.findall('script'):
                if script.get('id') != 'vulners':
                    continue
                for m in CVE_RE.finditer(script.get('output', '')):
                    cve_id = m.group(1).upper()
                    score  = float(m.group(2))
                    if cve_id not in cve_map:
                        cve_map[cve_id] = {
                            'score':    score,
                            'severity': _cvss_to_severity(score),
                            'ports':    [],
                            'services': [],
                        }
                    port_label = f"{portid}/{protocol}"
                    if port_label not in cve_map[cve_id]['ports']:
                        cve_map[cve_id]['ports'].append(port_label)
                    if svc_str and svc_str not in cve_map[cve_id]['services']:
                        cve_map[cve_id]['services'].append(svc_str)

    if not cve_map:
        print("[*] vulners: no CVEs in nmap output")
        return

    conn   = get_connection()
    cursor = conn.cursor()
    total  = 0
    inserted_ids = []

    try:
        cursor.execute(
            "SELECT DISTINCT cve_id FROM findings "
            "WHERE scan_id=? AND cve_id IS NOT NULL",
            (scan_id,)
        )
        existing_cves = {r[0] for r in cursor.fetchall()}

        for cve_id, info in cve_map.items():
            if cve_id in existing_cves:
                print(
                    f"[*] vulners: {cve_id} already in findings "
                    f"— skipping duplicate"
                )
                continue

            ports_str = ', '.join(info['ports'])
            svc_str   = ', '.join(info['services']) or 'unknown service'
            score     = info['score']
            severity  = info['severity']

            if len(info['ports']) > 1:
                title = (
                    f"{cve_id} — {svc_str} "
                    f"({len(info['ports'])} ports: {ports_str})"
                )
            else:
                title = (
                    f"{cve_id} — {svc_str} "
                    f"(port {ports_str})"
                )

            desc = (
                f"CVE detected by nmap vulners script.\n"
                f"Service: {svc_str}\n"
                f"Affected ports: {ports_str}\n"
                f"CVSS Score: {score}"
            )
            asset = target

            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO findings
                    (scan_id, tool, asset, title,
                     severity, description,
                     cvss_score, cve_id)
                    VALUES (?,?,?,?,?,?,?,?)
                ''', (
                    scan_id, 'nmap-vulners', asset,
                    title, severity, desc, score, cve_id
                ))
                if cursor.rowcount:
                    total += 1
                    inserted_ids.append((cursor.lastrowid, {
                        'id':          cursor.lastrowid,
                        'scan_id':     scan_id,
                        'tool':        'nmap-vulners',
                        'asset':       asset,
                        'title':       title,
                        'severity':    severity,
                        'description': desc,
                        'cvss_score':  score,
                        'cve_id':      cve_id,
                    }))
                    print(
                        f"[+] vulners: {cve_id} "
                        f"({severity} {score}) "
                        f"ports=[{ports_str}]"
                    )
            except Exception:
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO findings
                        (scan_id, tool, asset,
                         title, severity, description)
                        VALUES (?,?,?,?,?,?)
                    ''', (
                        scan_id, 'nmap-vulners', asset,
                        title, severity, desc
                    ))
                    if cursor.rowcount:
                        total += 1
                        inserted_ids.append((cursor.lastrowid, {
                            'id':          cursor.lastrowid,
                            'scan_id':     scan_id,
                            'tool':        'nmap-vulners',
                            'asset':       asset,
                            'title':       title,
                            'severity':    severity,
                            'description': desc,
                        }))
                except Exception:
                    pass

        conn.commit()
        skipped = len(cve_map) - total
        print(
            f"[+] vulners: {total} new CVE finding(s) added "
            f"({skipped} duplicates skipped) "
            f"for scan #{scan_id}"
        )

    except Exception as e:
        print(f"[!] vulners extraction failed: {e}")
    finally:
        conn.close()

    if inserted_ids:
        from backend.enrichment_worker import enrich_and_save_async
        for fid, fdict in inserted_ids:
            if fid:
                enrich_and_save_async(fid, fdict)


# ── Helper: get finding IDs inserted by a parser ─────────────
def _count_findings(scan_id, tool):
    """Return current finding count for a scan/tool pair."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id=? AND tool=?",
        (scan_id, tool)
    )
    count = cursor.fetchone()[0]
    conn.close()
    return count


def _enrich_new_findings(scan_id, tool, count_before):
    """
    After a parser runs, find any newly inserted findings and
    kick off background enrichment for each one.
    """
    from backend.enrichment_worker import enrich_and_save_async
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(findings)")
    cols    = [row[1] for row in cursor.fetchall()]
    col_sql = ', '.join(cols)

    if 'enriched_at' in cols:
        cursor.execute(
            f"SELECT {col_sql} FROM findings "
            f"WHERE scan_id=? AND tool=? AND enriched_at IS NULL "
            f"ORDER BY id DESC",
            (scan_id, tool)
        )
    else:
        cursor.execute(
            f"SELECT {col_sql} FROM findings "
            f"WHERE scan_id=? AND tool=? "
            f"ORDER BY id DESC",
            (scan_id, tool)
        )

    rows = cursor.fetchall()
    conn.close()

    new_findings = [dict(zip(cols, row)) for row in rows]
    for f in new_findings:
        if f.get('id'):
            enrich_and_save_async(f['id'], f)

    if new_findings:
        print(
            f"[~] Queued background enrichment for "
            f"{len(new_findings)} new {tool} finding(s)"
        )


# ── Tool output parser ────────────────────────────────────────
def parse_tool_output(scan_id, tool, output, target):
    try:
        if tool == 'nmap':
            from parsers.nmap_parser import parse_nmap
            parse_nmap(scan_id, output, target)
            _extract_vulners_findings(scan_id, output, target)
            _enrich_new_findings(scan_id, 'nmap', 0)

        elif tool == 'subfinder':
            from parsers.subfinder_parser import parse_subfinder
            parse_subfinder(scan_id, output, target)
            _enrich_new_findings(scan_id, tool, 0)

        elif tool == 'httpx':
            from parsers.httpx_parser import parse_httpx
            parse_httpx(scan_id, output, target)
            _enrich_new_findings(scan_id, tool, 0)

        elif tool == 'whatweb':
            from parsers.whatweb_parser import parse_whatweb
            json_file = '/tmp/whatweb_out.json'
            if os.path.exists(json_file):
                with open(json_file) as f:
                    content = f.read().strip()
                if content:
                    parse_whatweb(scan_id, content, target)
                    _enrich_new_findings(scan_id, tool, 0)
                else:
                    print("[-] WhatWeb output file is empty")
            else:
                print(f"[-] WhatWeb output file not found: {json_file}")

        elif tool == 'ffuf':
            from parsers.ffuf_parser import parse_ffuf
            json_file = '/tmp/ffuf_out.json'
            if os.path.exists(json_file):
                with open(json_file) as f:
                    content = f.read().strip()
                if content:
                    parse_ffuf(scan_id, content, target)
                    _enrich_new_findings(scan_id, tool, 0)
                else:
                    print("[-] ffuf output file is empty")
            else:
                print(f"[-] ffuf output file not found: {json_file}")

        elif tool == 'nikto':
            from parsers.nikto_parser import parse_nikto
            if output and output.strip():
                parse_nikto(scan_id, output, target)
                _enrich_new_findings(scan_id, tool, 0)
            else:
                print("[-] Nikto: no output to parse")

        elif tool == 'theharvester':
            from parsers.theharvester_parser import parse_theharvester
            parse_theharvester(scan_id, output, target)
            _enrich_new_findings(scan_id, tool, 0)

        elif tool == 'dnsrecon':
            from parsers.dnsrecon_parser import parse_dnsrecon
            parse_dnsrecon(scan_id, output, target)
            _enrich_new_findings(scan_id, tool, 0)

        elif tool == 'gobuster':
            from parsers.gobuster_parser import parse_gobuster
            txt_file = '/tmp/gobuster_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file) as f:
                    content = f.read().strip()
                if content:
                    parse_gobuster(scan_id, content, target)
                    _enrich_new_findings(scan_id, tool, 0)
                else:
                    print("[-] Gobuster output file is empty")
            else:
                print(f"[-] Gobuster output file not found: {txt_file}")

        elif tool == 'dirsearch':
            from parsers.dirsearch_parser import parse_dirsearch
            txt_file = '/tmp/dirsearch_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file) as f:
                    content = f.read().strip()
                if content:
                    parse_dirsearch(scan_id, content, target)
                    _enrich_new_findings(scan_id, tool, 0)
                else:
                    print("[-] Dirsearch output file is empty")
            else:
                print(f"[-] Dirsearch output file not found: {txt_file}")

        elif tool == 'wpscan':
            from parsers.wpscan_parser import parse_wpscan
            parse_wpscan(scan_id, output, target)
            _enrich_new_findings(scan_id, tool, 0)

        elif tool == 'nuclei':
            from parsers.nuclei_parser import parse_nuclei
            txt_file = '/tmp/nuclei_out.txt'
            if os.path.exists(txt_file):
                with open(txt_file) as f:
                    content = f.read().strip()
                if content:
                    parse_nuclei(scan_id, content, target)
                    _enrich_new_findings(scan_id, tool, 0)
                else:
                    print("[-] Nuclei output file is empty")
            else:
                parse_nuclei(scan_id, output, target)
                _enrich_new_findings(scan_id, tool, 0)

    except Exception as e:
        print(f"[-] Parser error for {tool}: {e}")


# ── Scan runner ───────────────────────────────────────────────
def run_scan(scan_id, target, profile, selected_tools, presets):
    from backend.command_builder import build_command, detect_scheme

    output_base = os.path.join('storage', str(scan_id))
    os.makedirs(output_base, exist_ok=True)

    insert_audit_log(
        scan_id, 'scan_started',
        f"Scan started for target: {target} "
        f"with profile: {profile}"
    )

    clear_temp_files()

    # ── Detect HTTP or HTTPS once before running any tools ────
    # This probes the target with a live request and returns
    # 'http' or 'https' based on which protocol the target
    # actually responds to. The result is passed to every
    # build_command() call so all tools use the correct protocol
    # without re-probing for each tool.
    print(f"[*] Detecting target scheme for {target}...")
    scheme = detect_scheme(target)
    print(f"[+] Using scheme: {scheme}:// for all tools")

    results = []
    for tool in selected_tools:
        preset  = presets.get(tool, 'quick')
        # Pass detected scheme to build_command
        command = build_command(tool, target, profile, preset, scheme=scheme)
        if not command:
            print(f"[-] Unknown tool: {tool}, skipping.")
            continue

        output_dir = os.path.join(output_base, tool)
        result     = run_tool(scan_id, tool, command, output_dir)
        results.append(result)

        if result['status'] == 'completed':
            parse_tool_output(
                scan_id, tool, result['stdout'], target
            )

    insert_audit_log(
        scan_id, 'scan_completed',
        f"Scan completed. {len(results)} tools ran."
    )

    conn   = get_connection()
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
    scan_id = insert_scan('Scheme Detection Test', '192.168.112.130', 'Standard')
    print(f"[*] Created scan ID: {scan_id}")
    results = run_scan(
        scan_id        = scan_id,
        target         = '192.168.112.130',
        profile        = 'Standard',
        selected_tools = ['nuclei', 'gobuster'],
        presets        = {'nuclei': 'quick', 'gobuster': 'quick'}
    )
    print("\n--- RESULTS SUMMARY ---")
    for r in results:
        print(
            f"[{r['status'].upper()}] {r['tool']} "
            f"— output: {r['output_file']}"
        )
