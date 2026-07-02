"""
AutoRed -- Shared report enrichment helper.
Both reports/report_builder.py (PDF/DOCX) and
reports/data_exporter.py (JSON/CSV) call this module to get
real CVE/CWE/CVSS/MITRE data per finding.

FAST PATH (default):
  If a finding already has enriched_at set in the database
  (written by background enrichment in enrichment_worker.py
  during the scan), its data is used directly -- no API call.
  Report generation for already-enriched scans is near-instant.

SLOW PATH (fallback):
  If a finding was NOT enriched during the scan (older scan,
  enrichment failed, or enriched_at column missing), it falls
  back to the live NVD/CIRCL/MITRE/Claude pipeline with a
  30 s timeout per finding and parallel execution (max 4 workers).

Each finding enrichment is individually wrapped so one failure
never stops the whole report -- it falls back to whatever was
already stored in the DB for that finding.
"""
import concurrent.futures


def _get_column_set(cursor):
    """Which optional columns actually exist on this DB's
    findings table -- older installs may be missing some columns."""
    cursor.execute("PRAGMA table_info(findings)")
    return {row[1] for row in cursor.fetchall()}


def _enrich_one_live(finding, index, total, progress_callback=None):
    """
    Live enrichment for a single finding that was not pre-enriched.
    Runs in a worker thread. Returns the extended finding dict.
    """
    from backend.cve_enricher import enrich_finding, get_attack_path_ai

    # Defaults -- guarantees every key exists even on failure
    finding.setdefault('cve_id', None)
    finding.setdefault('cvss_score', None)
    result_keys = {
        'cvss_severity': None, 'cvss_vector': None,
        'nvd_url': None, 'cve_description': None,
        'cwe_id': finding.get('cwe_id'), 'cwe_name': None,
        'cwe_risk': None, 'cwe_url': None,
        'mitre_tactic': None, 'mitre_tactic_id': None,
        'mitre_technique': None, 'mitre_tech_id': None,
        'mitre_url': None, 'attack_surface_tags': [],
        'exploit_level': None, 'exploit_reason': None,
        'no_cve_reason': None, 'attack_path': None,
        'verify_steps': None,
    }
    finding.update(result_keys)

    try:
        # enrich_finding with 30 s timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(enrich_finding, finding)
            try:
                result = future.result(timeout=30)
            except concurrent.futures.TimeoutError:
                print(
                    f"[!] enrich_finding timed out for finding "
                    f"{finding.get('id')} — using stored data"
                )
                result = {}

        nvd_best = result.get('nvd_best') or {}
        if nvd_best:
            cve_id = nvd_best.get('cve_id')
            if cve_id and 'No CVE' not in str(cve_id):
                finding['cve_id'] = cve_id
            if nvd_best.get('cvss_score') is not None:
                finding['cvss_score'] = nvd_best.get('cvss_score')
            finding['cvss_severity']   = nvd_best.get('cvss_severity')
            finding['cvss_vector']     = nvd_best.get('cvss_vector')
            finding['nvd_url']         = nvd_best.get('nvd_url')
            finding['cve_description'] = nvd_best.get('description')

        cwe_data = result.get('cwe_data')
        if cwe_data:
            finding['cwe_id']   = cwe_data.get('cwe_id') or finding['cwe_id']
            finding['cwe_name'] = cwe_data.get('name')
            finding['cwe_risk'] = cwe_data.get('risk')
            finding['cwe_url']  = cwe_data.get('url')

        mitre = result.get('mitre')
        if mitre:
            finding['mitre_tactic']    = mitre.get('tactic')
            finding['mitre_tactic_id'] = mitre.get('tactic_id')
            finding['mitre_technique'] = mitre.get('technique')
            finding['mitre_tech_id']   = mitre.get('tech_id')
            finding['mitre_url']       = mitre.get('url')

        finding['attack_surface_tags'] = result.get('attack_surface') or []
        finding['exploit_level']       = result.get('exploit_level')
        finding['exploit_reason']      = result.get('exploit_reason')
        finding['no_cve_reason']       = result.get('no_cve_reason')

        # get_attack_path_ai with 20 s timeout
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(get_attack_path_ai, finding, nvd_best)
                try:
                    attack, verify = future.result(timeout=20)
                    finding['attack_path']  = attack
                    finding['verify_steps'] = verify
                except concurrent.futures.TimeoutError:
                    print(
                        f"[!] get_attack_path_ai timed out for finding "
                        f"{finding.get('id')} — skipping attack path"
                    )
                    finding['attack_path'] = (
                        "Attack path generation timed out. "
                        "Open this finding individually to generate."
                    )
        except Exception as e:
            print(
                f"[!] Attack-path generation skipped for "
                f"finding {finding.get('id')}: {e}"
            )

    except Exception as e:
        print(
            f"[!] Live enrichment failed for finding "
            f"{finding.get('id')}, using stored data only: {e}"
        )

    if progress_callback:
        try:
            progress_callback(index + 1, total)
        except Exception:
            pass

    return finding


def _apply_defaults(finding):
    """
    Ensure every enrichment key exists on a finding dict
    that was pre-enriched from the DB, so callers never
    need defensive .get() chains.
    """
    finding.setdefault('cve_id', None)
    finding.setdefault('cvss_score', None)
    finding.setdefault('cvss_severity', None)
    finding.setdefault('cvss_vector', None)
    finding.setdefault('nvd_url', None)
    finding.setdefault('cve_description', None)
    finding.setdefault('cwe_id', None)
    finding.setdefault('cwe_name', None)
    finding.setdefault('cwe_risk', None)
    finding.setdefault('cwe_url', None)
    finding.setdefault('mitre_tactic', None)
    finding.setdefault('mitre_tactic_id', None)
    finding.setdefault('mitre_technique', None)
    finding.setdefault('mitre_tech_id', None)
    finding.setdefault('mitre_url', None)
    finding.setdefault('attack_surface_tags', [])
    finding.setdefault('exploit_level', None)
    finding.setdefault('exploit_reason', None)
    finding.setdefault('no_cve_reason', None)
    finding.setdefault('attack_path', None)
    finding.setdefault('verify_steps', None)
    return finding


def enrich_findings_for_report(findings, progress_callback=None,
                                max_workers=4):
    """
    findings: list of dicts from get_findings_with_db_columns().

    For each finding:
      - If enriched_at is set → already enriched during the scan,
        use DB data directly (fast path, no API call).
      - Otherwise → enrich live in parallel with timeouts (slow path).

    progress_callback(done, total): optional, for GUI progress bar.
    max_workers: parallel workers for slow-path findings (default 4).

    Returns a NEW list in the SAME ORDER as input, each dict
    extended with all enrichment keys (None/[] if unknown).
    """
    total = len(findings)
    if total == 0:
        return []

    # Split into fast (already enriched) and slow (needs live call)
    fast   = []  # (original_index, finding)
    slow   = []  # (original_index, finding)

    for i, raw in enumerate(findings):
        finding = dict(raw)
        if finding.get('enriched_at'):
            fast.append((i, _apply_defaults(finding)))
        else:
            slow.append((i, finding))

    print(
        f"[+] Report enrichment: {len(fast)} from DB cache, "
        f"{len(slow)} need live API calls"
    )

    result_map = {}

    # Fast path -- just apply defaults, no API calls
    for i, finding in fast:
        result_map[i] = finding
        if progress_callback:
            try:
                progress_callback(len(result_map), total)
            except Exception:
                pass

    # Slow path -- parallel live enrichment
    if slow:
        workers = min(max_workers, len(slow), 4)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers
        ) as pool:
            future_to_index = {
                pool.submit(
                    _enrich_one_live,
                    finding,
                    i,
                    total,
                    progress_callback
                ): i
                for i, finding in slow
            }
            for future in concurrent.futures.as_completed(future_to_index):
                i = future_to_index[future]
                try:
                    result_map[i] = future.result()
                except Exception as e:
                    # Absolute fallback
                    finding = dict(findings[i])
                    print(
                        f"[!] Unexpected enrichment error at index {i}: {e}"
                    )
                    result_map[i] = _apply_defaults(finding)

    # Return in original order
    return [result_map[i] for i in range(total)]


def get_findings_with_db_columns(scan_id):
    """
    Fetch findings for a scan including all optional columns
    (cve_id, cwe_id, cvss_score, attack_path, verify_steps,
    mitre_technique, mitre_tactic, cve_description, enriched_at)
    if they exist on this DB. Always returns plain dicts.
    """
    from backend.db import get_connection
    conn   = get_connection()
    cursor = conn.cursor()
    available = _get_column_set(cursor)
    base_cols = [
        'id', 'scan_id', 'tool', 'asset', 'category', 'severity',
        'title', 'description', 'evidence', 'recommendation',
        'status', 'created_at',
    ]
    optional_cols = [
        'cve_id', 'cwe_id', 'cvss_score', 'analyst_notes',
        'attack_path', 'verify_steps', 'mitre_technique',
        'mitre_tactic', 'cve_description', 'enriched_at',
    ]
    cols = [c for c in base_cols if c in available]
    cols += [c for c in optional_cols if c in available]
    col_sql = ', '.join(cols)
    cursor.execute(
        f"SELECT {col_sql} FROM findings WHERE scan_id=? "
        f"ORDER BY CASE severity "
        f"WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        f"WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 "
        f"WHEN 'Info' THEN 4 ELSE 5 END",
        (scan_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(zip(cols, row)) for row in rows]
