"""
AutoRed -- Background enrichment worker.
Called immediately after each finding is inserted into the
database during scan execution. Runs in a daemon thread so
it never blocks the scan progress UI.

By the time the user opens the findings dashboard or clicks
Export PDF, most findings will already have their CVE/CWE/
MITRE/attack_path data stored in the database -- making
report generation near-instant since no live API calls are
needed for already-enriched findings.
"""
import threading
from datetime import datetime


def enrich_and_save(finding_id, finding_dict):
    """
    Enrich one finding and write all results back to the
    findings table. Runs in a background daemon thread.
    Never raises -- all exceptions are caught and logged.
    """
    from backend.cve_enricher import enrich_finding, get_attack_path_ai
    from backend.db import get_connection

    print(f"[~] Background enrichment started for finding {finding_id}")

    try:
        result   = enrich_finding(finding_dict)
        nvd_best = result.get('nvd_best') or {}
        cwe_data = result.get('cwe_data') or {}
        mitre    = result.get('mitre')    or {}

        # Attack path -- separate Claude/GPT call
        attack_path  = None
        verify_steps = None
        try:
            attack_path, verify_steps = get_attack_path_ai(
                finding_dict, nvd_best
            )
        except Exception as e:
            print(
                f"[!] Attack-path skipped for finding "
                f"{finding_id}: {e}"
            )

        # Pull enriched values
        cve_id          = nvd_best.get('cve_id')
        cvss_score      = nvd_best.get('cvss_score')
        cwe_id          = cwe_data.get('cwe_id')
        mitre_technique = mitre.get('technique')
        mitre_tactic    = mitre.get('tactic')
        cve_description = nvd_best.get('description')

        # Sanitise cve_id -- don't write "No CVE found" strings
        if cve_id and 'No CVE' in str(cve_id):
            cve_id = None

        conn   = get_connection()
        cursor = conn.cursor()

        # Check which columns actually exist (safe for older DBs)
        cursor.execute("PRAGMA table_info(findings)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        # Build update dynamically based on available columns
        updates = []
        values  = []

        # Always try cve_id / cwe_id / cvss_score
        # Use COALESCE so we never overwrite a value already set
        # by path_enricher.py at parse time
        if 'cve_id' in existing_cols:
            updates.append("cve_id = COALESCE(cve_id, ?)")
            values.append(cve_id)
        if 'cwe_id' in existing_cols:
            updates.append("cwe_id = COALESCE(cwe_id, ?)")
            values.append(cwe_id)
        if 'cvss_score' in existing_cols:
            updates.append("cvss_score = COALESCE(cvss_score, ?)")
            values.append(cvss_score)

        # These columns may not exist on older installs --
        # add them first if missing, then update
        new_cols = {
            'attack_path':     'TEXT',
            'verify_steps':    'TEXT',
            'mitre_technique': 'TEXT',
            'mitre_tactic':    'TEXT',
            'cve_description': 'TEXT',
            'enriched_at':     'TEXT',
        }
        for col, col_type in new_cols.items():
            if col not in existing_cols:
                try:
                    cursor.execute(
                        f"ALTER TABLE findings ADD COLUMN {col} {col_type}"
                    )
                    print(f"[+] Added column findings.{col}")
                except Exception:
                    pass  # already exists or unsupported -- safe to ignore

        col_values = {
            'attack_path':     attack_path,
            'verify_steps':    verify_steps,
            'mitre_technique': mitre_technique,
            'mitre_tactic':    mitre_tactic,
            'cve_description': cve_description,
            'enriched_at':     datetime.now().isoformat(),
        }
        for col, val in col_values.items():
            updates.append(f"{col} = ?")
            values.append(val)

        if not updates:
            print(f"[!] No columns to update for finding {finding_id}")
            conn.close()
            return

        values.append(finding_id)
        cursor.execute(
            f"UPDATE findings SET {', '.join(updates)} WHERE id = ?",
            values
        )
        conn.commit()
        conn.close()
        print(f"[+] Background enrichment saved for finding {finding_id}")

    except Exception as e:
        print(
            f"[!] Background enrichment failed for finding "
            f"{finding_id}: {e}"
        )


def enrich_and_save_async(finding_id, finding_dict):
    """
    Fire-and-forget: spawns a daemon thread to enrich one finding.
    Returns immediately -- never blocks the caller.
    The thread is a daemon so it won't prevent the process
    from exiting if the user closes the app mid-scan.
    """
    t = threading.Thread(
        target=enrich_and_save,
        args=(finding_id, finding_dict),
        daemon=True,
        name=f"enrich-finding-{finding_id}",
    )
    t.start()
    return t
