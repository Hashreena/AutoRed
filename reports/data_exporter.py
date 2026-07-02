"""
AutoRed -- JSON/CSV export.

FIX: previously used conn.row_factory = None plus raw row[0],
row[1]... indexing. That's fragile -- if a column is ever added,
removed, or reordered on the findings/scans tables (this project
has already migrated several times: cve_id, cwe_id, cvss_score,
analyst_notes were all added after the original schema), every
index silently shifts and the export quietly writes the wrong
data into the wrong field with no error raised.

Now uses dict(row) + .get('column_name') everywhere, same safe
pattern already used in reports/report_builder.py and
gui/finding_detail.py, so column order never matters.

Also: JSON/CSV exports now include the real enriched CVE/CWE/
CVSS data (and MITRE/attack-path for JSON) per finding, instead
of only the bare tool-output fields.
"""

import json
import csv
import os

from backend.db import get_connection
from reports.report_enrichment import (
    get_findings_with_db_columns,
    enrich_findings_for_report,
)


def get_findings_for_export(scan_id, enrich=True, progress_callback=None):
    """
    Returns a list of finding dicts for this scan. When enrich=True
    (the default), each finding is extended with the live
    CVE/CWE/CVSS/MITRE/attack-path data via the same enrichment
    pipeline used in the GUI's finding detail view.
    """
    findings = get_findings_with_db_columns(scan_id)

    if enrich:
        findings = enrich_findings_for_report(
            findings, progress_callback=progress_callback
        )

    return findings


def get_scan_info(scan_id):
    """Returns the scan row as a plain dict -- safe column access
    by name instead of raw tuple index."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return {}

    return dict(row)


def export_json(scan_id, output_path, enrich=True, progress_callback=None):
    scan     = get_scan_info(scan_id)
    findings = get_findings_for_export(
        scan_id, enrich=enrich, progress_callback=progress_callback
    )

    export_data = {
        'scan': scan,
        'total_findings': len(findings),
        'summary': {
            'Critical': sum(1 for f in findings if f.get('severity') == 'Critical'),
            'High':     sum(1 for f in findings if f.get('severity') == 'High'),
            'Medium':   sum(1 for f in findings if f.get('severity') == 'Medium'),
            'Low':      sum(1 for f in findings if f.get('severity') == 'Low'),
            'Info':     sum(1 for f in findings if f.get('severity') == 'Info'),
        },
        'cve_summary': {
            'with_cve':    sum(1 for f in findings if f.get('cve_id')),
            'without_cve': sum(1 for f in findings if not f.get('cve_id')),
        },
        'findings': findings,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)

    print(f"[+] JSON exported to: {output_path}")
    return output_path


def export_csv(scan_id, output_path, enrich=True, progress_callback=None):
    findings = get_findings_for_export(
        scan_id, enrich=enrich, progress_callback=progress_callback
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # CSV needs a fixed, flat column set. We pick the fields that
    # matter for a spreadsheet view -- the full nested detail
    # (attack_surface_tags as a list, etc.) stays in the JSON
    # export, which handles nested structures naturally.
    fieldnames = [
        'id', 'tool', 'asset', 'category', 'severity', 'title',
        'description', 'evidence', 'recommendation', 'status',
        'cve_id', 'cvss_score', 'cvss_severity', 'cwe_id',
        'cwe_name', 'mitre_tech_id', 'mitre_technique',
        'exploit_level', 'no_cve_reason',
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(
            f, fieldnames=fieldnames, extrasaction='ignore'
        )
        writer.writeheader()
        for finding in findings:
            row = {k: finding.get(k, '') for k in fieldnames}
            # CSV cells can't hold None cleanly -- normalise to ''
            row = {k: ('' if v is None else v) for k, v in row.items()}
            writer.writerow(row)

    print(f"[+] CSV exported to: {output_path}")
    return output_path


if __name__ == '__main__':
    from backend.db import init_db
    init_db()
    scan_id   = 18
    json_path = f'storage/{scan_id}/report/findings.json'
    csv_path  = f'storage/{scan_id}/report/findings.csv'
    print("[*] Enriching and exporting JSON (this calls live "
          "CVE/CWE/MITRE lookups per finding, may take a while)...")
    export_json(scan_id, json_path)
    print("[*] Enriching and exporting CSV...")
    export_csv(scan_id, csv_path)
    print("[+] Both exports done!")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
