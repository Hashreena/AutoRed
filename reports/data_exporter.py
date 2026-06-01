import json
import csv
import os
from backend.db import get_connection

def get_findings_for_export(scan_id):
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, tool, asset, category, severity,
               title, description, evidence, recommendation, status
        FROM findings WHERE scan_id=?
        ORDER BY CASE severity
            WHEN "Critical" THEN 0
            WHEN "High" THEN 1
            WHEN "Medium" THEN 2
            WHEN "Low" THEN 3
            WHEN "Info" THEN 4
            ELSE 5 END
    ''', (scan_id,))
    rows = cursor.fetchall()
    conn.close()

    findings = []
    for row in rows:
        findings.append({
            'id': row[0],
            'tool': row[1],
            'asset': row[2],
            'category': row[3],
            'severity': row[4],
            'title': row[5],
            'description': row[6],
            'evidence': row[7],
            'recommendation': row[8],
            'status': row[9]
        })
    return findings

def get_scan_info(scan_id):
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'id': row[0],
            'name': row[1],
            'target': row[2],
            'profile': row[3],
            'status': row[4],
            'approval_ref': row[5],
            'created_at': row[6],
            'completed_at': row[7]
        }
    return {}

def export_json(scan_id, output_path):
    scan = get_scan_info(scan_id)
    findings = get_findings_for_export(scan_id)

    export_data = {
        'scan': scan,
        'total_findings': len(findings),
        'summary': {
            'Critical': sum(1 for f in findings if f['severity'] == 'Critical'),
            'High':     sum(1 for f in findings if f['severity'] == 'High'),
            'Medium':   sum(1 for f in findings if f['severity'] == 'Medium'),
            'Low':      sum(1 for f in findings if f['severity'] == 'Low'),
            'Info':     sum(1 for f in findings if f['severity'] == 'Info'),
        },
        'findings': findings
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"[+] JSON exported to: {output_path}")
    return output_path

def export_csv(scan_id, output_path):
    findings = get_findings_for_export(scan_id)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    fieldnames = [
        'id', 'tool', 'asset', 'category', 'severity',
        'title', 'description', 'evidence', 'recommendation', 'status'
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    print(f"[+] CSV exported to: {output_path}")
    return output_path

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    scan_id = 18
    json_path = f'storage/{scan_id}/report/findings.json'
    csv_path = f'storage/{scan_id}/report/findings.csv'

    export_json(scan_id, json_path)
    export_csv(scan_id, csv_path)

    print("[+] Both exports done!")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
