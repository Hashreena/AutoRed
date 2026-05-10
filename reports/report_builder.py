import os
from backend.db import get_connection

def clean(text):
    if not text:
        return ''
    return (str(text)
        .replace('\u2014', '-')
        .replace('\u2013', '-')
        .replace('\u2019', "'")
        .replace('\u2018', "'")
        .replace('\u201c', '"')
        .replace('\u201d', '"')
        .replace('\u2022', '-')
        .replace('\u00e9', 'e')
        .replace('\u00e0', 'a')
        .replace('\u00fc', 'u')
        .replace('\u00f6', 'o')
        .replace('\u00e4', 'a'))

def get_scan_data(scan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    scan = dict(cursor.fetchone())
    cursor.execute('''
        SELECT * FROM findings WHERE scan_id=?
        ORDER BY CASE severity
            WHEN "Critical" THEN 0
            WHEN "High" THEN 1
            WHEN "Medium" THEN 2
            WHEN "Low" THEN 3
            WHEN "Info" THEN 4
            ELSE 5 END
    ''', (scan_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scan, findings

def count_by_severity(findings):
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for f in findings:
        sev = f.get('severity', 'Info')
        counts[sev] = counts.get(sev, 0) + 1
    return counts

def generate_pdf(scan_id, output_path):
    from fpdf import FPDF

    scan, findings = get_scan_data(scan_id)
    counts = count_by_severity(findings)

    severity_colors = {
        'Critical': (139, 0, 0),
        'High':     (233, 69, 96),
        'Medium':   (255, 140, 0),
        'Low':      (180, 150, 0),
        'Info':     (74, 158, 255),
    }

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── COVER PAGE ──────────────────────────────────────────
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 26)
    pdf.set_text_color(233, 69, 96)
    pdf.ln(15)
    pdf.cell(0, 14, 'AutoRed', ln=True, align='C')

    pdf.set_font('Helvetica', '', 12)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 7, 'Reconnaissance Automation Platform', ln=True, align='C')
    pdf.cell(0, 7, 'Security Assessment Report', ln=True, align='C')
    pdf.ln(6)

    pdf.set_draw_color(233, 69, 96)
    pdf.line(30, pdf.get_y(), 180, pdf.get_y())
    pdf.ln(8)

    scan_details = [
        ('Scan Name',      str(scan.get('name', 'N/A'))),
        ('Target',         str(scan.get('target', 'N/A'))),
        ('Profile',        str(scan.get('profile', 'N/A'))),
        ('Date',           str(scan.get('created_at', 'N/A'))[:10]),
        ('Approval Ref',   str(scan.get('approval_ref') or 'N/A')),
        ('Total Findings', str(len(findings))),
    ]
    for label, value in scan_details:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(45, 8, clean(label) + ':', ln=False)
        pdf.set_font('Helvetica', '', 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, clean(value), ln=True)

    # ── EXECUTIVE SUMMARY ────────────────────────────────────
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(233, 69, 96)
    pdf.cell(0, 12, 'Executive Summary', ln=True)
    pdf.ln(3)

    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_fill_color(15, 52, 96)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(85, 10, 'Severity', border=1, fill=True, align='C')
    pdf.cell(85, 10, 'Count', border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 11)
    for severity, count in counts.items():
        color = severity_colors.get(severity, (100, 100, 100))
        pdf.set_text_color(*color)
        pdf.cell(85, 9, severity, border=1, align='C')
        pdf.set_text_color(0, 0, 0)
        pdf.cell(85, 9, str(count), border=1, align='C')
        pdf.ln()

    pdf.ln(6)
    total = len(findings)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 8, 'Finding Distribution:', ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(50, 50, 50)
    for severity, count in counts.items():
        if count > 0:
            pct = round((count / total) * 100) if total > 0 else 0
            pdf.cell(0, 7, f'  {severity}: {count} findings ({pct}%)', ln=True)

    # ── DETAILED FINDINGS ────────────────────────────────────
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(233, 69, 96)
    pdf.cell(0, 12, 'Detailed Findings', ln=True)
    pdf.ln(2)

    for i, finding in enumerate(findings, 1):
        if pdf.get_y() > 230:
            pdf.add_page()

        severity = finding.get('severity', 'Info')
        color = severity_colors.get(severity, (100, 100, 100))

        # Title
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(*color)
        raw_title = clean(f"{i}. [{severity}] {finding.get('title', 'N/A')}")
        pdf.cell(0, 8, raw_title[:95], ln=True)

        # Meta info — each on its own line using cell
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 6, clean('Tool: ' + str(finding.get('tool', 'N/A'))), ln=True)
        pdf.cell(0, 6, clean('Asset: ' + str(finding.get('asset', 'N/A')))[:95], ln=True)
        pdf.cell(0, 6, clean('Category: ' + str(finding.get('category', 'N/A')) +
                              '  |  Status: ' + str(finding.get('status', 'N/A'))), ln=True)
        pdf.ln(2)

        # Description
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(0, 6, 'Description:', ln=True)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(50, 50, 50)
        desc = clean(str(finding.get('description', 'N/A')))[:200]
        pdf.cell(0, 6, desc[:95], ln=True)
        if len(desc) > 95:
            pdf.cell(0, 6, desc[95:190], ln=True)
        pdf.ln(1)

        # Evidence
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(0, 6, 'Evidence:', ln=True)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(50, 50, 50)
        evid = clean(str(finding.get('evidence', 'N/A')))[:200]
        pdf.cell(0, 6, evid[:95], ln=True)
        if len(evid) > 95:
            pdf.cell(0, 6, evid[95:190], ln=True)
        pdf.ln(1)

        # Recommendation
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(0, 6, 'Recommendation:', ln=True)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(50, 50, 50)
        rec = clean(str(finding.get('recommendation', 'N/A')))[:200]
        pdf.cell(0, 6, rec[:95], ln=True)
        if len(rec) > 95:
            pdf.cell(0, 6, rec[95:190], ln=True)
        pdf.ln(2)

        # Divider
        pdf.set_draw_color(220, 220, 220)
        pdf.line(20, pdf.get_y(), 190, pdf.get_y())
        pdf.ln(5)

    # ── METHODOLOGY ──────────────────────────────────────────
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(233, 69, 96)
    pdf.cell(0, 12, 'Methodology', ln=True)
    pdf.ln(3)

    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(0, 0, 0)
    method_lines = [
        clean(f"Target: {scan.get('target', 'N/A')}"),
        clean(f"Profile: {scan.get('profile', 'N/A')}"),
        'Tools used: Nmap, Subfinder, httpx, WhatWeb, ffuf',
        '',
        'This assessment was conducted using AutoRed v1.0,',
        'a GUI-based reconnaissance automation platform',
        'developed as a Final Year Project at APU.',
        '',
        'All findings were automatically parsed, normalized,',
        'deduplicated and severity-scored before presentation.',
    ]
    for line in method_lines:
        pdf.cell(0, 7, line, ln=True)

    pdf.ln(6)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 8, 'Tools Summary:', ln=True)
    tools_info = [
        ('Nmap',      'Port scanning and service version detection'),
        ('Subfinder', 'Passive subdomain enumeration via OSINT'),
        ('httpx',     'HTTP probing to identify live web hosts'),
        ('WhatWeb',   'Web technology fingerprinting'),
        ('ffuf',      'Fast directory and endpoint fuzzing'),
    ]
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(50, 50, 50)
    for tool, desc in tools_info:
        pdf.cell(30, 7, tool, ln=False)
        pdf.cell(0, 7, '- ' + desc, ln=True)

    pdf.ln(6)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(233, 69, 96)
    pdf.cell(0, 8, 'Disclaimer:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, 'This report was generated by AutoRed v1.0 for authorized', ln=True)
    pdf.cell(0, 6, 'security assessment purposes only. Treat as confidential.', ln=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    print(f"[+] PDF report saved to: {output_path}")
    return output_path

def generate_docx(scan_id, output_path):
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    scan, findings = get_scan_data(scan_id)
    counts = count_by_severity(findings)

    doc = Document()

    title = doc.add_heading('AutoRed Security Assessment Report', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub = doc.add_paragraph('Reconnaissance Automation Platform')
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    doc.add_heading('Scan Details', level=1)
    details = [
        ('Scan Name',      clean(scan.get('name', 'N/A'))),
        ('Target',         clean(scan.get('target', 'N/A'))),
        ('Profile',        clean(scan.get('profile', 'N/A'))),
        ('Date',           clean(str(scan.get('created_at', 'N/A'))[:10])),
        ('Approval Ref',   clean(scan.get('approval_ref') or 'N/A')),
        ('Total Findings', str(len(findings))),
    ]
    tbl = doc.add_table(rows=len(details), cols=2)
    tbl.style = 'Table Grid'
    for i, (label, value) in enumerate(details):
        tbl.cell(i, 0).text = label
        tbl.cell(i, 1).text = value

    doc.add_heading('Executive Summary', level=1)
    sum_tbl = doc.add_table(rows=1, cols=2)
    sum_tbl.style = 'Table Grid'
    hdr = sum_tbl.rows[0].cells
    hdr[0].text = 'Severity'
    hdr[1].text = 'Count'
    for severity, count in counts.items():
        row = sum_tbl.add_row().cells
        row[0].text = severity
        row[1].text = str(count)

    doc.add_heading('Detailed Findings', level=1)
    for i, finding in enumerate(findings, 1):
        doc.add_heading(
            clean(f"{i}. [{finding.get('severity')}] {finding.get('title', 'N/A')}"),
            level=2
        )
        info = doc.add_paragraph()
        info.add_run('Tool: ').bold = True
        info.add_run(clean(finding.get('tool', 'N/A')))
        info.add_run('  |  Asset: ').bold = True
        info.add_run(clean(finding.get('asset', 'N/A')))
        info.add_run('  |  Status: ').bold = True
        info.add_run(clean(finding.get('status', 'N/A')))

        for section, key in [
            ('Description',    'description'),
            ('Evidence',       'evidence'),
            ('Recommendation', 'recommendation'),
        ]:
            p = doc.add_paragraph()
            p.add_run(f'{section}: ').bold = True
            p.add_run(clean(finding.get(key, 'N/A')))

    doc.add_heading('Methodology', level=1)
    doc.add_paragraph(clean(
        f"This assessment was conducted using AutoRed v1.0. "
        f"Target: {scan.get('target', 'N/A')}. "
        f"Profile: {scan.get('profile', 'N/A')}. "
        f"Tools used: Nmap, Subfinder, httpx, WhatWeb, ffuf. "
        f"All findings were automatically parsed, normalized, "
        f"deduplicated and severity-scored before presentation."
    ))

    doc.add_heading('Disclaimer', level=1)
    doc.add_paragraph(clean(
        'This report was generated by AutoRed v1.0 for authorized '
        'security assessment purposes only. Treat as confidential.'
    ))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc.save(output_path)
    print(f"[+] DOCX report saved to: {output_path}")
    return output_path

if __name__ == '__main__':
    from backend.db import init_db
    init_db()

    scan_id = 9
    pdf_path = f'storage/{scan_id}/report/report.pdf'
    docx_path = f'storage/{scan_id}/report/report.docx'

    print("[*] Generating PDF...")
    generate_pdf(scan_id, pdf_path)

    print("[*] Generating DOCX...")
    generate_docx(scan_id, docx_path)

    print("[+] Both reports generated successfully!")
