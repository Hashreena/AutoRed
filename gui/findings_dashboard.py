import os
import json
import urllib.request
import urllib.error
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView,
    QMessageBox, QMenu, QDialog, QScrollArea
)
from PyQt6.QtGui import QColor, QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}

DROPDOWN_STYLE = """
    QMenu {
        background-color: #161b22;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 4px;
        padding: 4px;
        font-size: 13px;
    }
    QMenu::item {
        padding: 8px 24px;
        border-radius: 4px;
    }
    QMenu::item:selected {
        background-color: #21262d;
        color: #e94560;
    }
    QMenu::separator {
        height: 1px;
        background: #30363d;
        margin: 4px 8px;
    }
"""

SECTION_COLORS = {
    'SCAN OVERVIEW':          '#4a9eff',
    'OVERVIEW':               '#4a9eff',
    'CRITICAL & HIGH ISSUES': '#e94560',
    'CRITICAL ISSUES':        '#e94560',
    'BUSINESS IMPACT':        '#ff8c00',
    'IMMEDIATE ACTIONS':      '#1d9e75',
    'TOP REMEDIATIONS':       '#1d9e75',
    'RECOMMENDATIONS':        '#1d9e75',
    'REFERENCES':             '#8b949e',
}


class PreloadWorker(QThread):
    done = pyqtSignal(int, dict)

    def __init__(self, finding_id, finding):
        super().__init__()
        self.finding_id = finding_id
        self.finding    = finding

    def run(self):
        try:
            from backend.cve_enricher import (
                enrich_finding, get_attack_path_ai
            )
            result   = enrich_finding(self.finding)
            nvd_best = result.get('nvd_best')
            attack, verify = get_attack_path_ai(
                self.finding, nvd_best
            )
            result['attack_path']  = attack
            result['verify_steps'] = verify
            self.done.emit(self.finding_id, result)
        except Exception as e:
            print(
                f"[!] Preload error for "
                f"{self.finding_id}: {e}"
            )
            self.done.emit(self.finding_id, {})


class SummaryWorker(QThread):
    done  = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, prompt):
        super().__init__()
        self.prompt = prompt

    def run(self):
        try:
            from gui.ai_chat import load_api_key, clean_markdown
            api_key = load_api_key()
            if not api_key:
                self.error.emit(
                    "No API key found.\n"
                    "Add ANTHROPIC_API_KEY to your .env file."
                )
                return

            payload = json.dumps({
                "model":      "claude-sonnet-4-5-20250929",
                "max_tokens": 2000,
                "messages":   [
                    {"role": "user", "content": self.prompt}
                ],
            }).encode('utf-8')

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type":      "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key":         api_key,
                },
                method="POST"
            )
            with urllib.request.urlopen(
                req, timeout=60
            ) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                text = data['content'][0]['text']
                self.done.emit(clean_markdown(text))

        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8')
            try:
                err = json.loads(body)
                msg = err.get(
                    'error', {}
                ).get('message', str(e))
            except Exception:
                msg = str(e)
            self.error.emit(f"API Error: {msg}")
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")


class FindingsDashboard(QWidget):
    def __init__(self, scan_id, on_finding_click=None,
                 on_audit_click=None, on_charts_click=None,
                 on_graph_click=None):
        super().__init__()
        self.scan_id          = scan_id
        self.on_finding_click = on_finding_click
        self.on_audit_click   = on_audit_click
        self.on_charts_click  = on_charts_click
        self.on_graph_click   = on_graph_click
        self.findings         = []
        self.summary_worker   = None
        self.enrich_cache     = {}
        self.enrich_workers   = []
        self.preload_queue    = []
        self.preload_total    = 0
        self.preload_done     = 0
        self.active_workers   = 0
        self.max_concurrent   = 2
        self.queue_index      = 0
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_findings()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 20, 30, 20)

        top_row = QHBoxLayout()
        title = QLabel(
            f"Findings Dashboard — Scan #{self.scan_id}"
        )
        title.setObjectName("dashTitle")
        top_row.addWidget(title)
        top_row.addStretch()

        audit_btn = QPushButton("Audit Log")
        audit_btn.setObjectName("auditBtn")
        audit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        audit_btn.clicked.connect(self.view_audit_log)
        top_row.addWidget(audit_btn)

        visualize_btn = QPushButton("Visualize ▾")
        visualize_btn.setObjectName("visualizeBtn")
        visualize_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        visualize_menu = QMenu(self)
        visualize_menu.setStyleSheet(DROPDOWN_STYLE)
        charts_action = QAction("View Charts", self)
        charts_action.triggered.connect(self.view_charts)
        visualize_menu.addAction(charts_action)
        visualize_btn.setMenu(visualize_menu)
        top_row.addWidget(visualize_btn)

        export_btn = QPushButton("Export ▾")
        export_btn.setObjectName("exportDropBtn")
        export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_menu = QMenu(self)
        export_menu.setStyleSheet(DROPDOWN_STYLE)

        pdf_action = QAction("Export PDF", self)
        pdf_action.triggered.connect(self.export_pdf)
        export_menu.addAction(pdf_action)

        word_action = QAction("Export Word", self)
        word_action.triggered.connect(self.export_docx)
        export_menu.addAction(word_action)

        export_menu.addSeparator()

        json_action = QAction("Export JSON", self)
        json_action.triggered.connect(self.export_json)
        export_menu.addAction(json_action)

        csv_action = QAction("Export CSV", self)
        csv_action.triggered.connect(self.export_csv_file)
        export_menu.addAction(csv_action)

        export_btn.setMenu(export_menu)
        top_row.addWidget(export_btn)

        ai_btn = QPushButton("🤖 AI Summary")
        ai_btn.setObjectName("aiSummaryBtn")
        ai_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ai_btn.clicked.connect(self.show_ai_summary)
        top_row.addWidget(ai_btn)

        layout.addLayout(top_row)
        layout.addSpacing(15)

        self.summary_row = QHBoxLayout()
        layout.addLayout(self.summary_row)
        layout.addSpacing(15)

        filter_row = QHBoxLayout()
        filter_lbl = QLabel("Filter by severity:")
        filter_lbl.setObjectName("filterLbl")
        filter_row.addWidget(filter_lbl)

        for severity in [
            'All', 'Critical', 'High',
            'Medium', 'Low', 'Info'
        ]:
            btn = QPushButton(severity)
            btn.setObjectName("filterBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, s=severity:
                self.filter_table(s)
            )
            filter_row.addWidget(btn)

        filter_row.addStretch()

        self.preload_lbl = QLabel("⏳ Loading intelligence...")
        self.preload_lbl.setStyleSheet(
            "color: #555; font-size: 10px; "
            "background: transparent; border: none;"
        )
        filter_row.addWidget(self.preload_lbl)

        layout.addLayout(filter_row)
        layout.addSpacing(10)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            '#', 'Severity', 'Tool',
            'Asset', 'Title', 'Status'
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setObjectName("findingsTable")
        self.table.verticalHeader().setVisible(False)
        self.table.cellClicked.connect(self.on_row_click)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 130)
        self.table.setColumnWidth(5, 90)
        layout.addWidget(self.table)

        hint = QLabel(
            "Click any row to view full finding details"
        )
        hint.setObjectName("hintLbl")
        layout.addWidget(hint)

    def load_findings(self):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, tool, asset, category, severity, title,
                   description, evidence, recommendation, status
            FROM findings WHERE scan_id=?
            ORDER BY CASE severity
                WHEN "Critical" THEN 0
                WHEN "High"     THEN 1
                WHEN "Medium"   THEN 2
                WHEN "Low"      THEN 3
                WHEN "Info"     THEN 4
                ELSE 5 END
        ''', (self.scan_id,))
        self.findings = [
            dict(row) for row in cursor.fetchall()
        ]
        conn.close()
        self.update_summary()
        self.populate_table(self.findings)
        self.start_preloading()

    def start_preloading(self):
        priority = [
            f for f in self.findings
            if f.get('severity') in ('Critical', 'High')
        ]
        others = [
            f for f in self.findings
            if f.get('severity') not in ('Critical', 'High')
        ]
        self.preload_queue  = (priority + others)[:20]
        self.preload_total  = len(self.preload_queue)
        self.preload_done   = 0
        self.active_workers = 0
        self.queue_index    = 0
        self.launch_next_workers()

    def launch_next_workers(self):
        while (
            self.active_workers < self.max_concurrent
            and self.queue_index < len(self.preload_queue)
        ):
            finding = self.preload_queue[self.queue_index]
            self.queue_index += 1
            fid     = finding.get('id')
            worker  = PreloadWorker(fid, finding)
            worker.done.connect(self.on_preload_done)
            worker.start()
            self.enrich_workers.append(worker)
            self.active_workers += 1

    def on_preload_done(self, finding_id, result):
        self.enrich_cache[finding_id] = result
        self.preload_done   += 1
        self.active_workers -= 1
        remaining = self.preload_total - self.preload_done

        if remaining > 0:
            self.preload_lbl.setText(
                f"⏳ Loading intelligence... "
                f"({self.preload_done}/{self.preload_total})"
            )
        else:
            self.preload_lbl.setText(
                "✅ Intelligence ready"
            )
            self.preload_lbl.setStyleSheet(
                "color: #1d9e75; font-size: 10px; "
                "background: transparent; border: none;"
            )

        print(
            f"[+] Preloaded finding {finding_id} — "
            f"CVE: {result.get('best_cve', 'none')} "
            f"Exploit: {result.get('exploit_level', 'N/A')}"
        )

        self.launch_next_workers()

    def update_summary(self):
        while self.summary_row.count():
            child = self.summary_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        counts = {}
        for f in self.findings:
            sev = f['severity']
            counts[sev] = counts.get(sev, 0) + 1

        total_card = self.make_card(
            "Total", str(len(self.findings)), "#4a9eff"
        )
        self.summary_row.addWidget(total_card)

        for severity, color in SEVERITY_COLORS.items():
            count = counts.get(severity, 0)
            card  = self.make_card(severity, str(count), color)
            self.summary_row.addWidget(card)

        self.summary_row.addStretch()

    def make_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("summaryCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 10, 15, 10)

        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"font-size: 24px; font-weight: bold; "
            f"color: {color}; border: none; "
            f"background: transparent;"
        )
        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            "font-size: 11px; color: #8b949e; "
            "border: none; background: transparent;"
        )
        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)
        return card

    def populate_table(self, findings):
        self.table.setRowCount(0)
        for i, finding in enumerate(findings, 1):
            row      = self.table.rowCount()
            self.table.insertRow(row)
            severity = finding['severity']
            color    = SEVERITY_COLORS.get(
                severity, '#888888'
            )

            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            num_item.setForeground(QColor('#555'))

            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            tool_item = QTableWidgetItem(finding['tool'])
            tool_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            asset_item  = QTableWidgetItem(finding['asset'])
            title_item  = QTableWidgetItem(finding['title'])

            status      = finding['status']
            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            if status == 'Confirmed':
                status_item.setForeground(QColor('#1d9e75'))
            elif status == 'Dismissed':
                status_item.setForeground(QColor('#555'))
            else:
                status_item.setForeground(QColor('#ff8c00'))

            self.table.setItem(row, 0, num_item)
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, tool_item)
            self.table.setItem(row, 3, asset_item)
            self.table.setItem(row, 4, title_item)
            self.table.setItem(row, 5, status_item)
            self.table.setRowHeight(row, 36)

    def filter_table(self, severity):
        if severity == 'All':
            self.populate_table(self.findings)
        else:
            filtered = [
                f for f in self.findings
                if f['severity'] == severity
            ]
            self.populate_table(filtered)

    def on_row_click(self, row, col):
        visible = []
        for i in range(self.table.rowCount()):
            num = int(self.table.item(i, 0).text()) - 1
            visible.append(self.findings[num])
        if self.on_finding_click and row < len(visible):
            finding    = visible[row]
            finding_id = finding.get('id')
            cached     = self.enrich_cache.get(finding_id)
            self.on_finding_click(finding, cached)

    def view_audit_log(self):
        if self.on_audit_click:
            self.on_audit_click(self.scan_id)

    def view_charts(self):
        if self.on_charts_click:
            self.on_charts_click(self.scan_id)

    def view_network_graph(self):
        if self.on_graph_click:
            self.on_graph_click(self.scan_id)

    def export_pdf(self):
        from reports.report_builder import generate_pdf
        import subprocess
        path = f'storage/{self.scan_id}/report/report.pdf'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        generate_pdf(self.scan_id, path)
        subprocess.Popen(['xdg-open', path])

    def export_docx(self):
        from reports.report_builder import generate_docx
        import subprocess
        path = f'storage/{self.scan_id}/report/report.docx'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        generate_docx(self.scan_id, path)
        subprocess.Popen(['xdg-open', path])

    def export_json(self):
        from reports.data_exporter import export_json
        path = (
            f'storage/{self.scan_id}/report/findings.json'
        )
        os.makedirs(os.path.dirname(path), exist_ok=True)
        export_json(self.scan_id, path)
        msg = QMessageBox()
        msg.setWindowTitle("Export Complete")
        msg.setText(f"JSON exported!\n\nSaved to:\n{path}")
        msg.exec()

    def export_csv_file(self):
        from reports.data_exporter import export_csv
        path = (
            f'storage/{self.scan_id}/report/findings.csv'
        )
        os.makedirs(os.path.dirname(path), exist_ok=True)
        export_csv(self.scan_id, path)
        msg = QMessageBox()
        msg.setWindowTitle("Export Complete")
        msg.setText(f"CSV exported!\n\nSaved to:\n{path}")
        msg.exec()

    def show_ai_summary(self):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, severity, title, description,
                   recommendation
            FROM findings WHERE scan_id=?
            ORDER BY CASE severity
                WHEN "Critical" THEN 0
                WHEN "High"     THEN 1
                WHEN "Medium"   THEN 2
                WHEN "Low"      THEN 3
                ELSE 4 END
        ''', (self.scan_id,))
        findings = cursor.fetchall()
        cursor.execute(
            'SELECT * FROM scans WHERE id=?', (self.scan_id,)
        )
        scan = cursor.fetchone()
        conn.close()

        counts = {
            'Critical': 0, 'High': 0,
            'Medium':   0, 'Low':  0, 'Info': 0
        }
        for f in findings:
            counts[f[1]] = counts.get(f[1], 0) + 1

        # ── Build enriched findings using cache ──────────────
        critical_high_lines = []
        for f in findings:
            fid      = f[0]
            severity = f[1]
            title    = f[2]

            if severity not in ('Critical', 'High'):
                continue

            cached   = self.enrich_cache.get(fid, {})
            nvd_best = cached.get('nvd_best')
            cve_id   = 'N/A'
            cvss     = 'N/A'

            if nvd_best:
                raw_cve = nvd_best.get('cve_id', 'N/A')
                if raw_cve and 'No CVE' not in raw_cve:
                    cve_id = raw_cve
                cvss = nvd_best.get('cvss_score', 'N/A')

            line = (
                f"[{severity}] {title} "
                f"| CVE: {cve_id} | CVSS: {cvss}"
            )
            critical_high_lines.append(line)

        critical_high_text = '\n'.join(critical_high_lines)

        all_findings_text = '\n'.join([
            f"[{f[1]}] {f[2]}"
            for f in findings
        ])

        # ── Build references from cache ──────────────────────
        references_text = ''
        seen_cves = []
        for f in findings:
            fid    = f[0]
            cached = self.enrich_cache.get(fid, {})
            nvd    = cached.get('nvd_best')
            if nvd:
                cve = nvd.get('cve_id', '')
                if (
                    cve and
                    'No CVE' not in cve and
                    cve not in seen_cves
                ):
                    seen_cves.append(cve)
                    desc    = nvd.get('description', '')[:80]
                    nvd_url = nvd.get('nvd_url', '')
                    references_text += (
                        f"• {cve}: {nvd_url} — {desc}\n"
                    )

        prompt = (
            f"Analyze this security scan and respond ONLY "
            f"in this exact format. No paragraphs.\n\n"
            f"SCAN DATA:\n"
            f"Target: "
            f"{scan['target'] if scan else 'Unknown'}\n"
            f"Date: "
            f"{scan['created_at'] if scan else 'Unknown'}\n"
            f"Profile: "
            f"{scan['profile'] if scan else 'Unknown'}\n"
            f"Critical: {counts['Critical']} | "
            f"High: {counts['High']} | "
            f"Medium: {counts['Medium']} | "
            f"Low: {counts['Low']} | "
            f"Info: {counts['Info']}\n\n"
            f"Critical and High Findings "
            f"(with real CVE and CVSS from NVD):\n"
            f"{critical_high_text}\n\n"
            f"All Findings:\n{all_findings_text[:600]}\n\n"
            f"Known CVE References (from NVD API):\n"
            f"{references_text if references_text else 'None detected yet'}\n\n"
            f"REQUIRED OUTPUT FORMAT:\n\n"
            f"SCAN OVERVIEW\n"
            f"• Target: [target ip or domain]\n"
            f"• Scan Date: [date]\n"
            f"• Profile: [scan profile]\n"
            f"• Total Findings: [number]\n"
            f"• Overall Risk Rating: [level] "
            f"— [one sentence justification]\n"
            f"• AI Confidence: [High/Medium/Low] "
            f"— [one sentence why]\n\n"
            f"CRITICAL & HIGH ISSUES\n"
            f"• [finding name] (CVSS: [use real CVSS from data above]) "
            f"— [why dangerous]. CVE: [use real CVE from data above, "
            f"if N/A write N/A]\n"
            f"• [list ALL critical and high findings, "
            f"use the real CVE and CVSS provided]\n\n"
            f"BUSINESS IMPACT\n"
            f"• [what attacker can do, max 4 points]\n\n"
            f"IMMEDIATE ACTIONS\n"
            f"• [fix action, max 5 points]\n\n"
            f"REFERENCES\n"
            f"• [use only the real CVE references provided above, "
            f"do not invent CVE numbers]\n\n"
            f"IMPORTANT: Only use CVE numbers from the data "
            f"provided above. Do not generate or guess CVE numbers."
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("AI Security Summary")
        dialog.setMinimumSize(660, 580)
        dialog.setStyleSheet("""
            QDialog {
                background: #0d1117;
                color: #e6edf3;
                font-family: Arial;
            }
            QLabel {
                background: transparent;
                border: none;
            }
        """)

        dl = QVBoxLayout(dialog)
        dl.setContentsMargins(24, 20, 24, 20)
        dl.setSpacing(10)

        header_row = QHBoxLayout()
        title_lbl = QLabel("🤖  AI Security Summary")
        title_lbl.setStyleSheet(
            "color: #e94560; font-size: 16px; "
            "font-weight: bold;"
        )
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        cache_count = len(self.enrich_cache)
        total       = min(len(self.findings), 20)
        if cache_count < total:
            cache_lbl = QLabel(
                f"⏳ Intelligence: {cache_count}/{total} ready"
            )
            cache_lbl.setStyleSheet(
                "color: #ff8c00; font-size: 10px; "
                "background: transparent; border: none;"
            )
            header_row.addWidget(cache_lbl)

        dl.addLayout(header_row)

        info_lbl = QLabel(
            f"Target: "
            f"{scan['target'] if scan else 'N/A'}  |  "
            f"Critical: {counts['Critical']}  "
            f"High: {counts['High']}  "
            f"Medium: {counts['Medium']}  "
            f"Low: {counts['Low']}  "
            f"Info: {counts['Info']}"
        )
        info_lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px;"
        )
        dl.addWidget(info_lbl)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(
            "background: #30363d; border: none; "
            "max-height: 1px;"
        )
        dl.addWidget(div)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none; background: #0d1117;
            }
            QScrollBar:vertical {
                background: #161b22; width: 6px;
                border-radius: 3px;
            }
            QScrollBar::handle:vertical {
                background: #30363d; border-radius: 3px;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height: 0; }
        """)

        self.scroll_widget = QWidget()
        self.scroll_widget.setStyleSheet(
            "background: #0d1117;"
        )
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setContentsMargins(4, 8, 4, 8)
        self.scroll_layout.setSpacing(4)

        self.waiting_lbl = QLabel(
            "Generating AI summary... please wait ⏳"
        )
        self.waiting_lbl.setStyleSheet(
            "color: #8b949e; font-size: 13px;"
        )
        self.scroll_layout.addWidget(self.waiting_lbl)
        self.scroll_layout.addStretch()

        scroll.setWidget(self.scroll_widget)
        dl.addWidget(scroll)

        note_lbl = QLabel(
            "✅ CVE data sourced from NVD API — "
            "not AI-generated"
        )
        note_lbl.setStyleSheet(
            "color: #1d9e75; font-size: 10px; "
            "background: transparent; border: none;"
        )
        dl.addWidget(note_lbl)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background: #e94560; color: white;
                border: none; border-radius: 6px;
                padding: 8px 24px; font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background: #c73652; }
        """)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(dialog.close)
        btn_row.addWidget(close_btn)
        dl.addLayout(btn_row)

        self.summary_worker = SummaryWorker(prompt)
        self.summary_worker.done.connect(self.render_summary)
        self.summary_worker.error.connect(
            lambda e: self.waiting_lbl.setText(
                f"Could not generate summary:\n\n{e}"
            )
        )
        self.summary_worker.start()

        dialog.exec()

    def render_summary(self, text):
        while self.scroll_layout.count() > 1:
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.waiting_lbl.hide()

        lines = text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                spacer = QLabel("")
                spacer.setFixedHeight(6)
                spacer.setStyleSheet(
                    "background: transparent; border: none;"
                )
                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1, spacer
                )
                continue

            upper      = line.upper()
            is_section = any(
                upper.startswith(k)
                for k in SECTION_COLORS
            )

            if is_section:
                color = '#e6edf3'
                for k, c in SECTION_COLORS.items():
                    if upper.startswith(k):
                        color = c
                        break

                lbl = QLabel(line)
                lbl.setStyleSheet(
                    f"color: {color}; font-size: 13px; "
                    f"font-weight: bold; "
                    f"background: transparent; "
                    f"border: none; margin-top: 10px;"
                )
                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1, lbl
                )

                div = QFrame()
                div.setFrameShape(QFrame.Shape.HLine)
                div.setFixedHeight(1)
                div.setStyleSheet(
                    f"background: {color}55; border: none;"
                )
                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1, div
                )

            elif line.startswith('•'):
                lbl = QLabel(line)
                lbl.setWordWrap(True)
                lbl.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )
                lbl.setStyleSheet(
                    "color: #e6edf3; font-size: 12px; "
                    "background: transparent; border: none; "
                    "padding-left: 10px; margin-top: 2px;"
                )
                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1, lbl
                )

            else:
                lbl = QLabel(line)
                lbl.setWordWrap(True)
                lbl.setStyleSheet(
                    "color: #8b949e; font-size: 12px; "
                    "background: transparent; border: none;"
                )
                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1, lbl
                )

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            #dashTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
                background: transparent;
                border: none;
            }
            #summaryCard {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                min-width: 80px;
                max-width: 120px;
            }
            #filterLbl {
                color: #8b949e;
                font-size: 12px;
                background: transparent;
            }
            #filterBtn {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 12px;
            }
            #filterBtn:hover {
                border: 1px solid #e94560;
                color: #e94560;
            }
            #findingsTable {
                background-color: #161b22;
                border: 1px solid #30363d;
                gridline-color: #21262d;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #21262d;
                color: #8b949e;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 4px 8px;
                background-color: #0d1117;
            }
            QTableWidget::item:selected {
                background-color: #21262d;
                color: #e94560;
            }
            #auditBtn {
                background-color: transparent;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px 16px;
            }
            #auditBtn:hover {
                border: 1px solid #e94560;
                color: #e94560;
            }
            #visualizeBtn {
                background-color: #9b59b6;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            #visualizeBtn:hover {
                background-color: #7d3c98;
            }
            #visualizeBtn::menu-indicator { image: none; }
            #exportDropBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            #exportDropBtn:hover {
                background-color: #c73652;
            }
            #exportDropBtn::menu-indicator { image: none; }
            #aiSummaryBtn {
                background-color: #1d9e75;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            #aiSummaryBtn:hover {
                background-color: #178a64;
            }
            #hintLbl {
                color: #444;
                font-size: 11px;
                margin-top: 4px;
                background: transparent;
            }
        """
