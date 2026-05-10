from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}

class FindingsDashboard(QWidget):
    def __init__(self, scan_id, on_finding_click=None, on_audit_click=None):
        super().__init__()
        self.scan_id = scan_id
        self.on_finding_click = on_finding_click
        self.on_audit_click = on_audit_click
        self.findings = []
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_findings()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 20, 30, 20)

        top_row = QHBoxLayout()
        title = QLabel(f"Findings Dashboard — Scan #{self.scan_id}")
        title.setObjectName("dashTitle")
        top_row.addWidget(title)
        top_row.addStretch()

        audit_btn = QPushButton("Audit Log")
        audit_btn.setObjectName("auditBtn")
        audit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        audit_btn.clicked.connect(self.view_audit_log)
        top_row.addWidget(audit_btn)

        export_pdf_btn = QPushButton("Export PDF")
        export_pdf_btn.setObjectName("exportBtn")
        export_pdf_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_pdf_btn.clicked.connect(self.export_pdf)
        top_row.addWidget(export_pdf_btn)

        export_docx_btn = QPushButton("Export Word")
        export_docx_btn.setObjectName("exportBtn")
        export_docx_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_docx_btn.clicked.connect(self.export_docx)
        top_row.addWidget(export_docx_btn)

        layout.addLayout(top_row)
        layout.addSpacing(15)

        self.summary_row = QHBoxLayout()
        layout.addLayout(self.summary_row)
        layout.addSpacing(15)

        filter_row = QHBoxLayout()
        filter_lbl = QLabel("Filter by severity:")
        filter_lbl.setObjectName("filterLbl")
        filter_row.addWidget(filter_lbl)

        for severity in ['All', 'Critical', 'High', 'Medium', 'Low', 'Info']:
            btn = QPushButton(severity)
            btn.setObjectName("filterBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, s=severity: self.filter_table(s)
            )
            filter_row.addWidget(btn)
        filter_row.addStretch()
        layout.addLayout(filter_row)
        layout.addSpacing(10)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            '#', 'Severity', 'Tool', 'Asset', 'Title', 'Status'
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

        hint = QLabel("Click any row to view full finding details")
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
                WHEN "High" THEN 1
                WHEN "Medium" THEN 2
                WHEN "Low" THEN 3
                WHEN "Info" THEN 4
                ELSE 5 END
        ''', (self.scan_id,))
        self.findings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        self.update_summary()
        self.populate_table(self.findings)

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
            card = self.make_card(severity, str(count), color)
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
            f"color: {color}; border: none;"
        )
        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 11px; color: #888; border: none;")

        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)
        return card

    def populate_table(self, findings):
        self.table.setRowCount(0)
        for i, finding in enumerate(findings, 1):
            row = self.table.rowCount()
            self.table.insertRow(row)

            severity = finding['severity']
            color = SEVERITY_COLORS.get(severity, '#888888')

            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(QColor('#888'))

            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            tool_item = QTableWidgetItem(finding['tool'])
            tool_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            asset_item = QTableWidgetItem(finding['asset'])
            title_item = QTableWidgetItem(finding['title'])

            status = finding['status']
            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if status == 'Confirmed':
                status_item.setForeground(QColor('#1d9e75'))
            elif status == 'Dismissed':
                status_item.setForeground(QColor('#888'))
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
                f for f in self.findings if f['severity'] == severity
            ]
            self.populate_table(filtered)

    def on_row_click(self, row, col):
        visible_findings = []
        for i in range(self.table.rowCount()):
            num = int(self.table.item(i, 0).text()) - 1
            visible_findings.append(self.findings[num])
        if self.on_finding_click and row < len(visible_findings):
            self.on_finding_click(visible_findings[row])

    def view_audit_log(self):
        if self.on_audit_click:
            self.on_audit_click(self.scan_id)

    def export_pdf(self):
        from reports.report_builder import generate_pdf
        import subprocess
        path = f'storage/{self.scan_id}/report/report.pdf'
        generate_pdf(self.scan_id, path)
        subprocess.Popen(['xdg-open', path])

    def export_docx(self):
        from reports.report_builder import generate_docx
        import subprocess
        path = f'storage/{self.scan_id}/report/report.docx'
        generate_docx(self.scan_id, path)
        subprocess.Popen(['xdg-open', path])

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #dashTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #summaryCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                min-width: 80px;
                max-width: 120px;
            }
            #filterLbl {
                color: #888;
                font-size: 12px;
            }
            #filterBtn {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 12px;
            }
            #filterBtn:hover {
                border: 1px solid #e94560;
                color: #e94560;
            }
            #findingsTable {
                background-color: #16213e;
                border: 1px solid #0f3460;
                gridline-color: #0f3460;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #e0e0e0;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 4px 8px;
            }
            QTableWidget::item:selected {
                background-color: #0f3460;
                color: #e94560;
            }
            #exportBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            #exportBtn:hover { background-color: #c73652; }
            #auditBtn {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 8px 16px;
            }
            #auditBtn:hover {
                border: 1px solid #e94560;
                color: #e94560;
            }
            #hintLbl {
                color: #444;
                font-size: 11px;
                margin-top: 4px;
            }
        """
