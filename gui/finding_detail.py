from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}

class FindingDetail(QWidget):
    def __init__(self, finding, on_close=None, on_status_change=None):
        super().__init__()
        self.finding = finding
        self.on_close = on_close
        self.on_status_change = on_status_change
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 20, 30, 20)

        top_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)
        layout.addSpacing(15)

        severity = self.finding.get('severity', 'Info')
        color = SEVERITY_COLORS.get(severity, '#888')

        sev_badge = QLabel(f"  {severity}  ")
        sev_badge.setStyleSheet(
            f"background-color: {color}; color: white; "
            f"font-weight: bold; font-size: 12px; "
            f"border-radius: 4px; padding: 4px 8px;"
        )
        sev_badge.setFixedHeight(28)
        sev_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_lbl = QLabel(self.finding.get('title', 'Untitled'))
        title_lbl.setObjectName("detailTitle")
        title_lbl.setWordWrap(True)

        layout.addWidget(sev_badge)
        layout.addSpacing(8)
        layout.addWidget(title_lbl)
        layout.addSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setObjectName("detailScroll")

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(15)

        fields = [
            ("Tool", self.finding.get('tool', 'N/A')),
            ("Asset", self.finding.get('asset', 'N/A')),
            ("Category", self.finding.get('category', 'N/A')),
            ("Status", self.finding.get('status', 'Potential')),
        ]

        for label, value in fields:
            row = QHBoxLayout()
            lbl = QLabel(f"{label}:")
            lbl.setObjectName("detailLabel")
            lbl.setFixedWidth(120)
            val = QLabel(str(value))
            val.setObjectName("detailValue")
            val.setWordWrap(True)
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            content_layout.addLayout(row)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setObjectName("divider")
        content_layout.addWidget(divider)

        sections = [
            ("Description", self.finding.get('description', 'No description.')),
            ("Evidence", self.finding.get('evidence', 'No evidence.')),
            ("Recommendation", self.finding.get('recommendation', 'No recommendation.')),
        ]

        for section_title, section_content in sections:
            sec_lbl = QLabel(section_title)
            sec_lbl.setObjectName("sectionTitle")
            content_layout.addWidget(sec_lbl)

            sec_text = QTextEdit()
            sec_text.setPlainText(section_content)
            sec_text.setReadOnly(True)
            sec_text.setObjectName("sectionText")
            sec_text.setMaximumHeight(100)
            content_layout.addWidget(sec_text)

        scroll.setWidget(content)
        layout.addWidget(scroll)
        layout.addSpacing(15)

        btn_row = QHBoxLayout()

        confirm_btn = QPushButton("Confirm Finding")
        confirm_btn.setObjectName("confirmBtn")
        confirm_btn.clicked.connect(lambda: self.update_status('Confirmed'))
        btn_row.addWidget(confirm_btn)

        dismiss_btn = QPushButton("Dismiss Finding")
        dismiss_btn.setObjectName("dismissBtn")
        dismiss_btn.clicked.connect(lambda: self.update_status('Dismissed'))
        btn_row.addWidget(dismiss_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def update_status(self, status):
        finding_id = self.finding.get('id')
        if finding_id:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE findings SET status=? WHERE id=?',
                (status, finding_id)
            )
            conn.commit()
            conn.close()
            self.finding['status'] = status
            print(f"[+] Finding {finding_id} marked as {status}")

            if self.on_status_change:
                self.on_status_change(status)

    def go_back(self):
        if self.on_close:
            self.on_close()

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #backBtn {
                background-color: transparent;
                color: #888;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 6px 16px;
            }
            #backBtn:hover {
                color: #e0e0e0;
                border: 1px solid #e0e0e0;
            }
            #detailTitle {
                color: #e0e0e0;
                font-size: 18px;
                font-weight: bold;
            }
            #detailLabel {
                color: #888;
                font-size: 12px;
            }
            #detailValue {
                color: #e0e0e0;
                font-size: 13px;
            }
            #sectionTitle {
                color: #e94560;
                font-size: 13px;
                font-weight: bold;
                margin-top: 5px;
            }
            #sectionText {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }
            #detailScroll {
                border: none;
                background-color: #1a1a2e;
            }
            #divider {
                color: #0f3460;
                margin: 5px 0;
            }
            #confirmBtn {
                background-color: #1d9e75;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 20px;
                font-weight: bold;
            }
            #confirmBtn:hover { background-color: #158a63; }
            #dismissBtn {
                background-color: transparent;
                color: #e94560;
                border: 1px solid #e94560;
                border-radius: 4px;
                padding: 8px 20px;
            }
            #dismissBtn:hover {
                background-color: #e94560;
                color: white;
            }
        """
