from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt
from backend.db import get_connection

class AuditLogViewer(QWidget):
    def __init__(self, scan_id, on_close=None):
        super().__init__()
        self.scan_id = scan_id
        self.on_close = on_close
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_logs()

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

        title = QLabel(f"Audit Log — Scan #{self.scan_id}")
        title.setObjectName("auditTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Full audit trail of all actions performed during this scan."
        )
        subtitle.setObjectName("auditSub")
        layout.addWidget(subtitle)
        layout.addSpacing(15)

        self.stats_row = QHBoxLayout()
        layout.addLayout(self.stats_row)
        layout.addSpacing(15)

        log_label = QLabel("Audit Trail:")
        log_label.setObjectName("logLabel")
        layout.addWidget(log_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("logText")
        layout.addWidget(self.log_text)

    def load_logs(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()
        cursor.execute('''
            SELECT action, detail, timestamp
            FROM audit_logs
            WHERE scan_id=?
            ORDER BY id ASC
        ''', (self.scan_id,))
        logs = cursor.fetchall()
        conn.close()

        self.update_stats(logs)
        self.populate_logs(logs)

    def update_stats(self, logs):
        while self.stats_row.count():
            child = self.stats_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        tool_starts = sum(1 for l in logs if l[0] == 'tool_started')
        tool_done = sum(1 for l in logs if l[0] == 'tool_finished')
        tool_errors = sum(1 for l in logs if l[0] in ['tool_error', 'tool_timeout'])
        parsed = sum(1 for l in logs if 'parsed' in l[0])

        cards = [
            ("Total Events",    str(len(logs)),      "#4a9eff"),
            ("Tools Started",   str(tool_starts),    "#1d9e75"),
            ("Tools Finished",  str(tool_done),      "#1d9e75"),
            ("Parse Events",    str(parsed),         "#ff8c00"),
            ("Errors",          str(tool_errors),    "#e94560"),
        ]
        for label, value, color in cards:
            card = self.make_card(label, value, color)
            self.stats_row.addWidget(card)
        self.stats_row.addStretch()

    def make_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("statsCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 8, 15, 8)
        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"font-size: 22px; font-weight: bold; "
            f"color: {color}; border: none;"
        )
        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 10px; color: #888; border: none;")
        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)
        return card

    def populate_logs(self, logs):
        if not logs:
            self.log_text.setPlainText("No audit logs found for this scan.")
            return

        lines = []
        for action, detail, timestamp in logs:
            ts = str(timestamp)[:19] if timestamp else 'N/A'

            if action == 'scan_started':
                prefix = '[START]  '
            elif action == 'scan_completed':
                prefix = '[DONE]   '
            elif action == 'tool_started':
                prefix = '[RUN]    '
            elif action == 'tool_finished':
                prefix = '[FINISH] '
            elif action in ['tool_error', 'tool_timeout']:
                prefix = '[ERROR]  '
            elif 'parsed' in action:
                prefix = '[PARSE]  '
            else:
                prefix = '[INFO]   '

            lines.append(f"{ts}  {prefix}{detail}")

        self.log_text.setPlainText('\n'.join(lines))

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
            #auditTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #auditSub {
                color: #888;
                font-size: 12px;
            }
            #logLabel {
                color: #aaa;
                font-size: 12px;
                margin-bottom: 4px;
            }
            #logText {
                background-color: #0d0d1a;
                color: #00ff41;
                font-family: Courier;
                font-size: 11px;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 10px;
            }
            #statsCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                min-width: 100px;
                max-width: 150px;
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
        """
