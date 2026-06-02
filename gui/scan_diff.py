from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
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

BG     = '#0d1117'
CARD   = '#161b22'
CARD2  = '#21262d'
BORDER = '#30363d'
TEXT   = '#e6edf3'
DIM    = '#8b949e'


class ScanDiffScreen(QWidget):
    def __init__(self, scan_a_id, scan_b_id,
                 on_close=None):
        super().__init__()
        self.scan_a_id = scan_a_id
        self.scan_b_id = scan_b_id
        self.on_close  = on_close
        self.setStyleSheet(self.get_stylesheet())
        self.load_data()
        self.init_ui()

    def load_data(self):
        conn   = get_connection()
        cursor = conn.cursor()

        def get_scan(scan_id):
            cursor.execute(
                'SELECT * FROM scans WHERE id=?',
                (scan_id,)
            )
            return cursor.fetchone()

        def get_findings(scan_id):
            cursor.execute('''
                SELECT title, severity, tool, asset,
                       description
                FROM findings WHERE scan_id=?
            ''', (scan_id,))
            return cursor.fetchall()

        self.scan_a    = get_scan(self.scan_a_id)
        self.scan_b    = get_scan(self.scan_b_id)
        findings_a_raw = get_findings(self.scan_a_id)
        findings_b_raw = get_findings(self.scan_b_id)
        conn.close()

        # Use title as key for comparison
        def to_dict(findings):
            d = {}
            for f in findings:
                key = f[0].strip().lower()
                d[key] = {
                    'title':       f[0],
                    'severity':    f[1],
                    'tool':        f[2],
                    'asset':       f[3] or '',
                    'description': f[4] or '',
                }
            return d

        dict_a = to_dict(findings_a_raw)
        dict_b = to_dict(findings_b_raw)

        keys_a = set(dict_a.keys())
        keys_b = set(dict_b.keys())

        # New — in B but not in A
        self.new_findings = [
            dict_b[k] for k in (keys_b - keys_a)
        ]
        self.new_findings.sort(
            key=lambda x: (
                ['Critical', 'High', 'Medium',
                 'Low', 'Info'].index(x['severity'])
                if x['severity'] in
                ['Critical', 'High', 'Medium', 'Low', 'Info']
                else 99
            )
        )

        # Fixed — in A but not in B
        self.fixed_findings = [
            dict_a[k] for k in (keys_a - keys_b)
        ]
        self.fixed_findings.sort(
            key=lambda x: (
                ['Critical', 'High', 'Medium',
                 'Low', 'Info'].index(x['severity'])
                if x['severity'] in
                ['Critical', 'High', 'Medium', 'Low', 'Info']
                else 99
            )
        )

        # Persisting — in both
        self.persist_findings = [
            dict_b[k] for k in (keys_a & keys_b)
        ]
        self.persist_findings.sort(
            key=lambda x: (
                ['Critical', 'High', 'Medium',
                 'Low', 'Info'].index(x['severity'])
                if x['severity'] in
                ['Critical', 'High', 'Medium', 'Low', 'Info']
                else 99
            )
        )

        # Counts
        self.count_a       = len(findings_a_raw)
        self.count_b       = len(findings_b_raw)
        self.count_new     = len(self.new_findings)
        self.count_fixed   = len(self.fixed_findings)
        self.count_persist = len(self.persist_findings)

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            f"QScrollArea {{ border: none; "
            f"background: {BG}; }}"
        )

        content = QWidget()
        content.setStyleSheet(f"background: {BG};")
        layout  = QVBoxLayout(content)
        layout.setContentsMargins(30, 20, 30, 30)
        layout.setSpacing(14)

        # ── Back button ───────────────────────────────────
        top_row  = QHBoxLayout()
        back_btn = QPushButton("← Back")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        # ── Header ────────────────────────────────────────
        title_lbl = QLabel("Scan Diff — Comparison Report")
        title_lbl.setObjectName("diffTitle")
        layout.addWidget(title_lbl)

        target_a = (
            self.scan_a['target']
            if self.scan_a else 'Unknown'
        )
        target_b = (
            self.scan_b['target']
            if self.scan_b else 'Unknown'
        )
        date_a = str(
            self.scan_a['created_at']
            if self.scan_a else ''
        )[:16]
        date_b = str(
            self.scan_b['created_at']
            if self.scan_b else ''
        )[:16]

        sub_lbl = QLabel(
            f"Scan A: #{self.scan_a_id} — "
            f"{target_a} ({date_a})   →   "
            f"Scan B: #{self.scan_b_id} — "
            f"{target_b} ({date_b})"
        )
        sub_lbl.setObjectName("diffSub")
        layout.addWidget(sub_lbl)

        # ── Summary cards ─────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)

        delta = self.count_b - self.count_a
        delta_str = (
            f"+{delta}" if delta > 0
            else str(delta)
        )
        delta_color = (
            '#e94560' if delta > 0
            else '#1d9e75' if delta < 0
            else '#8b949e'
        )

        summary_items = [
            (
                "Scan A Findings",
                str(self.count_a),
                '#4a9eff',
                f"#{self.scan_a_id} — {date_a}"
            ),
            (
                "Scan B Findings",
                str(self.count_b),
                '#4a9eff',
                f"#{self.scan_b_id} — {date_b}"
            ),
            (
                "Change",
                delta_str,
                delta_color,
                "net difference"
            ),
            (
                "🆕 New",
                str(self.count_new),
                '#e94560',
                "newly appeared"
            ),
            (
                "✅ Fixed",
                str(self.count_fixed),
                '#1d9e75',
                "remediated"
            ),
            (
                "⚠️ Persisting",
                str(self.count_persist),
                '#ff8c00',
                "still present"
            ),
        ]

        for label, value, color, sub in summary_items:
            card = QFrame()
            card.setObjectName("diffCard")
            cl   = QVBoxLayout(card)
            cl.setContentsMargins(14, 10, 14, 10)

            v = QLabel(value)
            v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.setStyleSheet(
                f"font-size: 24px; font-weight: bold; "
                f"color: {color}; background: transparent; "
                f"border: none;"
            )
            l = QLabel(label)
            l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            l.setStyleSheet(
                f"font-size: 11px; font-weight: bold; "
                f"color: {TEXT}; "
                f"background: transparent; border: none;"
            )
            s = QLabel(sub)
            s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            s.setStyleSheet(
                f"font-size: 9px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            cl.addWidget(v)
            cl.addWidget(l)
            cl.addWidget(s)
            cards_row.addWidget(card)

        layout.addLayout(cards_row)

        # ── Remediation rate ──────────────────────────────
        if self.count_a > 0:
            rate = int(
                (self.count_fixed / self.count_a) * 100
            )
            rate_color = (
                '#1d9e75' if rate >= 50
                else '#ff8c00' if rate >= 20
                else '#e94560'
            )
            rate_frame = QFrame()
            rate_frame.setObjectName("diffCard")
            rate_l = QHBoxLayout(rate_frame)
            rate_l.setContentsMargins(16, 10, 16, 10)

            rate_lbl = QLabel("Remediation Rate:")
            rate_lbl.setStyleSheet(
                f"font-size: 13px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            rate_l.addWidget(rate_lbl)

            rate_val = QLabel(f"{rate}%")
            rate_val.setStyleSheet(
                f"font-size: 18px; font-weight: bold; "
                f"color: {rate_color}; "
                f"background: transparent; border: none;"
            )
            rate_l.addWidget(rate_val)
            rate_l.addStretch()

            # Bar
            track = QFrame()
            track.setFixedHeight(10)
            track.setFixedWidth(300)
            track.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 5px; border: none;"
            )
            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)
            fill = QFrame()
            fill.setStyleSheet(
                f"background: {rate_color}; "
                f"border-radius: 5px; border: none;"
            )
            fill.setFixedWidth(max(4, int(rate * 3)))
            track_l.addWidget(fill)
            track_l.addStretch()
            rate_l.addWidget(track)

            verdict = QLabel(
                "Good progress!"
                if rate >= 50
                else "Needs attention"
                if rate >= 20
                else "Critical — most findings unresolved"
            )
            verdict.setStyleSheet(
                f"font-size: 11px; color: {rate_color}; "
                f"background: transparent; border: none; "
                f"margin-left: 10px;"
            )
            rate_l.addWidget(verdict)
            layout.addWidget(rate_frame)

        # ── New findings table ────────────────────────────
        if self.new_findings:
            layout.addWidget(
                self.make_section_header(
                    f"🆕  NEW FINDINGS ({self.count_new})",
                    "Appeared in Scan B — not in Scan A",
                    '#e94560'
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.new_findings, '#e9456022'
                )
            )

        # ── Fixed findings table ──────────────────────────
        if self.fixed_findings:
            layout.addWidget(
                self.make_section_header(
                    f"✅  FIXED FINDINGS ({self.count_fixed})",
                    "Were in Scan A — resolved in Scan B",
                    '#1d9e75'
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.fixed_findings, '#1d9e7522'
                )
            )

        # ── Persisting findings table ─────────────────────
        if self.persist_findings:
            layout.addWidget(
                self.make_section_header(
                    f"⚠️  PERSISTING FINDINGS "
                    f"({self.count_persist})",
                    "Present in both scans — not yet resolved",
                    '#ff8c00'
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.persist_findings, '#ff8c0022'
                )
            )

        if (
            not self.new_findings and
            not self.fixed_findings and
            not self.persist_findings
        ):
            empty = QLabel(
                "No findings to compare — "
                "both scans appear identical."
            )
            empty.setStyleSheet(
                f"color: {DIM}; font-size: 13px; "
                f"background: transparent; border: none;"
            )
            layout.addWidget(empty)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def make_section_header(self, title, sub, color):
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background: transparent; "
            "border: none; }"
        )
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(0, 4, 0, 0)
        fl.setSpacing(2)

        row = QHBoxLayout()
        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"color: {color}; font-size: 13px; "
            f"font-weight: bold; "
            f"background: transparent; border: none;"
        )
        row.addWidget(lbl)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(
            f"background: {color}55; border: none; "
            f"max-height: 1px;"
        )
        row.addWidget(line)
        fl.addLayout(row)

        sub_lbl = QLabel(sub)
        sub_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; "
            f"background: transparent; border: none;"
        )
        fl.addWidget(sub_lbl)
        return frame

    def build_findings_table(self, findings, row_bg):
        tbl = QTableWidget()
        tbl.setColumnCount(4)
        tbl.setHorizontalHeaderLabels([
            'Severity', 'Title', 'Tool', 'Asset'
        ])
        tbl.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        tbl.setColumnWidth(0, 80)
        tbl.setColumnWidth(2, 100)
        tbl.setColumnWidth(3, 160)
        tbl.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        tbl.verticalHeader().setVisible(False)
        tbl.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        tbl.setStyleSheet(f"""
            QTableWidget {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 6px;
                gridline-color: {CARD2};
            }}
            QHeaderView::section {{
                background: {CARD2};
                color: {DIM};
                padding: 6px 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }}
            QTableWidget::item {{
                padding: 4px 8px;
                background: {CARD};
                color: {TEXT};
            }}
            QTableWidget::item:selected {{
                background: {CARD2};
                color: #e94560;
            }}
        """)

        for f in findings:
            row      = tbl.rowCount()
            tbl.insertRow(row)
            severity = f['severity']
            color    = SEVERITY_COLORS.get(
                severity, '#888'
            )

            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            title_item = QTableWidgetItem(f['title'])
            tool_item  = QTableWidgetItem(f['tool'])
            tool_item.setForeground(QColor(DIM))
            tool_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            asset_item = QTableWidgetItem(f['asset'])
            asset_item.setForeground(QColor(DIM))

            tbl.setItem(row, 0, sev_item)
            tbl.setItem(row, 1, title_item)
            tbl.setItem(row, 2, tool_item)
            tbl.setItem(row, 3, asset_item)
            tbl.setRowHeight(row, 32)

        max_rows   = min(len(findings), 12)
        tbl_height = 38 + (max_rows * 33)
        tbl.setMaximumHeight(tbl_height)
        return tbl

    def go_back(self):
        if self.on_close:
            self.on_close()

    def get_stylesheet(self):
        return f"""
            QWidget {{
                background-color: {BG};
                color: {TEXT};
                font-family: Arial;
                font-size: 13px;
            }}
            QScrollArea {{ border: none; }}
            #diffTitle {{
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
                background: transparent;
                border: none;
            }}
            #diffSub {{
                color: {DIM};
                font-size: 11px;
                background: transparent;
                border: none;
            }}
            #diffCard {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            #backBtn {{
                background: transparent;
                color: {DIM};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 12px;
            }}
            #backBtn:hover {{
                color: {TEXT};
                border-color: {TEXT};
            }}
        """
