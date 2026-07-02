from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from backend.db import get_connection
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    color = hex_color.strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


class ScanDiffScreen(QWidget):
    def __init__(
        self,
        scan_a_id,
        scan_b_id,
        on_close=None,
        on_finding_click=None,
        prefs=None
    ):
        super().__init__()

        self.scan_a_id = scan_a_id
        self.scan_b_id = scan_b_id
        self.on_close = on_close
        self.on_finding_click = on_finding_click

        self.prefs = prefs or load_prefs()
        self._set_theme_colors()

        self.setStyleSheet(self.get_stylesheet())

        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)

        self.load_data()
        self.init_ui()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self.BG = self.t["bg"]
        self.PAGE = self.t.get("page", self.t.get("sidebar_bg", self.BG))
        self.BG_DEEP = self.t.get("bg_deep", self.BG)

        self.CARD = self.t["card_bg"]
        self.CARD2 = self.t["card_bg_2"]

        self.BORDER = self.t["border"]
        self.BORDER_SOFT = self.t["border_soft"]

        self.TEXT = self.t["text"]
        self.DIM = self.t["text_muted"]
        self.SOFT = self.t["text_soft"]

        self.ACCENT = self.t["accent"]
        self.ACCENT_HOVER = self.t["accent_hover"]
        self.ACCENT_DARK = self.t["accent_dark"]

        self.SUCCESS = self.t["success"]
        self.SUCCESS_HOVER = self.t.get("success_hover", self.SUCCESS)

        self.WARNING = self.t["warning"]
        self.WARNING_HOVER = self.t.get("warning_hover", "#EA580C")

        self.MEDIUM = self.t.get(
            "medium",
            "#CA8A04" if not self.dark else "#FACC15"
        )
        self.INFO = self.t["info"]

        self.HOVER = self.t.get(
            "hover",
            rgba_from_hex(self.ACCENT, 18 if not self.dark else 25)
        )
        self.SELECTION_BG = self.t.get(
            "selection_bg",
            rgba_from_hex(self.ACCENT, 28 if not self.dark else 35)
        )
        self.SELECTION_TEXT = self.t.get(
            "selection_text",
            "#7F1D1D" if not self.dark else "#FEE2E2"
        )
        self.BUTTON_SOFT = self.t.get(
            "button_soft",
            "#FFFFFF" if not self.dark else "rgba(15, 23, 42, 205)"
        )
        self.CARD_HOVER = self.t.get(
            "card_hover",
            rgba_from_hex(self.ACCENT, 55 if not self.dark else 75)
        )

        self.SEVERITY_COLORS = {
            "Critical": self.ACCENT,
            "High": self.WARNING,
            "Medium": self.MEDIUM,
            "Low": self.SUCCESS,
            "Info": self.INFO,
        }

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()

        self.setStyleSheet(self.get_stylesheet())

        while self.outer.count():
            child = self.outer.takeAt(0)

            if child.widget():
                child.widget().deleteLater()

        self.init_ui()

    # ─────────────────────────────────────────────
    # Data loading
    # ─────────────────────────────────────────────

    def load_data(self):
        conn = get_connection()
        cursor = conn.cursor()

        def get_scan(scan_id):
            cursor.execute(
                "SELECT * FROM scans WHERE id=?",
                (scan_id,)
            )
            return cursor.fetchone()

        def get_findings(scan_id):
            cursor.execute("PRAGMA table_info(findings)")
            available = {row[1] for row in cursor.fetchall()}

            base_cols = [
                "id",
                "title",
                "severity",
                "tool",
                "asset",
                "description",
                "evidence",
                "recommendation",
                "category",
            ]

            optional_cols = [
                "cve_id",
                "cwe_id",
                "cvss_score",
            ]

            cols = [col for col in base_cols if col in available]
            cols += [
                col for col in optional_cols
                if col in available
            ]

            col_sql = ", ".join(cols)

            cursor.execute(
                f"SELECT {col_sql} FROM findings WHERE scan_id=?",
                (scan_id,)
            )

            rows = cursor.fetchall()
            self._finding_cols = cols

            return rows

        self.scan_a = get_scan(self.scan_a_id)
        self.scan_b = get_scan(self.scan_b_id)

        findings_a_raw = get_findings(self.scan_a_id)
        findings_b_raw = get_findings(self.scan_b_id)

        conn.close()

        def to_dict(findings):
            cols = self._finding_cols
            data = {}

            for finding in findings:
                row = dict(zip(cols, finding))
                key = row["title"].strip().lower()

                data[key] = {
                    "id": row.get("id"),
                    "title": row.get("title", ""),
                    "severity": row.get("severity", "Info"),
                    "tool": row.get("tool", ""),
                    "asset": row.get("asset") or "",
                    "description": row.get("description") or "",
                    "evidence": row.get("evidence") or "",
                    "recommendation": row.get("recommendation") or "",
                    "category": row.get("category") or "",
                    "cve_id": row.get("cve_id") or "",
                    "cwe_id": row.get("cwe_id") or "",
                    "cvss_score": row.get("cvss_score"),
                }

            return data

        dict_a = to_dict(findings_a_raw)
        dict_b = to_dict(findings_b_raw)

        keys_a = set(dict_a.keys())
        keys_b = set(dict_b.keys())

        severity_order = [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
        ]

        def sort_key(item):
            severity = item.get("severity", "Info")

            if severity in severity_order:
                return severity_order.index(severity)

            return 99

        self.new_findings = [
            dict_b[key] for key in (keys_b - keys_a)
        ]
        self.new_findings.sort(key=sort_key)

        self.fixed_findings = [
            dict_a[key] for key in (keys_a - keys_b)
        ]
        self.fixed_findings.sort(key=sort_key)

        self.persist_findings = [
            dict_b[key] for key in (keys_a & keys_b)
        ]
        self.persist_findings.sort(key=sort_key)

        self.count_a = len(findings_a_raw)
        self.count_b = len(findings_b_raw)
        self.count_new = len(self.new_findings)
        self.count_fixed = len(self.fixed_findings)
        self.count_persist = len(self.persist_findings)

    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            f"""
            QScrollArea {{
                border: none;
                background: {self.BG};
            }}
            """
        )

        content = QWidget()
        content.setStyleSheet(
            f"""
            background-color: {self.BG};
            """
        )

        layout = QVBoxLayout(content)
        layout.setContentsMargins(30, 20, 30, 30)
        layout.setSpacing(14)

        # ── Back button ───────────────────────────────────

        top_row = QHBoxLayout()

        back_btn = QPushButton("← Back")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)

        top_row.addWidget(back_btn)
        top_row.addStretch()

        layout.addLayout(top_row)

        # ── Header card ───────────────────────────────────

        header_card = QFrame()
        header_card.setObjectName("headerCard")

        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(6)

        title_lbl = QLabel("Scan Diff — Comparison Report")
        title_lbl.setObjectName("diffTitle")
        header_layout.addWidget(title_lbl)

        target_a = (
            self.scan_a["target"]
            if self.scan_a else "Unknown"
        )

        target_b = (
            self.scan_b["target"]
            if self.scan_b else "Unknown"
        )

        date_a = str(
            self.scan_a["created_at"]
            if self.scan_a else ""
        )[:16]

        date_b = str(
            self.scan_b["created_at"]
            if self.scan_b else ""
        )[:16]

        sub_lbl = QLabel(
            f"Scan A: #{self.scan_a_id} — "
            f"{target_a} ({date_a})   →   "
            f"Scan B: #{self.scan_b_id} — "
            f"{target_b} ({date_b})"
        )
        sub_lbl.setObjectName("diffSub")
        sub_lbl.setWordWrap(True)
        header_layout.addWidget(sub_lbl)

        hint_lbl = QLabel(
            "💡 Click any finding row below to view its full details"
        )
        hint_lbl.setObjectName("hintLbl")
        header_layout.addWidget(hint_lbl)

        layout.addWidget(header_card)

        # ── Summary cards ─────────────────────────────────

        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)

        summary_items = [
            (
                "Scan A Findings",
                str(self.count_a),
                self.INFO,
                f"#{self.scan_a_id} — {date_a}"
            ),
            (
                "Scan B Findings",
                str(self.count_b),
                self.INFO,
                f"#{self.scan_b_id} — {date_b}"
            ),
            (
                "🆕 New",
                str(self.count_new),
                self.ACCENT,
                "newly appeared"
            ),
            (
                "✅ Fixed",
                str(self.count_fixed),
                self.SUCCESS,
                "remediated"
            ),
            (
                "⚠️ Persisting",
                str(self.count_persist),
                self.WARNING,
                "still present"
            ),
        ]

        for label, value, color, sub in summary_items:
            card = self.make_summary_card(
                label,
                value,
                color,
                sub
            )
            cards_row.addWidget(card)

        layout.addLayout(cards_row)

        # ── Remediation rate ──────────────────────────────

        if self.count_a > 0:
            rate = int(
                (self.count_fixed / self.count_a) * 100
            )

            if rate >= 50:
                rate_color = self.SUCCESS
            elif rate >= 20:
                rate_color = self.WARNING
            else:
                rate_color = self.ACCENT

            rate_frame = QFrame()
            rate_frame.setObjectName("rateCard")

            rate_l = QHBoxLayout(rate_frame)
            rate_l.setContentsMargins(16, 10, 16, 10)
            rate_l.setSpacing(10)

            rate_lbl = QLabel("Remediation Rate:")
            rate_lbl.setStyleSheet(
                f"""
                font-size: {self.fs}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            rate_l.addWidget(rate_lbl)

            rate_val = QLabel(f"{rate}%")
            rate_val.setStyleSheet(
                f"""
                font-size: {self.fs + 5}px;
                font-weight: 900;
                color: {rate_color};
                background: transparent;
                border: none;
                """
            )
            rate_l.addWidget(rate_val)
            rate_l.addStretch()

            track = QFrame()
            track.setFixedHeight(10)
            track.setFixedWidth(300)
            track.setStyleSheet(
                f"""
                background-color: {self.CARD2};
                border-radius: 5px;
                border: none;
                """
            )

            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill = QFrame()
            fill.setStyleSheet(
                f"""
                background-color: {rate_color};
                border-radius: 5px;
                border: none;
                """
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
                f"""
                font-size: {self.fs - 2}px;
                color: {rate_color};
                background: transparent;
                border: none;
                margin-left: 10px;
                font-weight: 800;
                """
            )
            rate_l.addWidget(verdict)

            layout.addWidget(rate_frame)

        # ── New findings table ────────────────────────────

        if self.new_findings:
            layout.addWidget(
                self.make_section_header(
                    f"🆕  NEW FINDINGS ({self.count_new})",
                    "Appeared in Scan B — not in Scan A",
                    self.ACCENT
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.new_findings
                )
            )

        # ── Fixed findings table ──────────────────────────

        if self.fixed_findings:
            layout.addWidget(
                self.make_section_header(
                    f"✅  FIXED FINDINGS ({self.count_fixed})",
                    "Were in Scan A — resolved in Scan B",
                    self.SUCCESS
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.fixed_findings
                )
            )

        # ── Persisting findings table ─────────────────────

        if self.persist_findings:
            layout.addWidget(
                self.make_section_header(
                    f"⚠️  PERSISTING FINDINGS "
                    f"({self.count_persist})",
                    "Present in both scans — not yet resolved",
                    self.WARNING
                )
            )
            layout.addWidget(
                self.build_findings_table(
                    self.persist_findings
                )
            )

        if (
            not self.new_findings
            and not self.fixed_findings
            and not self.persist_findings
        ):
            empty = QLabel(
                "No findings to compare — both scans appear identical."
            )
            empty.setStyleSheet(
                f"""
                color: {self.DIM};
                font-size: {self.fs}px;
                background: transparent;
                border: none;
                """
            )
            layout.addWidget(empty)

        layout.addStretch()

        scroll.setWidget(content)
        self.outer.addWidget(scroll)

    # ─────────────────────────────────────────────
    # Reusable widgets
    # ─────────────────────────────────────────────

    def make_summary_card(self, label, value, color, sub):
        card = QFrame()
        card.setObjectName("diffCard")
        card.setStyleSheet(
            f"""
            QFrame#diffCard {{
                background-color: {self.CARD};
                border: 1px solid {color};
                border-radius: 10px;
            }}

            QFrame#diffCard:hover {{
                background-color: {self.CARD2};
            }}
            """
        )

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 10, 14, 10)
        cl.setSpacing(2)

        v = QLabel(value)
        v.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.setStyleSheet(
            f"""
            font-size: {self.fs + 11}px;
            font-weight: 900;
            color: {color};
            background: transparent;
            border: none;
            """
        )

        l = QLabel(label)
        l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        l.setStyleSheet(
            f"""
            font-size: {self.fs - 2}px;
            font-weight: 800;
            color: {self.TEXT};
            background: transparent;
            border: none;
            """
        )

        s = QLabel(sub)
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s.setStyleSheet(
            f"""
            font-size: {self.fs - 4}px;
            color: {self.DIM};
            background: transparent;
            border: none;
            """
        )

        cl.addWidget(v)
        cl.addWidget(l)
        cl.addWidget(s)

        return card

    def make_section_header(self, title, sub, color):
        frame = QFrame()
        frame.setStyleSheet(
            """
            QFrame {
                background: transparent;
                border: none;
            }
            """
        )

        fl = QVBoxLayout(frame)
        fl.setContentsMargins(0, 4, 0, 0)
        fl.setSpacing(2)

        row = QHBoxLayout()

        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )

        row.addWidget(lbl)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(
            f"""
            background: {color};
            border: none;
            max-height: 1px;
            """
        )

        row.addWidget(line)

        fl.addLayout(row)

        sub_lbl = QLabel(sub)
        sub_lbl.setStyleSheet(
            f"""
            color: {self.DIM};
            font-size: {self.fs - 3}px;
            background: transparent;
            border: none;
            """
        )

        fl.addWidget(sub_lbl)

        return frame

    def build_findings_table(self, findings):
        tbl = QTableWidget()
        tbl.setColumnCount(4)
        tbl.setHorizontalHeaderLabels(
            [
                "Severity",
                "Title",
                "Tool",
                "Asset",
            ]
        )

        tbl.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch
        )

        tbl.setColumnWidth(0, 90)
        tbl.setColumnWidth(2, 110)
        tbl.setColumnWidth(3, 170)

        tbl.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        tbl.verticalHeader().setVisible(False)

        tbl.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )

        tbl.setCursor(Qt.CursorShape.PointingHandCursor)
        tbl.setMouseTracking(True)
        tbl.setAlternatingRowColors(True)

        tbl.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {self.CARD};
                alternate-background-color: {self.CARD2};
                border: 1px solid {self.BORDER};
                border-radius: 10px;
                gridline-color: {self.BORDER};
                color: {self.TEXT};
                selection-background-color: {self.SELECTION_BG};
                selection-color: {self.SELECTION_TEXT};
            }}

            QHeaderView::section {{
                background-color: {self.BG_DEEP};
                color: {self.DIM};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {self.BORDER};
                font-weight: 900;
                font-size: {self.fs - 2}px;
            }}

            QTableWidget::item {{
                padding: 5px 8px;
                background-color: transparent;
                color: {self.TEXT};
                border: none;
            }}

            QTableWidget::item:selected {{
                background-color: {self.SELECTION_BG};
                color: {self.SELECTION_TEXT};
            }}
            """
        )

        muted = QColor(self.DIM)
        text = QColor(self.TEXT)

        for finding in findings:
            row = tbl.rowCount()
            tbl.insertRow(row)

            severity = finding["severity"]
            color = self.SEVERITY_COLORS.get(severity, self.DIM)

            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            title_item = QTableWidgetItem(finding["title"])
            title_item.setForeground(text)

            tool_item = QTableWidgetItem(finding["tool"])
            tool_item.setForeground(muted)
            tool_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            asset_item = QTableWidgetItem(finding["asset"])
            asset_item.setForeground(muted)

            tbl.setItem(row, 0, sev_item)
            tbl.setItem(row, 1, title_item)
            tbl.setItem(row, 2, tool_item)
            tbl.setItem(row, 3, asset_item)

            tbl.setRowHeight(row, 36)

        if self.on_finding_click:
            tbl.cellClicked.connect(
                lambda row, col: self._on_row_clicked(
                    row,
                    findings
                )
            )

        max_rows = min(len(findings), 20)
        tbl_height = 42 + (max_rows * 36)
        tbl.setMaximumHeight(tbl_height)

        return tbl

    # ─────────────────────────────────────────────
    # Navigation
    # ─────────────────────────────────────────────

    def _on_row_clicked(self, row, findings):
        if 0 <= row < len(findings) and self.on_finding_click:
            self.on_finding_click(findings[row])

    def go_back(self):
        if self.on_close:
            self.on_close()

    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────

    def get_stylesheet(self):
        return f"""
            QWidget {{
                background-color: {self.BG};
                color: {self.TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {self.fs}px;
            }}

            QScrollArea {{
                border: none;
                background-color: {self.BG};
            }}

            #headerCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}

            #headerCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}

            #diffTitle {{
                color: {self.ACCENT};
                font-size: {self.fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #diffSub {{
                color: {self.DIM};
                font-size: {self.fs - 2}px;
                background: transparent;
                border: none;
            }}

            #hintLbl {{
                color: {self.DIM};
                font-size: {self.fs - 3}px;
                background: transparent;
                border: none;
                margin-top: 2px;
            }}

            #rateCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 10px;
            }}

            #rateCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}

            #backBtn {{
                background-color: {self.BUTTON_SOFT};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: {self.fs - 1}px;
                font-weight: 800;
            }}

            #backBtn:hover {{
                color: {self.ACCENT};
                border-color: {self.ACCENT};
                background-color: {self.HOVER};
            }}

            #backBtn:pressed {{
                background-color: {rgba_from_hex(self.ACCENT_DARK, 80)};
            }}

            QScrollBar:vertical {{
                background: {self.BG};
                width: 10px;
                margin: 0px;
            }}

            QScrollBar::handle:vertical {{
                background: {self.BORDER_SOFT};
                border-radius: 5px;
                min-height: 28px;
            }}

            QScrollBar::handle:vertical:hover {{
                background: {self.ACCENT};
            }}

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """
