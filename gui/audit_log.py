from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt

from backend.db import get_connection
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    color = str(hex_color).strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


class AuditLogViewer(QWidget):
    def __init__(self, scan_id, on_close=None, prefs=None):
        super().__init__()

        self.scan_id = scan_id
        self.on_close = on_close

        self.prefs = prefs or load_prefs()
        self._set_theme_colors()

        self.setStyleSheet(self.get_stylesheet())

        self.init_ui()
        self.load_logs()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self.BG = self.t["bg"]
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

        self.BRAND_RED = self.t.get("brand_red", self.ACCENT)
        self.BRAND_RED_HOVER = self.t.get(
            "brand_red_hover",
            self.ACCENT_HOVER
        )

        self.SUCCESS = self.t["success"]
        self.SUCCESS_HOVER = self.t.get(
            "success_hover",
            self.SUCCESS
        )

        self.WARNING = self.t["warning"]
        self.INFO_BLUE = self.t["info"]

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
            "#FFFFFF" if not self.dark else "rgba(15, 23, 42, 185)"
        )

        self.CARD_HOVER = self.t.get(
            "card_hover",
            rgba_from_hex(self.ACCENT, 55 if not self.dark else 85)
        )

        if self.dark:
            self.TERM_BG = "#010409"
            self.TERM_FG = "#86EFAC"
            self.TERM_BORDER = self.BORDER
        else:
            self.TERM_BG = "#FFFFFF"
            self.TERM_FG = "#166534"
            self.TERM_BORDER = self.BORDER

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()

        self.setStyleSheet(self.get_stylesheet())

        # Rebuild stat cards so inline styles update.
        self.load_logs()

    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 22, 30, 22)
        layout.setSpacing(12)

        # ── Header card ─────────────────────────────

        header_card = QFrame()
        header_card.setObjectName("headerCard")

        header_layout = QHBoxLayout(header_card)
        header_layout.setContentsMargins(16, 14, 16, 14)
        header_layout.setSpacing(12)

        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)

        header_layout.addWidget(back_btn)

        title_col = QVBoxLayout()
        title_col.setSpacing(3)

        title = QLabel(f"Audit Log — Scan #{self.scan_id}")
        title.setObjectName("auditTitle")
        title_col.addWidget(title)

        subtitle = QLabel(
            "Full audit trail of all actions performed during this scan."
        )
        subtitle.setObjectName("auditSub")
        subtitle.setWordWrap(True)
        title_col.addWidget(subtitle)

        header_layout.addLayout(title_col, 1)

        layout.addWidget(header_card)

        # ── Stats cards ──────────────────────────────

        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(10)

        layout.addLayout(self.stats_row)

        # ── Audit log console ────────────────────────

        log_header = QHBoxLayout()

        log_label = QLabel("AUDIT TRAIL")
        log_label.setObjectName("logLabel")
        log_header.addWidget(log_label)

        log_hint = QLabel("Chronological scan activity and parser events")
        log_hint.setObjectName("logHint")
        log_hint.setAlignment(Qt.AlignmentFlag.AlignRight)
        log_header.addWidget(log_hint)

        layout.addLayout(log_header)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("logText")

        layout.addWidget(self.log_text, 1)

    # ─────────────────────────────────────────────
    # Data loading
    # ─────────────────────────────────────────────

    def load_logs(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT action, detail, timestamp
            FROM audit_logs
            WHERE scan_id=?
            ORDER BY id ASC
            """,
            (self.scan_id,)
        )

        logs = cursor.fetchall()

        conn.close()

        self.update_stats(logs)
        self.populate_logs(logs)

    def update_stats(self, logs):
        while self.stats_row.count():
            child = self.stats_row.takeAt(0)

            if child.widget():
                child.widget().deleteLater()

        tool_starts = sum(
            1 for log in logs
            if log[0] == "tool_started"
        )

        tool_done = sum(
            1 for log in logs
            if log[0] == "tool_finished"
        )

        tool_errors = sum(
            1 for log in logs
            if log[0] in ["tool_error", "tool_timeout"]
        )

        parsed = sum(
            1 for log in logs
            if "parsed" in log[0]
        )

        cards = [
            ("Total Events", str(len(logs)), self.INFO_BLUE),
            ("Tools Started", str(tool_starts), self.ACCENT),
            ("Tools Finished", str(tool_done), self.SUCCESS),
            ("Parse Events", str(parsed), self.WARNING),
            ("Errors", str(tool_errors), self.BRAND_RED),
        ]

        for label, value, color in cards:
            card = self.make_card(label, value, color)
            self.stats_row.addWidget(card)

        self.stats_row.addStretch()

    def make_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("statsCard")
        card.setStyleSheet(
            f"""
            QFrame#statsCard {{
                background-color: {self.CARD};
                border: 1px solid {color};
                border-radius: 10px;
                min-width: 105px;
                max-width: 155px;
            }}

            QFrame#statsCard:hover {{
                background-color: {self.CARD2};
                border: 1px solid {color};
            }}
            """
        )

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 9, 14, 9)
        card_layout.setSpacing(2)

        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs + 9}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            f"""
            color: {self.DIM};
            font-size: {self.fs - 3}px;
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )

        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)

        return card

    def populate_logs(self, logs):
        if not logs:
            self.log_text.setPlainText(
                "No audit logs found for this scan."
            )
            return

        lines = []

        for action, detail, timestamp in logs:
            ts = str(timestamp)[:19] if timestamp else "N/A"

            if action == "scan_started":
                prefix = "[START]  "

            elif action == "scan_completed":
                prefix = "[DONE]   "

            elif action == "tool_started":
                prefix = "[RUN]    "

            elif action == "tool_finished":
                prefix = "[FINISH] "

            elif action in ["tool_error", "tool_timeout"]:
                prefix = "[ERROR]  "

            elif "parsed" in action:
                prefix = "[PARSE]  "

            else:
                prefix = "[INFO]   "

            lines.append(f"{ts}  {prefix}{detail}")

        self.log_text.setPlainText("\n".join(lines))

        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )

    # ─────────────────────────────────────────────
    # Navigation
    # ─────────────────────────────────────────────

    def go_back(self):
        if self.on_close:
            self.on_close()

    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────

    def get_stylesheet(self):
        fs = self.fs

        return f"""
            QWidget {{
                background-color: {self.BG};
                color: {self.TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}

            #headerCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}

            #headerCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}

            #auditTitle {{
                color: {self.ACCENT};
                font-size: {fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #auditSub {{
                color: {self.DIM};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}

            #logLabel {{
                color: {self.TEXT};
                font-size: {fs - 1}px;
                font-weight: 900;
                letter-spacing: 1px;
                background: transparent;
                border: none;
            }}

            #logHint {{
                color: {self.DIM};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
            }}

            #logText {{
                background-color: {self.TERM_BG};
                color: {self.TERM_FG};
                font-family: "Courier New", monospace;
                font-size: {fs - 2}px;
                border: 1px solid {self.TERM_BORDER};
                border-radius: 10px;
                padding: 11px;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}

            #logText:focus {{
                border-color: {self.ACCENT};
            }}

            #backBtn {{
                background-color: {self.BUTTON_SOFT};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: {fs - 1}px;
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
                margin: 0;
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

            QMessageBox {{
                background-color: {self.BG};
                color: {self.TEXT};
            }}

            QMessageBox QLabel {{
                color: {self.TEXT};
                background: transparent;
                border: none;
            }}

            QMessageBox QPushButton {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 7px;
                padding: 7px 18px;
                font-weight: 800;
            }}

            QMessageBox QPushButton:hover {{
                background-color: {self.ACCENT_HOVER};
            }}
        """
