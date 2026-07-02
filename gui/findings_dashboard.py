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
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# AutoRed Theme Helpers
# Supports Dark Theme + Light Theme from preferences.py
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    color = hex_color.strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


def _is_light_theme(theme):
    return theme.get("bg", "#020617").upper() in (
        "#F8FAFC",
        "#FFFFFF",
        "#F1F5F9",
        "#EEF2F7",
        "#E2E8F0",
    ) or theme.get("text", "#E5EDF7").upper() == "#0F172A"


BG_MAIN = "#020617"
BG_PAGE = "#07111F"
BG_DEEP = "#01030A"

CARD_BG = "#0F172A"
CARD_BG_2 = "#111827"

BORDER = "#22304A"
BORDER_SOFT = "#334155"

TEXT_MAIN = "#E5EDF7"
TEXT_MUTED = "#94A3B8"
TEXT_SOFT = "#64748B"

ACCENT = "#EF4444"
ACCENT_HOVER = "#DC2626"
ACCENT_DARK = "#991B1B"

BRAND_RED = "#EF4444"
BRAND_RED_HOVER = "#DC2626"

SUCCESS = "#22C55E"
SUCCESS_HOVER = "#16A34A"

WARNING = "#F97316"
WARNING_HOVER = "#EA580C"

MEDIUM_YELLOW = "#FACC15"
INFO_BLUE = "#60A5FA"

PURPLE = "#8B5CF6"
PURPLE_HOVER = "#7C3AED"

HOVER_BG = "rgba(239, 68, 68, 25)"
SELECTION_BG = "rgba(239, 68, 68, 35)"
SELECTION_TEXT = "#FEE2E2"
BUTTON_SOFT = "rgba(15, 23, 42, 205)"
CARD_HOVER = "rgba(239, 68, 68, 75)"

SEVERITY_COLORS = {}
STATUS_COLORS = {}
SECTION_COLORS = {}
UNIFIED_THEME = {}


def apply_theme_palette(theme):
    global BG_MAIN, BG_PAGE, BG_DEEP
    global CARD_BG, CARD_BG_2, BORDER, BORDER_SOFT
    global TEXT_MAIN, TEXT_MUTED, TEXT_SOFT
    global ACCENT, ACCENT_HOVER, ACCENT_DARK
    global BRAND_RED, BRAND_RED_HOVER
    global SUCCESS, SUCCESS_HOVER
    global WARNING, WARNING_HOVER
    global MEDIUM_YELLOW, INFO_BLUE, PURPLE, PURPLE_HOVER
    global HOVER_BG, SELECTION_BG, SELECTION_TEXT
    global BUTTON_SOFT, CARD_HOVER
    global SEVERITY_COLORS, STATUS_COLORS, SECTION_COLORS, UNIFIED_THEME

    light = _is_light_theme(theme)

    BG_MAIN = theme.get("bg", "#F8FAFC" if light else "#020617")
    BG_PAGE = theme.get("page", theme.get("sidebar_bg", "#FFFFFF" if light else "#07111F"))
    BG_DEEP = theme.get("bg_deep", "#EEF2F7" if light else "#01030A")

    CARD_BG = theme.get("card_bg", "#FFFFFF" if light else "#0F172A")
    CARD_BG_2 = theme.get("card_bg_2", "#F1F5F9" if light else "#111827")

    BORDER = theme.get("border", "#CBD5E1" if light else "#22304A")
    BORDER_SOFT = theme.get("border_soft", "#94A3B8" if light else "#334155")

    TEXT_MAIN = theme.get("text", "#0F172A" if light else "#E5EDF7")
    TEXT_MUTED = theme.get("text_muted", "#475569" if light else "#94A3B8")
    TEXT_SOFT = theme.get("text_soft", "#64748B")

    ACCENT = theme.get("accent", "#EF4444")
    ACCENT_HOVER = theme.get("accent_hover", "#DC2626")
    ACCENT_DARK = theme.get("accent_dark", "#991B1B")

    BRAND_RED = theme.get("brand_red", ACCENT)
    BRAND_RED_HOVER = theme.get("brand_red_hover", ACCENT_HOVER)

    SUCCESS = theme.get("success", "#16A34A" if light else "#22C55E")
    SUCCESS_HOVER = theme.get("success_hover", "#15803D" if light else "#16A34A")

    WARNING = theme.get("warning", "#EA580C" if light else "#F97316")
    WARNING_HOVER = theme.get("warning_hover", "#C2410C" if light else "#EA580C")

    MEDIUM_YELLOW = theme.get("medium", "#CA8A04" if light else "#FACC15")
    INFO_BLUE = theme.get("info", "#2563EB" if light else "#60A5FA")

    PURPLE = theme.get("purple", "#7C3AED" if light else "#8B5CF6")
    PURPLE_HOVER = theme.get("purple_hover", "#6D28D9" if light else "#7C3AED")

    HOVER_BG = theme.get("hover", rgba_from_hex(ACCENT, 18 if light else 25))
    SELECTION_BG = theme.get("selection_bg", rgba_from_hex(ACCENT, 28 if light else 35))
    SELECTION_TEXT = theme.get("selection_text", "#7F1D1D" if light else "#FEE2E2")
    BUTTON_SOFT = theme.get("button_soft", "#FFFFFF" if light else "rgba(15, 23, 42, 205)")
    CARD_HOVER = theme.get("card_hover", rgba_from_hex(ACCENT, 55 if light else 75))

    SEVERITY_COLORS = {
        "Critical": BRAND_RED,
        "High": WARNING,
        "Medium": MEDIUM_YELLOW,
        "Low": SUCCESS,
        "Info": INFO_BLUE,
    }

    STATUS_COLORS = {
        "Confirmed": SUCCESS,
        "Dismissed": TEXT_MUTED,
        "False Positive": TEXT_MUTED,
        "Potential": WARNING,
        "Open": WARNING,
        "Remediated": SUCCESS,
    }

    SECTION_COLORS = {
        "SCAN OVERVIEW": INFO_BLUE,
        "OVERVIEW": INFO_BLUE,
        "CRITICAL & HIGH ISSUES": BRAND_RED,
        "CRITICAL ISSUES": BRAND_RED,
        "BUSINESS IMPACT": WARNING,
        "IMMEDIATE ACTIONS": SUCCESS,
        "TOP REMEDIATIONS": SUCCESS,
        "RECOMMENDATIONS": SUCCESS,
        "REFERENCES": TEXT_MUTED,
    }

    UNIFIED_THEME = {
        "bg": BG_MAIN,
        "page": BG_PAGE,
        "bg_deep": BG_DEEP,
        "card_bg": CARD_BG,
        "card_bg_2": CARD_BG_2,
        "border": BORDER,
        "border_soft": BORDER_SOFT,
        "hover": HOVER_BG,
        "selection_bg": SELECTION_BG,
        "selection_text": SELECTION_TEXT,
        "button_soft": BUTTON_SOFT,
        "card_hover": CARD_HOVER,
        "text": TEXT_MAIN,
        "text_muted": TEXT_MUTED,
        "text_soft": TEXT_SOFT,
        "accent": ACCENT,
        "accent_hover": ACCENT_HOVER,
        "accent_dark": ACCENT_DARK,
        "brand_red": BRAND_RED,
        "brand_red_hover": BRAND_RED_HOVER,
        "success": SUCCESS,
        "success_hover": SUCCESS_HOVER,
        "warning": WARNING,
        "info": INFO_BLUE,
        "purple": PURPLE,
    }


apply_theme_palette(get_theme(True))

_ACTIVE_WORKERS = []


class PreloadWorker(QThread):
    done = pyqtSignal(int, dict)

    def __init__(self, finding_id, finding):
        super().__init__()

        self.finding_id = finding_id
        self.finding = finding

    def run(self):
        try:
            from backend.cve_enricher import (
                enrich_finding,
                get_attack_path_ai,
            )

            result = enrich_finding(self.finding)
            nvd_best = result.get("nvd_best")

            attack, verify = get_attack_path_ai(
                self.finding,
                nvd_best
            )

            result["attack_path"] = attack
            result["verify_steps"] = verify

            self.done.emit(self.finding_id, result)

        except Exception as e:
            print(f"[!] Preload error for {self.finding_id}: {e}")
            self.done.emit(self.finding_id, {})


class ExportWorker(QThread):
    """
    Runs PDF/JSON export off the main thread. Report generation
    now calls live CVE/CWE/MITRE/attack-path enrichment per
    finding (see reports/report_enrichment.py), which can take a
    noticeable amount of time for scans with many findings --
    doing this on the UI thread would freeze the whole app for
    that entire duration.
    """
    progress = pyqtSignal(int, int)
    done     = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, kind, scan_id, output_path):
        super().__init__()
        self.kind        = kind
        self.scan_id     = scan_id
        self.output_path = output_path

    def run(self):
        try:
            def on_progress(done, total):
                self.progress.emit(done, total)

            if self.kind == 'pdf':
                from reports.report_builder import generate_pdf
                generate_pdf(
                    self.scan_id, self.output_path,
                    progress_callback=on_progress
                )
            else:
                from reports.data_exporter import export_json
                export_json(
                    self.scan_id, self.output_path,
                    progress_callback=on_progress
                )

            self.done.emit(self.output_path)

        except Exception as e:
            self.error.emit(str(e))


class SummaryWorker(QThread):
    done = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, prompt):
        super().__init__()

        self.prompt = prompt

    def run(self):
        try:
            from gui.ai_chat import (
                load_api_key,
                clean_markdown,
            )

            api_key = load_api_key()

            if not api_key:
                self.error.emit(
                    "No API key found.\n"
                    "Add ANTHROPIC_API_KEY to your .env file."
                )
                return

            payload = json.dumps(
                {
                    "model": "claude-sonnet-4-5-20250929",
                    "max_tokens": 2000,
                    "messages": [
                        {
                            "role": "user",
                            "content": self.prompt,
                        }
                    ],
                }
            ).encode("utf-8")

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key": api_key,
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["content"][0]["text"]
                self.done.emit(clean_markdown(text))

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")

            try:
                err = json.loads(body)
                msg = err.get("error", {}).get("message", str(e))
            except Exception:
                msg = str(e)

            self.error.emit(f"API Error: {msg}")

        except Exception as e:
            self.error.emit(f"Error: {str(e)}")


class FindingsDashboard(QWidget):
    def __init__(
        self,
        scan_id,
        on_finding_click=None,
        on_audit_click=None,
        on_charts_click=None,
        on_graph_click=None,
        on_back=None,
        prefs=None,
    ):
        super().__init__()

        self.scan_id = scan_id

        self.on_finding_click = on_finding_click
        self.on_audit_click = on_audit_click
        self.on_charts_click = on_charts_click
        self.on_graph_click = on_graph_click
        self.on_back = on_back

        self.findings = []
        self.visible_findings = []

        self.summary_worker = None
        self._export_worker = None
        self.enrich_cache = {}
        self.enrich_workers = []

        self.preload_queue = []
        self.preload_total = 0
        self.preload_done = 0
        self.active_workers = 0
        self.max_concurrent = 2
        self.queue_index = 0

        self.ch_rows = []
        self.current_filter = "All"
        self.filter_buttons = {}

        self.preload_ready = False

        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        self.setStyleSheet(self.get_stylesheet())

        self.init_ui()
        self.load_findings()

    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        self.setStyleSheet(self.get_stylesheet())

        self.update_summary()

        if self.current_filter == "All":
            self.populate_table(self.findings)
        else:
            self.populate_table(
                [
                    finding for finding in self.findings
                    if finding.get("severity") == self.current_filter
                ]
            )

        self._update_filter_button_styles()

        if hasattr(self, "preload_lbl"):
            if self.preload_ready:
                self.preload_lbl.setStyleSheet(
                    "color: " + SUCCESS + "; font-size: " +
                    str(self.fs - 3) + "px; background: transparent; "
                    "border: none;"
                )
            else:
                self.preload_lbl.setStyleSheet(
                    "color: " + TEXT_MUTED + "; font-size: " +
                    str(self.fs - 3) + "px; background: transparent; "
                    "border: none;"
                )

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 22, 30, 22)
        layout.setSpacing(12)

        top_card = QFrame()
        top_card.setObjectName("topCard")

        top_card_layout = QHBoxLayout(top_card)
        top_card_layout.setContentsMargins(16, 14, 16, 14)
        top_card_layout.setSpacing(10)

        if self.on_back:
            back_btn = QPushButton("← Back")
            back_btn.setObjectName("backBtn")
            back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            back_btn.clicked.connect(self.on_back)
            top_card_layout.addWidget(back_btn)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel(f"Findings Dashboard — Scan #{self.scan_id}")
        title.setObjectName("dashTitle")
        title_col.addWidget(title)

        subtitle = QLabel(
            "Review detected vulnerabilities, severity distribution, and enriched intelligence."
        )
        subtitle.setObjectName("dashSub")
        title_col.addWidget(subtitle)

        top_card_layout.addLayout(title_col, 1)

        audit_btn = QPushButton("Audit Log")
        audit_btn.setObjectName("actionBtn")
        audit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        audit_btn.clicked.connect(self.view_audit_log)
        top_card_layout.addWidget(audit_btn)

        visualize_btn = QPushButton("Visualize ▾")
        visualize_btn.setObjectName("actionBtn")
        visualize_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        visualize_menu = QMenu(self)

        charts_action = QAction("View Charts", self)
        charts_action.triggered.connect(self.view_charts)
        visualize_menu.addAction(charts_action)

        graph_action = QAction("View Attack Graph", self)
        graph_action.triggered.connect(self.view_network_graph)
        visualize_menu.addAction(graph_action)

        visualize_btn.setMenu(visualize_menu)
        top_card_layout.addWidget(visualize_btn)

        export_btn = QPushButton("Export ▾")
        export_btn.setObjectName("actionBtn")
        export_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        export_menu = QMenu(self)

        pdf_action = QAction("Export PDF", self)
        pdf_action.triggered.connect(self.export_pdf)
        export_menu.addAction(pdf_action)

        json_action = QAction("Export JSON", self)
        json_action.triggered.connect(self.export_json)
        export_menu.addAction(json_action)

        export_btn.setMenu(export_menu)
        top_card_layout.addWidget(export_btn)

        ai_btn = QPushButton("✦ AI Summary")
        ai_btn.setObjectName("primaryActionBtn")
        ai_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ai_btn.clicked.connect(self.show_ai_summary)
        top_card_layout.addWidget(ai_btn)

        layout.addWidget(top_card)

        self.summary_row = QHBoxLayout()
        self.summary_row.setSpacing(10)
        layout.addLayout(self.summary_row)

        filter_card = QFrame()
        filter_card.setObjectName("filterCard")

        filter_row = QHBoxLayout(filter_card)
        filter_row.setContentsMargins(14, 10, 14, 10)
        filter_row.setSpacing(8)

        filter_lbl = QLabel("Filter by severity:")
        filter_lbl.setObjectName("filterLbl")
        filter_row.addWidget(filter_lbl)

        for severity in [
            "All",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
        ]:
            btn = QPushButton(severity)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, s=severity: self.filter_table(s)
            )

            self.filter_buttons[severity] = btn
            filter_row.addWidget(btn)

        filter_row.addStretch()

        self.preload_lbl = QLabel("⏳ Loading intelligence...")
        self.preload_lbl.setStyleSheet(
            "color: " + TEXT_MUTED + "; font-size: " +
            str(self.fs - 3) + "px; background: transparent; "
            "border: none;"
        )
        filter_row.addWidget(self.preload_lbl)

        layout.addWidget(filter_card)

        self._update_filter_button_styles()

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            [
                "#",
                "Severity",
                "Tool",
                "Asset",
                "Title",
                "Status",
                "Action",
            ]
        )

        self.table.horizontalHeader().setSectionResizeMode(
            4,
            QHeaderView.ResizeMode.Stretch,
        )

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setObjectName("findingsTable")
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        self.table.cellClicked.connect(self.on_row_click)

        self.table.setColumnWidth(0, 46)
        self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(2, 105)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(5, 105)
        self.table.setColumnWidth(6, 60)

        layout.addWidget(self.table)

        hint = QLabel(
            "Click any row to view full finding details  •  "
            "Click 🗑️ to permanently remove a finding from this scan"
        )
        hint.setObjectName("hintLbl")
        layout.addWidget(hint)

    def load_findings(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, tool, asset, category, severity,
                   title, description, evidence,
                   recommendation, status
            FROM findings
            WHERE scan_id=?
            ORDER BY CASE severity
                WHEN "Critical" THEN 0
                WHEN "High"     THEN 1
                WHEN "Medium"   THEN 2
                WHEN "Low"      THEN 3
                WHEN "Info"     THEN 4
                ELSE 5 END
            """,
            (self.scan_id,),
        )

        self.findings = [
            dict(row) for row in cursor.fetchall()
        ]

        conn.close()

        self.update_summary()
        self.populate_table(self.findings)
        self.start_preloading()

    def start_preloading(self):
        priority = [
            finding for finding in self.findings
            if finding.get("severity") in ("Critical", "High")
        ]

        others = [
            finding for finding in self.findings
            if finding.get("severity") not in ("Critical", "High")
        ]

        self.preload_queue = (priority + others)[:20]
        self.preload_total = len(self.preload_queue)
        self.preload_done = 0
        self.active_workers = 0
        self.queue_index = 0

        if self.preload_total == 0:
            self.preload_ready = True
            self.preload_lbl.setText("✅ No intelligence required")
            self.preload_lbl.setStyleSheet(
                "color: " + SUCCESS + "; font-size: " +
                str(self.fs - 3) + "px; background: transparent; "
                "border: none;"
            )
            return

        self.launch_next_workers()

    def launch_next_workers(self):
        while (
            self.active_workers < self.max_concurrent
            and self.queue_index < len(self.preload_queue)
        ):
            finding = self.preload_queue[self.queue_index]
            self.queue_index += 1

            fid = finding.get("id")

            worker = PreloadWorker(fid, finding)
            worker.done.connect(self.on_preload_done)
            worker.start()

            self.enrich_workers.append(worker)
            self.active_workers += 1

    def on_preload_done(self, finding_id, result):
        self.enrich_cache[finding_id] = result

        self.preload_done += 1
        self.active_workers -= 1

        remaining = self.preload_total - self.preload_done

        if remaining > 0:
            self.preload_lbl.setText(
                f"⏳ Loading intelligence... "
                f"({self.preload_done}/{self.preload_total})"
            )
        else:
            self.preload_ready = True
            self.preload_lbl.setText("✅ Intelligence ready")
            self.preload_lbl.setStyleSheet(
                "color: " + SUCCESS + "; font-size: " +
                str(self.fs - 3) + "px; background: transparent; "
                "border: none;"
            )

        self.launch_next_workers()

    def _detach_worker(self, worker, signals):
        if worker is None:
            return

        for sig in signals:
            try:
                getattr(worker, sig).disconnect()
            except (TypeError, RuntimeError):
                pass

        try:
            if worker.isRunning():
                _ACTIVE_WORKERS.append(worker)
                worker.finished.connect(
                    lambda w=worker:
                    _ACTIVE_WORKERS.remove(w)
                    if w in _ACTIVE_WORKERS
                    else None
                )
        except RuntimeError:
            pass

    def stop_all_workers(self):
        for worker in self.enrich_workers:
            self._detach_worker(worker, ("done",))

        self.enrich_workers.clear()
        self.active_workers = 0

        if self.summary_worker:
            self._detach_worker(
                self.summary_worker,
                ("done", "error")
            )
            self.summary_worker = None

        export_worker = getattr(self, "_export_worker", None)
        if export_worker:
            self._detach_worker(
                export_worker,
                ("progress", "done", "error")
            )
            self._export_worker = None

    def cleanup(self):
        self.stop_all_workers()

    def delete_finding(self, finding_id, finding_title):
        short_title = (
            finding_title[:80] + "…"
            if len(finding_title) > 80 else finding_title
        )

        reply = QMessageBox.question(
            self,
            "Remove Finding",
            f"Remove this finding permanently?\n\n"
            f"\"{short_title}\"\n\n"
            f"This cannot be undone. The finding will no longer "
            f"appear in this dashboard, in the email report, or "
            f"in any PDF/JSON export for this scan.",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM findings WHERE id=?", (finding_id,)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(
                self, "Delete Failed",
                f"Could not remove finding:\n{e}"
            )
            return

        self.findings = [
            f for f in self.findings if f.get("id") != finding_id
        ]
        self.enrich_cache.pop(finding_id, None)

        self.update_summary()
        self.filter_table(self.current_filter)

    def update_summary(self):
        while self.summary_row.count():
            child = self.summary_row.takeAt(0)

            if child.widget():
                child.widget().deleteLater()

        counts = {}

        for finding in self.findings:
            severity = finding.get("severity", "Info")
            counts[severity] = counts.get(severity, 0) + 1

        total_card = self.make_card(
            "Total",
            str(len(self.findings)),
            INFO_BLUE,
        )
        self.summary_row.addWidget(total_card)

        for severity, color in SEVERITY_COLORS.items():
            count = counts.get(severity, 0)
            card = self.make_card(
                severity,
                str(count),
                color,
            )
            self.summary_row.addWidget(card)

        self.summary_row.addStretch()

    def make_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("summaryCard")
        card.setStyleSheet(
            "QFrame#summaryCard { background-color: " + CARD_BG +
            "; border: 1px solid " + color +
            "; border-radius: 10px; min-width: 92px; max-width: 128px; } "
            "QFrame#summaryCard:hover { background-color: " + CARD_BG_2 + "; }"
        )

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 10, 14, 10)
        card_layout.setSpacing(2)

        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            "color: " + color + "; font-size: " + str(self.fs + 11) +
            "px; font-weight: 900; background: transparent; border: none;"
        )

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            "color: " + TEXT_MUTED + "; font-size: " + str(self.fs - 2) +
            "px; font-weight: 700; background: transparent; border: none;"
        )

        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)

        return card

    def populate_table(self, findings):
        self.visible_findings = list(findings)

        muted = QColor(TEXT_MUTED)
        text = QColor(TEXT_MAIN)

        self.table.setRowCount(0)

        for i, finding in enumerate(self.visible_findings, 1):
            row = self.table.rowCount()
            self.table.insertRow(row)

            severity = finding.get("severity", "Info")
            severity_color = SEVERITY_COLORS.get(severity, TEXT_MUTED)

            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(muted)

            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(QColor(severity_color))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            tool_item = QTableWidgetItem(finding.get("tool", ""))
            tool_item.setForeground(text)
            tool_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            asset_item = QTableWidgetItem(finding.get("asset", ""))
            asset_item.setForeground(text)

            title_item = QTableWidgetItem(finding.get("title", ""))
            title_item.setForeground(text)

            status = finding.get("status", "Potential")
            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            status_color = STATUS_COLORS.get(status, WARNING)
            status_item.setForeground(QColor(status_color))

            self.table.setItem(row, 0, num_item)
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, tool_item)
            self.table.setItem(row, 3, asset_item)
            self.table.setItem(row, 4, title_item)
            self.table.setItem(row, 5, status_item)

            delete_btn = QPushButton("🗑️")
            delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            delete_btn.setToolTip("Remove this finding")
            delete_btn.setFixedSize(30, 26)
            delete_btn.setStyleSheet(
                "QPushButton { background-color: transparent; "
                "border: 1px solid " + BORDER + "; border-radius: 6px; "
                "font-size: " + str(self.fs - 1) + "px; } "
                "QPushButton:hover { background-color: " + SELECTION_BG +
                "; border-color: " + ACCENT + "; }"
            )

            finding_id = finding.get("id")
            finding_title = finding.get("title", "")
            delete_btn.clicked.connect(
                lambda _, fid=finding_id, ftitle=finding_title:
                self.delete_finding(fid, ftitle)
            )

            btn_wrap = QWidget()
            btn_wrap_layout = QHBoxLayout(btn_wrap)
            btn_wrap_layout.setContentsMargins(0, 0, 0, 0)
            btn_wrap_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_wrap_layout.addWidget(delete_btn)

            self.table.setCellWidget(row, 6, btn_wrap)

            self.table.setRowHeight(row, 38)

    def filter_table(self, severity):
        self.current_filter = severity

        if severity == "All":
            self.populate_table(self.findings)
        else:
            filtered = [
                finding for finding in self.findings
                if finding.get("severity") == severity
            ]
            self.populate_table(filtered)

        self._update_filter_button_styles()

    def _update_filter_button_styles(self):
        for severity, btn in self.filter_buttons.items():
            active = severity == self.current_filter
            btn.setStyleSheet(self._filter_button_style(active))

    def _filter_button_style(self, active=False):
        if active:
            return (
                "QPushButton { background-color: " + SELECTION_BG +
                "; color: " + SELECTION_TEXT + "; border: 1px solid " +
                rgba_from_hex(ACCENT, 145) + "; border-radius: 7px; "
                "padding: 6px 13px; font-size: " + str(self.fs - 2) +
                "px; font-weight: 900; }"
            )

        return (
            "QPushButton { background-color: " + BUTTON_SOFT +
            "; color: " + TEXT_MUTED + "; border: 1px solid " + BORDER +
            "; border-radius: 7px; padding: 6px 13px; font-size: " +
            str(self.fs - 2) + "px; font-weight: 700; } "
            "QPushButton:hover { color: " + SELECTION_TEXT +
            "; border-color: " + ACCENT + "; background-color: " +
            HOVER_BG + "; }"
        )

    def on_row_click(self, row, col):
        if col == 6:
            return

        if (
            self.on_finding_click
            and row < len(self.visible_findings)
        ):
            finding = self.visible_findings[row]
            finding_id = finding.get("id")
            cached = self.enrich_cache.get(finding_id)

            self.stop_all_workers()
            self.on_finding_click(finding, cached)

    def view_audit_log(self):
        if self.on_audit_click:
            self.stop_all_workers()
            self.on_audit_click(self.scan_id)

    def view_charts(self):
        if self.on_charts_click:
            self.stop_all_workers()
            self.on_charts_click(self.scan_id)

    def view_network_graph(self):
        if self.on_graph_click:
            self.stop_all_workers()
            self.on_graph_click(self.scan_id)

    def export_pdf(self):
        path = f"storage/{self.scan_id}/report/report.pdf"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._run_export_with_progress('pdf', path)

    def export_json(self):
        path = f"storage/{self.scan_id}/report/findings.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._run_export_with_progress('json', path)

    def _run_export_with_progress(self, kind, path):
        progress_dialog = QDialog(self)
        progress_dialog.setWindowTitle(
            "Generating Report" if kind == 'pdf' else "Exporting JSON"
        )
        progress_dialog.setFixedSize(420, 140)
        progress_dialog.setStyleSheet(
            "QDialog { background: " + BG_MAIN + "; color: " +
            TEXT_MAIN + "; } QLabel { background: transparent; "
            "border: none; }"
        )
        progress_dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

        pl = QVBoxLayout(progress_dialog)
        pl.setContentsMargins(22, 22, 22, 22)
        pl.setSpacing(10)

        title_lbl = QLabel(
            "Generating PDF report..." if kind == 'pdf'
            else "Exporting findings to JSON..."
        )
        title_lbl.setStyleSheet(
            "color: " + ACCENT + "; font-size: " + str(self.fs) +
            "px; font-weight: 800;"
        )
        pl.addWidget(title_lbl)

        status_lbl = QLabel(
            "Fetching CVE, CWE, and MITRE ATT&CK data for each "
            "finding -- this can take a moment for larger scans."
        )
        status_lbl.setWordWrap(True)
        status_lbl.setStyleSheet(
            "color: " + TEXT_MUTED + "; font-size: " + str(self.fs - 2) + "px;"
        )
        pl.addWidget(status_lbl)

        progress_lbl = QLabel("Starting...")
        progress_lbl.setStyleSheet(
            "color: " + INFO_BLUE + "; font-size: " + str(self.fs - 1) +
            "px; font-weight: 700;"
        )
        pl.addWidget(progress_lbl)

        worker = ExportWorker(kind, self.scan_id, path)

        def on_progress(done, total):
            if total > 0:
                progress_lbl.setText(f"Enriching finding {done} of {total}...")
            else:
                progress_lbl.setText("Building report...")

        def on_done(output_path):
            progress_dialog.accept()
            if kind == 'pdf':
                import subprocess
                try:
                    subprocess.Popen(["xdg-open", output_path])
                except Exception:
                    pass
            else:
                msg = QMessageBox(self)
                msg.setWindowTitle("Export Complete")
                msg.setText(f"JSON exported!\n\nSaved to:\n{output_path}")
                msg.exec()

        def on_error(error_msg):
            progress_dialog.reject()
            QMessageBox.warning(
                self, "Export Failed",
                f"Could not generate the report:\n\n{error_msg}"
            )

        worker.progress.connect(on_progress)
        worker.done.connect(on_done)
        worker.error.connect(on_error)

        self._export_worker = worker
        worker.start()

        progress_dialog.exec()

    def show_ai_summary(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, severity, title, description,
                   recommendation, asset, tool,
                   evidence, category
            FROM findings
            WHERE scan_id=?
            ORDER BY CASE severity
                WHEN "Critical" THEN 0
                WHEN "High"     THEN 1
                WHEN "Medium"   THEN 2
                WHEN "Low"      THEN 3
                ELSE 4 END
            """,
            (self.scan_id,),
        )

        findings = cursor.fetchall()

        cursor.execute(
            "SELECT * FROM scans WHERE id=?",
            (self.scan_id,),
        )

        scan = cursor.fetchone()

        conn.close()

        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        }

        for finding in findings:
            counts[finding[1]] = counts.get(finding[1], 0) + 1

        ch_count = sum(
            1 for finding in findings
            if finding[1] in ("Critical", "High")
        )

        cached_ch = sum(
            1 for finding in findings
            if finding[1] in ("Critical", "High")
            and finding[0] in self.enrich_cache
        )

        if cached_ch < ch_count:
            msg = QMessageBox(self)
            msg.setWindowTitle("Intelligence Loading")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText(
                f"Intelligence is still loading "
                f"({cached_ch}/{ch_count} Critical/High findings ready).\n\n"
                f"The summary will take longer as missing data will be fetched now.\n\n"
                f"Tip: wait for '✅ Intelligence ready' before clicking "
                f"AI Summary for faster results."
            )
            msg.exec()

        from backend.cve_enricher import enrich_finding

        for finding in findings:
            fid = finding[0]
            severity = finding[1]

            if severity not in ("Critical", "High"):
                continue

            if fid not in self.enrich_cache:
                try:
                    finding_dict = {
                        "id": fid,
                        "title": finding[2],
                        "description": finding[3] or "",
                        "severity": severity,
                        "asset": finding[5] or "",
                        "tool": finding[6] or "",
                        "evidence": finding[7] or "",
                        "recommendation": finding[4] or "",
                        "category": finding[8] or "",
                    }

                    result = enrich_finding(finding_dict)
                    self.enrich_cache[fid] = result

                except Exception as e:
                    print(f"[!] Enrich error: {e}")

        self.ch_rows = []
        critical_high_lines = []

        for finding in findings:
            fid = finding[0]
            severity = finding[1]
            title = finding[2]
            desc = finding[3] or ""

            if severity not in ("Critical", "High"):
                continue

            cached = self.enrich_cache.get(fid, {})
            nvd_best = cached.get("nvd_best")
            cwe_data = cached.get("cwe_data")
            mitre = cached.get("mitre")

            cve_id = "N/A"
            cvss = "N/A"
            cwe = "N/A"
            mitre_id = "N/A"

            if nvd_best:
                raw_cve = nvd_best.get("cve_id", "N/A")

                if raw_cve and "No CVE" not in str(raw_cve):
                    cve_id = raw_cve

                raw_cvss = nvd_best.get("cvss_score")

                if raw_cvss:
                    cvss = str(raw_cvss)

            if cwe_data:
                cwe = (
                    f"{cwe_data.get('cwe_id', 'N/A')}"
                    f" — "
                    f"{cwe_data.get('name', '')}"
                )

            elif nvd_best:
                weak = nvd_best.get("weaknesses", [])

                if weak:
                    cwe = weak[0]

            if mitre:
                tech_id = mitre.get("tech_id", "N/A")
                technique = mitre.get("technique", "")
                mitre_id = f"{tech_id} {technique}".strip()

            self.ch_rows.append(
                {
                    "severity": severity,
                    "title": title,
                    "cve": cve_id,
                    "cvss": cvss,
                    "cwe": cwe,
                    "mitre": mitre_id,
                    "desc": desc[:100],
                }
            )

            critical_high_lines.append(
                f"[{severity}] {title} "
                f"| CVE: {cve_id} | CVSS: {cvss} "
                f"| CWE: {cwe} | MITRE: {mitre_id}"
            )

        critical_high_text = "\n".join(critical_high_lines)

        all_findings_text = "\n".join(
            [
                f"[{finding[1]}] {finding[2]}"
                for finding in findings
            ]
        )

        references_text = ""
        seen_cves = []

        for finding in findings:
            fid = finding[0]
            cached = self.enrich_cache.get(fid, {})
            nvd = cached.get("nvd_best")

            if nvd:
                cve = nvd.get("cve_id", "")

                if (
                    cve
                    and "No CVE" not in cve
                    and cve not in seen_cves
                ):
                    seen_cves.append(cve)

                    desc = nvd.get("description", "")[:80]
                    nvd_url = nvd.get("nvd_url", "")

                    references_text += (
                        f"• {cve}: {nvd_url} — {desc}\n"
                    )

        prompt = (
            f"Analyze this security scan and respond ONLY in this exact format. "
            f"No paragraphs.\n\n"
            f"SCAN DATA:\n"
            f"Target: {scan['target'] if scan else 'Unknown'}\n"
            f"Date: {scan['created_at'] if scan else 'Unknown'}\n"
            f"Profile: {scan['profile'] if scan else 'Unknown'}\n"
            f"Critical: {counts['Critical']} | "
            f"High: {counts['High']} | "
            f"Medium: {counts['Medium']} | "
            f"Low: {counts['Low']} | "
            f"Info: {counts['Info']}\n\n"
            f"Critical and High Findings:\n"
            f"{critical_high_text}\n\n"
            f"All Findings:\n"
            f"{all_findings_text[:600]}\n\n"
            f"Known CVE References:\n"
            f"{references_text if references_text else 'None'}"
            f"\n\n"
            f"REQUIRED OUTPUT FORMAT:\n\n"
            f"SCAN OVERVIEW\n"
            f"• Target: [target]\n"
            f"• Scan Date: [date]\n"
            f"• Profile: [profile]\n"
            f"• Total Findings: [number]\n"
            f"• Overall Risk Rating: [level] — [reason]\n"
            f"• AI Confidence: [High/Medium/Low] — [reason]\n\n"
            f"CRITICAL & HIGH ISSUES\n"
            f"• [finding] (CVSS: [score]) — [why dangerous]. "
            f"CVE: [real CVE or N/A]. "
            f"CWE: [real CWE or N/A]. "
            f"MITRE: [real MITRE or N/A]\n\n"
            f"BUSINESS IMPACT\n"
            f"• [max 4 points]\n\n"
            f"IMMEDIATE ACTIONS\n"
            f"• [max 5 points]\n\n"
            f"REFERENCES\n"
            f"• [real CVEs only]\n\n"
            f"Do not invent CVE/CWE/MITRE identifiers."
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("AI Security Summary")
        dialog.setMinimumSize(850, 650)
        dialog.setStyleSheet(
            "QDialog { background: " + BG_MAIN + "; color: " +
            TEXT_MAIN + '; font-family: "Segoe UI", Arial, sans-serif; } '
            "QLabel { background: transparent; border: none; }"
        )

        dl = QVBoxLayout(dialog)
        dl.setContentsMargins(24, 20, 24, 20)
        dl.setSpacing(10)

        header_row = QHBoxLayout()

        title_lbl = QLabel("✦ AI Security Summary")
        title_lbl.setStyleSheet(
            "color: " + ACCENT + "; font-size: " + str(self.fs + 5) +
            "px; font-weight: 900; background: transparent; border: none;"
        )

        header_row.addWidget(title_lbl)
        header_row.addStretch()

        dl.addLayout(header_row)

        info_lbl = QLabel(
            f"Target: {scan['target'] if scan else 'N/A'}  •  "
            f"Critical: {counts['Critical']}  "
            f"High: {counts['High']}  "
            f"Medium: {counts['Medium']}  "
            f"Low: {counts['Low']}  "
            f"Info: {counts['Info']}"
        )
        info_lbl.setStyleSheet(
            "color: " + TEXT_MUTED + "; font-size: " + str(self.fs - 2) +
            "px; background: transparent; border: none;"
        )
        info_lbl.setWordWrap(True)
        dl.addWidget(info_lbl)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(
            "background: " + BORDER + "; border: none; max-height: 1px;"
        )
        dl.addWidget(div)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: " + BG_MAIN + "; } "
            "QScrollBar:vertical { background: " + CARD_BG +
            "; width: 8px; border-radius: 4px; } "
            "QScrollBar::handle:vertical { background: " + BORDER_SOFT +
            "; border-radius: 4px; } "
            "QScrollBar::handle:vertical:hover { background: " + ACCENT + "; } "
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical "
            "{ height: 0; }"
        )

        self.scroll_widget = QWidget()
        self.scroll_widget.setStyleSheet(f"background: {BG_MAIN};")

        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setContentsMargins(4, 8, 4, 8)
        self.scroll_layout.setSpacing(6)

        self.waiting_lbl = QLabel(
            "Generating AI summary... please wait ⏳"
        )
        self.waiting_lbl.setStyleSheet(
            "color: " + TEXT_MUTED + "; font-size: " + str(self.fs) +
            "px; background: transparent; border: none;"
        )

        self.scroll_layout.addWidget(self.waiting_lbl)
        self.scroll_layout.addStretch()

        scroll.setWidget(self.scroll_widget)
        dl.addWidget(scroll)

        note_lbl = QLabel(
            "CVE/CWE/MITRE data is sourced from NVD API and MITRE ATT&CK, not invented by AI."
        )
        note_lbl.setStyleSheet(
            "color: " + SUCCESS + "; font-size: " + str(self.fs - 3) +
            "px; background: transparent; border: none;"
        )
        note_lbl.setWordWrap(True)
        dl.addWidget(note_lbl)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setObjectName("dialogCloseBtn")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(dialog.close)

        close_btn.setStyleSheet(
            "QPushButton { background: " + ACCENT + "; color: white; "
            "border: none; border-radius: 8px; padding: 9px 26px; "
            "font-size: " + str(self.fs - 1) + "px; font-weight: 900; } "
            "QPushButton:hover { background: " + ACCENT_HOVER + "; } "
            "QPushButton:pressed { background: " + ACCENT_DARK + "; }"
        )

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

    def _reset_summary_scroll_layout(self):
        if not hasattr(self, "scroll_layout"):
            return

        while self.scroll_layout.count():
            item = self.scroll_layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()

        self.scroll_layout.addStretch()

    def render_ch_table(self):
        if not self.ch_rows:
            return

        tbl = QTableWidget()
        tbl.setColumnCount(6)
        tbl.setHorizontalHeaderLabels(
            [
                "Severity",
                "Issue",
                "CVE",
                "CVSS",
                "CWE",
                "MITRE",
            ]
        )

        tbl.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch,
        )

        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.verticalHeader().setVisible(False)
        tbl.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )

        tbl.setColumnWidth(0, 85)
        tbl.setColumnWidth(2, 120)
        tbl.setColumnWidth(3, 65)
        tbl.setColumnWidth(4, 170)
        tbl.setColumnWidth(5, 140)

        tbl.setStyleSheet(
            "QTableWidget { background: " + CARD_BG +
            "; border: 1px solid " + rgba_from_hex(ACCENT, 90) +
            "; border-radius: 8px; gridline-color: " + BORDER +
            "; color: " + TEXT_MAIN +
            "; selection-background-color: " + SELECTION_BG +
            "; selection-color: " + SELECTION_TEXT + "; } "
            "QHeaderView::section { background: " + rgba_from_hex(ACCENT, 25) +
            "; color: " + TEXT_MUTED + "; padding: 7px 8px; border: none; "
            "font-weight: 900; font-size: " + str(self.fs - 2) + "px; } "
            "QTableWidget::item { padding: 5px 8px; background: " + BG_DEEP +
            "; color: " + TEXT_MAIN + "; } "
            "QTableWidget::item:selected { background: " + SELECTION_BG +
            "; color: " + SELECTION_TEXT + "; }"
        )

        muted = QColor(TEXT_MUTED)
        text = QColor(TEXT_MAIN)

        for row_data in self.ch_rows:
            row = tbl.rowCount()
            tbl.insertRow(row)

            sev = row_data["severity"]
            color = SEVERITY_COLORS.get(sev, TEXT_MUTED)

            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            title_item = QTableWidgetItem(row_data["title"])
            title_item.setForeground(text)

            cve_item = QTableWidgetItem(row_data["cve"])
            cve_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if row_data["cve"] != "N/A":
                cve_item.setForeground(QColor(INFO_BLUE))
            else:
                cve_item.setForeground(muted)

            cvss_item = QTableWidgetItem(row_data["cvss"])
            cvss_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            try:
                score = float(row_data["cvss"])

                if score >= 9.0:
                    cvss_item.setForeground(QColor(BRAND_RED))
                elif score >= 7.0:
                    cvss_item.setForeground(QColor(WARNING))
                elif score >= 4.0:
                    cvss_item.setForeground(QColor(MEDIUM_YELLOW))
                else:
                    cvss_item.setForeground(QColor(SUCCESS))

            except Exception:
                cvss_item.setForeground(muted)

            cwe_item = QTableWidgetItem(row_data.get("cwe", "N/A"))
            cwe_item.setForeground(QColor(WARNING))

            mitre_item = QTableWidgetItem(row_data.get("mitre", "N/A"))
            mitre_item.setForeground(QColor(PURPLE))

            tbl.setItem(row, 0, sev_item)
            tbl.setItem(row, 1, title_item)
            tbl.setItem(row, 2, cve_item)
            tbl.setItem(row, 3, cvss_item)
            tbl.setItem(row, 4, cwe_item)
            tbl.setItem(row, 5, mitre_item)

            tbl.setRowHeight(row, 34)

        max_rows = min(len(self.ch_rows), 10)
        tbl_height = 42 + (max_rows * 35)
        tbl.setMaximumHeight(tbl_height)

        self.scroll_layout.insertWidget(
            self.scroll_layout.count() - 1,
            tbl
        )

    def render_summary(self, text):
        self._reset_summary_scroll_layout()

        lines = text.strip().split("\n")

        in_ch_section = False
        ch_section_rendered = False

        for line in lines:
            line = line.strip()

            if not line:
                spacer = QLabel("")
                spacer.setFixedHeight(6)
                spacer.setStyleSheet(
                    "background: transparent; border: none;"
                )

                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1,
                    spacer
                )

                continue

            upper = line.upper()

            is_section = any(
                upper.startswith(key)
                for key in SECTION_COLORS
            )

            if is_section:
                is_ch = any(
                    upper.startswith(key)
                    for key in [
                        "CRITICAL & HIGH",
                        "CRITICAL ISSUES",
                    ]
                )

                color = TEXT_MAIN

                for key, section_color in SECTION_COLORS.items():
                    if upper.startswith(key):
                        color = section_color
                        break

                lbl = QLabel(line)
                lbl.setStyleSheet(
                    "color: " + color + "; font-size: " + str(self.fs) +
                    "px; font-weight: 900; background: transparent; "
                    "border: none; margin-top: 10px;"
                )

                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1,
                    lbl
                )

                sec_div = QFrame()
                sec_div.setFrameShape(QFrame.Shape.HLine)
                sec_div.setFixedHeight(1)
                sec_div.setStyleSheet(
                    "background: " + color + "; border: none; max-height: 1px;"
                )

                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1,
                    sec_div
                )

                if is_ch:
                    in_ch_section = True
                    ch_section_rendered = False
                else:
                    in_ch_section = False

            elif in_ch_section and line.startswith("•"):
                if not ch_section_rendered:
                    self.render_ch_table()
                    ch_section_rendered = True

            else:
                in_ch_section = False

                lbl = QLabel(line)
                lbl.setWordWrap(True)
                lbl.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )

                if line.startswith("•"):
                    lbl.setStyleSheet(
                        "color: " + TEXT_MAIN + "; font-size: " +
                        str(self.fs - 1) + "px; background: transparent; "
                        "border: none; padding-left: 10px; margin-top: 2px;"
                    )
                else:
                    lbl.setStyleSheet(
                        "color: " + TEXT_MUTED + "; font-size: " +
                        str(self.fs - 1) + "px; background: transparent; "
                        "border: none;"
                    )

                self.scroll_layout.insertWidget(
                    self.scroll_layout.count() - 1,
                    lbl
                )

    def get_stylesheet(self):
        fs = self.fs

        return (
            "QWidget { background-color: " + BG_MAIN + "; color: " +
            TEXT_MAIN + '; font-family: "Segoe UI", Arial, sans-serif; '
            "font-size: " + str(fs) + "px; } "
            "#topCard { background-color: " + CARD_BG +
            "; border: 1px solid " + BORDER + "; border-radius: 12px; } "
            "#topCard:hover { border: 1px solid " + CARD_HOVER + "; } "
            "#dashTitle { color: " + ACCENT + "; font-size: " +
            str(fs + 7) + "px; font-weight: 900; background: transparent; "
            "border: none; } "
            "#dashSub { color: " + TEXT_MUTED + "; font-size: " +
            str(fs - 2) + "px; background: transparent; border: none; } "
            "#summaryCard { background-color: " + CARD_BG +
            "; border-radius: 10px; } "
            "#filterCard { background-color: " + CARD_BG +
            "; border: 1px solid " + BORDER + "; border-radius: 10px; } "
            "#filterCard:hover { border: 1px solid " + CARD_HOVER + "; } "
            "#filterLbl { color: " + TEXT_MUTED + "; font-size: " +
            str(fs - 1) + "px; font-weight: 700; background: transparent; "
            "border: none; } "
            "#findingsTable { background-color: " + CARD_BG +
            "; alternate-background-color: " + CARD_BG_2 +
            "; border: 1px solid " + BORDER + "; gridline-color: " + BORDER +
            "; border-radius: 10px; color: " + TEXT_MAIN +
            "; selection-background-color: " + SELECTION_BG +
            "; selection-color: " + SELECTION_TEXT + "; } "
            "QHeaderView::section { background-color: " + BG_DEEP +
            "; color: " + TEXT_MUTED + "; padding: 9px; border: none; "
            "border-bottom: 1px solid " + BORDER + "; font-weight: 900; "
            "font-size: " + str(fs - 2) + "px; } "
            "QTableWidget::item { padding: 6px 8px; background-color: "
            "transparent; color: " + TEXT_MAIN + "; border: none; } "
            "QTableWidget::item:selected { background-color: " + SELECTION_BG +
            "; color: " + SELECTION_TEXT + "; } "
            "#backBtn { background-color: " + BUTTON_SOFT + "; color: " +
            TEXT_MAIN + "; border: 1px solid " + BORDER +
            "; border-radius: 8px; padding: 8px 16px; font-size: " +
            str(fs - 1) + "px; font-weight: 800; } "
            "#backBtn:hover { border-color: " + ACCENT + "; color: " +
            SELECTION_TEXT + "; background-color: " + HOVER_BG + "; } "
            "#actionBtn { background-color: " + BUTTON_SOFT + "; color: " +
            TEXT_MAIN + "; border: 1px solid " + BORDER +
            "; border-radius: 8px; padding: 8px 16px; font-size: " +
            str(fs - 1) + "px; font-weight: 800; } "
            "#actionBtn:hover { border-color: " + ACCENT + "; color: " +
            SELECTION_TEXT + "; background-color: " + HOVER_BG + "; } "
            "#actionBtn::menu-indicator { image: none; } "
            "#primaryActionBtn { background-color: " + ACCENT +
            "; color: white; border: none; border-radius: 8px; "
            "padding: 8px 16px; font-size: " + str(fs - 1) +
            "px; font-weight: 900; } "
            "#primaryActionBtn:hover { background-color: " + ACCENT_HOVER + "; } "
            "#primaryActionBtn:pressed { background-color: " + ACCENT_DARK + "; } "
            "#hintLbl { color: " + TEXT_MUTED + "; font-size: " +
            str(fs - 2) + "px; margin-top: 4px; background: transparent; "
            "border: none; } "
            "QMenu { background-color: " + CARD_BG + "; color: " +
            TEXT_MAIN + "; border: 1px solid " + BORDER +
            "; border-radius: 8px; padding: 6px; } "
            "QMenu::item { padding: 8px 20px; border-radius: 6px; } "
            "QMenu::item:selected { background-color: " + SELECTION_BG +
            "; color: " + SELECTION_TEXT + "; } "
            "QMessageBox { background-color: " + BG_MAIN + "; color: " +
            TEXT_MAIN + "; } "
            "QMessageBox QLabel { color: " + TEXT_MAIN +
            "; background: transparent; border: none; } "
            "QMessageBox QPushButton { background-color: " + ACCENT +
            "; color: white; border: none; border-radius: 7px; "
            "padding: 7px 18px; font-weight: 800; } "
            "QMessageBox QPushButton:hover { background-color: " + ACCENT_HOVER + "; } "
            "QScrollBar:vertical { background: " + BG_MAIN +
            "; width: 10px; margin: 0px; } "
            "QScrollBar::handle:vertical { background: " + BORDER_SOFT +
            "; border-radius: 5px; min-height: 28px; } "
            "QScrollBar::handle:vertical:hover { background: " + ACCENT + "; } "
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical "
            "{ height: 0px; }"
        )
