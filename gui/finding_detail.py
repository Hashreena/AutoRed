import re

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QScrollArea,
    QMessageBox, QApplication, QSizePolicy,
    QProgressBar
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QUrl,
    QTimer, QPropertyAnimation, QEasingCurve
)
from PyQt6.QtGui import (
    QDesktopServices, QColor, QTextCursor
)
from PyQt6.QtWidgets import QGraphicsDropShadowEffect

from backend.db import get_connection
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# AutoRed Theme Palette
# Supports Dark Theme + Light Theme from preferences.py
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    """
    Convert #RRGGBB to Qt-friendly rgba(r,g,b,a).
    alpha uses Qt/QSS 0-255 style.
    """
    color = str(hex_color).strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    try:
        red = int(color[0:2], 16)
        green = int(color[2:4], 16)
        blue = int(color[4:6], 16)
    except ValueError:
        return f"rgba(239, 68, 68, {alpha})"

    return f"rgba({red}, {green}, {blue}, {alpha})"


def is_light_theme(theme):
    return (
        theme.get("bg", "").upper() in (
            "#F8FAFC",
            "#FFFFFF",
            "#F1F5F9",
            "#EEF2F7",
            "#E2E8F0",
        )
        or theme.get("text", "").upper() == "#0F172A"
    )


# Defaults are dark theme. These globals are refreshed by
# apply_theme_palette() so the existing inline styles in this screen
# can support both dark and light themes cleanly.
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

ACCENT_RED = "#EF4444"
ACCENT_HOVER = "#DC2626"
ACCENT_DARK = "#991B1B"
ACCENT_BLUE = ACCENT_RED

CRITICAL = "#EF4444"
HIGH = "#F97316"
MEDIUM = "#FACC15"
LOW = "#22C55E"
INFO = "#60A5FA"
SUCCESS = "#22C55E"

SUCCESS_HOVER = "#16A34A"
SUCCESS_PRESS = "#15803D"

SEVERITY_COLORS = {}
SEVERITY_BADGE_TEXT = {}

TAG_BG = "{SELECTION_BG}"
TAG_BORDER = "rgba(239, 68, 68, 115)"
TAG_TEXT = "#FEE2E2"

HOVER_BG = "rgba(239, 68, 68, 25)"
SELECTION_BG = "{SELECTION_BG}"
SELECTION_TEXT = "#FEE2E2"
BUTTON_SOFT = "{BUTTON_SOFT}"
CARD_HOVER = "rgba(239, 68, 68, 75)"
COMMAND_BG = "#010409"
COMMAND_TEXT = "#FEE2E2"
PANEL_BG_SOFT = "{PANEL_BG_SOFT}"
NOTES_BG = "{NOTES_BG}"
LOADER_BG = "#010409"
LOADER_TRACK = "#020617"


def apply_theme_palette(theme):
    global BG_MAIN, BG_PAGE, BG_DEEP
    global CARD_BG, CARD_BG_2, BORDER, BORDER_SOFT
    global TEXT_MAIN, TEXT_MUTED, TEXT_SOFT
    global ACCENT_RED, ACCENT_HOVER, ACCENT_DARK, ACCENT_BLUE
    global CRITICAL, HIGH, MEDIUM, LOW, INFO, SUCCESS
    global SUCCESS_HOVER, SUCCESS_PRESS
    global SEVERITY_COLORS, SEVERITY_BADGE_TEXT
    global TAG_BG, TAG_BORDER, TAG_TEXT
    global HOVER_BG, SELECTION_BG, SELECTION_TEXT
    global BUTTON_SOFT, CARD_HOVER
    global COMMAND_BG, COMMAND_TEXT, PANEL_BG_SOFT, NOTES_BG
    global LOADER_BG, LOADER_TRACK

    light = is_light_theme(theme)

    BG_MAIN = theme.get("bg", "#F8FAFC" if light else "#020617")
    BG_PAGE = theme.get(
        "page",
        theme.get("sidebar_bg", "#FFFFFF" if light else "#07111F")
    )
    BG_DEEP = theme.get("bg_deep", "#EEF2F7" if light else "#01030A")

    CARD_BG = theme.get("card_bg", "#FFFFFF" if light else "#0F172A")
    CARD_BG_2 = theme.get("card_bg_2", "#F1F5F9" if light else "#111827")

    BORDER = theme.get("border", "#CBD5E1" if light else "#22304A")
    BORDER_SOFT = theme.get("border_soft", "#94A3B8" if light else "#334155")

    TEXT_MAIN = theme.get("text", "#0F172A" if light else "#E5EDF7")
    TEXT_MUTED = theme.get("text_muted", "#475569" if light else "#94A3B8")
    TEXT_SOFT = theme.get("text_soft", "#64748B")

    ACCENT_RED = theme.get("accent", "#EF4444")
    ACCENT_HOVER = theme.get("accent_hover", "#DC2626")
    ACCENT_DARK = theme.get("accent_dark", "#991B1B")
    ACCENT_BLUE = ACCENT_RED

    CRITICAL = theme.get("brand_red", ACCENT_RED)
    HIGH = theme.get("warning", "#EA580C" if light else "#F97316")
    MEDIUM = theme.get("medium", "#CA8A04" if light else "#FACC15")
    LOW = theme.get("success", "#16A34A" if light else "#22C55E")
    INFO = theme.get("info", "#2563EB" if light else "#60A5FA")
    SUCCESS = theme.get("success", "#16A34A" if light else "#22C55E")

    SUCCESS_HOVER = theme.get("success_hover", "#15803D" if light else "#16A34A")
    SUCCESS_PRESS = "#166534" if light else "#15803D"

    HOVER_BG = theme.get("hover", rgba_from_hex(ACCENT_RED, 18 if light else 25))
    SELECTION_BG = theme.get(
        "selection_bg",
        rgba_from_hex(ACCENT_RED, 28 if light else 35)
    )
    SELECTION_TEXT = theme.get(
        "selection_text",
        "#7F1D1D" if light else "#FEE2E2"
    )
    BUTTON_SOFT = theme.get(
        "button_soft",
        "#FFFFFF" if light else "{BUTTON_SOFT}"
    )
    CARD_HOVER = theme.get(
        "card_hover",
        rgba_from_hex(ACCENT_RED, 55 if light else 75)
    )

    TAG_BG = rgba_from_hex(ACCENT_RED, 22 if light else 35)
    TAG_BORDER = rgba_from_hex(ACCENT_RED, 90 if light else 115)
    TAG_TEXT = "#7F1D1D" if light else "#FEE2E2"

    COMMAND_BG = "#F8FAFC" if light else "#010409"
    COMMAND_TEXT = "#7F1D1D" if light else "#FEE2E2"
    PANEL_BG_SOFT = rgba_from_hex(CARD_BG_2, 190 if light else 90)
    NOTES_BG = "#FFFFFF" if light else "{NOTES_BG}"
    LOADER_BG = "#FFFFFF" if light else "#010409"
    LOADER_TRACK = "#E2E8F0" if light else "#020617"

    SEVERITY_COLORS = {
        "Critical": CRITICAL,
        "High": HIGH,
        "Medium": MEDIUM,
        "Low": LOW,
        "Info": INFO,
    }

    SEVERITY_BADGE_TEXT = {
        "Critical": "#7F1D1D" if light else "#fecaca",
        "High": "#7C2D12" if light else "#fed7aa",
        "Medium": "#713F12" if light else "#fef3c7",
        "Low": "#14532D" if light else "#bbf7d0",
        "Info": "#1E3A8A" if light else "#DBEAFE",
    }


apply_theme_palette(get_theme(True))

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

_ACTIVE_WORKERS = []


class EnrichWorker(QThread):
    done = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, finding):
        super().__init__()
        self.finding = finding

    def run(self):
        try:
            from backend.cve_enricher import (
                enrich_finding,
                get_attack_path_ai
            )

            result = enrich_finding(self.finding)
            nvd_best = result.get("nvd_best")

            attack, verify = get_attack_path_ai(
                self.finding,
                nvd_best
            )

            result["attack_path"] = attack
            result["verify_steps"] = verify

            self.done.emit(result)

        except Exception as e:
            self.error.emit(str(e))


class FindingDetail(QWidget):
    def __init__(
        self,
        finding,
        on_close=None,
        on_status_change=None,
        cached_data=None,
        prefs=None,
        on_audit_log=None,
        on_visualize=None,
        on_export_report=None,
        on_ai_summary=None,
    ):
        super().__init__()

        self.finding = finding
        self.on_close = on_close
        self.on_status_change = on_status_change

        # Kept for compatibility if main_window.py still passes these.
        self.on_audit_log = on_audit_log
        self.on_visualize = on_visualize
        self.on_export_report = on_export_report
        self.on_ai_summary = on_ai_summary

        self.enrich_worker = None
        self.cached_data = cached_data
        self.enrich_result = cached_data or {}
        self._pending_notes = None

        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        self.current_detail_tab = "description"
        self.detail_buttons = {}

        self.setStyleSheet(self.get_stylesheet())

        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)

        self.init_ui()

        if cached_data:
            QTimer.singleShot(
                50,
                lambda: self.on_enriched(cached_data)
            )
        else:
            self.start_enrichment()

    # ─────────────────────────────────────────────
    # Basic helpers
    # ─────────────────────────────────────────────

    def sel(self, widget):
        widget.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        return widget

    def _rgba(self, hex_color, alpha):
        hex_color = hex_color.lstrip("#")

        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        a = int(alpha * 255)

        return f"rgba({r}, {g}, {b}, {a})"

    def _add_glow(self, widget, color=ACCENT_BLUE, blur=24, alpha=90):
        effect = QGraphicsDropShadowEffect()
        effect.setBlurRadius(blur)

        c = QColor(color)
        c.setAlpha(alpha)

        effect.setColor(c)
        effect.setOffset(0, 0)

        widget.setGraphicsEffect(effect)

    def _cvss_band(self, score):
        if score is None:
            return ""

        try:
            score = float(score)
        except (TypeError, ValueError):
            return ""

        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.1:
            return "Low"

        return "Info"

    # ─────────────────────────────────────────────
    # Theme refresh
    # ─────────────────────────────────────────────

    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        if hasattr(self, "notes_input"):
            self._pending_notes = self.notes_input.toPlainText()

        self.setStyleSheet(self.get_stylesheet())

        while self.outer.count():
            item = self.outer.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.init_ui()

        if self.enrich_result:
            self.on_enriched(self.enrich_result)

    # ─────────────────────────────────────────────
    # Loading widgets
    # ─────────────────────────────────────────────

    class _HackingLoader(QFrame):
        def __init__(self, parent_widget, accent="#22c55e"):
            super().__init__()

            self.accent = accent
            self._pct = 0

            super().setStyleSheet(
                f"""
                QFrame {{
                    background: {LOADER_BG};
                    border: 1px solid {rgba_from_hex(accent, 85)};
                    border-radius: 8px;
                }}
                """
            )

            lay = QVBoxLayout(self)
            lay.setContentsMargins(12, 10, 12, 10)
            lay.setSpacing(6)

            self.status_lbl = QLabel("")
            self.status_lbl.setWordWrap(True)
            self.status_lbl.setStyleSheet(
                f"""
                color: {accent};
                font-family: 'Courier New', monospace;
                font-size: {parent_widget.fs - 1}px;
                background: transparent;
                border: none;
                """
            )
            lay.addWidget(self.status_lbl)

            self.track = QFrame()
            self.track.setFixedHeight(6)
            self.track.setStyleSheet(
                f"""
                background: {LOADER_TRACK};
                border-radius: 3px;
                border: none;
                """
            )

            track_l = QHBoxLayout(self.track)
            track_l.setContentsMargins(0, 0, 0, 0)

            self.fill = QFrame()
            self.fill.setFixedWidth(4)
            self.fill.setStyleSheet(
                f"""
                background: {accent};
                border-radius: 3px;
                border: none;
                """
            )

            track_l.addWidget(self.fill)
            track_l.addStretch()

            lay.addWidget(self.track)

        def setText(self, text):
            self.status_lbl.setText(f"> {text}")

        def setStyleSheet(self, qss):
            if not hasattr(self, "status_lbl"):
                super().setStyleSheet(qss)
                return

            self.status_lbl.setStyleSheet(qss)
            self.track.hide()

            super().setStyleSheet(
                "QFrame { background: transparent; border: none; }"
            )

        def advance(self, pct_step=7):
            self._pct = min(96, self._pct + pct_step)
            width = max(4, int(self._pct / 100 * 280))
            self.fill.setFixedWidth(width)

    def _make_scanning_widget(self, sources, verb):
        loader = self._HackingLoader(self, accent=SUCCESS)

        state = {
            "i": 0,
            "dots": 0,
        }

        def tick():
            try:
                source = sources[state["i"] % len(sources)]
                dots = "." * (state["dots"] % 4)

                loader.setText(
                    f"SCANNING {verb.upper()} {source.upper()}{dots}"
                )
                loader.advance(6)

                state["dots"] += 1

                if state["dots"] % 3 == 0:
                    state["i"] += 1

            except RuntimeError:
                timer.stop()

        timer = QTimer(loader)
        timer.timeout.connect(tick)
        timer.start(280)
        tick()

        loader._loading_timer = timer

        return loader

    def _make_pulsing_label(self, base_text):
        loader = self._HackingLoader(self, accent=ACCENT_BLUE)

        state = {"dots": 0}

        def tick():
            try:
                dots = "." * (state["dots"] % 4)
                loader.setText(f"{base_text.upper()}{dots}")
                loader.advance(5)
                state["dots"] += 1

            except RuntimeError:
                timer.stop()

        timer = QTimer(loader)
        timer.timeout.connect(tick)
        timer.start(320)
        tick()

        loader._loading_timer = timer

        return loader

    @staticmethod
    def _stop_loading_timer(label):
        timer = getattr(label, "_loading_timer", None)

        if timer is not None:
            try:
                timer.stop()
            except RuntimeError:
                pass

    # ─────────────────────────────────────────────
    # Main UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("mainScroll")

        content = QWidget()
        content.setObjectName("contentRoot")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(34, 26, 34, 26)
        layout.setSpacing(18)

        top_bar_wrap = QWidget()
        top_bar_wrap.setObjectName("topBarWrap")
        top_bar_wrap.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )
        top_bar_wrap.setMaximumHeight(58)

        top_bar_layout = self._build_top_bar()
        top_bar_layout.setContentsMargins(0, 0, 0, 0)
        top_bar_wrap.setLayout(top_bar_layout)

        layout.addWidget(top_bar_wrap)

        self.hero_card = self._build_hero_card()
        self.hero_card.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )
        self.hero_card.setFixedHeight(135)

        layout.addWidget(self.hero_card)
        layout.addSpacing(4)

        main_row = QHBoxLayout()
        main_row.setSpacing(18)

        left_col = QVBoxLayout()
        left_col.setSpacing(14)

        right_col = QVBoxLayout()
        right_col.setSpacing(14)

        # LEFT COLUMN
        left_col.addWidget(
            self.make_section_header(
                "🛡️",
                "THREAT INTELLIGENCE & EXPOSURE ANALYSIS"
            )
        )

        intel_grid = QHBoxLayout()
        intel_grid.setSpacing(10)

        self.cve_card = self.make_card(border=self._rgba(INFO, 0.28))
        self.cve_layout = QVBoxLayout(self.cve_card)
        self.cve_layout.setContentsMargins(14, 12, 14, 12)
        self.cve_layout.setSpacing(8)

        self.intel_loading = self._make_scanning_widget(
            sources=["NVD", "CIRCL", "MITRE", "Claude AI"],
            verb="Querying"
        )
        self.cve_layout.addWidget(self.intel_loading)

        intel_grid.addWidget(self.cve_card, 1)

        self.cwe_card = self.make_card(border=self._rgba(HIGH, 0.28))
        self.cwe_layout = QVBoxLayout(self.cwe_card)
        self.cwe_layout.setContentsMargins(14, 12, 14, 12)
        self.cwe_layout.setSpacing(8)

        cwe_placeholder = self.sel(
            QLabel("Awaiting CWE classification...")
        )
        cwe_placeholder.setObjectName("mutedText")
        self.cwe_layout.addWidget(cwe_placeholder)

        intel_grid.addWidget(self.cwe_card, 1)

        left_col.addLayout(intel_grid)

        exp_grid = QHBoxLayout()
        exp_grid.setSpacing(10)

        self.exploit_card = self.make_card(border=self._rgba(SUCCESS, 0.28))
        self.exploit_layout = QVBoxLayout(self.exploit_card)
        self.exploit_layout.setContentsMargins(14, 12, 14, 12)
        self.exploit_layout.setSpacing(8)

        exp_placeholder = self.sel(QLabel("Assessing exploitability..."))
        exp_placeholder.setObjectName("mutedText")
        self.exploit_layout.addWidget(exp_placeholder)

        exp_grid.addWidget(self.exploit_card, 1)

        self.surface_card = self.make_card(border=self._rgba(INFO, 0.28))
        self.surface_layout = QVBoxLayout(self.surface_card)
        self.surface_layout.setContentsMargins(14, 12, 14, 12)
        self.surface_layout.setSpacing(8)

        surf_placeholder = self.sel(QLabel("Mapping attack surface..."))
        surf_placeholder.setObjectName("mutedText")
        self.surface_layout.addWidget(surf_placeholder)

        exp_grid.addWidget(self.surface_card, 1)

        left_col.addLayout(exp_grid)

        left_col.addWidget(
            self.make_section_header(
                "📋",
                "FINDING DETAILS"
            )
        )

        self.detail_card = self.make_card()
        detail_layout = QVBoxLayout(self.detail_card)
        detail_layout.setContentsMargins(14, 12, 14, 12)
        detail_layout.setSpacing(10)

        detail_layout.addLayout(self._build_detail_buttons())

        self.detail_content = QFrame()
        self.detail_content.setObjectName("detailContent")

        self.detail_content_layout = QVBoxLayout(self.detail_content)
        self.detail_content_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_content_layout.setSpacing(8)

        detail_layout.addWidget(self.detail_content)

        left_col.addWidget(self.detail_card)

        verify_notes_row = QHBoxLayout()
        verify_notes_row.setSpacing(10)

        verify_col = QVBoxLayout()
        verify_col.setSpacing(8)

        verify_col.addWidget(
            self.make_section_header(
                "✅",
                "HOW TO VERIFY THIS FINDING"
            )
        )

        self.verify_card = self.make_card(border=self._rgba(SUCCESS, 0.32))
        self.verify_layout = QVBoxLayout(self.verify_card)
        self.verify_layout.setContentsMargins(14, 12, 14, 12)
        self.verify_layout.setSpacing(8)

        self.verify_lbl = self._make_pulsing_label(
            "Generating verification steps"
        )
        self.verify_layout.addWidget(self.verify_lbl)

        verify_col.addWidget(self.verify_card)
        verify_notes_row.addLayout(verify_col, 3)

        notes_col = QVBoxLayout()
        notes_col.setSpacing(8)

        notes_col.addWidget(
            self.make_section_header(
                "📝",
                "YOUR TECHNICAL NOTES",
                "Add your manual verification results"
            )
        )

        notes_card = self.make_card()
        notes_layout = QVBoxLayout(notes_card)
        notes_layout.setContentsMargins(10, 10, 10, 10)

        self.notes_input = QTextEdit()
        self.notes_input.setObjectName("notesInput")
        self.notes_input.setPlaceholderText(
            "e.g. Manually verified — connected to port 23, "
            "captured banner, confirmed plaintext authentication risk..."
        )
        self.notes_input.setMinimumHeight(158)

        if self._pending_notes is not None:
            self.notes_input.setPlainText(self._pending_notes)
        else:
            saved = self.finding.get("analyst_notes", "")
            if saved:
                self.notes_input.setPlainText(saved)

        notes_layout.addWidget(self.notes_input)

        self.notes_counter = QLabel("0 / 4000")
        self.notes_counter.setObjectName("counterText")
        self.notes_counter.setAlignment(Qt.AlignmentFlag.AlignRight)
        notes_layout.addWidget(self.notes_counter)

        self.notes_input.textChanged.connect(self._update_note_counter)
        self._update_note_counter()

        notes_col.addWidget(notes_card)
        verify_notes_row.addLayout(notes_col, 2)

        left_col.addLayout(verify_notes_row)

        # RIGHT COLUMN
        right_col.addWidget(
            self.make_section_header(
                "💥",
                "MITRE ATT&CK CLASSIFICATION"
            )
        )

        self.mitre_frame = self.make_card(border=self._rgba(CRITICAL, 0.30))
        self.mitre_layout = QVBoxLayout(self.mitre_frame)
        self.mitre_layout.setContentsMargins(14, 12, 14, 12)
        self.mitre_layout.setSpacing(8)

        self.mitre_loading = self._make_scanning_widget(
            sources=["MITRE ATT&CK"],
            verb="Mapping technique against"
        )
        self.mitre_layout.addWidget(self.mitre_loading)

        right_col.addWidget(self.mitre_frame)

        right_col.addWidget(
            self.make_section_header(
                "🔴",
                "ATTACK PATH RECOMMENDATION"
            )
        )

        self.ap_frame = self.make_card(border=self._rgba(CRITICAL, 0.30))
        self.ap_layout = QVBoxLayout(self.ap_frame)
        self.ap_layout.setContentsMargins(14, 12, 14, 12)
        self.ap_layout.setSpacing(10)

        self.ap_lbl = self._make_pulsing_label(
            "Generating AI attack path recommendations"
        )
        self.ap_layout.addWidget(self.ap_lbl)

        right_col.addWidget(self.ap_frame)

        right_col.addWidget(
            self.make_section_header(
                "📊",
                "RISK ANALYTICS"
            )
        )
        right_col.addWidget(self._build_risk_analytics_card())

        right_col.addWidget(
            self.make_section_header(
                "📡",
                "EXPOSURE SUMMARY"
            )
        )
        right_col.addWidget(self._build_exposure_summary_card())

        right_col.addStretch()

        main_row.addLayout(left_col, 5)
        main_row.addLayout(right_col, 3)

        layout.addLayout(main_row)

        layout.addWidget(self._build_bottom_actions())

        scroll.setWidget(content)
        self.outer.addWidget(scroll)

        self.show_detail_tab("description")

        self._animate_fade_in(content)

    # ─────────────────────────────────────────────
    # Header / top bar
    # ─────────────────────────────────────────────

    def _build_top_bar(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        back_btn = QPushButton("← Back to Findings")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        row.addWidget(back_btn)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        scan_id = self.finding.get("scan_id")
        title_text = f"Finding Detail — Scan #{scan_id}" if scan_id else "Finding Detail"

        title = QLabel(title_text)
        title.setObjectName("pageTitle")

        target = self.finding.get("asset", "N/A")
        profile = self.finding.get("profile", "Standard")
        finding_id = self.finding.get("id", "N/A")

        meta = QLabel(
            f"Target: {target}  •  Profile: {profile}  •  Finding: {finding_id}"
        )
        meta.setObjectName("pageMeta")

        title_col.addWidget(title)
        title_col.addWidget(meta)

        row.addLayout(title_col, 1)
        row.addStretch()

        return row

    def _build_hero_card(self):
        severity = self.finding.get("severity", "Info")
        sev_color = SEVERITY_COLORS.get(severity, INFO)
        sev_text = SEVERITY_BADGE_TEXT.get(severity, "#FEE2E2")

        card = QFrame()
        card.setObjectName("heroCard")
        card.setFixedHeight(150)
        card.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )

        card.setStyleSheet(
            f"""
            QFrame#heroCard {{
                background-color: {CARD_BG};
                border: 1px solid {sev_color};
                border-radius: 12px;
            }}
            """
        )

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(14)

        title_row = QHBoxLayout()
        title_row.setSpacing(12)

        badge = QLabel(severity.upper())
        badge.setStyleSheet(
            f"""
            QLabel {{
                background-color: {self._rgba(sev_color, 0.22)};
                color: {sev_text};
                border: 1px solid {sev_color};
                border-radius: 6px;
                padding: 6px 14px;
                font-size: {self.fs - 1}px;
                font-weight: 900;
            }}
            """
        )

        title = self.sel(QLabel(self.finding.get("title", "Untitled finding")))
        title.setWordWrap(True)
        title.setStyleSheet(
            f"""
            QLabel {{
                color: {TEXT_MAIN};
                font-size: {self.fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
            """
        )

        title_row.addWidget(badge)
        title_row.addWidget(title, 1)

        layout.addLayout(title_row)

        chip_row = QHBoxLayout()
        chip_row.setSpacing(10)

        cvss_val = self.finding.get("cvss_score")
        cvss_txt = (
            f"{cvss_val}  {self._cvss_band(cvss_val)}"
            if cvss_val is not None
            else "Pending"
        )

        cwe_txt = self.finding.get("cwe_id") or "Pending"

        self.chip_tool = self._info_chip("◎", "Tool", str(self.finding.get("tool", "N/A")))
        self.chip_asset = self._info_chip("▣", "Asset", str(self.finding.get("asset", "N/A")))
        self.chip_category = self._info_chip("▦", "Category", str(self.finding.get("category", "N/A")))
        self.chip_cvss = self._info_chip("◉", "Exposure CVSS", cvss_txt)
        self.chip_cwe = self._info_chip("▥", "CWE", cwe_txt)
        self.chip_mitre = self._info_chip("◇", "MITRE ATT&CK", "Pending")

        for chip in (
            self.chip_tool,
            self.chip_asset,
            self.chip_category,
            self.chip_cvss,
            self.chip_cwe,
            self.chip_mitre,
        ):
            chip_row.addWidget(chip, 1)

        layout.addLayout(chip_row)

        return card

    def _info_chip(self, icon, label, value):
        chip = QFrame()
        chip.setObjectName("infoChip")
        chip.setMinimumHeight(62)

        chip.setStyleSheet(
            f"""
            QFrame#infoChip {{
                background-color: {BUTTON_SOFT};
                border: 1px solid {BORDER};
                border-radius: 12px;
            }}
            """
        )

        cl = QHBoxLayout(chip)
        cl.setContentsMargins(12, 8, 12, 8)
        cl.setSpacing(10)

        icon_lbl = QLabel(icon)
        icon_lbl.setFixedSize(30, 30)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(
            f"""
            QLabel {{
                color: {ACCENT_BLUE};
                font-size: {self.fs + 2}px;
                background-color: rgba(239, 68, 68, 30);
                border: 1px solid rgba(239, 68, 68, 70);
                border-radius: 8px;
            }}
            """
        )

        text_col = QVBoxLayout()
        text_col.setSpacing(1)

        cap = QLabel(label)
        cap.setStyleSheet(
            f"""
            QLabel {{
                color: {TEXT_MUTED};
                font-size: {self.fs - 4}px;
                background: transparent;
                border: none;
            }}
            """
        )

        val = self.sel(QLabel(value))
        val.setWordWrap(True)
        val.setStyleSheet(
            f"""
            QLabel {{
                color: {TEXT_MAIN};
                font-size: {self.fs - 2}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}
            """
        )

        text_col.addWidget(cap)
        text_col.addWidget(val)

        cl.addWidget(icon_lbl)
        cl.addLayout(text_col)
        cl.addStretch()

        chip._value_label = val

        return chip

    # ─────────────────────────────────────────────
    # Detail tabs
    # ─────────────────────────────────────────────

    def _build_detail_buttons(self):
        row = QHBoxLayout()
        row.setSpacing(8)

        self.detail_buttons = {}

        tabs = [
            ("description", "Description"),
            ("evidence", "Evidence"),
            ("remediation", "Remediation"),
            ("cwe", "CWE Explanation"),
        ]

        for key, label in tabs:
            btn = QPushButton(label)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(self._detail_tab_stylesheet(active=False))
            btn.clicked.connect(lambda _, k=key: self.show_detail_tab(k))

            self.detail_buttons[key] = btn
            row.addWidget(btn)

        row.addStretch()

        return row

    def show_detail_tab(self, key):
        self.current_detail_tab = key

        for tab_key, btn in self.detail_buttons.items():
            btn.setStyleSheet(
                self._detail_tab_stylesheet(active=(tab_key == key))
            )

        self._clear_layout(self.detail_content_layout)

        if key == "description":
            self.detail_content_layout.addWidget(
                self._detail_text_panel(
                    "Description",
                    self.finding.get("description")
                    or "No description available for this finding."
                )
            )

        elif key == "evidence":
            self.detail_content_layout.addWidget(
                self._detail_text_panel(
                    "Evidence",
                    self.finding.get("evidence")
                    or "No evidence available for this finding."
                )
            )

        elif key == "remediation":
            self.detail_content_layout.addWidget(
                self._detail_text_panel(
                    "Remediation",
                    self.finding.get("recommendation")
                    or self._generate_default_remediation()
                )
            )

        elif key == "cwe":
            self.detail_content_layout.addWidget(
                self._detail_text_panel(
                    "CWE Explanation",
                    self._build_cwe_explanation_text()
                )
            )

        self.detail_content_layout.addStretch()

    def _detail_tab_stylesheet(self, active=False):
        if active:
            return f"""
                QPushButton {{
                    background: {SELECTION_BG};
                    color: {SELECTION_TEXT};
                    border: 1px solid {ACCENT_RED};
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-size: {self.fs - 2}px;
                    font-weight: 900;
                }}
            """

        return f"""
            QPushButton {{
                background: {BUTTON_SOFT};
                color: {TEXT_MUTED};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: {self.fs - 2}px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                color: {TEXT_MAIN};
                border-color: {ACCENT_RED};
                background: {HOVER_BG};
            }}
        """

    def _detail_text_panel(self, title, body):
        frame = QFrame()
        frame.setObjectName("detailPanel")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        title_lbl = QLabel(title.upper())
        title_lbl.setObjectName("miniPanelTitle")
        layout.addWidget(title_lbl)

        body_lbl = self.sel(QLabel(str(body)))
        body_lbl.setWordWrap(True)
        body_lbl.setObjectName("bodyText")
        layout.addWidget(body_lbl)

        return frame

    # ─────────────────────────────────────────────
    # Graph cards
    # ─────────────────────────────────────────────

    def _build_risk_analytics_card(self):
        card = self.make_card(border=self._rgba(ACCENT_BLUE, 0.30))

        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        title = QLabel("FINDING RISK BREAKDOWN")
        title.setObjectName("blueMiniTitle")
        layout.addWidget(title)

        cvss_score = self.finding.get("cvss_score")

        try:
            cvss_value = float(cvss_score)
        except (TypeError, ValueError):
            cvss_value = 0.0

        severity = self.finding.get("severity", "Info")
        finding_title = (self.finding.get("title") or "").lower()

        cvss_bar = int(min(cvss_value * 10, 100))

        if severity == "Critical":
            severity_bar = 95
        elif severity == "High":
            severity_bar = 80
        elif severity == "Medium":
            severity_bar = 55
        elif severity == "Low":
            severity_bar = 30
        else:
            severity_bar = 15

        if any(x in finding_title for x in ["telnet", "ftp", "vnc", "mysql", "postgres", "bindshell"]):
            exposure_bar = 90
        elif any(x in finding_title for x in ["ssh", "smtp", "http"]):
            exposure_bar = 60
        else:
            exposure_bar = 40

        if "telnet" in finding_title or "bindshell" in finding_title:
            credential_bar = 85
        elif "ftp" in finding_title or "mysql" in finding_title or "postgres" in finding_title:
            credential_bar = 70
        else:
            credential_bar = 35

        if severity in ("Critical", "High"):
            urgency_bar = 90
        elif severity == "Medium":
            urgency_bar = 60
        else:
            urgency_bar = 35

        rows = [
            ("CVSS Severity", cvss_bar, SEVERITY_COLORS.get(severity, INFO)),
            ("Severity Weight", severity_bar, SEVERITY_COLORS.get(severity, INFO)),
            ("Network Exposure", exposure_bar, HIGH),
            ("Credential Risk", credential_bar, CRITICAL),
            ("Remediation Urgency", urgency_bar, SUCCESS),
        ]

        for label, value, color in rows:
            layout.addWidget(
                self._risk_bar_row(label, value, color)
            )

        summary = QLabel(
            "This graph separates the finding into SOC risk dimensions so the analyst can quickly see why it matters."
        )
        summary.setWordWrap(True)
        summary.setObjectName("mutedText")
        layout.addWidget(summary)

        return card

    def _build_exposure_summary_card(self):
        card = self.make_card(border=self._rgba(HIGH, 0.30))

        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        title = QLabel("EXPOSURE GRAPH")
        title.setObjectName("orangeMiniTitle")
        layout.addWidget(title)

        finding_title = (self.finding.get("title") or "").lower()
        asset = self.finding.get("asset", "N/A")
        tool = self.finding.get("tool", "N/A")

        if "telnet" in finding_title or "23/tcp" in finding_title:
            exposure_rows = [
                ("Plaintext Protocol", 95, CRITICAL),
                ("Remote Access Exposure", 90, HIGH),
                ("Credential Interception", 90, CRITICAL),
                ("Service Hardening Need", 80, MEDIUM),
            ]
            analyst_note = (
                "Telnet exposure is high-risk because authentication and session data may be transmitted in plaintext."
            )

        elif "ftp" in finding_title or "21/tcp" in finding_title:
            exposure_rows = [
                ("Plaintext Protocol", 85, HIGH),
                ("Remote File Access", 80, HIGH),
                ("Credential Exposure", 75, HIGH),
                ("Misconfiguration Risk", 65, MEDIUM),
            ]
            analyst_note = (
                "FTP exposure should be reviewed because plain FTP can expose credentials and file transfer activity."
            )

        elif "mysql" in finding_title or "3306" in finding_title:
            exposure_rows = [
                ("Database Exposure", 90, HIGH),
                ("Credential Attack Surface", 80, HIGH),
                ("Data Impact", 85, CRITICAL),
                ("Network Restriction Need", 75, MEDIUM),
            ]
            analyst_note = (
                "Database services should not be exposed unnecessarily. Restrict access to trusted hosts only."
            )

        else:
            exposure_rows = [
                ("Service Exposure", 70, MEDIUM),
                ("Attack Surface Impact", 60, MEDIUM),
                ("Exploit Likelihood", 45, HIGH),
                ("Validation Priority", 55, INFO),
            ]
            analyst_note = (
                "Review the exposed service and validate whether it is required for business operations."
            )

        meta = QLabel(f"Asset: {asset}  •  Source tool: {tool}")
        meta.setWordWrap(True)
        meta.setObjectName("mutedText")
        layout.addWidget(meta)

        for label, value, color in exposure_rows:
            layout.addWidget(
                self._risk_bar_row(label, value, color)
            )

        note = QLabel(analyst_note)
        note.setWordWrap(True)
        note.setStyleSheet(
            f"""
            color: {TEXT_MAIN};
            background: rgba(249, 115, 22, 25);
            border: 1px solid rgba(249, 115, 22, 80);
            border-radius: 8px;
            padding: 9px;
            font-size: {self.fs - 2}px;
            """
        )

        layout.addWidget(note)

        return card

    def _risk_bar_row(self, label, value, color):
        row_frame = QFrame()
        row_frame.setObjectName("riskBarRow")

        row = QVBoxLayout(row_frame)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(8)

        label_text = QLabel(label)
        label_text.setStyleSheet(
            f"""
            color: {TEXT_MAIN};
            font-size: {self.fs - 2}px;
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )

        value_text = QLabel(f"{value}/100")
        value_text.setAlignment(Qt.AlignmentFlag.AlignRight)
        value_text.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs - 2}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )

        top.addWidget(label_text, 1)
        top.addWidget(value_text)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(value)
        bar.setTextVisible(False)
        bar.setFixedHeight(9)

        bar.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: {BUTTON_SOFT};
                border: 1px solid rgba(148, 163, 184, 35);
                border-radius: 4px;
            }}

            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
            """
        )

        row.addLayout(top)
        row.addWidget(bar)

        return row_frame

    # ─────────────────────────────────────────────
    # CWE explanation / remediation text
    # ─────────────────────────────────────────────

    def _build_cwe_explanation_text(self):
        result = self.enrich_result or {}
        nvd = result.get("nvd_best") or {}
        cwe_data = result.get("cwe_data") or {}

        cwe_id = (
            cwe_data.get("cwe_id")
            or self.finding.get("cwe_id")
            or "Not assigned"
        )
        cwe_name = cwe_data.get("name") or "No CWE weakness name returned"
        cwe_risk = cwe_data.get("risk") or "No CWE risk basis returned"

        score = (
            nvd.get("cvss_score")
            or self.finding.get("cvss_score")
            or "N/A"
        )
        vector = nvd.get("cvss_vector") or "N/A"
        title = self.finding.get("title", "")
        service = self._extract_service_name()

        explanation = (
            f"CWE ID: {cwe_id}\n"
            f"Weakness Name: {cwe_name}\n"
            f"Risk Basis: {cwe_risk}\n"
            f"Exposure CVSS: {score}\n"
            f"Vector: {vector}\n\n"
        )

        if cwe_id and cwe_id != "Not assigned":
            explanation += (
                "Security meaning:\n"
                "This tab explains the underlying weakness category behind the finding. "
                "Unlike a CVE, which normally refers to a specific public vulnerability in "
                "a product or version, a CWE describes the general weakness type or insecure "
                "condition that creates risk. This is useful when the finding is caused by an "
                "open service, weak protocol, missing hardening control, exposed path, or other "
                "configuration issue that may not have a direct CVE.\n\n"
            )
        else:
            explanation += (
                "Security meaning:\n"
                "No direct CWE was assigned to this finding. Treat this as a general exposure "
                "or configuration issue and validate the evidence manually.\n\n"
            )

        if service:
            explanation += (
                f"Finding context:\n"
                f"The finding title is '{title}'. The affected service appears to involve "
                f"{service}. For services such as Telnet, FTP, VNC, exposed databases, or other "
                f"remote access services, the main concern is often insecure exposure, weak "
                f"authentication, plaintext communication, or unnecessary attack surface.\n\n"
            )
        else:
            explanation += (
                f"Finding context:\n"
                f"The finding title is '{title}'. Review the description and evidence to confirm "
                f"which weakness category applies.\n\n"
            )

        explanation += (
            "Recommended analyst action:\n"
            "Validate the finding manually, confirm whether the exposed service or weakness "
            "is required, check whether a secure alternative exists, apply hardening or "
            "patching where appropriate, and document whether the issue is confirmed, accepted "
            "risk, or a false positive."
        )

        return explanation

    # Backward-compatible alias in case other code still calls the old name.
    def _build_cve_explanation_text(self):
        return self._build_cwe_explanation_text()

    def _generate_default_remediation(self):
        title = (self.finding.get("title") or "").lower()

        if "telnet" in title or "23/tcp" in title:
            return (
                "Disable Telnet immediately. Telnet transmits credentials and session "
                "data in cleartext. Replace Telnet with SSH, restrict management access "
                "to trusted administrator networks, and verify that port 23 is closed "
                "after remediation."
            )

        if "ftp" in title or "21/tcp" in title:
            return (
                "Disable plain FTP where possible. Replace it with SFTP or FTPS. "
                "If FTP is required temporarily, restrict access by firewall rules, "
                "disable anonymous login, enforce strong credentials, and monitor logs."
            )

        if "bindshell" in title or "1524" in title:
            return (
                "Investigate this service immediately because bind shells are commonly "
                "associated with compromise or intentionally vulnerable services. "
                "Terminate the service, isolate the host if needed, review process "
                "ownership, and perform forensic validation."
            )

        if "mysql" in title or "3306" in title:
            return (
                "Restrict MySQL exposure to trusted hosts only. Disable public access, "
                "enforce strong authentication, remove default accounts, and apply "
                "database security hardening."
            )

        if "postgres" in title or "5432" in title:
            return (
                "Restrict PostgreSQL access to trusted hosts only. Review pg_hba.conf, "
                "enforce strong authentication, patch the database service, and avoid "
                "public exposure."
            )

        if "vnc" in title or "5900" in title:
            return (
                "Restrict or disable VNC. If remote desktop access is required, tunnel it "
                "through VPN or SSH, enforce strong authentication, and disable public "
                "network exposure."
            )

        return (
            self.finding.get("recommendation")
            or "Review the affected service, validate the finding manually, apply vendor "
               "patches or secure configuration changes, restrict unnecessary exposure, "
               "and re-scan to confirm remediation."
        )

    def _extract_cve_from_title(self):
        title = self.finding.get("title", "")
        match = CVE_PATTERN.search(title)
        return match.group(0).upper() if match else ""

    def _extract_service_name(self):
        title = (self.finding.get("title") or "").lower()

        services = [
            "telnet",
            "ftp",
            "ssh",
            "smtp",
            "mysql",
            "postgresql",
            "vnc",
            "netbios",
            "smb",
            "http",
            "https",
        ]

        for service in services:
            if service in title:
                if service in ("ftp", "ssh", "smtp", "smb", "http", "https"):
                    return service.upper()
                return service.capitalize()

        return ""

    # ─────────────────────────────────────────────
    # Reusable UI
    # ─────────────────────────────────────────────

    def make_card(self, border=None):
        if border is None:
            border = BORDER

        frame = QFrame()
        frame.setObjectName("siemCard")
        frame.setStyleSheet(
            f"""
            QFrame#siemCard {{
                background: {CARD_BG};
                border: 1px solid {border};
                border-radius: 12px;
            }}
            """
        )
        return frame

    def make_section_header(self, icon, title, subtitle=None):
        frame = QFrame()
        frame.setObjectName("sectionHeaderWrap")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(3)

        row = QHBoxLayout()
        row.setSpacing(8)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(
            f"""
            color: {ACCENT_RED};
            background: transparent;
            border: none;
            font-size: {self.fs + 1}px;
            font-weight: 900;
            """
        )

        title_lbl = QLabel(title)
        title_lbl.setObjectName("sectionHeader")

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setObjectName("sectionLine")

        row.addWidget(icon_lbl)
        row.addWidget(title_lbl)
        row.addWidget(line, 1)

        layout.addLayout(row)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("sectionSubtitle")
            layout.addWidget(sub)

        return frame

    def kv_row(self, key, value, val_color=None):
        if val_color is None:
            val_color = TEXT_MAIN

        row = QHBoxLayout()
        row.setSpacing(8)

        key_lbl = QLabel(f"{key}:")
        key_lbl.setFixedWidth(140)
        key_lbl.setObjectName("kvKey")

        value_lbl = self.sel(QLabel(str(value)))
        value_lbl.setWordWrap(True)
        value_lbl.setStyleSheet(
            f"""
            color: {val_color};
            font-size: {self.fs - 1}px;
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )

        row.addWidget(key_lbl)
        row.addWidget(value_lbl, 1)

        return row

    def badge(self, text, color, fg="white"):
        lbl = self.sel(QLabel(f"  {text}  "))
        lbl.setStyleSheet(
            f"""
            background: {self._rgba(color, 0.22)};
            color: {fg};
            border: 1px solid {self._rgba(color, 0.70)};
            border-radius: 6px;
            padding: 4px 10px;
            font-size: {self.fs - 2}px;
            font-weight: 800;
            """
        )
        return lbl

    def _build_bottom_actions(self):
        bar = QFrame()
        bar.setObjectName("bottomBar")

        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 10, 0, 0)
        row.setSpacing(10)

        save_btn = QPushButton("◎  Save Notes")
        save_btn.setObjectName("saveBtn")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self.save_notes)

        export_btn = QPushButton("▣  Export as PDF")
        export_btn.setObjectName("pdfBtn")
        export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_btn.clicked.connect(self.export_finding_pdf)

        row.addWidget(save_btn)
        row.addWidget(export_btn)
        row.addStretch()

        return bar

    # ─────────────────────────────────────────────
    # Enrichment rendering
    # ─────────────────────────────────────────────

    def start_enrichment(self):
        self.enrich_worker = EnrichWorker(self.finding)
        self.enrich_worker.done.connect(self.on_enriched)
        self.enrich_worker.error.connect(self.on_enrich_error)
        self.enrich_worker.start()

    def on_enriched(self, result):
        self.enrich_result = result

        self.render_intel(result)
        self.render_mitre(result)
        self.render_attack_path(result)
        self.render_verify_steps(result)

        if self.current_detail_tab == "cwe":
            self.show_detail_tab("cwe")

    def render_intel(self, result):
        self._stop_loading_timer(self.intel_loading)

        nvd = result.get("nvd_best") or {}
        cwe_data = result.get("cwe_data")
        tags = result.get("attack_surface", [])
        level = result.get("exploit_level", "")
        reason = result.get("exploit_reason", "")

        cve_id = nvd.get("cve_id", "")
        has_cve = bool(cve_id and "No CVE" not in str(cve_id))

        self._clear_layout(self.cve_layout)
        self._clear_layout(self.cwe_layout)
        self._clear_layout(self.exploit_layout)
        self._clear_layout(self.surface_layout)

        cve_header = QLabel("CVE IDENTIFIER")
        cve_header.setObjectName("blueMiniTitle")
        self.cve_layout.addWidget(cve_header)

        header_cvss = None

        if has_cve:
            score = nvd.get("cvss_score", "N/A")
            severity = nvd.get("cvss_severity", "")
            vector = nvd.get("cvss_vector", "")
            nvd_url = nvd.get("nvd_url", "")

            header_cvss = score

            sev_color = {
                "CRITICAL": CRITICAL,
                "HIGH": HIGH,
                "MEDIUM": MEDIUM,
                "LOW": LOW,
            }.get(str(severity).upper(), INFO)

            id_lbl = self.sel(QLabel(cve_id))
            id_lbl.setStyleSheet(
                f"""
                color: {INFO};
                font-size: {self.fs + 2}px;
                font-weight: 900;
                background: transparent;
                border: none;
                """
            )
            self.cve_layout.addWidget(id_lbl)

            self.cve_layout.addLayout(
                self.kv_row(
                    "CVSS",
                    f"{score}  {severity or ''}".strip(),
                    sev_color
                )
            )

            if vector:
                vec_lbl = self.sel(QLabel(f"Vector: {vector}"))
                vec_lbl.setWordWrap(True)
                vec_lbl.setObjectName("mutedText")
                self.cve_layout.addWidget(vec_lbl)

            explanation = self.sel(QLabel(self._short_cve_explanation(nvd)))
            explanation.setWordWrap(True)
            explanation.setObjectName("mutedText")
            self.cve_layout.addWidget(explanation)

            if nvd_url:
                btn = QPushButton("🔗  View on NVD")
                btn.setObjectName("linkButton")
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.clicked.connect(
                    lambda _, u=nvd_url: QDesktopServices.openUrl(QUrl(u))
                )
                self.cve_layout.addWidget(btn)

        else:
            no_cve = self.sel(
                QLabel(
                    "No direct CVE assigned — this is a configuration "
                    "or protocol exposure."
                )
            )
            no_cve.setWordWrap(True)
            no_cve.setObjectName("mutedText")
            self.cve_layout.addWidget(no_cve)

            score = nvd.get("cvss_score", "")

            if score:
                header_cvss = score
                self.cve_layout.addLayout(
                    self.kv_row("Exposure CVSS", str(score), HIGH)
                )

            vector = nvd.get("cvss_vector", "")

            if vector:
                vec_lbl = self.sel(QLabel(f"Vector: {vector}"))
                vec_lbl.setWordWrap(True)
                vec_lbl.setObjectName("mutedText")
                self.cve_layout.addWidget(vec_lbl)

            explanation = self.sel(QLabel(self._build_cwe_explanation_text()))
            explanation.setWordWrap(True)
            explanation.setObjectName("mutedText")
            self.cve_layout.addWidget(explanation)

        self.cve_layout.addStretch()

        cwe_header = QLabel("CWE WEAKNESS CLASSIFICATION")
        cwe_header.setObjectName("orangeMiniTitle")
        self.cwe_layout.addWidget(cwe_header)

        cwe_id_text = ""

        if cwe_data:
            cwe_id_text = cwe_data.get("cwe_id", "")

            self.cwe_layout.addLayout(
                self.kv_row("CWE ID", cwe_data.get("cwe_id", "N/A"), HIGH)
            )
            self.cwe_layout.addLayout(
                self.kv_row("Weakness Name", cwe_data.get("name", "N/A"))
            )

            risk_lbl = self.sel(
                QLabel(f"Risk Basis: {cwe_data.get('risk', '')}")
            )
            risk_lbl.setWordWrap(True)
            risk_lbl.setObjectName("mutedText")
            self.cwe_layout.addWidget(risk_lbl)

            cwe_url = cwe_data.get("url", "")

            if cwe_url:
                cwe_btn = QPushButton("🔗  View on MITRE CWE")
                cwe_btn.setObjectName("linkButton")
                cwe_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                cwe_btn.clicked.connect(
                    lambda _, u=cwe_url: QDesktopServices.openUrl(QUrl(u))
                )
                self.cwe_layout.addWidget(cwe_btn)

        else:
            no_cwe = self.sel(QLabel("No CWE classification available."))
            no_cwe.setObjectName("mutedText")
            self.cwe_layout.addWidget(no_cwe)

        self.cwe_layout.addStretch()

        exp_header = QLabel("EXPLOITABILITY ASSESSMENT")
        exp_header.setObjectName("greenMiniTitle")
        self.exploit_layout.addWidget(exp_header)

        color_map = {
            "Easy": SUCCESS,
            "Moderate": HIGH,
            "Difficult": MEDIUM,
            "Unknown": TEXT_MUTED,
        }

        exp_color = color_map.get(level or "Unknown", TEXT_MUTED)

        exp_row = QHBoxLayout()

        if level:
            exp_row.addWidget(
                self.badge(f"⚡ {level}", exp_color)
            )

        exp_score = nvd.get("exploitability", "")

        if exp_score:
            score_lbl = self.sel(QLabel(f"NVD Score: {exp_score}"))
            score_lbl.setObjectName("mutedText")
            exp_row.addWidget(score_lbl)

        exp_row.addStretch()
        self.exploit_layout.addLayout(exp_row)

        if reason:
            reason_lbl = self.sel(QLabel(f"Basis: {reason}"))
            reason_lbl.setWordWrap(True)
            reason_lbl.setObjectName("mutedText")
            self.exploit_layout.addWidget(reason_lbl)

        if not level and not exp_score:
            no_exp = self.sel(
                QLabel(
                    "Exploitability not determined — manual assessment required."
                )
            )
            no_exp.setObjectName("mutedText")
            self.exploit_layout.addWidget(no_exp)

        self.exploit_layout.addStretch()

        surf_header = QLabel("ATTACK SURFACE TAGS")
        surf_header.setObjectName("blueMiniTitle")
        self.surface_layout.addWidget(surf_header)

        if tags:
            # Display tags vertically instead of one long horizontal row.
            # This prevents the finding detail screen from becoming too wide
            # when many attack-surface tags are returned.
            tag_list = QVBoxLayout()
            tag_list.setSpacing(7)
            tag_list.setContentsMargins(0, 0, 0, 0)

            for tag in tags:
                lbl = self.sel(QLabel(f"•  {tag}"))
                lbl.setWordWrap(True)
                lbl.setMinimumWidth(0)
                lbl.setSizePolicy(
                    QSizePolicy.Policy.Expanding,
                    QSizePolicy.Policy.Fixed
                )
                lbl.setStyleSheet(
                    f"""
                    background: {TAG_BG};
                    color: {TAG_TEXT};
                    border: 1px solid {TAG_BORDER};
                    border-radius: 6px;
                    padding: 6px 11px;
                    font-size: {self.fs - 2}px;
                    font-weight: 800;
                    """
                )
                tag_list.addWidget(lbl)

            self.surface_layout.addLayout(tag_list)

        else:
            no_tags = self.sel(QLabel("No attack surface tags detected."))
            no_tags.setObjectName("mutedText")
            self.surface_layout.addWidget(no_tags)

        self.surface_layout.addStretch()

        if header_cvss is not None:
            band = self._cvss_band(header_cvss)
            self.chip_cvss._value_label.setText(
                f"{header_cvss}  {band}"
            )

        if cwe_id_text:
            self.chip_cwe._value_label.setText(cwe_id_text)

        if self.current_detail_tab == "cwe":
            self.show_detail_tab("cwe")

    def _short_cve_explanation(self, nvd):
        cve_id = nvd.get("cve_id", "This CVE")
        score = nvd.get("cvss_score", "N/A")
        severity = nvd.get("cvss_severity", "Unknown")

        return (
            f"{cve_id} is linked to this finding through scanner enrichment. "
            f"The current CVSS value is {score} and the severity is {severity}. "
            f"Use the CWE Explanation tab for the full analyst explanation."
        )

    def render_mitre(self, result):
        self._stop_loading_timer(self.mitre_loading)
        self._clear_layout(self.mitre_layout)

        mitre = result.get("mitre")

        if not mitre:
            lbl = self.sel(QLabel("No MITRE ATT&CK mapping found."))
            lbl.setObjectName("mutedText")
            self.mitre_layout.addWidget(lbl)
            self.chip_mitre._value_label.setText("Not found")
            return

        tactic = mitre.get("tactic", "")
        tactic_id = mitre.get("tactic_id", "")
        tech = mitre.get("technique", "")
        tech_id = mitre.get("tech_id", "")
        sub = mitre.get("subtechnique") or "N/A"
        source = mitre.get("source", "MITRE ATT&CK GitHub")

        self.chip_mitre._value_label.setText(tech_id or "N/A")

        rows = [
            ("Tactic", f"{tactic} ({tactic_id})", HIGH),
            ("Technique", f"{tech} ({tech_id})", TEXT_MAIN),
            ("Sub-technique", sub, TEXT_MUTED),
            ("Source", source, TEXT_MUTED),
        ]

        for label, value, color in rows:
            self.mitre_layout.addLayout(
                self.kv_row(label, value, color)
            )

        url = mitre.get("url", "")

        if url:
            btn = QPushButton(f"🔗  Open MITRE ATT&CK — {tech_id}")
            btn.setObjectName("linkButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda _, u=url: QDesktopServices.openUrl(QUrl(u))
            )
            self.mitre_layout.addWidget(btn)

    # ─────────────────────────────────────────────
    # Attack path / verify rendering
    # ─────────────────────────────────────────────

    def _parse_steps(self, raw_text):
        if not raw_text:
            return []

        parts = [
            p.strip()
            for p in raw_text.split("•")
            if p.strip()
        ]

        if len(parts) <= 1:
            parts = [
                p.strip()
                for p in raw_text.split("\n")
                if p.strip()
            ]

        steps = []

        cmd_pattern = re.compile(
            r"(?:^|:\s*)"
            r"((?:nmap|hydra|nc|netcat|telnet|ssh|curl|wget|tcpdump|"
            r"wireshark|msfconsole|sqlmap|gobuster|nikto|searchsploit|"
            r"john|hashcat|smbclient|enum4linux)[^\n]*)",
            re.IGNORECASE,
        )

        for part in parts:
            part = part.strip()
            m = cmd_pattern.search(part)

            if m:
                cmd_text = m.group(1).strip().rstrip(".")
                prose = part[:m.start()].strip().rstrip(":").strip()
                steps.append(
                    {
                        "prose": prose or part,
                        "cmd": cmd_text,
                    }
                )
            else:
                steps.append(
                    {
                        "prose": part,
                        "cmd": None,
                    }
                )

        return steps

    def _render_step_cards(self, target_layout, steps, accent):
        for i, step in enumerate(steps, 1):
            row = QHBoxLayout()
            row.setSpacing(10)

            num = QLabel(str(i))
            num.setFixedSize(24, 24)
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num.setStyleSheet(
                f"""
                background: {self._rgba(accent, 0.16)};
                color: {accent};
                border: 1px solid {self._rgba(accent, 0.65)};
                border-radius: 12px;
                font-weight: 900;
                font-size: {self.fs - 3}px;
                """
            )
            row.addWidget(num, 0, Qt.AlignmentFlag.AlignTop)

            col = QVBoxLayout()
            col.setSpacing(5)

            prose_lbl = self.sel(QLabel(step["prose"]))
            prose_lbl.setWordWrap(True)
            prose_lbl.setObjectName("bodyText")
            col.addWidget(prose_lbl)

            if step["cmd"]:
                cmd_row = QHBoxLayout()
                cmd_row.setSpacing(6)

                cmd_lbl = self.sel(QLabel(step["cmd"]))
                cmd_lbl.setWordWrap(True)
                cmd_lbl.setObjectName("commandBox")

                cmd_row.addWidget(cmd_lbl, 1)

                copy_btn = QPushButton("⧉")
                copy_btn.setFixedSize(28, 28)
                copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                copy_btn.setToolTip("Copy command")
                copy_btn.setObjectName("copyBtn")
                copy_btn.clicked.connect(
                    lambda _, c=step["cmd"]: self._copy_to_clipboard(c)
                )

                cmd_row.addWidget(copy_btn)

                col.addLayout(cmd_row)

            row.addLayout(col, 1)

            target_layout.addLayout(row)

    def _copy_to_clipboard(self, text):
        QApplication.clipboard().setText(text)

    def render_attack_path(self, result):
        self._stop_loading_timer(self.ap_lbl)

        attack = result.get("attack_path")

        try:
            self.ap_layout.removeWidget(self.ap_lbl)
            self.ap_lbl.deleteLater()
        except RuntimeError:
            pass

        if attack:
            steps = self._parse_steps(attack)

            if steps:
                self._render_step_cards(
                    self.ap_layout,
                    steps,
                    CRITICAL
                )
            else:
                fallback = self.sel(QLabel(attack))
                fallback.setWordWrap(True)
                fallback.setObjectName("bodyText")
                self.ap_layout.addWidget(fallback)
        else:
            no_data = self.sel(
                QLabel(
                    "Attack path not available. Check AI API key in .env file."
                )
            )
            no_data.setObjectName("mutedText")
            self.ap_layout.addWidget(no_data)

    def render_verify_steps(self, result):
        self._stop_loading_timer(self.verify_lbl)

        verify = result.get("verify_steps")

        try:
            self.verify_layout.removeWidget(self.verify_lbl)
            self.verify_lbl.deleteLater()
        except RuntimeError:
            pass

        if verify:
            steps = self._parse_steps(verify)

            if steps:
                self._render_step_cards(
                    self.verify_layout,
                    steps,
                    HIGH
                )
            else:
                fallback = self.sel(QLabel(verify))
                fallback.setWordWrap(True)
                fallback.setObjectName("bodyText")
                self.verify_layout.addWidget(fallback)
        else:
            no_data = self.sel(QLabel("Verification steps not available."))
            no_data.setObjectName("mutedText")
            self.verify_layout.addWidget(no_data)

    def on_enrich_error(self, error):
        for lbl_name in (
            "intel_loading",
            "mitre_loading",
            "ap_lbl",
            "verify_lbl",
        ):
            lbl = getattr(self, lbl_name, None)
            if lbl is not None:
                self._stop_loading_timer(lbl)

        self.intel_loading.setStyleSheet(
            f"""
            color: {TEXT_MUTED};
            font-size: {self.fs - 1}px;
            background: transparent;
            border: none;
            """
        )

        self.intel_loading.setText(
            f"⚠️  Intelligence unavailable: {error}"
        )

        self.ap_lbl.setText("Attack path unavailable.")
        self.verify_lbl.setText("Verification steps unavailable.")

    # ─────────────────────────────────────────────
    # Notes / export
    # ─────────────────────────────────────────────

    def _update_note_counter(self):
        if not hasattr(self, "notes_input"):
            return

        text = self.notes_input.toPlainText()
        length = len(text)

        if length > 4000:
            self.notes_input.blockSignals(True)
            self.notes_input.setPlainText(text[:4000])

            cursor = self.notes_input.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.notes_input.setTextCursor(cursor)

            self.notes_input.blockSignals(False)
            length = 4000

        if hasattr(self, "notes_counter"):
            self.notes_counter.setText(f"{length} / 4000")

    def save_notes(self):
        notes = self.notes_input.toPlainText().strip()
        finding_id = self.finding.get("id")

        if finding_id:
            try:
                conn = get_connection()
                cursor = conn.cursor()

                try:
                    cursor.execute(
                        "ALTER TABLE findings ADD COLUMN analyst_notes TEXT"
                    )
                    conn.commit()
                except Exception:
                    pass

                cursor.execute(
                    "UPDATE findings SET analyst_notes=? WHERE id=?",
                    (notes, finding_id)
                )
                conn.commit()
                conn.close()

                self.finding["analyst_notes"] = notes

                QMessageBox.information(
                    self,
                    "Notes Saved",
                    "Analyst notes saved successfully."
                )

            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Save Notes Error",
                    f"Could not save notes:\n{e}"
                )

    def export_finding_pdf(self):
        import subprocess

        try:
            from reports.finding_pdf_export import generate_finding_pdf

            finding_id = self.finding.get("id", "unknown")
            scan_id = self.finding.get("scan_id", "unknown")

            self.finding["analyst_notes"] = (
                self.notes_input.toPlainText().strip()
            )

            path = generate_finding_pdf(
                scan_id=scan_id,
                finding=self.finding,
                enrich_cache={
                    finding_id: self.enrich_result
                },
            )

            try:
                subprocess.Popen(["xdg-open", path])
            except Exception:
                pass

            QMessageBox.information(
                self,
                "Export Complete",
                f"Professional finding report exported.\n\nSaved to:\n{path}"
            )

        except Exception as e:
            QMessageBox.warning(
                self,
                "Export Error",
                f"Export failed:\n{e}"
            )

    # ─────────────────────────────────────────────
    # Navigation / cleanup
    # ─────────────────────────────────────────────

    def go_back(self):
        if self.on_close:
            self.on_close()

    def cleanup(self):
        for lbl_name in (
            "intel_loading",
            "mitre_loading",
            "ap_lbl",
            "verify_lbl",
        ):
            lbl = getattr(self, lbl_name, None)

            if lbl is not None:
                self._stop_loading_timer(lbl)

        worker = getattr(self, "enrich_worker", None)

        if worker is None:
            return

        for sig in ("done", "error"):
            try:
                getattr(worker, sig).disconnect()
            except (TypeError, RuntimeError):
                pass

        try:
            if worker.isRunning():
                _ACTIVE_WORKERS.append(worker)
                worker.finished.connect(
                    lambda: _ACTIVE_WORKERS.remove(worker)
                    if worker in _ACTIVE_WORKERS
                    else None
                )
        except RuntimeError:
            pass

        self.enrich_worker = None

    # ─────────────────────────────────────────────
    # Animation
    # ─────────────────────────────────────────────

    def _animate_fade_in(self, widget):
        from PyQt6.QtWidgets import QGraphicsOpacityEffect

        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)

        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(320)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()

        self._fade_anim = anim

    @staticmethod
    def _clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                FindingDetail._clear_layout(item.layout())

    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────

    def get_stylesheet(self):
        fs = self.fs

        return f"""
            QWidget {{
                background-color: {BG_MAIN};
                color: {TEXT_MAIN};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}

            #mainScroll {{
                border: none;
                background: {BG_MAIN};
            }}

            #contentRoot {{
                background-color: {BG_MAIN};
            }}

            #topBarWrap {{
                background: transparent;
                border: none;
            }}

            #backBtn {{
                background: {BUTTON_SOFT};
                color: {TEXT_MAIN};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 8px 14px;
                font-size: {fs - 1}px;
                font-weight: 700;
            }}

            #backBtn:hover {{
                border-color: {ACCENT_BLUE};
                background: {HOVER_BG};
            }}

            #pageTitle {{
                color: {TEXT_MAIN};
                font-size: {fs + 8}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #pageMeta {{
                color: {TEXT_MUTED};
                font-size: {fs - 3}px;
                background: transparent;
                border: none;
            }}

            #sectionHeaderWrap {{
                background: transparent;
                border: none;
            }}

            #sectionHeader {{
                color: {TEXT_MAIN};
                font-size: {fs}px;
                font-weight: 900;
                letter-spacing: 0.8px;
                background: transparent;
                border: none;
            }}

            #sectionSubtitle {{
                color: {TEXT_MUTED};
                font-size: {fs - 4}px;
                font-weight: 700;
                letter-spacing: 0.8px;
                background: transparent;
                border: none;
            }}

            #sectionLine {{
                background: {BORDER};
                border: none;
                max-height: 1px;
            }}

            #mutedText {{
                color: {TEXT_MUTED};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}

            #bodyText {{
                color: {TEXT_MAIN};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
                line-height: 1.5;
            }}

            #kvKey {{
                color: {TEXT_MUTED};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}

            #blueMiniTitle {{
                color: {INFO};
                font-size: {fs - 4}px;
                font-weight: 900;
                letter-spacing: 1.5px;
                background: transparent;
                border: none;
            }}

            #orangeMiniTitle {{
                color: {HIGH};
                font-size: {fs - 4}px;
                font-weight: 900;
                letter-spacing: 1.5px;
                background: transparent;
                border: none;
            }}

            #greenMiniTitle {{
                color: {SUCCESS};
                font-size: {fs - 4}px;
                font-weight: 900;
                letter-spacing: 1.5px;
                background: transparent;
                border: none;
            }}

            #linkButton {{
                background: transparent;
                color: {INFO};
                border: 1px solid rgba(96, 165, 250, 90);
                border-radius: 7px;
                padding: 7px 12px;
                font-size: {fs - 2}px;
                font-weight: 700;
            }}

            #linkButton:hover {{
                background: rgba(96, 165, 250, 30);
                border-color: {INFO};
            }}

            #detailContent {{
                background: transparent;
                border: none;
            }}

            #detailPanel {{
                background: {PANEL_BG_SOFT};
                border: 1px solid rgba(148, 163, 184, 35);
                border-radius: 8px;
            }}

            #miniPanelTitle {{
                color: {TEXT_MUTED};
                font-size: {fs - 4}px;
                font-weight: 900;
                letter-spacing: 1.2px;
                background: transparent;
                border: none;
            }}

            #commandBox {{
                background: {COMMAND_BG};
                color: {COMMAND_TEXT};
                font-family: "Consolas", "Courier New", monospace;
                font-size: {fs - 2}px;
                border: 1px solid {BORDER};
                border-radius: 7px;
                padding: 9px 12px;
            }}

            #copyBtn {{
                background: {BUTTON_SOFT};
                color: {TEXT_MUTED};
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}

            #copyBtn:hover {{
                color: {TEXT_MAIN};
                border-color: {ACCENT_BLUE};
            }}

            #notesInput {{
                background: {NOTES_BG};
                color: {TEXT_MAIN};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 10px;
                font-size: {fs - 1}px;
            }}

            #notesInput:focus {{
                border-color: {ACCENT_BLUE};
            }}

            #counterText {{
                color: {TEXT_SOFT};
                font-size: {fs - 4}px;
                background: transparent;
                border: none;
            }}

            #riskBarRow {{
                background: transparent;
                border: none;
            }}

            #bottomBar {{
                background: transparent;
                border: none;
            }}

            #saveBtn {{
                background: {SUCCESS};
                color: white;
                border: none;
                border-radius: 9px;
                padding: 10px 22px;
                font-size: {fs}px;
                font-weight: 900;
                min-width: 135px;
            }}

            #saveBtn:hover {{
                background: {SUCCESS_HOVER};
            }}

            #saveBtn:pressed {{
                background: {SUCCESS_PRESS};
            }}

            #pdfBtn {{
                background: {ACCENT_RED};
                color: white;
                border: none;
                border-radius: 9px;
                padding: 10px 22px;
                font-size: {fs}px;
                font-weight: 900;
                min-width: 145px;
            }}

            #pdfBtn:hover {{
                background: rgba(220, 38, 38, 240);
            }}
        """
