import re
import matplotlib
matplotlib.use("Agg")

from matplotlib.backends.backend_qtagg import (
    FigureCanvasQTAgg as FigureCanvas
)
from matplotlib.figure import Figure
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.patches as mpatches
import numpy as np

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QScrollArea,
    QGridLayout, QSizePolicy, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer
from PyQt6.QtGui import QColor

from backend.db import get_connection
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# AutoRed Theme System
# Supports Dark Theme + Light Theme from preferences.py
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    """
    Convert #RRGGBB to rgba(r,g,b,a).

    alpha can be:
    - 0.0 to 1.0 for Qt/matplotlib-style opacity
    - 0 to 255 for stylesheet alpha
    """
    color = str(hex_color).strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


def _is_light_theme(theme):
    return (
        theme.get("bg", "").upper()
        in ("#F8FAFC", "#FFFFFF", "#F1F5F9", "#EEF2F7", "#E2E8F0")
        or theme.get("text", "").upper() == "#0F172A"
    )


# Globals are kept because many chart builders reference them.
# They are refreshed every time preferences are applied.
BG_MAIN = "#020617"
BG_SOFT = "#07111F"

CARD_BG = "#0F172A"
CARD_BG_HOV = "#111827"

BORDER = "#22304A"
BORDER_SOFT = "#334155"
BORDER_GLOW = "#EF4444"

TEXT_MAIN = "#E5EDF7"
TEXT_MUTED = "#94A3B8"
TEXT_SOFT = "#64748B"

ACCENT_RED = "#EF4444"
ACCENT_HOVER = "#DC2626"
ACCENT_DARK = "#991B1B"

ACCENT_BLUE = ACCENT_RED
ACCENT_CYAN = ACCENT_HOVER
ACCENT_PURPLE = "#8B5CF6"
ACCENT = ACCENT_RED

SUCCESS = "#22C55E"
SUCCESS_HOVER = "#16A34A"
WARNING = "#F97316"
MEDIUM_YELLOW = "#FACC15"
INFO_BLUE = "#60A5FA"

HOVER_BG = "rgba(239, 68, 68, 25)"
SELECTION_BG = "rgba(239, 68, 68, 35)"
SELECTION_TEXT = "#FEE2E2"
BUTTON_SOFT = "rgba(15, 23, 42, 205)"
CARD_HOVER = "rgba(239, 68, 68, 130)"

SEVERITY_COLORS = {}
SEVERITY_BADGE_BG = {}
SEVERITY_BADGE_BORDER = {}
SEVERITY_BADGE_TEXT = {}

SEVERITY_ORDER = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info",
]

SEV_TO_CVSS = {
    "Critical": 9.8,
    "High": 7.5,
    "Medium": 5.3,
    "Low": 2.5,
    "Info": 0.0,
}

ASSET_PALETTE = []
TOOL_COLORS = {}

TOOL_EMOJI = {
    "nmap": "🔍",
    "subfinder": "🌐",
    "httpx": "📡",
    "whatweb": "🕵️",
    "ffuf": "💨",
    "nikto": "🎯",
    "theharvester": "🌾",
    "dnsrecon": "🔎",
    "gobuster": "👻",
    "dirsearch": "📂",
    "wpscan": "🔒",
    "nuclei": "⚡",
}

DONE_GREEN = SUCCESS
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

SRC_COLORS = {}


def apply_theme_palette(theme):
    global BG_MAIN, BG_SOFT, CARD_BG, CARD_BG_HOV
    global BORDER, BORDER_SOFT, BORDER_GLOW
    global TEXT_MAIN, TEXT_MUTED, TEXT_SOFT
    global ACCENT_RED, ACCENT_HOVER, ACCENT_DARK
    global ACCENT_BLUE, ACCENT_CYAN, ACCENT_PURPLE, ACCENT
    global SUCCESS, SUCCESS_HOVER, WARNING, MEDIUM_YELLOW, INFO_BLUE
    global HOVER_BG, SELECTION_BG, SELECTION_TEXT, BUTTON_SOFT, CARD_HOVER
    global SEVERITY_COLORS, SEVERITY_BADGE_BG
    global SEVERITY_BADGE_BORDER, SEVERITY_BADGE_TEXT
    global ASSET_PALETTE, TOOL_COLORS, DONE_GREEN, SRC_COLORS

    light = _is_light_theme(theme)

    BG_MAIN = theme.get("bg", "#F8FAFC" if light else "#020617")
    BG_SOFT = theme.get(
        "bg_deep",
        "#EEF2F7" if light else "#07111F"
    )

    CARD_BG = theme.get("card_bg", "#FFFFFF" if light else "#0F172A")
    CARD_BG_HOV = theme.get(
        "card_bg_2",
        "#F1F5F9" if light else "#111827"
    )

    BORDER = theme.get("border", "#CBD5E1" if light else "#22304A")
    BORDER_SOFT = theme.get(
        "border_soft",
        "#94A3B8" if light else "#334155"
    )
    BORDER_GLOW = theme.get("accent", "#EF4444")

    TEXT_MAIN = theme.get("text", "#0F172A" if light else "#E5EDF7")
    TEXT_MUTED = theme.get(
        "text_muted",
        "#475569" if light else "#94A3B8"
    )
    TEXT_SOFT = theme.get("text_soft", "#64748B")

    ACCENT_RED = theme.get("accent", "#EF4444")
    ACCENT_HOVER = theme.get("accent_hover", "#DC2626")
    ACCENT_DARK = theme.get("accent_dark", "#991B1B")

    ACCENT_BLUE = ACCENT_RED
    ACCENT_CYAN = ACCENT_HOVER
    ACCENT_PURPLE = theme.get("purple", "#7C3AED" if light else "#8B5CF6")
    ACCENT = ACCENT_RED

    SUCCESS = theme.get("success", "#16A34A" if light else "#22C55E")
    SUCCESS_HOVER = theme.get(
        "success_hover",
        "#15803D" if light else "#16A34A"
    )
    WARNING = theme.get("warning", "#EA580C" if light else "#F97316")
    MEDIUM_YELLOW = theme.get(
        "medium",
        "#CA8A04" if light else "#FACC15"
    )
    INFO_BLUE = theme.get("info", "#2563EB" if light else "#60A5FA")

    HOVER_BG = theme.get(
        "hover",
        rgba_from_hex(ACCENT_RED, 18 if light else 25)
    )
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
        "#FFFFFF" if light else "rgba(15, 23, 42, 205)"
    )
    CARD_HOVER = theme.get(
        "card_hover",
        rgba_from_hex(ACCENT_RED, 55 if light else 130)
    )

    SEVERITY_COLORS = {
        "Critical": ACCENT_RED,
        "High": WARNING,
        "Medium": MEDIUM_YELLOW,
        "Low": SUCCESS,
        "Info": INFO_BLUE,
    }

    SEVERITY_BADGE_BG = {
        "Critical": rgba_from_hex(ACCENT_RED, 0.18),
        "High": rgba_from_hex(WARNING, 0.18),
        "Medium": rgba_from_hex(MEDIUM_YELLOW, 0.16),
        "Low": rgba_from_hex(SUCCESS, 0.16),
        "Info": rgba_from_hex(INFO_BLUE, 0.16),
    }

    SEVERITY_BADGE_BORDER = {
        "Critical": rgba_from_hex(ACCENT_RED, 0.35),
        "High": rgba_from_hex(WARNING, 0.35),
        "Medium": rgba_from_hex(MEDIUM_YELLOW, 0.35),
        "Low": rgba_from_hex(SUCCESS, 0.35),
        "Info": rgba_from_hex(INFO_BLUE, 0.35),
    }

    if light:
        SEVERITY_BADGE_TEXT = {
            "Critical": "#7F1D1D",
            "High": "#7C2D12",
            "Medium": "#713F12",
            "Low": "#14532D",
            "Info": "#1E3A8A",
        }
    else:
        SEVERITY_BADGE_TEXT = {
            "Critical": "#FEE2E2",
            "High": "#FED7AA",
            "Medium": "#FEF3C7",
            "Low": "#BBF7D0",
            "Info": "#BFDBFE",
        }

    ASSET_PALETTE = [
        ACCENT_RED,
        WARNING,
        ACCENT_PURPLE,
        SUCCESS,
        INFO_BLUE,
        MEDIUM_YELLOW,
        ACCENT_HOVER,
        "#A78BFA" if not light else "#6D28D9",
    ]

    TOOL_COLORS = {
        "nmap": ACCENT_RED,
        "subfinder": SUCCESS,
        "httpx": INFO_BLUE,
        "whatweb": WARNING,
        "ffuf": ACCENT_PURPLE,
        "nikto": "#F87171" if not light else "#DC2626",
        "theharvester": "#FB923C" if not light else "#EA580C",
        "dnsrecon": "#34D399" if not light else "#059669",
        "gobuster": INFO_BLUE,
        "dirsearch": MEDIUM_YELLOW,
        "wpscan": "#2DD4BF" if not light else "#0D9488",
        "nuclei": ACCENT_RED,
    }

    DONE_GREEN = SUCCESS

    SRC_COLORS = {
        "NVD": INFO_BLUE,
        "CIRCL": SUCCESS,
        "MITRE": ACCENT_PURPLE,
        "Claude": WARNING,
    }


apply_theme_palette(get_theme(True))

class ChartsView(QWidget):
    def __init__(self, scan_id, on_close=None, prefs=None):
        super().__init__()

        self.scan_id = scan_id
        self.on_close = on_close
        self.findings = []
        self.scan_info = {}
        self.prefs = prefs or load_prefs()

        self._set_theme_colors()
        self.setStyleSheet(self.get_stylesheet())

        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)

        self.load_data()
        self._build()

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)

        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        self.BG = BG_MAIN
        self.CARD = CARD_BG
        self.CARD2 = CARD_BG_HOV
        self.BORDER = BORDER
        self.BORDER_SOFT = BORDER_SOFT
        self.TEXT = TEXT_MAIN
        self.DIM = TEXT_MUTED
        self.SOFT = TEXT_SOFT

        self.ACCENT = ACCENT_RED
        self.ACCENT_HOVER = ACCENT_HOVER
        self.ACCENT_DARK = ACCENT_DARK

        self.SUCCESS = SUCCESS
        self.WARNING = WARNING
        self.MEDIUM = MEDIUM_YELLOW
        self.INFO = INFO_BLUE
        self.PURPLE = ACCENT_PURPLE

        self.HOVER = HOVER_BG
        self.SELECTION_BG = SELECTION_BG
        self.SELECTION_TEXT = SELECTION_TEXT
        self.BUTTON_SOFT = BUTTON_SOFT
        self.CARD_HOVER = CARD_HOVER

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()
        self.setStyleSheet(self.get_stylesheet())

        while self.outer.count():
            child = self.outer.takeAt(0)

            if child.widget():
                child.widget().deleteLater()

        self._build()

    # ─────────────────────────────────────────────
    # Data loading
    # ─────────────────────────────────────────────

    def load_data(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT tool, severity, title, status,
                   asset, evidence, description
            FROM findings
            WHERE scan_id=?
            """,
            (self.scan_id,)
        )

        rows = cursor.fetchall()

        self.findings = [
            {
                "tool": row[0],
                "severity": row[1],
                "title": row[2],
                "status": row[3],
                "asset": row[4] or "",
                "evidence": row[5] or "",
                "description": row[6] or "",
            }
            for row in rows
        ]

        cursor.execute(
            """
            SELECT name, target, profile,
                   status, created_at
            FROM scans
            WHERE id=?
            """,
            (self.scan_id,)
        )

        row = cursor.fetchone()

        if row:
            self.scan_info = {
                "name": row[0],
                "target": row[1],
                "profile": row[2],
                "status": row[3],
                "created_at": row[4],
            }

        cursor.execute(
            "SELECT tool, status FROM tool_runs WHERE scan_id=?",
            (self.scan_id,)
        )

        self.tool_runs = {
            row[0]: row[1]
            for row in cursor.fetchall()
        }

        conn.close()

    # ─────────────────────────────────────────────
    # Derived intelligence summary
    # ─────────────────────────────────────────────

    def get_intel_summary(self):
        cve_findings = []
        cwe_only = []

        for finding in self.findings:
            cve = CVE_PATTERN.search(finding["title"] or "")

            if cve:
                cve_findings.append(
                    (
                        finding,
                        cve.group(0).upper()
                    )
                )

            else:
                cwe_only.append(finding)

        total = len(self.findings) or 1

        avg_cvss = round(
            sum(
                SEV_TO_CVSS.get(finding["severity"], 0)
                for finding in self.findings
            ) / total,
            1
        )

        return {
            "cve_count": len(cve_findings),
            "cwe_only": len(cwe_only),
            "avg_cvss": avg_cvss,
            "cve_findings": cve_findings,
        }

    # ─────────────────────────────────────────────
    # Attack surface
    # ─────────────────────────────────────────────

    def compute_attack_surface(self):
        findings = self.findings

        port_findings = [
            finding for finding in findings
            if finding["tool"] == "nmap"
        ]
        open_ports = len(port_findings)

        subdomains = len(
            [
                finding for finding in findings
                if finding["tool"] in ("subfinder", "dnsrecon")
            ]
        )

        ch_count = sum(
            1 for finding in findings
            if finding["severity"] in ("Critical", "High")
        )

        emails = len(
            [
                finding for finding in findings
                if finding["tool"] == "theharvester"
            ]
        )

        insecure_keywords = [
            "telnet",
            "ftp",
            "rsh",
            "rlogin",
            "cleartext",
            "unencrypted",
            "plaintext",
            "backdoor",
            "default credential",
            "anonymous",
            "no authentication",
        ]

        technologies = []
        insecure_tech = []

        for finding in port_findings:
            title = finding["title"]

            if title and title not in technologies:
                technologies.append(title)

            title_lower = title.lower()

            for keyword in insecure_keywords:
                if keyword in title_lower and title not in insecure_tech:
                    insecure_tech.append(title)

        for finding in findings:
            if finding["tool"] not in (
                "nuclei",
                "nikto",
                "whatweb",
                "httpx",
            ):
                continue

            title = finding["title"]

            if title and title not in technologies:
                technologies.append(title)

            desc_lower = (
                finding["description"] + " " + finding["evidence"]
            ).lower()

            for keyword in insecure_keywords:
                if (
                    keyword in desc_lower
                    or keyword in title.lower()
                ) and title not in insecure_tech:
                    insecure_tech.append(title)

        port_score = min(25, int(open_ports * 1.5))
        sub_score = min(20, int(subdomains * 1.3))
        vuln_score = min(35, ch_count * 4)
        tech_score = min(15, len(insecure_tech) * 5)
        email_score = min(5, emails)

        total_score = min(
            100,
            port_score
            + sub_score
            + vuln_score
            + tech_score
            + email_score
        )

        score_breakdown = [
            (
                "Port Exposure",
                port_score,
                25,
                f"{open_ports} open ports × 1.5",
                WARNING,
            ),
            (
                "Subdomain Footprint",
                sub_score,
                20,
                f"{subdomains} subdomains × 1.3",
                ACCENT_RED,
            ),
            (
                "Vulnerability Density",
                vuln_score,
                35,
                f"{ch_count} Critical/High × 4",
                SEVERITY_COLORS["Critical"],
            ),
            (
                "Insecure Services",
                tech_score,
                15,
                f"{len(insecure_tech)} insecure × 5",
                SEVERITY_COLORS["High"],
            ),
            (
                "Email Exposure",
                email_score,
                5,
                f"{emails} emails harvested",
                SUCCESS,
            ),
        ]

        if total_score >= 70:
            rating = "CRITICAL"
            rating_color = SEVERITY_COLORS["Critical"]

        elif total_score >= 50:
            rating = "HIGH RISK"
            rating_color = SEVERITY_COLORS["High"]

        elif total_score >= 30:
            rating = "MEDIUM RISK"
            rating_color = SEVERITY_COLORS["Medium"]

        else:
            rating = "LOW RISK"
            rating_color = SEVERITY_COLORS["Low"]

        def level(value, thresholds):
            low, medium, high = thresholds

            if value >= high:
                return (
                    "High",
                    SEVERITY_COLORS["High"],
                    value / high,
                )

            if value >= medium:
                return (
                    "Medium",
                    SEVERITY_COLORS["Medium"],
                    value / high,
                )

            if value >= low:
                return (
                    "Low",
                    SEVERITY_COLORS["Low"],
                    value / high,
                )

            return (
                "Minimal",
                self.DIM,
                0.05,
            )

        metrics = [
            (
                "Port Exposure",
                level(open_ports, (3, 8, 15)),
            ),
            (
                "Subdomain Footprint",
                level(subdomains, (3, 8, 15)),
            ),
            (
                "Vulnerability Density",
                level(ch_count, (1, 4, 10)),
            ),
            (
                "Insecure Services",
                level(len(insecure_tech), (1, 2, 4)),
            ),
            (
                "Email Exposure",
                level(emails, (1, 3, 6)),
            ),
        ]

        return {
            "score": total_score,
            "rating": rating,
            "rating_color": rating_color,
            "open_ports": open_ports,
            "subdomains": subdomains,
            "ch_count": ch_count,
            "technologies": technologies,
            "insecure_tech": insecure_tech,
            "emails": emails,
            "metrics": metrics,
            "score_breakdown": score_breakdown,
        }

    # ─────────────────────────────────────────────
    # Main build
    # ─────────────────────────────────────────────

    def _build(self):
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
            background: {self.BG};
            """
        )

        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 16, 24, 24)
        layout.setSpacing(12)

        # ── Back + Title ──────────────────────────────

        top_row = QHBoxLayout()

        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)

        top_row.addWidget(back_btn)
        top_row.addStretch()

        layout.addLayout(top_row)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        title_lbl = QLabel("Security")
        title_lbl.setObjectName("dashTitle")
        title_row.addWidget(title_lbl)

        title_accent = QLabel("Analytics Dashboard")
        title_accent.setObjectName("dashTitleAccent")
        title_row.addWidget(title_accent)

        title_row.addStretch()

        date = str(
            self.scan_info.get("created_at", "")
        )[:16]

        date_pill = QFrame()
        date_pill.setStyleSheet(
            f"""
            background: {self.CARD};
            border: 1px solid {self.BORDER};
            border-radius: 8px;
            """
        )

        date_l = QHBoxLayout(date_pill)
        date_l.setContentsMargins(12, 6, 12, 6)
        date_l.setSpacing(6)

        date_icon = QLabel("📅")
        date_icon.setStyleSheet(
            f"""
            font-size: {self.fs - 2}px;
            background: transparent;
            border: none;
            """
        )
        date_l.addWidget(date_icon)

        date_txt = QLabel(
            f"Last Scan: {date}" if date else "No scans yet"
        )
        date_txt.setStyleSheet(
            f"""
            font-size: {self.fs - 2}px;
            color: {self.DIM};
            background: transparent;
            border: none;
            """
        )
        date_l.addWidget(date_txt)

        title_row.addWidget(date_pill)

        layout.addLayout(title_row)

        target = self.scan_info.get("target", "")
        profile = self.scan_info.get("profile", "")

        sub = QLabel(
            f"Scan #{self.scan_id}  ·  Target: {target}  ·  "
            f"Profile: {profile}  ·  "
            f"{len(self.findings)} findings  ·  {date}"
        )
        sub.setObjectName("dashSub")

        layout.addWidget(sub)
        layout.addSpacing(4)

        layout.addLayout(self.build_stat_cards())

        row2 = QHBoxLayout()
        row2.setSpacing(10)
        row2.addWidget(self.build_donut_card(), 1)
        row2.addWidget(self.build_heatmap_card(), 2)

        layout.addLayout(row2)

        layout.addWidget(
            self._section_header(
                "⚡  THREAT INTELLIGENCE & CVSS ANALYSIS"
            )
        )

        row3 = QHBoxLayout()
        row3.setSpacing(10)
        row3.addWidget(self.build_cvss_distribution_card(), 2)
        row3.addWidget(self.build_intel_sources_card(), 1)

        layout.addLayout(row3)

        layout.addWidget(
            self._section_header(
                "🎯  TOP VULNERABILITIES BY RISK SCORE"
            )
        )
        layout.addWidget(self.build_top_vulns_table())

        layout.addWidget(
            self._section_header(
                "🛠  TOOL ANALYSIS"
            )
        )

        row5 = QHBoxLayout()
        row5.setSpacing(10)
        row5.addWidget(self.build_stacked_bar_card(), 3)
        row5.addWidget(self.build_tool_status_card(), 2)

        layout.addLayout(row5)

        layout.addWidget(
            self._section_header(
                "🛡  ATTACK SURFACE ANALYSIS"
            )
        )

        layout.addLayout(self.build_attack_surface_row())

        scroll.setWidget(content)
        self.outer.addWidget(scroll)

        self._animate_fade_in(content)

    def _animate_fade_in(self, widget):
        from PyQt6.QtWidgets import QGraphicsOpacityEffect

        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)

        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(350)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()

        self._fade_anim = anim

    def _section_header(self, text):
        wrap = QWidget()
        wrap.setStyleSheet(
            """
            background: transparent;
            """
        )

        row = QHBoxLayout(wrap)
        row.setContentsMargins(0, 14, 0, 6)
        row.setSpacing(10)

        bar = QFrame()
        bar.setFixedSize(4, 18)
        bar.setStyleSheet(
            f"""
            background: qlineargradient(
                x1:0, y1:0, x2:0, y2:1,
                stop:0 {ACCENT_RED},
                stop:1 {ACCENT_DARK}
            );
            border-radius: 2px;
            border: none;
            """
        )
        row.addWidget(bar)

        lbl = QLabel(text)
        lbl.setObjectName("sectionHeader")

        row.addWidget(lbl)
        row.addStretch()

        return wrap
    # ─────────────────────────────────────────────
    # KPI Cards
    # ─────────────────────────────────────────────

    def build_stat_cards(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        counts = {}

        for finding in self.findings:
            counts[finding["severity"]] = (
                counts.get(finding["severity"], 0) + 1
            )

        critical = counts.get("Critical", 0)
        high = counts.get("High", 0)
        ports = sum(
            1 for finding in self.findings
            if finding["tool"] == "nmap"
        )

        intel = self.get_intel_summary()

        score = min(
            100,
            critical * 25
            + high * 15
            + counts.get("Medium", 0) * 5
            + counts.get("Low", 0) * 1
        )

        if score >= 75:
            risk_color = SEVERITY_COLORS["Critical"]
            risk_label = "CRITICAL"

        elif score >= 50:
            risk_color = SEVERITY_COLORS["High"]
            risk_label = "HIGH"

        elif score >= 25:
            risk_color = SEVERITY_COLORS["Medium"]
            risk_label = "MEDIUM"

        else:
            risk_color = SEVERITY_COLORS["Low"]
            risk_label = "LOW"

        cards = [
            (
                "TOTAL FINDINGS",
                str(len(self.findings)),
                ACCENT_RED,
                "across all tools",
                "▦",
                False,
            ),
            (
                "CRITICAL & HIGH",
                str(critical + high),
                SEVERITY_COLORS["Critical"],
                f"{critical} critical  ·  {high} high",
                "⛨",
                False,
            ),
            (
                "CVES IDENTIFIED",
                str(intel["cve_count"]),
                ACCENT_PURPLE,
                "NVD + CIRCL + MITRE",
                "❖",
                False,
            ),
            (
                "AVG CVSS SCORE",
                str(intel["avg_cvss"]),
                WARNING,
                "severity-weighted average",
                "◎",
                False,
            ),
            (
                "RISK SCORE",
                str(score),
                risk_color,
                risk_label,
                "⛨",
                score >= 75,
            ),
        ]

        for label, value, color, sub_text, icon, is_critical in cards:
            card = QFrame()
            card_id = f"kpiCard{abs(hash(label)) % 100000}"
            card.setObjectName(card_id)
            card.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Preferred
            )

            border_w = "1.5px" if is_critical else "1px"
            glow_col = (
                SEVERITY_COLORS["Critical"]
                if is_critical
                else color
            )

            card.setStyleSheet(
                f"""
                #{card_id} {{
                    background-color: {self.CARD};
                    border: {border_w} solid {glow_col}99;
                    border-radius: 12px;
                }}

                #{card_id}:hover {{
                    background-color: {self.CARD2};
                    border: {border_w} solid {glow_col};
                }}
                """
            )

            cl = QVBoxLayout(card)
            cl.setContentsMargins(16, 14, 16, 14)
            cl.setSpacing(4)

            lbl = QLabel(label)
            lbl.setObjectName("cardTitle")
            lbl.setStyleSheet(
                f"""
                color: {self.DIM};
                font-size: {self.fs - 3}px;
                font-weight: 700;
                background: transparent;
                border: none;
                letter-spacing: 1.2px;
                """
            )
            cl.addWidget(lbl)

            num_row = QHBoxLayout()
            num_row.setSpacing(8)

            num = QLabel(value)
            num.setStyleSheet(
                f"""
                font-size: {self.fs + 18}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                margin-top: 2px;
                """
            )
            num_row.addWidget(num)
            num_row.addStretch()

            icon_lbl = QLabel(icon)
            icon_lbl.setFixedSize(34, 34)
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_lbl.setStyleSheet(
                f"""
                font-size: {self.fs + 13}px;
                color: {color};
                background: transparent;
                border: none;
                """
            )
            num_row.addWidget(icon_lbl)

            cl.addLayout(num_row)

            sub = QLabel(sub_text)
            sub.setStyleSheet(
                f"""
                font-size: {self.fs - 3}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            cl.addWidget(sub)

            row.addWidget(card, 1)

        return row

    # ─────────────────────────────────────────────
    # Severity Donut
    # ─────────────────────────────────────────────

    def build_donut_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(260)

        outer = QVBoxLayout(card)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(6)

        title = QLabel("SEVERITY DISTRIBUTION")
        title.setObjectName("cardTitle")
        outer.addWidget(title)

        counts = {}

        for finding in self.findings:
            counts[finding["severity"]] = (
                counts.get(finding["severity"], 0) + 1
            )

        total = len(self.findings) or 1

        labels = [
            severity for severity in SEVERITY_ORDER
            if counts.get(severity, 0) > 0
        ]

        values = [
            counts[severity]
            for severity in labels
        ]

        colors = [
            SEVERITY_COLORS[severity]
            for severity in labels
        ]

        body = QHBoxLayout()
        body.setSpacing(10)

        fig = Figure(
            figsize=(2.4, 2.3),
            facecolor=self.CARD
        )

        ax = fig.add_subplot(111)
        ax.set_facecolor(self.CARD)

        if values:
            ax.pie(
                values,
                colors=colors,
                startangle=90,
                wedgeprops={
                    "width": 0.55,
                    "edgecolor": self.CARD,
                    "linewidth": 2,
                },
            )

            ax.text(
                0,
                0.08,
                str(total),
                ha="center",
                va="center",
                fontsize=20,
                fontweight="bold",
                color=self.TEXT,
            )

            ax.text(
                0,
                -0.22,
                "Findings",
                ha="center",
                va="center",
                fontsize=8,
                color=self.DIM,
            )

        else:
            ax.text(
                0,
                0,
                "No findings",
                ha="center",
                va="center",
                color=self.TEXT,
                fontsize=10,
            )

        ax.axis("equal")
        fig.tight_layout(pad=0.2)

        canvas = FigureCanvas(fig)
        canvas.setStyleSheet(
            f"""
            background-color: {self.CARD};
            """
        )
        canvas.setMinimumWidth(170)

        body.addWidget(canvas, 0)

        legend_col = QVBoxLayout()
        legend_col.setSpacing(6)
        legend_col.addStretch(0)

        for severity in labels:
            row = QHBoxLayout()
            row.setSpacing(8)

            dot = QLabel("●")
            dot.setStyleSheet(
                f"""
                color: {SEVERITY_COLORS[severity]};
                font-size: {self.fs}px;
                background: transparent;
                border: none;
                """
            )
            dot.setFixedWidth(14)
            row.addWidget(dot)

            name_lbl = QLabel(severity)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            name_lbl.setFixedWidth(60)
            row.addWidget(name_lbl)

            count_lbl = QLabel(str(counts[severity]))
            count_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                font-weight: 700;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            count_lbl.setFixedWidth(24)
            row.addWidget(count_lbl)

            pct = round(counts[severity] / total * 100)

            pct_lbl = QLabel(f"{pct}%")
            pct_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                color: {SEVERITY_COLORS[severity]};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(pct_lbl)
            row.addStretch()

            legend_col.addLayout(row)

        legend_col.addStretch(1)

        body.addLayout(legend_col, 1)
        outer.addLayout(body)

        return card

    # ─────────────────────────────────────────────
    # Findings by Asset
    # ─────────────────────────────────────────────

    def build_heatmap_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(260)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 10, 14, 10)
        cl.setSpacing(10)

        title = QLabel("FINDINGS BY ASSET")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        asset_counts = {}

        for finding in self.findings:
            asset = finding["asset"]
            severity = finding["severity"]

            if asset not in asset_counts:
                asset_counts[asset] = {
                    sev: 0
                    for sev in SEVERITY_ORDER
                }

            asset_counts[asset][severity] = (
                asset_counts[asset].get(severity, 0) + 1
            )

        sorted_assets = sorted(
            asset_counts.keys(),
            key=lambda asset: sum(asset_counts[asset].values()),
            reverse=True,
        )[:8]

        if not sorted_assets:
            lbl = QLabel("No asset data available")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"""
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            cl.addWidget(lbl)
            return card

        def short(asset, n=44):
            if len(asset) <= n:
                return asset

            return asset[:n - 1] + "…"

        totals = {
            asset: sum(asset_counts[asset].values())
            for asset in sorted_assets
        }

        max_total = max(totals.values()) or 1

        for i, asset in enumerate(sorted_assets):
            row = QHBoxLayout()
            row.setSpacing(10)

            square = QFrame()
            square.setFixedSize(10, 10)
            square.setStyleSheet(
                f"""
                background: {ASSET_PALETTE[i % len(ASSET_PALETTE)]};
                border-radius: 2px;
                border: none;
                """
            )

            square_wrap = QVBoxLayout()
            square_wrap.addWidget(square)
            square_wrap.setContentsMargins(0, 4, 0, 0)

            row.addLayout(square_wrap)

            name_lbl = QLabel(short(asset))
            name_lbl.setFixedWidth(190)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(name_lbl)

            track = QFrame()
            track.setFixedHeight(16)
            track.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 4px;
                border: none;
                """
            )

            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill_width = max(
                6,
                int(
                    (totals[asset] / max_total) * 260
                )
            )

            fill = QFrame()
            fill.setFixedWidth(fill_width)
            fill.setFixedHeight(16)
            fill.setStyleSheet(
                f"""
                background: {ASSET_PALETTE[i % len(ASSET_PALETTE)]};
                border-radius: 4px;
                border: none;
                """
            )

            track_l.addWidget(fill)
            track_l.addStretch()

            row.addWidget(track, 1)

            pct = round(
                totals[asset] / sum(totals.values()) * 100
            )

            count_lbl = QLabel(
                f"{totals[asset]} ({pct}%)"
            )
            count_lbl.setFixedWidth(60)
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            count_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                font-weight: 700;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(count_lbl)

            cl.addLayout(row)

        cl.addStretch()

        return card

    # ─────────────────────────────────────────────
    # CVSS Distribution
    # ─────────────────────────────────────────────

    def build_cvss_distribution_card(self):
        card = QFrame()
        card.setObjectName("siemCard")

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 12, 14, 14)
        cl.setSpacing(10)

        title = QLabel("CVSS SCORE DISTRIBUTION")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        counts = {}

        for finding in self.findings:
            counts[finding["severity"]] = (
                counts.get(finding["severity"], 0) + 1
            )

        total = len(self.findings) or 1
        max_count = max(counts.values()) if counts else 1

        bands = [
            (
                "Critical",
                "9.0 – 10.0",
                SEVERITY_COLORS["Critical"],
                counts.get("Critical", 0),
            ),
            (
                "High",
                "7.0 – 8.9",
                SEVERITY_COLORS["High"],
                counts.get("High", 0),
            ),
            (
                "Medium",
                "4.0 – 6.9",
                SEVERITY_COLORS["Medium"],
                counts.get("Medium", 0),
            ),
            (
                "Low",
                "0.1 – 3.9",
                SEVERITY_COLORS["Low"],
                counts.get("Low", 0),
            ),
            (
                "Info",
                "No Score",
                SEVERITY_COLORS["Info"],
                counts.get("Info", 0),
            ),
        ]

        for severity, score_range, color, count in bands:
            pct = round(count / total * 100)

            row = QHBoxLayout()
            row.setSpacing(10)

            info = QVBoxLayout()
            info.setSpacing(1)

            name_lbl = QLabel(severity)
            name_lbl.setFixedWidth(68)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )

            range_lbl = QLabel(score_range)
            range_lbl.setFixedWidth(68)
            range_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 4}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )

            info.addWidget(name_lbl)
            info.addWidget(range_lbl)

            row.addLayout(info)

            bar_col = QVBoxLayout()
            bar_col.setSpacing(0)
            bar_col.addStretch()

            track = QFrame()
            track.setFixedHeight(6)
            track.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 3px;
                border: none;
                """
            )

            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill_width = max(
                4,
                int(
                    (count / max_count) * 280
                )
            )

            fill = QFrame()
            fill.setFixedWidth(fill_width)
            fill.setFixedHeight(6)
            fill.setStyleSheet(
                f"""
                background: {color};
                border-radius: 3px;
                border: none;
                """
            )

            track_l.addWidget(fill)
            track_l.addStretch()

            bar_col.addWidget(track)
            bar_col.addStretch()

            row.addLayout(bar_col, 1)

            badge = QFrame()
            badge.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 4px;
                border: none;
                """
            )

            badge_l = QHBoxLayout(badge)
            badge_l.setContentsMargins(8, 4, 8, 4)

            badge_lbl = QLabel(f"{count}  ({pct}%)")
            badge_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )

            badge_l.addWidget(badge_lbl)
            row.addWidget(badge)

            cl.addLayout(row)

        cl.addStretch()

        return card

    def build_intel_sources_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(220)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(10)

        title = QLabel("CVE INTELLIGENCE SOURCES")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        intel = self.get_intel_summary()
        cve_count = intel["cve_count"]
        cwe_count = intel["cwe_only"]
        total = len(self.findings) or 1

        sources = [
            (
                "NVD",
                SRC_COLORS["NVD"],
                cve_count,
            ),
            (
                "CIRCL",
                SRC_COLORS["CIRCL"],
                cve_count,
            ),
            (
                "MITRE",
                SRC_COLORS["MITRE"],
                cve_count,
            ),
            (
                "Claude",
                SRC_COLORS["Claude"],
                min(2, cve_count),
            ),
        ]

        for name, color, count in sources:
            row = QHBoxLayout()
            row.setSpacing(8)

            dot = QLabel("●")
            dot.setStyleSheet(
                f"""
                color: {color};
                font-size: {self.fs + 1}px;
                background: transparent;
                border: none;
                """
            )
            dot.setFixedWidth(16)
            row.addWidget(dot)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs}px;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            name_lbl.setFixedWidth(56)
            row.addWidget(name_lbl)

            badge = QLabel("ACTIVE")
            badge.setStyleSheet(
                f"""
                font-size: {self.fs - 5}px;
                font-weight: 700;
                color: #BBF7D0;
                background: rgba(34, 197, 94, 0.16);
                border: 1px solid rgba(34, 197, 94, 0.35);
                border-radius: 8px;
                padding: 2px 8px;
                """
            )
            row.addWidget(badge)

            row.addStretch()

            cnt = QLabel(str(count))
            cnt.setStyleSheet(
                f"""
                font-size: {self.fs}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(cnt)

            cl.addLayout(row)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(
            f"""
            border: none;
            border-top: 1px solid {self.BORDER};
            """
        )
        cl.addWidget(div)

        def _stat_row(label, value, color):
            row = QHBoxLayout()

            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )

            val = QLabel(value)
            val.setStyleSheet(
                f"""
                font-size: {self.fs}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )

            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)

            return row

        cl.addLayout(
            _stat_row(
                "CVE identified",
                f"{cve_count}  ({round(cve_count / total * 100)}%)",
                ACCENT_PURPLE,
            )
        )

        cl.addLayout(
            _stat_row(
                "CWE-only",
                f"{cwe_count}  ({round(cwe_count / total * 100)}%)",
                WARNING,
            )
        )

        avg_cvss = intel["avg_cvss"]

        avg_color = SEVERITY_COLORS.get(
            "Critical"
            if avg_cvss >= 9
            else "High"
            if avg_cvss >= 7
            else "Medium"
            if avg_cvss >= 4
            else "Low"
        )

        cl.addLayout(
            _stat_row(
                "Avg CVSS",
                str(avg_cvss),
                avg_color,
            )
        )

        cl.addStretch()

        return card

    # ─────────────────────────────────────────────
    # Top Vulnerabilities Table
    # ─────────────────────────────────────────────

    def _severity_pill(self, severity):
        bg = SEVERITY_BADGE_BG.get(
            severity,
            "rgba(148,163,184,0.16)"
        )

        border = SEVERITY_BADGE_BORDER.get(
            severity,
            "#475569"
        )

        fg = SEVERITY_BADGE_TEXT.get(
            severity,
            "#CBD5E1"
        )

        wrap = QWidget()
        wrap.setStyleSheet(
            """
            background: transparent;
            """
        )

        wl = QHBoxLayout(wrap)
        wl.setContentsMargins(2, 2, 2, 2)
        wl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pill = QLabel(severity.upper())
        pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pill.setStyleSheet(
            f"""
            background: {bg};
            color: {fg};
            border: 1px solid {border};
            border-radius: 9px;
            padding: 2px 10px;
            font-size: {self.fs - 4}px;
            font-weight: 800;
            """
        )

        wl.addWidget(pill)

        return wrap

    def build_top_vulns_table(self):
        card = QFrame()
        card.setObjectName("siemCard")

        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        enriched = []

        for finding in self.findings:
            if finding["severity"] not in (
                "Critical",
                "High",
                "Medium",
            ):
                continue

            cve_match = CVE_PATTERN.search(
                finding["title"] or ""
            )

            cve_id = (
                cve_match.group(0).upper()
                if cve_match
                else None
            )

            cvss = SEV_TO_CVSS.get(
                finding["severity"],
                0.0
            )

            source = (
                "NVD + CIRCL"
                if cve_id
                else "CWE Derived"
            )

            enriched.append(
                {
                    **finding,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "source": source,
                }
            )

        enriched.sort(
            key=lambda item: (
                SEVERITY_ORDER.index(item["severity"])
                if item["severity"] in SEVERITY_ORDER
                else 99,
                -item["cvss"],
            )
        )

        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(
            [
                "Finding / CVE",
                "Tool",
                "Severity",
                "CVSS",
                "Source",
            ]
        )

        header = table.horizontalHeader()
        header.setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.Stretch
        )
        header.setFixedHeight(32)

        table.setColumnWidth(1, 70)
        table.setColumnWidth(2, 90)
        table.setColumnWidth(3, 55)
        table.setColumnWidth(4, 100)

        table.verticalHeader().setVisible(False)
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)

        table.setStyleSheet(
            f"""
            QTableWidget {{
                background: {self.CARD};
                border: none;
                font-size: {self.fs - 2}px;
                color: {self.TEXT};
                alternate-background-color: {self.CARD2};
                selection-background-color: {self.SELECTION_BG};
                selection-color: {self.SELECTION_TEXT};
            }}

            QHeaderView::section {{
                background: {self.CARD2};
                color: {self.DIM};
                padding: 7px 8px;
                border: none;
                border-right: 1px solid {self.BORDER};
                border-bottom: 1px solid {self.BORDER};
                font-size: {self.fs - 4}px;
                font-weight: 900;
                letter-spacing: 1px;
                text-transform: uppercase;
            }}

            QTableWidget::item {{
                padding: 4px 8px;
                border-bottom: 1px solid {self.BORDER};
                background: transparent;
            }}

            QTableWidget::item:selected {{
                background: {self.SELECTION_BG};
                color: {self.SELECTION_TEXT};
            }}
            """
        )

        for finding in enriched[:20]:
            row = table.rowCount()
            table.insertRow(row)

            title_short = (
                finding["title"][:50] + ".."
                if len(finding["title"]) > 50
                else finding["title"]
            )

            if finding["cve_id"]:
                display = f"{finding['cve_id']}  ·  {title_short}"
            else:
                display = title_short

            title_item = QTableWidgetItem(display)
            title_item.setForeground(QColor(self.TEXT))

            if finding["cve_id"]:
                title_item.setForeground(QColor(ACCENT_PURPLE))

            tool_item = QTableWidgetItem(finding["tool"])
            tool_item.setForeground(QColor(self.DIM))
            tool_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            sev_placeholder = QTableWidgetItem("")
            sev_placeholder.setFlags(
                Qt.ItemFlag.ItemIsEnabled
            )

            cvss_item = QTableWidgetItem(
                str(finding["cvss"])
            )
            cvss_item.setForeground(
                QColor(
                    SEVERITY_COLORS.get(
                        finding["severity"],
                        self.DIM,
                    )
                )
            )
            cvss_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            source_item = QTableWidgetItem(
                finding["source"]
            )
            source_item.setForeground(
                QColor(ACCENT_PURPLE)
                if finding["cve_id"]
                else QColor(self.DIM)
            )
            source_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            table.setItem(row, 0, title_item)
            table.setItem(row, 1, tool_item)
            table.setItem(row, 2, sev_placeholder)
            table.setCellWidget(
                row,
                2,
                self._severity_pill(finding["severity"])
            )
            table.setItem(row, 3, cvss_item)
            table.setItem(row, 4, source_item)

            table.setRowHeight(row, 30)

        table.setMaximumHeight(
            min(len(enriched), 8) * 31 + 38
        )

        cl.addWidget(table)

        footer = QHBoxLayout()

        shown = min(len(enriched), 20)
        total_count = len(enriched)

        footer_lbl = QLabel(
            f"Showing 1-{shown} of {total_count}"
        )
        footer_lbl.setStyleSheet(
            f"""
            font-size: {self.fs - 3}px;
            color: {self.DIM};
            background: transparent;
            border: none;
            """
        )
        footer.addWidget(footer_lbl)
        footer.addStretch()

        view_all = QLabel("View all")
        view_all.setStyleSheet(
            f"""
            font-size: {self.fs - 3}px;
            color: {ACCENT_RED};
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )
        footer.addWidget(view_all)

        cl.addLayout(footer)

        return card

    # ─────────────────────────────────────────────
    # Tool Severity Heatmap
    # ─────────────────────────────────────────────

    def build_stacked_bar_card(self):
        card = QFrame()
        card.setObjectName("siemCard")

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(10)

        title = QLabel("TOOL SEVERITY HEATMAP")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        tool_sev = {}

        for finding in self.findings:
            tool = finding["tool"]
            severity = finding["severity"]

            if tool not in tool_sev:
                tool_sev[tool] = {}

            tool_sev[tool][severity] = (
                tool_sev[tool].get(severity, 0) + 1
            )

        tools = sorted(
            tool_sev.keys(),
            key=lambda tool: sum(tool_sev[tool].values()),
            reverse=True,
        )

        if not tools:
            lbl = QLabel("No tool/severity data available")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"""
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            cl.addWidget(lbl)

            return card

        cols = SEVERITY_ORDER

        col_max = {
            severity: max(
                (
                    tool_sev[tool].get(severity, 0)
                    for tool in tools
                ),
                default=0,
            )
            or 1
            for severity in cols
        }

        grid = QGridLayout()
        grid.setSpacing(6)

        grid.addWidget(QLabel(""), 0, 0)

        for j, severity in enumerate(cols):
            header = QLabel(severity)
            header.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header.setStyleSheet(
                f"""
                color: {SEVERITY_COLORS[severity]};
                font-size: {self.fs - 3}px;
                font-weight: 800;
                background: transparent;
                border: none;
                """
            )
            grid.addWidget(header, 0, j + 1)

        for i, tool in enumerate(tools, start=1):
            tool_lbl = QLabel(tool)
            tool_lbl.setStyleSheet(
                f"""
                color: {self.TEXT};
                font-size: {self.fs - 2}px;
                font-weight: 700;
                background: transparent;
                border: none;
                """
            )
            grid.addWidget(
                tool_lbl,
                i,
                0,
                Qt.AlignmentFlag.AlignVCenter
            )

            for j, severity in enumerate(cols):
                value = tool_sev[tool].get(severity, 0)

                cell = QLabel(
                    str(value)
                    if value > 0
                    else ""
                )
                cell.setFixedSize(64, 36)
                cell.setAlignment(Qt.AlignmentFlag.AlignCenter)

                if value > 0:
                    base_color = SEVERITY_COLORS[severity]
                    intensity = value / col_max[severity]
                    alpha = 0.16 + (intensity * 0.34)

                    bg = self._rgba(base_color, alpha)
                    border = self._rgba(base_color, 0.55)

                    fg = {
                        "Critical": "#FEE2E2",
                        "High": "#FED7AA",
                        "Medium": "#FEF3C7",
                        "Low": "#BBF7D0",
                        "Info": "#BFDBFE",
                    }[severity]

                else:
                    bg = self.CARD2
                    border = "rgba(148, 163, 184, 0.12)"
                    fg = self.SOFT

                cell.setStyleSheet(
                    f"""
                    background: {bg};
                    border: 1px solid {border};
                    border-radius: 8px;
                    color: {fg};
                    font-size: {self.fs - 2}px;
                    font-weight: 900;
                    """
                )

                grid.addWidget(cell, i, j + 1)

        cl.addLayout(grid)
        cl.addStretch()

        return card

    # ─────────────────────────────────────────────
    # Tool Status Grid
    # ─────────────────────────────────────────────

    def build_tool_status_card(self):
        card = QFrame()
        card.setObjectName("siemCard")

        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        title = QLabel("TOOLS STATUS")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        tool_counts = {}

        for finding in self.findings:
            tool_counts[finding["tool"]] = (
                tool_counts.get(finding["tool"], 0) + 1
            )

        grid = QGridLayout()
        grid.setSpacing(6)

        all_tools = [
            "nmap",
            "subfinder",
            "httpx",
            "whatweb",
            "ffuf",
            "nikto",
            "theharvester",
            "dnsrecon",
            "gobuster",
            "dirsearch",
            "wpscan",
            "nuclei",
        ]

        for i, tool in enumerate(all_tools):
            cell = QFrame()
            cell.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 8px;
                border: 1px solid {self.BORDER};
                """
            )

            cell_layout = QVBoxLayout(cell)
            cell_layout.setContentsMargins(10, 8, 10, 8)
            cell_layout.setSpacing(2)

            emoji = TOOL_EMOJI.get(tool, "🔧")

            name_lbl = QLabel(f"{emoji} {tool}")
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 4}px;
                font-weight: 700;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            cell_layout.addWidget(name_lbl)

            count = tool_counts.get(tool, 0)

            count_color = (
                ACCENT_RED
                if count > 0
                else self.DIM
            )

            count_lbl = QLabel(str(count))
            count_lbl.setStyleSheet(
                f"""
                font-size: {self.fs + 2}px;
                font-weight: 900;
                color: {count_color};
                background: transparent;
                border: none;
                """
            )
            cell_layout.addWidget(count_lbl)

            run_status = self.tool_runs.get(tool, "")

            if run_status == "running":
                status_text = "● Running"
                status_color = MEDIUM_YELLOW

            elif run_status == "completed" or count > 0:
                status_text = "✓ Done"
                status_color = DONE_GREEN

            elif run_status in ("failed", "timeout", "error"):
                status_text = "✗ Failed"
                status_color = SEVERITY_COLORS["Critical"]

            else:
                status_text = "— Not run"
                status_color = self.DIM

            status_lbl = QLabel(status_text)
            status_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 5}px;
                font-weight: 700;
                color: {status_color};
                background: transparent;
                border: none;
                """
            )
            cell_layout.addWidget(status_lbl)

            grid.addWidget(cell, i // 3, i % 3)

        cl.addLayout(grid)

        return card

    # ─────────────────────────────────────────────
    # Attack Surface
    # ─────────────────────────────────────────────

    def build_attack_surface_row(self):
        data = self.compute_attack_surface()

        row = QHBoxLayout()
        row.setSpacing(10)

        row.addWidget(self.build_score_card(data), 2)
        row.addWidget(self.build_score_explanation(data), 2)
        row.addWidget(self.build_metrics_card(data), 2)

        return row

    def build_score_card(self, data):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(300)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(8)

        title = QLabel("ATTACK SURFACE SCORE")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        score = data["score"]
        color = data["rating_color"]

        fig = Figure(
            figsize=(3, 2.2),
            facecolor=self.CARD
        )

        ax = fig.add_subplot(111)
        ax.set_facecolor(self.CARD)
        ax.set_xlim(-1.3, 1.3)
        ax.set_ylim(-1.3, 1.3)
        ax.set_aspect("equal")
        ax.axis("off")

        theta_full = np.linspace(
            np.pi * 1.25,
            -np.pi * 0.25,
            200
        )

        ax.plot(
            np.cos(theta_full),
            np.sin(theta_full),
            color=self.CARD2,
            linewidth=10,
            solid_capstyle="round"
        )

        fraction = score / 100.0

        theta_score = np.linspace(
            np.pi * 1.25,
            np.pi * 1.25 - fraction * np.pi * 1.5,
            200
        )

        ax.plot(
            np.cos(theta_score),
            np.sin(theta_score),
            color=color,
            linewidth=10,
            solid_capstyle="round"
        )

        ax.text(
            0,
            0.1,
            str(score),
            ha="center",
            va="center",
            color=self.TEXT,
            fontsize=22,
            fontweight="bold"
        )

        ax.text(
            0,
            -0.35,
            "/100",
            ha="center",
            va="center",
            color=self.DIM,
            fontsize=10
        )

        fig.tight_layout(pad=0.2)

        canvas = FigureCanvas(fig)
        canvas.setStyleSheet(
            f"""
            background-color: {self.CARD};
            """
        )
        canvas.setFixedHeight(160)

        cl.addWidget(canvas)

        rating_lbl = QLabel(data["rating"])
        rating_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rating_lbl.setStyleSheet(
            f"""
            font-size: {self.fs + 3}px;
            font-weight: 900;
            color: {color};
            background: transparent;
            border: none;
            """
        )
        cl.addWidget(rating_lbl)

        breakdown_row = QHBoxLayout()
        breakdown_row.setSpacing(6)

        blocks = [
            (
                str(data["open_ports"]),
                "Ports",
                WARNING,
            ),
            (
                str(data["subdomains"]),
                "Subdomains",
                ACCENT_RED,
            ),
            (
                str(data["ch_count"]),
                "C/H Vulns",
                SEVERITY_COLORS["Critical"],
            ),
            (
                str(data["emails"]),
                "Emails",
                SUCCESS,
            ),
        ]

        for value, label, color in blocks:
            block = QFrame()
            block.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 4px;
                border: none;
                """
            )

            bl = QVBoxLayout(block)
            bl.setContentsMargins(6, 4, 6, 4)
            bl.setSpacing(1)

            value_lbl = QLabel(value)
            value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value_lbl.setStyleSheet(
                f"""
                font-size: {self.fs}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )

            label_lbl = QLabel(label)
            label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 5}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )

            bl.addWidget(value_lbl)
            bl.addWidget(label_lbl)

            breakdown_row.addWidget(block)

        cl.addLayout(breakdown_row)

        return card

    def build_score_explanation(self, data):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(300)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 14, 14, 14)
        cl.setSpacing(8)

        title = QLabel("HOW SCORE WAS CALCULATED")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        total = data["score"]
        color = data["rating_color"]

        formula_lbl = QLabel(f"Total Score = {total}/100")
        formula_lbl.setStyleSheet(
            f"""
            font-size: {self.fs}px;
            font-weight: 900;
            color: {color};
            background: transparent;
            border: none;
            """
        )
        cl.addWidget(formula_lbl)

        for name, points, max_points, formula, col in data["score_breakdown"]:
            row = QHBoxLayout()

            info_col = QVBoxLayout()
            info_col.setSpacing(1)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                font-weight: 900;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            info_col.addWidget(name_lbl)

            formula_txt = QLabel(formula)
            formula_txt.setStyleSheet(
                f"""
                font-size: {self.fs - 4}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            info_col.addWidget(formula_txt)

            row.addLayout(info_col)
            row.addStretch()

            points_frame = QFrame()
            points_frame.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 4px;
                border: none;
                """
            )

            points_l = QHBoxLayout(points_frame)
            points_l.setContentsMargins(8, 4, 8, 4)

            points_lbl = QLabel(f"{points} pts")
            points_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                font-weight: 900;
                color: {col};
                background: transparent;
                border: none;
                """
            )

            points_l.addWidget(points_lbl)
            row.addWidget(points_frame)

            cl.addLayout(row)

            track = QFrame()
            track.setFixedHeight(4)
            track.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 2px;
                border: none;
                """
            )

            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill = QFrame()
            fill.setStyleSheet(
                f"""
                background: {col};
                border-radius: 2px;
                border: none;
                """
            )
            fill.setFixedWidth(
                max(
                    4,
                    int(
                        (points / max(max_points, 1)) * 180
                    )
                )
            )

            track_l.addWidget(fill)
            track_l.addStretch()

            cl.addWidget(track)

        cl.addStretch()

        score = data["score"]

        if score >= 70:
            why = (
                "Score ≥ 70 → CRITICAL. Target has extensive open services, "
                "multiple critical vulnerabilities, and a large subdomain footprint."
            )

        elif score >= 50:
            why = (
                "Score ≥ 50 → HIGH RISK. Significant vulnerabilities and "
                "exposed services detected."
            )

        elif score >= 30:
            why = (
                "Score ≥ 30 → MEDIUM RISK. Some exposure detected but limited "
                "critical findings."
            )

        else:
            why = (
                "Score < 30 → LOW RISK. Minimal exposed services and "
                "few vulnerabilities found."
            )

        why_lbl = QLabel(why)
        why_lbl.setWordWrap(True)
        why_lbl.setStyleSheet(
            f"""
            font-size: {self.fs - 3}px;
            color: {self.DIM};
            background: {self.CARD2};
            border: none;
            border-radius: 4px;
            padding: 8px;
            """
        )

        cl.addWidget(why_lbl)

        return card

    def build_metrics_card(self, data):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(300)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 14, 14, 14)
        cl.setSpacing(8)

        title = QLabel("EXPOSURE METRICS")
        title.setObjectName("cardTitle")
        cl.addWidget(title)

        for metric_name, metric_data in data["metrics"]:
            level, color, pct = metric_data

            row = QHBoxLayout()
            row.setSpacing(8)

            name_lbl = QLabel(metric_name)
            name_lbl.setFixedWidth(160)
            name_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                color: {self.DIM};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(name_lbl)

            track = QFrame()
            track.setFixedHeight(8)
            track.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-radius: 4px;
                border: none;
                """
            )

            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill = QFrame()
            fill.setStyleSheet(
                f"""
                background: {color};
                border-radius: 4px;
                border: none;
                """
            )
            fill.setFixedWidth(
                max(
                    6,
                    int(
                        min(pct, 1.0) * 140
                    )
                )
            )

            track_l.addWidget(fill)
            track_l.addStretch()

            row.addWidget(track, 1)

            level_lbl = QLabel(level)
            level_lbl.setFixedWidth(55)
            level_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            level_lbl.setStyleSheet(
                f"""
                font-size: {self.fs - 2}px;
                font-weight: 900;
                color: {color};
                background: transparent;
                border: none;
                """
            )
            row.addWidget(level_lbl)

            cl.addLayout(row)

        cl.addStretch()

        recs_lbl = QLabel("TOP RECOMMENDATIONS")
        recs_lbl.setObjectName("cardTitle")
        recs_lbl.setStyleSheet(
            f"""
            color: {self.DIM};
            font-size: {self.fs - 3}px;
            font-weight: 900;
            letter-spacing: 1px;
            background: transparent;
            border: none;
            margin-top: 4px;
            """
        )
        cl.addWidget(recs_lbl)

        for rec in self.generate_recommendations(data)[:3]:
            rec_frame = QFrame()
            rec_frame.setStyleSheet(
                f"""
                background: {self.CARD2};
                border-left: 3px solid {SEVERITY_COLORS["High"]};
                border-radius: 6px;
                padding: 0;
                """
            )

            rec_l = QHBoxLayout(rec_frame)
            rec_l.setContentsMargins(10, 8, 10, 8)
            rec_l.setSpacing(8)

            icon = QLabel("🛡️")
            icon.setStyleSheet(
                f"""
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
                """
            )
            icon.setAlignment(Qt.AlignmentFlag.AlignTop)
            rec_l.addWidget(icon)

            rec_txt = QLabel(rec)
            rec_txt.setWordWrap(True)
            rec_txt.setStyleSheet(
                f"""
                font-size: {self.fs - 3}px;
                color: {self.TEXT};
                background: transparent;
                border: none;
                """
            )
            rec_l.addWidget(rec_txt, 1)

            cl.addWidget(rec_frame)

        return card

    def generate_recommendations(self, data):
        recs = []

        if data["open_ports"] > 10:
            recs.append(
                f"Reduce port exposure — {data['open_ports']} open ports "
                f"detected. Close unnecessary services."
            )

        if data["insecure_tech"]:
            names = ", ".join(data["insecure_tech"][:3])
            recs.append(
                f"Disable insecure services: {names}. "
                f"These transmit data in cleartext."
            )

        if data["ch_count"] > 0:
            recs.append(
                f"Remediate {data['ch_count']} Critical/High findings — "
                f"prioritise by CVSS score."
            )

        if data["subdomains"] > 10:
            recs.append(
                f"Audit subdomain footprint — {data['subdomains']} "
                f"subdomains found. Decommission unused ones."
            )

        if data["emails"] > 5:
            recs.append(
                f"{data['emails']} email addresses exposed via OSINT. "
                f"Consider email protection."
            )

        if not recs:
            recs.append(
                "Attack surface appears low. Continue monitoring for changes."
            )

        return recs

    def go_back(self):
        if self.on_close:
            self.on_close()

    def _rgba(self, hex_color, alpha):
        hex_color = hex_color.lstrip("#")

        red = int(hex_color[0:2], 16)
        green = int(hex_color[2:4], 16)
        blue = int(hex_color[4:6], 16)

        return f"rgba({red}, {green}, {blue}, {alpha})"

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

            #dashTitle {{
                color: {self.TEXT};
                font-size: {self.fs + 8}px;
                font-weight: 900;
                background: transparent;
                border: none;
                letter-spacing: 0.3px;
            }}

            #dashTitleAccent {{
                color: {ACCENT_RED};
                font-size: {self.fs + 8}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #dashSub {{
                color: {self.DIM};
                font-size: {self.fs - 2}px;
                background: transparent;
                border: none;
            }}

            #sectionHeader {{
                color: {self.TEXT};
                font-size: {self.fs - 1}px;
                font-weight: 900;
                background: transparent;
                border: none;
                margin-top: 14px;
                letter-spacing: 1.1px;
                text-transform: uppercase;
            }}

            #siemCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}

            #siemCard:hover {{
                border: 1px solid {self.CARD_HOVER};
                background-color: {self.CARD2};
            }}

            #criticalCard {{
                background-color: {self.CARD};
                border: 1px solid {rgba_from_hex(ACCENT_RED, 140)};
                border-radius: 12px;
            }}

            #cardTitle {{
                color: {self.DIM};
                font-size: {self.fs - 3}px;
                font-weight: 800;
                background: transparent;
                border: none;
                letter-spacing: 1.2px;
                text-transform: uppercase;
            }}

            #backBtn {{
                background-color: {self.BUTTON_SOFT};
                color: {self.DIM};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: {self.fs - 1}px;
                font-weight: 800;
            }}

            #backBtn:hover {{
                color: {self.SELECTION_TEXT};
                border-color: {ACCENT_RED};
                background-color: {self.HOVER};
            }}

            #backBtn:pressed {{
                background-color: rgba(127, 29, 29, 120);
            }}

            QTableWidget {{
                background-color: {self.CARD};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                gridline-color: {self.BORDER};
                selection-background-color: {self.SELECTION_BG};
                selection-color: {self.SELECTION_TEXT};
            }}

            QHeaderView::section {{
                background-color: {self.CARD2};
                color: {self.DIM};
                border: none;
                border-bottom: 1px solid {self.BORDER};
                padding: 8px;
                font-weight: 900;
            }}

            QTableWidget::item {{
                background-color: transparent;
                color: {self.TEXT};
                border: none;
            }}

            QTableWidget::item:selected {{
                background-color: {self.SELECTION_BG};
                color: {self.SELECTION_TEXT};
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
                background: {ACCENT_RED};
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
                background-color: {ACCENT_RED};
                color: white;
                border: none;
                border-radius: 7px;
                padding: 7px 18px;
                font-weight: 800;
            }}

            QMessageBox QPushButton:hover {{
                background-color: {ACCENT_HOVER};
            }}
        """

