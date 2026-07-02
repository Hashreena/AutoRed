from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QProgressBar
)
from PyQt6.QtCore import Qt

from backend.db import get_connection
from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# AutoRed Theme System
# Supports Dark Theme + Light Theme
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
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
MEDIUM_YELLOW = "#FACC15"
INFO_BLUE = "#60A5FA"

PURPLE = "#8B5CF6"

HOVER_BG = "rgba(239, 68, 68, 25)"
SELECTION_TEXT = "#FEE2E2"
BUTTON_SOFT = "rgba(15, 23, 42, 185)"
CARD_HOVER = "rgba(239, 68, 68, 85)"

UNIFIED_THEME = {}

SEVERITY_COLORS = {}
SEVERITY_BG = {}
SEVERITY_TEXT = {}

SEVERITY_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "🔵",
}


def apply_theme_palette(theme):
    global BG_MAIN, BG_PAGE, BG_DEEP
    global CARD_BG, CARD_BG_2, BORDER, BORDER_SOFT
    global TEXT_MAIN, TEXT_MUTED, TEXT_SOFT
    global ACCENT, ACCENT_HOVER, ACCENT_DARK
    global BRAND_RED, BRAND_RED_HOVER
    global SUCCESS, SUCCESS_HOVER
    global WARNING, MEDIUM_YELLOW, INFO_BLUE, PURPLE
    global HOVER_BG, SELECTION_TEXT, BUTTON_SOFT, CARD_HOVER
    global UNIFIED_THEME, SEVERITY_COLORS, SEVERITY_BG, SEVERITY_TEXT

    light = _is_light_theme(theme)

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

    ACCENT = theme.get("accent", "#EF4444")
    ACCENT_HOVER = theme.get("accent_hover", "#DC2626")
    ACCENT_DARK = theme.get("accent_dark", "#991B1B")

    BRAND_RED = theme.get("brand_red", ACCENT)
    BRAND_RED_HOVER = theme.get("brand_red_hover", ACCENT_HOVER)

    SUCCESS = theme.get("success", "#16A34A" if light else "#22C55E")
    SUCCESS_HOVER = theme.get("success_hover", "#15803D" if light else "#16A34A")

    WARNING = theme.get("warning", "#EA580C" if light else "#F97316")
    MEDIUM_YELLOW = theme.get("medium", "#CA8A04" if light else "#FACC15")
    INFO_BLUE = theme.get("info", "#2563EB" if light else "#60A5FA")

    PURPLE = theme.get("purple", "#7C3AED" if light else "#8B5CF6")

    HOVER_BG = theme.get("hover", rgba_from_hex(ACCENT, 18 if light else 25))
    SELECTION_TEXT = theme.get("selection_text", "#7F1D1D" if light else "#FEE2E2")
    BUTTON_SOFT = theme.get(
        "button_soft",
        "#FFFFFF" if light else "rgba(15, 23, 42, 185)"
    )
    CARD_HOVER = theme.get("card_hover", rgba_from_hex(ACCENT, 55 if light else 85))

    SEVERITY_COLORS = {
        "Critical": BRAND_RED,
        "High": WARNING,
        "Medium": MEDIUM_YELLOW,
        "Low": SUCCESS,
        "Info": INFO_BLUE,
    }

    SEVERITY_BG = {
        "Critical": rgba_from_hex(BRAND_RED, 22 if not light else 18),
        "High": rgba_from_hex(WARNING, 22 if not light else 18),
        "Medium": rgba_from_hex(MEDIUM_YELLOW, 20 if not light else 18),
        "Low": rgba_from_hex(SUCCESS, 18),
        "Info": rgba_from_hex(INFO_BLUE, 18),
    }

    if light:
        SEVERITY_TEXT = {
            "Critical": "#7F1D1D",
            "High": "#7C2D12",
            "Medium": "#713F12",
            "Low": "#14532D",
            "Info": "#1E3A8A",
        }
    else:
        SEVERITY_TEXT = {
            "Critical": "#FEE2E2",
            "High": "#FED7AA",
            "Medium": "#FEF3C7",
            "Low": "#BBF7D0",
            "Info": "#BFDBFE",
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
        "medium": MEDIUM_YELLOW,
        "info": INFO_BLUE,
        "purple": PURPLE,
        "button_soft": BUTTON_SOFT,
        "card_hover": CARD_HOVER,
        "selection_text": SELECTION_TEXT,
    }


apply_theme_palette(get_theme(True))


ATTACK_PATHS = {
    "telnet": [
        "Attacker on network",
        "Connect to Port 23",
        "Capture plaintext credentials",
        "Full system access",
    ],
    "bindshell": [
        "Attacker on network",
        "Connect to Port 1524",
        "Instant root shell",
        "Complete system compromise",
    ],
    "ftp": [
        "Attacker on network",
        "Connect to Port 21",
        "Brute force or sniff credentials",
        "File system access",
    ],
    "mysql": [
        "Attacker on network",
        "Connect to Port 3306",
        "Default or weak credentials",
        "Full database access",
    ],
    "postgresql": [
        "Attacker on network",
        "Connect to Port 5432",
        "Empty password exploit",
        "Full database access",
    ],
    "vnc": [
        "Attacker on network",
        "Connect to Port 5900",
        "Default password login",
        "Full desktop control",
    ],
    "phpmyadmin": [
        "Attacker finds /phpMyAdmin",
        "Brute force login page",
        "Database admin access",
        "Data exfiltration or RCE",
    ],
    "phpinfo": [
        "Attacker finds phpinfo.php",
        "Reads server configuration",
        "Identifies exploitable versions",
        "Targeted exploitation",
    ],
    "cve-2020-1938": [
        "Attacker reaches AJP port",
        "Exploit Ghostcat",
        "Read arbitrary server files",
        "Remote Code Execution",
    ],
    "cve-2012-1823": [
        "Attacker sends crafted HTTP request",
        "Exploit PHP-CGI",
        "Remote code execution",
        "Full server compromise",
    ],
    "cve-2011-2523": [
        "Attacker connects to vsftpd",
        "Trigger backdoor",
        "Root shell via Port 6200",
        "Complete system compromise",
    ],
    "smb": [
        "Attacker on network",
        "Connect to Port 445",
        "Exploit SMB vulnerability",
        "Lateral movement or RCE",
    ],
    "ssh": [
        "Attacker on network",
        "Connect to Port 22",
        "Brute force weak credentials",
        "Remote shell access",
    ],
    "directory listing": [
        "Attacker browses web server",
        "Finds open directory listing",
        "Enumerates sensitive files",
        "Information disclosure",
    ],
    "directory indexing": [
        "Attacker browses web server",
        "Finds open directory listing",
        "Enumerates sensitive files",
        "Information disclosure",
    ],
    "http trace": [
        "Attacker sends TRACE request",
        "Server reflects headers back",
        "Capture session cookies",
        "Session hijacking",
    ],
    "multiviews": [
        "Attacker sends crafted requests",
        "Apache MultiViews brute forces files",
        "Discovers hidden resources",
        "Further targeted exploitation",
    ],
    "irc": [
        "Attacker connects to IRC port",
        "Identifies IRC daemon version",
        "Exploit known IRC vulnerabilities",
        "Remote code execution",
    ],
    "java rmi": [
        "Attacker scans for RMI port",
        "Connect to Java RMI service",
        "Exploit deserialization flaw",
        "Remote code execution",
    ],
    "rmi": [
        "Attacker scans for RMI port",
        "Connect to Java RMI service",
        "Exploit deserialization flaw",
        "Remote code execution",
    ],
    "smtp": [
        "Attacker connects to Port 25",
        "Enumerate valid email users",
        "Relay spam or phishing emails",
        "Information disclosure",
    ],
    "nfs": [
        "Attacker scans for NFS port",
        "Mount exposed NFS share",
        "Access sensitive files",
        "Data exfiltration",
    ],
    "wordpress": [
        "Attacker runs WPScan",
        "Discovers vulnerable plugins",
        "Exploit plugin vulnerability",
        "Admin access or RCE",
    ],
    "wp-": [
        "Attacker runs WPScan",
        "Discovers WordPress vulnerability",
        "Exploit vulnerable component",
        "Admin access or RCE",
    ],
    "apache": [
        "Attacker identifies Apache version",
        "Searches for known CVEs",
        "Exploits unpatched vulnerability",
        "Server compromise",
    ],
    "php": [
        "Attacker identifies PHP version",
        "Searches for known CVEs",
        "Exploits PHP vulnerability",
        "Remote code execution",
    ],
    "htaccess": [
        "Attacker finds exposed .htaccess",
        "Reads server configuration rules",
        "Identifies bypass opportunities",
        "Access restricted resources",
    ],
    "htpasswd": [
        "Attacker finds exposed .htpasswd",
        "Downloads password hashes",
        "Cracks hashes offline",
        "Authenticated access",
    ],
    "backup": [
        "Attacker finds backup file",
        "Downloads source code or data",
        "Extracts credentials or secrets",
        "Full application compromise",
    ],
    "config": [
        "Attacker finds config file",
        "Reads database credentials",
        "Connects directly to database",
        "Full data access",
    ],
    "shell": [
        "Attacker finds exposed shell",
        "Executes arbitrary commands",
        "Establishes persistence",
        "Full system compromise",
    ],
    "sql injection": [
        "Attacker injects SQL payload",
        "Extracts database contents",
        "Bypasses authentication",
        "Data exfiltration or RCE",
    ],
    "xss": [
        "Attacker injects script payload",
        "Victim executes malicious script",
        "Session cookies stolen",
        "Account takeover",
    ],
    "path traversal": [
        "Attacker sends traversal payload",
        "Reads files outside web root",
        "Accesses sensitive system files",
        "Credential disclosure",
    ],
}


def get_attack_path(title, asset):
    combined = f"{title} {asset}".lower()

    for keyword, path in ATTACK_PATHS.items():
        if keyword in combined:
            return path

    return None


def calculate_risk_score(findings):
    counts = {}

    for finding in findings:
        severity = finding.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1

    score = (
        counts.get("Critical", 0) * 20 +
        counts.get("High", 0) * 8 +
        counts.get("Medium", 0) * 3 +
        counts.get("Low", 0) * 1
    )

    return min(100, score)


def get_risk_label(score):
    if score >= 80:
        return "CRITICAL RISK", BRAND_RED

    if score >= 60:
        return "HIGH RISK", WARNING

    if score >= 40:
        return "MEDIUM RISK", MEDIUM_YELLOW

    if score >= 20:
        return "LOW RISK", SUCCESS

    return "MINIMAL RISK", INFO_BLUE


class CollapsibleSection(QWidget):
    def __init__(
        self,
        severity,
        findings,
        expanded=True,
        theme=None,
        font_size=13,
        parent=None,
    ):
        super().__init__(parent)

        self.severity = severity
        self.findings = findings
        self.expanded = expanded

        self.t = theme or UNIFIED_THEME
        self.fs = font_size

        self.color = SEVERITY_COLORS[severity]
        self.bg = SEVERITY_BG[severity]
        self.text_color = SEVERITY_TEXT.get(severity, TEXT_MAIN)
        self.icon = SEVERITY_ICONS[severity]

        self.init_ui()

    def init_ui(self):
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(0)

        outer = QFrame()
        outer.setObjectName("severitySection")
        outer.setStyleSheet(
            f"""
            QFrame#severitySection {{
                background-color: {CARD_BG};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}

            QFrame#severitySection:hover {{
                border: 1px solid {CARD_HOVER};
            }}
            """
        )

        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.header_btn = QPushButton()
        self.header_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header_btn.clicked.connect(self.toggle)
        self.header_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {self.bg};
                color: {self.color};
                border: none;
                border-radius: 10px 10px 0 0;
                border-bottom: 1px solid {self.color};
                padding: 12px 16px;
                font-size: {self.fs}px;
                font-weight: 900;
                text-align: left;
            }}

            QPushButton:hover {{
                background-color: {HOVER_BG};
            }}
            """
        )

        self.update_header_text()

        outer_layout.addWidget(self.header_btn)

        self.content_widget = QWidget()
        self.content_widget.setStyleSheet(
            f"""
            background-color: {CARD_BG};
            border: none;
            """
        )

        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        for index, finding in enumerate(self.findings):
            card = self.build_finding_card(finding, index)
            self.content_layout.addWidget(card)

        self.content_widget.setVisible(self.expanded)

        outer_layout.addWidget(self.content_widget)

        self.layout_.addWidget(outer)

    def update_header_text(self):
        arrow = "▾" if self.expanded else "▸"

        self.header_btn.setText(
            f"{self.icon}  {self.severity.upper()} FINDINGS "
            f"({len(self.findings)})  {arrow}"
        )

    def toggle(self):
        self.expanded = not self.expanded
        self.content_widget.setVisible(self.expanded)
        self.update_header_text()

    def build_finding_card(self, finding, index):
        card = QFrame()
        card.setStyleSheet(
            f"""
            QFrame {{
                background-color: {CARD_BG};
                border: none;
                border-bottom: 1px solid {BORDER};
            }}
            """
        )

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 14, 20, 14)
        card_layout.setSpacing(8)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        num = QLabel(f"{index + 1}.")
        num.setFixedWidth(28)
        num.setStyleSheet(
            f"""
            color: {TEXT_MUTED};
            font-size: {self.fs - 1}px;
            font-weight: 800;
            background: transparent;
            border: none;
            """
        )
        title_row.addWidget(num)

        title_lbl = QLabel(finding.get("title", "Untitled Finding"))
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"""
            color: {TEXT_MAIN};
            font-size: {self.fs}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )
        title_row.addWidget(title_lbl, 1)

        tool_badge = QLabel(finding.get("tool", "tool"))
        tool_badge.setStyleSheet(
            f"""
            color: {SELECTION_TEXT};
            font-size: {self.fs - 3}px;
            font-weight: 800;
            background-color: {HOVER_BG};
            border: 1px solid {CARD_HOVER};
            border-radius: 6px;
            padding: 3px 8px;
            """
        )
        title_row.addWidget(tool_badge)

        card_layout.addLayout(title_row)

        description = finding.get("description", "")

        if description:
            desc_text = description

            if len(desc_text) > 220:
                desc_text = desc_text[:220] + "..."

            desc = QLabel(desc_text)
            desc.setWordWrap(True)
            desc.setStyleSheet(
                f"""
                color: {TEXT_MUTED};
                font-size: {self.fs - 2}px;
                background: transparent;
                border: none;
                """
            )

            card_layout.addWidget(desc)

        attack_path = get_attack_path(
            finding.get("title", ""),
            finding.get("asset", "")
        )

        if attack_path:
            path_frame = QFrame()
            path_frame.setStyleSheet(
                f"""
                QFrame {{
                    background-color: {BG_DEEP};
                    border: 1px solid {self.color};
                    border-radius: 8px;
                }}
                """
            )

            path_layout = QVBoxLayout(path_frame)
            path_layout.setContentsMargins(12, 9, 12, 10)
            path_layout.setSpacing(7)

            path_title = QLabel("⚡ ATTACK PATH")
            path_title.setStyleSheet(
                f"""
                color: {self.color};
                font-size: {self.fs - 3}px;
                font-weight: 900;
                background: transparent;
                border: none;
                letter-spacing: 1px;
                """
            )

            path_layout.addWidget(path_title)

            path_row = QHBoxLayout()
            path_row.setSpacing(5)

            for step_index, step in enumerate(attack_path):
                step_lbl = QLabel(step)
                step_lbl.setStyleSheet(
                    f"""
                    color: {TEXT_MAIN};
                    font-size: {self.fs - 3}px;
                    font-weight: 700;
                    background-color: {CARD_BG};
                    border: 1px solid {BORDER};
                    border-radius: 6px;
                    padding: 5px 8px;
                    """
                )

                path_row.addWidget(step_lbl)

                if step_index < len(attack_path) - 1:
                    arrow = QLabel("→")
                    arrow.setStyleSheet(
                        f"""
                        color: {self.color};
                        font-size: {self.fs}px;
                        font-weight: 900;
                        background: transparent;
                        border: none;
                        """
                    )
                    path_row.addWidget(arrow)

            path_row.addStretch()

            path_layout.addLayout(path_row)
            card_layout.addWidget(path_frame)

        recommendation = finding.get("recommendation", "")

        if recommendation:
            rec_text = recommendation

            if len(rec_text) > 190:
                rec_text = rec_text[:190] + "..."

            rec_frame = QFrame()
            rec_frame.setStyleSheet(
                f"""
                QFrame {{
                    background-color: {rgba_from_hex(SUCCESS, 18)};
                    border: 1px solid {rgba_from_hex(SUCCESS, 90)};
                    border-radius: 8px;
                }}
                """
            )

            rec_layout = QHBoxLayout(rec_frame)
            rec_layout.setContentsMargins(12, 8, 12, 8)
            rec_layout.setSpacing(8)

            fix_icon = QLabel("✓")
            fix_icon.setFixedWidth(16)
            fix_icon.setStyleSheet(
                f"""
                color: {SUCCESS};
                font-size: {self.fs + 1}px;
                font-weight: 900;
                background: transparent;
                border: none;
                """
            )

            rec_layout.addWidget(fix_icon)

            rec = QLabel(rec_text)
            rec.setWordWrap(True)
            rec.setStyleSheet(
                f"""
                color: {SUCCESS};
                font-size: {self.fs - 2}px;
                background: transparent;
                border: none;
                """
            )

            rec_layout.addWidget(rec, 1)

            card_layout.addWidget(rec_frame)

        return card


class AttackSummaryView(QWidget):
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
        self.init_ui()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)

        self.t = get_theme(self.dark)
        apply_theme_palette(self.t)

        self.BG = BG_MAIN
        self.BG_DEEP = BG_DEEP
        self.CARD = CARD_BG
        self.CARD2 = CARD_BG_2
        self.BORDER = BORDER
        self.BORDER_SOFT = BORDER_SOFT
        self.TEXT = TEXT_MAIN
        self.DIM = TEXT_MUTED
        self.SOFT = TEXT_SOFT

        self.ACCENT = ACCENT
        self.ACCENT_HOVER = ACCENT_HOVER
        self.ACCENT_DARK = ACCENT_DARK

        self.SUCCESS = SUCCESS
        self.WARNING = WARNING
        self.MEDIUM = MEDIUM_YELLOW
        self.INFO = INFO_BLUE
        self.PURPLE = PURPLE

        self.HOVER = HOVER_BG
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

        self.init_ui()

    # ─────────────────────────────────────────────
    # Data loading
    # ─────────────────────────────────────────────

    def load_data(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT tool, asset, severity, title,
                   description, recommendation
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
            (self.scan_id,)
        )

        rows = cursor.fetchall()

        self.findings = [
            {
                "tool": row[0],
                "asset": row[1],
                "severity": row[2],
                "title": row[3],
                "description": row[4] or "",
                "recommendation": row[5] or "",
            }
            for row in rows
        ]

        cursor.execute(
            """
            SELECT name, target, profile, created_at
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
                "created_at": str(row[3])[:16],
            }

        conn.close()

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
        layout.setContentsMargins(30, 22, 30, 30)
        layout.setSpacing(12)

        header = self.build_header()
        layout.addWidget(header)

        layout.addWidget(self.build_risk_score())
        layout.addWidget(self.build_stats_row())

        grouped = self.group_findings()

        if grouped["Critical"]:
            layout.addWidget(
                CollapsibleSection(
                    "Critical",
                    grouped["Critical"],
                    expanded=True,
                    theme=self.t,
                    font_size=self.fs,
                )
            )

        if grouped["High"]:
            layout.addWidget(
                CollapsibleSection(
                    "High",
                    grouped["High"],
                    expanded=True,
                    theme=self.t,
                    font_size=self.fs,
                )
            )

        if grouped["Medium"]:
            layout.addWidget(
                CollapsibleSection(
                    "Medium",
                    grouped["Medium"],
                    expanded=False,
                    theme=self.t,
                    font_size=self.fs,
                )
            )

        if grouped["Low"]:
            layout.addWidget(
                CollapsibleSection(
                    "Low",
                    grouped["Low"],
                    expanded=False,
                    theme=self.t,
                    font_size=self.fs,
                )
            )

        if grouped["Info"]:
            layout.addWidget(
                CollapsibleSection(
                    "Info",
                    grouped["Info"],
                    expanded=False,
                    theme=self.t,
                    font_size=self.fs,
                )
            )

        layout.addWidget(self.build_recommendations())

        scroll.setWidget(content)

        self.outer.addWidget(scroll)

    def group_findings(self):
        grouped = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Info": [],
        }

        for finding in self.findings:
            severity = finding.get("severity", "Info")

            if severity not in grouped:
                severity = "Info"

            if severity in ("Critical", "High", "Medium"):
                grouped[severity].append(finding)

            elif get_attack_path(
                finding.get("title", ""),
                finding.get("asset", "")
            ):
                grouped[severity].append(finding)

        return grouped

    def build_header(self):
        frame = QFrame()
        frame.setObjectName("headerCard")

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)

        layout.addWidget(back_btn)

        title_col = QVBoxLayout()
        title_col.setSpacing(3)

        title = QLabel("Attack Surface Summary")
        title.setObjectName("pageTitle")
        title_col.addWidget(title)

        target = self.scan_info.get("target", "Unknown")
        profile = self.scan_info.get("profile", "")
        date = self.scan_info.get("created_at", "")

        sub = QLabel(
            f"Target: {target}  •  Profile: {profile}  •  "
            f"Scan #{self.scan_id}  •  {date}"
        )
        sub.setObjectName("pageSub")
        sub.setWordWrap(True)
        title_col.addWidget(sub)

        layout.addLayout(title_col, 1)

        return frame

    def build_risk_score(self):
        score = calculate_risk_score(self.findings)
        label, color = get_risk_label(score)

        frame = QFrame()
        frame.setObjectName("siemCard")

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(28)

        left = QVBoxLayout()
        left.setSpacing(4)

        score_lbl = QLabel(f"{score}/100")
        score_lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs + 30}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )
        left.addWidget(score_lbl)

        risk_lbl = QLabel(label)
        risk_lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs}px;
            font-weight: 900;
            background: transparent;
            border: none;
            letter-spacing: 1px;
            """
        )
        left.addWidget(risk_lbl)

        desc = QLabel("Risk score based on finding severity weights")
        desc.setStyleSheet(
            f"""
            color: {self.DIM};
            font-size: {self.fs - 3}px;
            background: transparent;
            border: none;
            """
        )
        left.addWidget(desc)

        layout.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(7)

        bar = QProgressBar()
        bar.setMaximum(100)
        bar.setValue(score)
        bar.setFixedHeight(22)
        bar.setFixedWidth(390)
        bar.setTextVisible(False)
        bar.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: {self.BG_DEEP};
                border: 1px solid {self.BORDER};
                border-radius: 7px;
            }}

            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 7px;
            }}
            """
        )
        right.addWidget(bar)

        formula = QLabel(
            "Critical×20  +  High×8  +  Medium×3  +  Low×1  —  max 100"
        )
        formula.setStyleSheet(
            f"""
            color: {self.DIM};
            font-size: {self.fs - 3}px;
            background: transparent;
            border: none;
            """
        )
        right.addWidget(formula)

        layout.addLayout(right)
        layout.addStretch()

        return frame

    def build_stats_row(self):
        frame = QFrame()
        frame.setStyleSheet(
            """
            background: transparent;
            border: none;
            """
        )

        layout = QHBoxLayout(frame)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)

        counts = {}
        tools = set()

        for finding in self.findings:
            severity = finding.get("severity", "Info")
            tool = finding.get("tool", "")

            counts[severity] = counts.get(severity, 0) + 1

            if tool:
                tools.add(tool)

        stats = [
            ("Total Findings", str(len(self.findings)), INFO_BLUE),
            ("Critical", str(counts.get("Critical", 0)), BRAND_RED),
            ("High", str(counts.get("High", 0)), WARNING),
            ("Medium", str(counts.get("Medium", 0)), MEDIUM_YELLOW),
            ("Low", str(counts.get("Low", 0)), SUCCESS),
            ("Info", str(counts.get("Info", 0)), INFO_BLUE),
            ("Tools Run", str(len(tools)), PURPLE),
        ]

        for label, value, color in stats:
            card = self.make_stat_card(label, value, color)
            layout.addWidget(card)

        return frame

    def make_stat_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(
            f"""
            QFrame#statCard {{
                background-color: {CARD_BG};
                border: 1px solid {color};
                border-radius: 10px;
                min-width: 92px;
            }}

            QFrame#statCard:hover {{
                background-color: {CARD_BG_2};
                border: 1px solid {color};
            }}
            """
        )

        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)

        value_lbl = QLabel(value)
        value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs + 7}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )

        label_lbl = QLabel(label)
        label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label_lbl.setStyleSheet(
            f"""
            color: {TEXT_MUTED};
            font-size: {self.fs - 4}px;
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )

        layout.addWidget(value_lbl)
        layout.addWidget(label_lbl)

        return card

    def build_recommendations(self):
        frame = QFrame()
        frame.setObjectName("siemCard")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = QLabel("TOP RECOMMENDATIONS")
        title.setStyleSheet(
            f"""
            color: {TEXT_MUTED};
            font-size: {self.fs - 2}px;
            font-weight: 900;
            background: transparent;
            border: none;
            letter-spacing: 1px;
            """
        )
        layout.addWidget(title)

        critical_high = [
            finding for finding in self.findings
            if finding.get("severity") in ["Critical", "High"]
            and finding.get("recommendation")
        ][:8]

        if not critical_high:
            empty = QLabel(
                "No high-priority recommendations available for this scan."
            )
            empty.setStyleSheet(
                f"""
                color: {TEXT_MUTED};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
                """
            )
            layout.addWidget(empty)
            return frame

        for index, finding in enumerate(critical_high, 1):
            row = QHBoxLayout()
            row.setSpacing(8)

            num = QLabel(f"{index}.")
            num.setFixedWidth(22)
            num.setStyleSheet(
                f"""
                color: {ACCENT};
                font-size: {self.fs - 1}px;
                font-weight: 900;
                background: transparent;
                border: none;
                """
            )
            row.addWidget(num)

            severity = finding.get("severity", "Info")
            icon = SEVERITY_ICONS.get(severity, "🔵")

            recommendation = finding.get("recommendation", "")

            if len(recommendation) > 95:
                recommendation = recommendation[:95] + "..."

            text = QLabel(
                f"{icon}  {finding.get('title', 'Untitled')}  —  "
                f"{recommendation}"
            )
            text.setWordWrap(True)
            text.setStyleSheet(
                f"""
                color: {TEXT_MAIN};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
                """
            )

            row.addWidget(text, 1)
            layout.addLayout(row)

            if index < len(critical_high):
                divider = QFrame()
                divider.setFrameShape(QFrame.Shape.HLine)
                divider.setStyleSheet(
                    f"""
                    background: {BORDER};
                    border: none;
                    max-height: 1px;
                    """
                )
                layout.addWidget(divider)

        return frame

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
        return f"""
            QWidget {{
                background-color: {self.BG};
                color: {self.TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {self.fs}px;
            }}

            QScrollArea {{
                border: none;
                background: {self.BG};
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

            #headerCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}

            #headerCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}

            #siemCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 10px;
            }}

            #siemCard:hover {{
                background-color: {self.CARD2};
                border: 1px solid {self.CARD_HOVER};
            }}

            #pageTitle {{
                color: {self.ACCENT};
                font-size: {self.fs + 8}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #pageSub {{
                color: {self.DIM};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
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
        """
