import os
import re
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_qtagg import (
    FigureCanvasQTAgg as FigureCanvas
)
from matplotlib.figure import Figure
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QGridLayout
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

TOOL_COLORS = {
    'nmap':         '#4a9eff',
    'subfinder':    '#1d9e75',
    'httpx':        '#e94560',
    'whatweb':      '#ff8c00',
    'ffuf':         '#9b59b6',
    'nikto':        '#e74c3c',
    'theharvester': '#f39c12',
    'dnsrecon':     '#2ecc71',
    'gobuster':     '#3498db',
    'dirsearch':    '#e67e22',
    'wpscan':       '#1abc9c',
    'nuclei':       '#e94560',
}

TOOL_EMOJI = {
    'nmap':         '🔍',
    'subfinder':    '🌐',
    'httpx':        '📡',
    'whatweb':      '🕵️',
    'ffuf':         '💨',
    'nikto':        '🎯',
    'theharvester': '🌾',
    'dnsrecon':     '🔎',
    'gobuster':     '👻',
    'dirsearch':    '📂',
    'wpscan':       '🔒',
    'nuclei':       '⚡',
}

BG     = '#0d1117'
CARD   = '#161b22'
CARD2  = '#21262d'
BORDER = '#30363d'
TEXT   = '#e6edf3'
DIM    = '#8b949e'


class ChartsView(QWidget):
    def __init__(self, scan_id, on_close=None):
        super().__init__()
        self.scan_id   = scan_id
        self.on_close  = on_close
        self.findings  = []
        self.scan_info = {}
        self.setStyleSheet(self.get_stylesheet())
        self.load_data()
        self.init_ui()

    def load_data(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tool, severity, title, status,
                   asset, evidence, description
            FROM findings WHERE scan_id=?
        ''', (self.scan_id,))
        rows = cursor.fetchall()
        self.findings = [
            {
                'tool':        r[0],
                'severity':    r[1],
                'title':       r[2],
                'status':      r[3],
                'asset':       r[4] or '',
                'evidence':    r[5] or '',
                'description': r[6] or '',
            }
            for r in rows
        ]
        cursor.execute('''
            SELECT name, target, profile, status, created_at
            FROM scans WHERE id=?
        ''', (self.scan_id,))
        row = cursor.fetchone()
        if row:
            self.scan_info = {
                'name':       row[0],
                'target':     row[1],
                'profile':    row[2],
                'status':     row[3],
                'created_at': row[4],
            }
        cursor.execute('''
            SELECT tool, status FROM tool_runs
            WHERE scan_id=?
        ''', (self.scan_id,))
        self.tool_runs = {
            r[0]: r[1] for r in cursor.fetchall()
        }
        conn.close()

    def compute_attack_surface(self):
        findings = self.findings

        # ── Count open ports ──────────────────────────────
        port_findings = [
            f for f in findings if f['tool'] == 'nmap'
        ]
        open_ports = len(port_findings)

        # ── Count subdomains ──────────────────────────────
        subdomain_findings = [
            f for f in findings
            if f['tool'] in ('subfinder', 'dnsrecon')
        ]
        subdomains = len(subdomain_findings)

        # ── Count Critical/High ───────────────────────────
        ch_count = sum(
            1 for f in findings
            if f['severity'] in ('Critical', 'High')
        )

        # ── Count emails ──────────────────────────────────
        email_findings = [
            f for f in findings
            if f['tool'] == 'theharvester'
        ]
        emails = len(email_findings)

        # ── Extract technologies from all tools ───────────
        technologies  = []
        insecure_tech = []
        insecure_keywords = [
            'telnet', 'ftp', 'rsh', 'rlogin',
            'cleartext', 'unencrypted', 'plaintext',
            'backdoor', 'default credential',
            'anonymous', 'no authentication',
        ]

        for f in findings:
            if f['tool'] != 'whatweb':
                continue
            title = f['title']
            if title and title not in technologies:
                technologies.append(title)

        for f in port_findings:
            title = f['title']
            if title and title not in technologies:
                technologies.append(title)
            t_lower = title.lower()
            for kw in insecure_keywords:
                if kw in t_lower:
                    if title not in insecure_tech:
                        insecure_tech.append(title)

        for f in findings:
            if f['tool'] not in ('nuclei', 'nikto'):
                continue
            title = f['title']
            if title and title not in technologies:
                technologies.append(title)
            desc_lower = (
                f['description'] + ' ' + f['evidence']
            ).lower()
            for kw in insecure_keywords:
                if (
                    kw in desc_lower or
                    kw in title.lower()
                ):
                    if title not in insecure_tech:
                        insecure_tech.append(title)

        for f in findings:
            if f['tool'] != 'httpx':
                continue
            title = f['title']
            if title and title not in technologies:
                technologies.append(title)

        # ── Score components ──────────────────────────────
        port_score  = min(25, int(open_ports * 1.5))
        sub_score   = min(20, int(subdomains * 1.3))
        vuln_score  = min(35, ch_count * 4)
        tech_score  = min(15, len(insecure_tech) * 5)
        email_score = min(5,  emails)

        total_score = min(100, (
            port_score + sub_score +
            vuln_score + tech_score + email_score
        ))

        score_breakdown = [
            (
                'Port Exposure',
                port_score, 25,
                f"{open_ports} open ports × 1.5",
                '#ff8c00'
            ),
            (
                'Subdomain Footprint',
                sub_score, 20,
                f"{subdomains} subdomains × 1.3",
                '#4a9eff'
            ),
            (
                'Vulnerability Density',
                vuln_score, 35,
                f"{ch_count} Critical/High × 4",
                '#e94560'
            ),
            (
                'Insecure Services',
                tech_score, 15,
                f"{len(insecure_tech)} insecure × 5",
                '#ff4444'
            ),
            (
                'Email Exposure',
                email_score, 5,
                f"{emails} emails harvested",
                '#1d9e75'
            ),
        ]

        # ── Rating ────────────────────────────────────────
        if total_score >= 70:
            rating       = 'CRITICAL'
            rating_color = '#8b0000'
        elif total_score >= 50:
            rating       = 'HIGH RISK'
            rating_color = '#e94560'
        elif total_score >= 30:
            rating       = 'MEDIUM RISK'
            rating_color = '#ff8c00'
        else:
            rating       = 'LOW RISK'
            rating_color = '#ffd700'

        def level(val, thresholds):
            low, med, high = thresholds
            if val >= high:
                return ('High',    '#e94560', val / high)
            elif val >= med:
                return ('Medium',  '#ff8c00', val / high)
            elif val >= low:
                return ('Low',     '#ffd700', val / high)
            return     ('Minimal', DIM,       0.05)

        metrics = [
            ('Port Exposure',
             level(open_ports,        (3,  8,  15))),
            ('Subdomain Footprint',
             level(subdomains,         (3,  8,  15))),
            ('Vulnerability Density',
             level(ch_count,           (1,  4,  10))),
            ('Insecure Services',
             level(len(insecure_tech), (1,  2,   4))),
            ('Email Exposure',
             level(emails,            (1,  3,   6))),
        ]

        return {
            'score':           total_score,
            'rating':          rating,
            'rating_color':    rating_color,
            'open_ports':      open_ports,
            'subdomains':      subdomains,
            'ch_count':        ch_count,
            'technologies':    technologies,
            'insecure_tech':   insecure_tech,
            'emails':          emails,
            'metrics':         metrics,
            'score_breakdown': score_breakdown,
        }

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
        layout.setContentsMargins(24, 16, 24, 24)
        layout.setSpacing(12)

        top_row  = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        title = QLabel(
            "AutoRed — Security Findings Dashboard"
        )
        title.setObjectName("dashTitle")
        layout.addWidget(title)

        target  = self.scan_info.get('target', '')
        profile = self.scan_info.get('profile', '')
        date    = str(
            self.scan_info.get('created_at', '')
        )[:16]
        sub = QLabel(
            f"Scan #{self.scan_id}  ·  "
            f"Target: {target}  ·  "
            f"Profile: {profile}  ·  "
            f"{len(self.findings)} findings  ·  {date}"
        )
        sub.setObjectName("dashSub")
        layout.addWidget(sub)
        layout.addSpacing(4)

        layout.addLayout(self.build_stat_cards())
        layout.addLayout(self.build_middle_row())
        layout.addLayout(self.build_bottom_row())

        as_header = QLabel("ATTACK SURFACE ANALYSIS")
        as_header.setObjectName("sectionHeader")
        layout.addWidget(as_header)
        layout.addLayout(self.build_attack_surface_row())

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def make_card(self, title_text,
                  widget=None, min_h=None):
        card = QFrame()
        card.setObjectName("siemCard")
        if min_h:
            card.setMinimumHeight(min_h)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)
        t = QLabel(title_text.upper())
        t.setObjectName("cardTitle")
        cl.addWidget(t)
        if widget:
            cl.addWidget(widget)
        return card, cl

    def build_stat_cards(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        counts = {}
        for f in self.findings:
            counts[f['severity']] = (
                counts.get(f['severity'], 0) + 1
            )

        tool_counts = {}
        for f in self.findings:
            tool_counts[f['tool']] = (
                tool_counts.get(f['tool'], 0) + 1
            )

        critical = counts.get('Critical', 0)
        high     = counts.get('High', 0)
        ports    = sum(
            1 for f in self.findings
            if f['tool'] == 'nmap'
        )

        stats = [
            (
                "Total Findings",
                str(len(self.findings)),
                "#4a9eff",
                "across all tools"
            ),
            (
                "Critical & High",
                str(critical + high),
                "#e94560",
                f"{critical} critical · {high} high"
            ),
            (
                "Open Ports",
                str(ports),
                "#ff8c00",
                "detected by Nmap"
            ),
            (
                "Tools Run",
                str(len(tool_counts)),
                "#1d9e75",
                "of 12 available"
            ),
        ]

        for label, value, color, sub_text in stats:
            card = QFrame()
            card.setObjectName("siemCard")
            cl   = QVBoxLayout(card)
            cl.setContentsMargins(14, 12, 14, 12)

            lbl = QLabel(label.upper())
            lbl.setObjectName("cardTitle")
            cl.addWidget(lbl)

            num = QLabel(value)
            num.setStyleSheet(
                f"font-size: 28px; font-weight: bold; "
                f"color: {color}; "
                f"background: transparent; border: none;"
            )
            cl.addWidget(num)

            sub = QLabel(sub_text)
            sub.setStyleSheet(
                f"font-size: 10px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            cl.addWidget(sub)
            row.addWidget(card)

        return row

    def build_middle_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(self.build_severity_card(), 1)
        row.addWidget(self.build_tool_bar_card(), 2)
        row.addWidget(self.build_critical_table(), 2)
        return row

    def build_severity_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(220)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        t = QLabel("SEVERITY BREAKDOWN")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        counts = {}
        for f in self.findings:
            counts[f['severity']] = (
                counts.get(f['severity'], 0) + 1
            )
        total = len(self.findings) or 1

        sev_row = QHBoxLayout()
        sev_row.setSpacing(4)
        for sev, color in SEVERITY_COLORS.items():
            count = counts.get(sev, 0)
            block = QFrame()
            block.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 5px; border: none;"
            )
            bl = QVBoxLayout(block)
            bl.setContentsMargins(4, 6, 4, 6)
            bl.setSpacing(1)

            num = QLabel(str(count))
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num.setStyleSheet(
                f"font-size: 16px; font-weight: bold; "
                f"color: {color}; "
                f"background: transparent; border: none;"
            )
            lbl = QLabel(sev[:4])
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"font-size: 9px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            bl.addWidget(num)
            bl.addWidget(lbl)
            sev_row.addWidget(block)

        cl.addLayout(sev_row)
        canvas = self.create_severity_mini_chart(
            counts, total
        )
        cl.addWidget(canvas)
        return card

    def create_severity_mini_chart(self, counts, total):
        fig = Figure(figsize=(3, 1.8), facecolor=CARD)
        ax  = fig.add_subplot(111)
        ax.set_facecolor(CARD)

        sevs   = ['Critical', 'High', 'Medium', 'Low', 'Info']
        vals   = [counts.get(s, 0) for s in sevs]
        colors = [SEVERITY_COLORS[s] for s in sevs]

        if any(v > 0 for v in vals):
            bars = ax.bar(
                [s[:4] for s in sevs], vals,
                color=colors, width=0.6
            )
            for bar, val in zip(bars, vals):
                if val > 0:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.3,
                        str(val),
                        ha='center', va='bottom',
                        color=TEXT, fontsize=7
                    )

        ax.set_facecolor(CARD)
        ax.tick_params(colors=DIM, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(BORDER)
        ax.yaxis.grid(
            True, color=BORDER,
            linestyle='--', alpha=0.4
        )
        ax.set_axisbelow(True)
        fig.tight_layout(pad=0.3)

        canvas = FigureCanvas(fig)
        canvas.setStyleSheet(f"background-color: {CARD};")
        return canvas

    def build_tool_bar_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(220)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        t = QLabel("FINDINGS BY TOOL")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        tool_counts = {}
        for f in self.findings:
            tool_counts[f['tool']] = (
                tool_counts.get(f['tool'], 0) + 1
            )
        sorted_tools = sorted(
            tool_counts.items(),
            key=lambda x: x[1], reverse=True
        )
        max_val = (
            max(tool_counts.values())
            if tool_counts else 1
        )

        bar_widget = QWidget()
        bar_widget.setStyleSheet("background: transparent;")
        bar_layout = QVBoxLayout(bar_widget)
        bar_layout.setContentsMargins(0, 0, 0, 0)
        bar_layout.setSpacing(5)

        for tool, count in sorted_tools:
            row = QHBoxLayout()
            row.setSpacing(6)

            lbl = QLabel(tool)
            lbl.setFixedWidth(80)
            lbl.setStyleSheet(
                f"font-size: 10px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            lbl.setAlignment(
                Qt.AlignmentFlag.AlignRight |
                Qt.AlignmentFlag.AlignVCenter
            )
            row.addWidget(lbl)

            track = QFrame()
            track.setFixedHeight(12)
            track.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 3px; border: none;"
            )
            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill_pct = int((count / max_val) * 100)
            fill     = QFrame()
            fill.setStyleSheet(
                f"background: "
                f"{TOOL_COLORS.get(tool, '#4a9eff')}; "
                f"border-radius: 3px; border: none;"
            )
            fill.setFixedWidth(
                max(4, int(fill_pct * 2.2))
            )
            track_l.addWidget(fill)
            track_l.addStretch()
            row.addWidget(track, 1)

            val_lbl = QLabel(str(count))
            val_lbl.setFixedWidth(24)
            val_lbl.setStyleSheet(
                f"font-size: 10px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            row.addWidget(val_lbl)
            bar_layout.addLayout(row)

        cl.addWidget(bar_widget)
        return card

    def build_critical_table(self):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(220)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        t = QLabel("CRITICAL FINDINGS")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(
            ['Finding', 'Tool', 'Sev']
        )
        table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        table.setColumnWidth(1, 70)
        table.setColumnWidth(2, 55)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        table.setStyleSheet(f"""
            QTableWidget {{
                background: {CARD};
                border: none;
                gridline-color: {CARD2};
                font-size: 10px;
                color: {TEXT};
            }}
            QHeaderView::section {{
                background: {CARD2};
                color: {DIM};
                padding: 4px;
                border: none;
                font-size: 9px;
                font-weight: bold;
            }}
            QTableWidget::item {{
                padding: 3px 6px;
                background: {CARD};
            }}
            QTableWidget::item:selected {{
                background: {CARD2};
            }}
        """)

        crits = [
            f for f in self.findings
            if f['severity'] in ['Critical', 'High']
        ]
        crits.sort(
            key=lambda x: (
                0 if x['severity'] == 'Critical' else 1
            )
        )

        for f in crits[:10]:
            row        = table.rowCount()
            table.insertRow(row)
            title_short = (
                f['title'][:35] + '..'
                if len(f['title']) > 35
                else f['title']
            )
            title_item = QTableWidgetItem(title_short)
            tool_item  = QTableWidgetItem(f['tool'])
            sev_item   = QTableWidgetItem(f['severity'])
            color = SEVERITY_COLORS.get(
                f['severity'], '#888'
            )
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            tool_item.setForeground(QColor(DIM))
            tool_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            table.setItem(row, 0, title_item)
            table.setItem(row, 1, tool_item)
            table.setItem(row, 2, sev_item)
            table.setRowHeight(row, 26)

        cl.addWidget(table)
        return card

    def build_bottom_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(self.build_stacked_bar_card(), 3)
        row.addWidget(self.build_tool_status_card(), 2)
        return row

    def build_stacked_bar_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        t = QLabel("SEVERITY DISTRIBUTION PER TOOL")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        tool_sev = {}
        for f in self.findings:
            tool = f['tool']
            sev  = f['severity']
            if tool not in tool_sev:
                tool_sev[tool] = {}
            tool_sev[tool][sev] = (
                tool_sev[tool].get(sev, 0) + 1
            )

        tools = sorted(
            tool_sev.keys(),
            key=lambda t: sum(tool_sev[t].values()),
            reverse=True
        )
        sevs = [
            'Critical', 'High', 'Medium', 'Low', 'Info'
        ]

        fig = Figure(figsize=(8, 2.8), facecolor=CARD)
        ax  = fig.add_subplot(111)
        ax.set_facecolor(BG)

        if tools:
            bottoms = [0] * len(tools)
            for sev in sevs:
                vals = [
                    tool_sev[t].get(sev, 0)
                    for t in tools
                ]
                if any(v > 0 for v in vals):
                    ax.bar(
                        tools, vals, bottom=bottoms,
                        color=SEVERITY_COLORS[sev],
                        label=sev, width=0.55
                    )
                    bottoms = [
                        b + v
                        for b, v in zip(bottoms, vals)
                    ]

            ax.set_xlabel('Tool', color=DIM, fontsize=8)
            ax.set_ylabel(
                'Findings', color=DIM, fontsize=8
            )
            ax.tick_params(
                colors=TEXT, labelsize=7, axis='y'
            )
            ax.tick_params(
                colors=TEXT, labelsize=7,
                axis='x', rotation=25
            )
            for spine in ax.spines.values():
                spine.set_color(BORDER)
            ax.yaxis.grid(
                True, color=BORDER,
                linestyle='--', alpha=0.4
            )
            ax.set_axisbelow(True)
            ax.legend(
                loc='upper right',
                facecolor=CARD, edgecolor=BORDER,
                labelcolor=TEXT, fontsize=7,
                framealpha=0.9
            )

        fig.tight_layout(pad=0.5)
        canvas = FigureCanvas(fig)
        canvas.setStyleSheet(f"background-color: {CARD};")
        cl.addWidget(canvas)
        return card

    def build_tool_status_card(self):
        card = QFrame()
        card.setObjectName("siemCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        t = QLabel("TOOLS STATUS")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        tool_counts = {}
        for f in self.findings:
            tool_counts[f['tool']] = (
                tool_counts.get(f['tool'], 0) + 1
            )

        grid      = QGridLayout()
        grid.setSpacing(6)
        all_tools = [
            'nmap',         'subfinder',    'httpx',
            'whatweb',      'ffuf',         'nikto',
            'theharvester', 'dnsrecon',     'gobuster',
            'dirsearch',    'wpscan',       'nuclei',
        ]

        for i, tool in enumerate(all_tools):
            cell = QFrame()
            cell.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 6px; border: none;"
            )
            cl2 = QVBoxLayout(cell)
            cl2.setContentsMargins(8, 6, 8, 6)
            cl2.setSpacing(1)

            emoji    = TOOL_EMOJI.get(tool, '🔧')
            name_lbl = QLabel(f"{emoji} {tool}")
            name_lbl.setStyleSheet(
                f"font-size: 9px; font-weight: bold; "
                f"color: {TEXT}; "
                f"background: transparent; border: none;"
            )
            cl2.addWidget(name_lbl)

            count = tool_counts.get(tool, 0)
            clr   = '#e94560' if count > 0 else DIM
            count_lbl = QLabel(str(count))
            count_lbl.setStyleSheet(
                f"font-size: 14px; font-weight: bold; "
                f"color: {clr}; "
                f"background: transparent; border: none;"
            )
            cl2.addWidget(count_lbl)

            run_status = self.tool_runs.get(tool, '')
            if run_status == 'completed':
                status_text  = '✓ Done'
                status_color = '#3fb950'
            elif run_status in (
                'failed', 'timeout', 'error'
            ):
                status_text  = '✗ Failed'
                status_color = '#e94560'
            elif count > 0:
                status_text  = '✓ Done'
                status_color = '#3fb950'
            else:
                status_text  = '— Not run'
                status_color = DIM

            status_lbl = QLabel(status_text)
            status_lbl.setStyleSheet(
                f"font-size: 9px; color: {status_color}; "
                f"background: transparent; border: none;"
            )
            cl2.addWidget(status_lbl)
            grid.addWidget(cell, i // 3, i % 3)

        cl.addLayout(grid)
        return card

    # ── Attack Surface Score ──────────────────────────────

    def build_attack_surface_row(self):
        data = self.compute_attack_surface()
        row  = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(self.build_score_card(data), 2)
        row.addWidget(
            self.build_score_explanation(data), 2
        )
        row.addWidget(self.build_metrics_card(data), 2)
        return row

    def build_score_card(self, data):
        card = QFrame()
        card.setObjectName("siemCard")
        card.setMinimumHeight(300)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(8)

        t = QLabel("ATTACK SURFACE SCORE")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        score = data['score']
        color = data['rating_color']

        import numpy as np
        fig = Figure(figsize=(3, 2.2), facecolor=CARD)
        ax  = fig.add_subplot(111)
        ax.set_facecolor(CARD)
        ax.set_xlim(-1.3, 1.3)
        ax.set_ylim(-1.3, 1.3)
        ax.set_aspect('equal')
        ax.axis('off')

        theta_full = np.linspace(
            np.pi * 1.25, -np.pi * 0.25, 200
        )
        ax.plot(
            np.cos(theta_full), np.sin(theta_full),
            color=CARD2, linewidth=10,
            solid_capstyle='round'
        )
        frac        = score / 100.0
        theta_score = np.linspace(
            np.pi * 1.25,
            np.pi * 1.25 - frac * np.pi * 1.5,
            200
        )
        ax.plot(
            np.cos(theta_score), np.sin(theta_score),
            color=color, linewidth=10,
            solid_capstyle='round'
        )
        ax.text(
            0, 0.1, str(score),
            ha='center', va='center',
            color=TEXT, fontsize=22, fontweight='bold'
        )
        ax.text(
            0, -0.35, '/100',
            ha='center', va='center',
            color=DIM, fontsize=10
        )

        fig.tight_layout(pad=0.2)
        canvas = FigureCanvas(fig)
        canvas.setStyleSheet(f"background-color: {CARD};")
        canvas.setFixedHeight(160)
        cl.addWidget(canvas)

        rating_lbl = QLabel(data['rating'])
        rating_lbl.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        rating_lbl.setStyleSheet(
            f"font-size: 16px; font-weight: bold; "
            f"color: {color}; "
            f"background: transparent; border: none;"
        )
        cl.addWidget(rating_lbl)

        breakdown_row = QHBoxLayout()
        breakdown_row.setSpacing(6)
        items = [
            (str(data['open_ports']),  'Ports',      '#ff8c00'),
            (str(data['subdomains']),  'Subdomains', '#4a9eff'),
            (str(data['ch_count']),    'C/H Vulns',  '#e94560'),
            (str(data['emails']),      'Emails',     '#1d9e75'),
        ]
        for val, lbl, col in items:
            block = QFrame()
            block.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 4px; border: none;"
            )
            bl = QVBoxLayout(block)
            bl.setContentsMargins(6, 4, 6, 4)
            bl.setSpacing(1)

            v = QLabel(val)
            v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.setStyleSheet(
                f"font-size: 13px; font-weight: bold; "
                f"color: {col}; "
                f"background: transparent; border: none;"
            )
            l = QLabel(lbl)
            l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            l.setStyleSheet(
                f"font-size: 8px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            bl.addWidget(v)
            bl.addWidget(l)
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

        t = QLabel("HOW SCORE WAS CALCULATED")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        total = data['score']
        color = data['rating_color']

        formula_lbl = QLabel(
            f"Total Score = {total}/100"
        )
        formula_lbl.setStyleSheet(
            f"font-size: 13px; font-weight: bold; "
            f"color: {color}; "
            f"background: transparent; border: none;"
        )
        cl.addWidget(formula_lbl)

        for (name, pts, max_pts,
             formula, col) in data['score_breakdown']:

            row = QHBoxLayout()
            row.setSpacing(8)

            info_col = QVBoxLayout()
            info_col.setSpacing(1)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(
                f"font-size: 11px; font-weight: bold; "
                f"color: {TEXT}; "
                f"background: transparent; border: none;"
            )
            info_col.addWidget(name_lbl)

            formula_txt = QLabel(formula)
            formula_txt.setStyleSheet(
                f"font-size: 9px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            info_col.addWidget(formula_txt)
            row.addLayout(info_col)
            row.addStretch()

            pts_frame = QFrame()
            pts_frame.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 4px; border: none;"
            )
            pts_l = QHBoxLayout(pts_frame)
            pts_l.setContentsMargins(8, 4, 8, 4)

            pts_lbl = QLabel(f"{pts} pts")
            pts_lbl.setStyleSheet(
                f"font-size: 12px; font-weight: bold; "
                f"color: {col}; "
                f"background: transparent; border: none;"
            )
            pts_l.addWidget(pts_lbl)
            row.addWidget(pts_frame)
            cl.addLayout(row)

            track = QFrame()
            track.setFixedHeight(4)
            track.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 2px; border: none;"
            )
            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill_w = max(
                4,
                int((pts / max(max_pts, 1)) * 180)
            )
            fill = QFrame()
            fill.setStyleSheet(
                f"background: {col}; "
                f"border-radius: 2px; border: none;"
            )
            fill.setFixedWidth(fill_w)
            track_l.addWidget(fill)
            track_l.addStretch()
            cl.addWidget(track)

        cl.addStretch()

        score = data['score']
        if score >= 70:
            why = (
                "Score ≥ 70 → CRITICAL. "
                "Target has extensive open services, "
                "multiple critical vulnerabilities, "
                "and a large subdomain footprint."
            )
        elif score >= 50:
            why = (
                "Score ≥ 50 → HIGH RISK. "
                "Significant vulnerabilities and "
                "exposed services detected."
            )
        elif score >= 30:
            why = (
                "Score ≥ 30 → MEDIUM RISK. "
                "Some exposure detected but limited "
                "critical findings."
            )
        else:
            why = (
                "Score < 30 → LOW RISK. "
                "Minimal exposed services and "
                "few vulnerabilities found."
            )

        why_lbl = QLabel(why)
        why_lbl.setWordWrap(True)
        why_lbl.setStyleSheet(
            f"font-size: 10px; color: {DIM}; "
            f"background: {CARD2}; border: none; "
            f"border-radius: 4px; padding: 8px;"
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

        t = QLabel("EXPOSURE METRICS")
        t.setObjectName("cardTitle")
        cl.addWidget(t)

        for metric_name, (
            level, color, pct
        ) in data['metrics']:
            row = QHBoxLayout()
            row.setSpacing(8)

            name_lbl = QLabel(metric_name)
            name_lbl.setFixedWidth(160)
            name_lbl.setStyleSheet(
                f"font-size: 11px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            row.addWidget(name_lbl)

            track = QFrame()
            track.setFixedHeight(8)
            track.setStyleSheet(
                f"background: {CARD2}; "
                f"border-radius: 4px; border: none;"
            )
            track_l = QHBoxLayout(track)
            track_l.setContentsMargins(0, 0, 0, 0)

            fill = QFrame()
            fill.setStyleSheet(
                f"background: {color}; "
                f"border-radius: 4px; border: none;"
            )
            fill_w = max(6, int(min(pct, 1.0) * 140))
            fill.setFixedWidth(fill_w)
            track_l.addWidget(fill)
            track_l.addStretch()
            row.addWidget(track, 1)

            lv_lbl = QLabel(level)
            lv_lbl.setFixedWidth(55)
            lv_lbl.setAlignment(
                Qt.AlignmentFlag.AlignRight
            )
            lv_lbl.setStyleSheet(
                f"font-size: 11px; font-weight: bold; "
                f"color: {color}; "
                f"background: transparent; border: none;"
            )
            row.addWidget(lv_lbl)
            cl.addLayout(row)

        cl.addStretch()

        score = data['score']
        if score >= 70:
            desc = (
                "Target has critical attack surface. "
                "Immediate remediation required."
            )
        elif score >= 50:
            desc = (
                "Significant exposure detected. "
                "High-priority findings need attention."
            )
        elif score >= 30:
            desc = (
                "Moderate exposure. "
                "Review and address medium/high findings."
            )
        else:
            desc = (
                "Low exposure detected. "
                "Continue monitoring for changes."
            )

        # ── Recommendations ───────────────────────────────
        recs_lbl = QLabel("TOP RECOMMENDATIONS")
        recs_lbl.setObjectName("cardTitle")
        recs_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px; "
            f"background: transparent; border: none; "
            f"margin-top: 4px;"
        )
        cl.addWidget(recs_lbl)

        recs = self.generate_recommendations(data)
        for rec in recs[:3]:
            rec_frame = QFrame()
            rec_frame.setStyleSheet(
                f"background: {CARD2}; "
                f"border-left: 3px solid #e94560; "
                f"border-radius: 0; padding: 0;"
            )
            rec_l = QVBoxLayout(rec_frame)
            rec_l.setContentsMargins(10, 6, 8, 6)
            rec_txt = QLabel(rec)
            rec_txt.setWordWrap(True)
            rec_txt.setStyleSheet(
                f"font-size: 10px; color: {TEXT}; "
                f"background: transparent; border: none;"
            )
            rec_l.addWidget(rec_txt)
            cl.addWidget(rec_frame)

        return card

    def generate_recommendations(self, data):
        recs = []

        if data['open_ports'] > 10:
            recs.append(
                f"Reduce port exposure — "
                f"{data['open_ports']} open ports "
                f"detected. Close unnecessary services."
            )

        if data['insecure_tech']:
            names = ', '.join(data['insecure_tech'][:3])
            recs.append(
                f"Disable insecure services: {names}. "
                f"These transmit data in cleartext."
            )

        if data['ch_count'] > 0:
            recs.append(
                f"Remediate {data['ch_count']} "
                f"Critical/High findings — "
                f"prioritise by CVSS score."
            )

        if data['subdomains'] > 10:
            recs.append(
                f"Audit subdomain footprint — "
                f"{data['subdomains']} subdomains found. "
                f"Decommission unused ones."
            )

        if data['emails'] > 5:
            recs.append(
                f"{data['emails']} email addresses "
                f"exposed via OSINT. "
                f"Consider email protection."
            )

        if not recs:
            recs.append(
                "Attack surface appears low. "
                "Continue monitoring for changes."
            )

        return recs

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
            #dashTitle {{
                color: #e94560;
                font-size: 18px;
                font-weight: bold;
                background: transparent;
                border: none;
            }}
            #dashSub {{
                color: {DIM};
                font-size: 11px;
                background: transparent;
                border: none;
            }}
            #sectionHeader {{
                color: #e94560;
                font-size: 13px;
                font-weight: bold;
                background: transparent;
                border: none;
                margin-top: 8px;
                letter-spacing: 1px;
            }}
            #siemCard {{
                background-color: {CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            #cardTitle {{
                color: {DIM};
                font-size: 10px;
                font-weight: bold;
                background: transparent;
                border: none;
                letter-spacing: 1px;
            }}
            #backBtn {{
                background-color: transparent;
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
