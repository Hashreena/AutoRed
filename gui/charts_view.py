import os
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
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
    'nmap': '🔍', 'subfinder': '🌐', 'httpx': '📡',
    'whatweb': '🕵️', 'ffuf': '💨', 'nikto': '🎯',
    'theharvester': '🌾', 'dnsrecon': '🔎', 'gobuster': '👻',
    'dirsearch': '📂', 'wpscan': '🔒', 'nuclei': '⚡',
}

BG      = '#0d1117'
CARD    = '#161b22'
CARD2   = '#21262d'
BORDER  = '#30363d'
TEXT    = '#e6edf3'
DIM     = '#8b949e'


class ChartsView(QWidget):
    def __init__(self, scan_id, on_close=None):
        super().__init__()
        self.scan_id = scan_id
        self.on_close = on_close
        self.findings = []
        self.scan_info = {}
        self.setStyleSheet(self.get_stylesheet())
        self.load_data()
        self.init_ui()

    def load_data(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tool, severity, title, status
            FROM findings WHERE scan_id=?
        ''', (self.scan_id,))
        rows = cursor.fetchall()
        self.findings = [
            {'tool': r[0], 'severity': r[1],
             'title': r[2], 'status': r[3]}
            for r in rows
        ]

        cursor.execute('''
            SELECT name, target, profile, status, created_at
            FROM scans WHERE id=?
        ''', (self.scan_id,))
        row = cursor.fetchone()
        if row:
            self.scan_info = {
                'name': row[0], 'target': row[1],
                'profile': row[2], 'status': row[3],
                'created_at': row[4]
            }

        cursor.execute('''
            SELECT tool, status FROM tool_runs
            WHERE scan_id=?
        ''', (self.scan_id,))
        self.tool_runs = {r[0]: r[1] for r in cursor.fetchall()}
        conn.close()

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            f"QScrollArea {{ border: none; background: {BG}; }}"
        )

        content = QWidget()
        content.setStyleSheet(f"background: {BG};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 16, 24, 24)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        title = QLabel(
            f"AutoRed — Security Findings Dashboard"
        )
        title.setObjectName("dashTitle")
        layout.addWidget(title)

        target = self.scan_info.get('target', '')
        profile = self.scan_info.get('profile', '')
        date = str(self.scan_info.get('created_at', ''))[:16]
        sub = QLabel(
            f"Scan #{self.scan_id}  ·  Target: {target}  ·  "
            f"Profile: {profile}  ·  {len(self.findings)} findings  ·  {date}"
        )
        sub.setObjectName("dashSub")
        layout.addWidget(sub)
        layout.addSpacing(4)

        layout.addLayout(self.build_stat_cards())
        layout.addLayout(self.build_middle_row())
        layout.addLayout(self.build_bottom_row())

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def make_card(self, title_text, widget=None, min_h=None):
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
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

        tool_counts = {}
        for f in self.findings:
            tool_counts[f['tool']] = tool_counts.get(f['tool'], 0) + 1

        critical = counts.get('Critical', 0)
        high     = counts.get('High', 0)
        ports    = sum(
            1 for f in self.findings
            if f['tool'] == 'nmap'
        )

        stats = [
            ("Total Findings",   str(len(self.findings)),
             "#4a9eff",          "across all tools"),
            ("Critical & High",  str(critical + high),
             "#e94560",          f"{critical} critical · {high} high"),
            ("Open Ports",       str(ports),
             "#ff8c00",          "detected by Nmap"),
            ("Tools Run",        str(len(tool_counts)),
             "#1d9e75",          f"of 12 available"),
        ]

        for label, value, color, sub_text in stats:
            card = QFrame()
            card.setObjectName("siemCard")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 12, 14, 12)

            lbl = QLabel(label.upper())
            lbl.setObjectName("cardTitle")
            cl.addWidget(lbl)

            num = QLabel(value)
            num.setStyleSheet(
                f"font-size: 28px; font-weight: bold; "
                f"color: {color}; background: transparent; border: none;"
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
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

        total = len(self.findings) or 1

        sev_row = QHBoxLayout()
        sev_row.setSpacing(4)
        for sev, color in SEVERITY_COLORS.items():
            count = counts.get(sev, 0)
            block = QFrame()
            block.setStyleSheet(
                f"background: {CARD2}; border-radius: 5px; border: none;"
            )
            bl = QVBoxLayout(block)
            bl.setContentsMargins(4, 6, 4, 6)
            bl.setSpacing(1)

            num = QLabel(str(count))
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num.setStyleSheet(
                f"font-size: 16px; font-weight: bold; "
                f"color: {color}; background: transparent; border: none;"
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

        canvas = self.create_severity_mini_chart(counts, total)
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
                        bar.get_x() + bar.get_width()/2,
                        bar.get_height() + 0.3,
                        str(val),
                        ha='center', va='bottom',
                        color=TEXT, fontsize=7
                    )

        ax.set_facecolor(CARD)
        ax.tick_params(colors=DIM, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(BORDER)
        ax.yaxis.grid(True, color=BORDER, linestyle='--', alpha=0.4)
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
            tool_counts[f['tool']] = tool_counts.get(f['tool'], 0) + 1

        sorted_tools = sorted(
            tool_counts.items(), key=lambda x: x[1], reverse=True
        )
        max_val = max(tool_counts.values()) if tool_counts else 1

        bar_widget = QWidget()
        bar_widget.setStyleSheet(f"background: transparent;")
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
                f"background: transparent; border: none; "
                f"text-align: right;"
            )
            lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(lbl)

            track = QFrame()
            track.setFixedHeight(12)
            track.setStyleSheet(
                f"background: {CARD2}; border-radius: 3px; border: none;"
            )
            track_layout = QHBoxLayout(track)
            track_layout.setContentsMargins(0, 0, 0, 0)

            fill_pct = int((count / max_val) * 100)
            fill = QFrame()
            fill.setStyleSheet(
                f"background: {TOOL_COLORS.get(tool, '#4a9eff')}; "
                f"border-radius: 3px; border: none;"
            )
            fill.setFixedWidth(max(4, int(fill_pct * 2.2)))
            track_layout.addWidget(fill)
            track_layout.addStretch()

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
        table.setHorizontalHeaderLabels(['Finding', 'Tool', 'Sev'])
        table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        table.setColumnWidth(1, 70)
        table.setColumnWidth(2, 55)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
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
        crits.sort(key=lambda x: (
            0 if x['severity'] == 'Critical' else 1
        ))

        for f in crits[:10]:
            row = table.rowCount()
            table.insertRow(row)

            title_short = f['title'][:35] + '..' \
                if len(f['title']) > 35 else f['title']
            title_item = QTableWidgetItem(title_short)
            tool_item = QTableWidgetItem(f['tool'])
            sev_item = QTableWidgetItem(f['severity'])

            color = SEVERITY_COLORS.get(f['severity'], '#888')
            sev_item.setForeground(QColor(color))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            tool_item.setForeground(QColor(DIM))
            tool_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

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
            tool_sev[tool][sev] = tool_sev[tool].get(sev, 0) + 1

        tools = sorted(
            tool_sev.keys(),
            key=lambda t: sum(tool_sev[t].values()),
            reverse=True
        )
        sevs = ['Critical', 'High', 'Medium', 'Low', 'Info']

        fig = Figure(figsize=(8, 2.8), facecolor=CARD)
        ax  = fig.add_subplot(111)
        ax.set_facecolor(BG)

        if tools:
            bottoms = [0] * len(tools)
            for sev in sevs:
                vals = [tool_sev[t].get(sev, 0) for t in tools]
                if any(v > 0 for v in vals):
                    ax.bar(
                        tools, vals, bottom=bottoms,
                        color=SEVERITY_COLORS[sev],
                        label=sev, width=0.55
                    )
                    bottoms = [b + v for b, v in zip(bottoms, vals)]

            ax.set_xlabel('Tool', color=DIM, fontsize=8)
            ax.set_ylabel('Findings', color=DIM, fontsize=8)
            ax.tick_params(colors=TEXT, labelsize=7, axis='y')
            ax.tick_params(colors=TEXT, labelsize=7,
                          axis='x', rotation=25)
            for spine in ax.spines.values():
                spine.set_color(BORDER)
            ax.yaxis.grid(True, color=BORDER,
                         linestyle='--', alpha=0.4)
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
            tool_counts[f['tool']] = tool_counts.get(f['tool'], 0) + 1

        grid = QGridLayout()
        grid.setSpacing(6)

        all_tools = [
            'nmap', 'subfinder', 'httpx', 'whatweb', 'ffuf',
            'nikto', 'theharvester', 'dnsrecon', 'gobuster',
            'dirsearch', 'wpscan', 'nuclei'
        ]

        for i, tool in enumerate(all_tools):
            cell = QFrame()
            cell.setStyleSheet(
                f"background: {CARD2}; border-radius: 6px; border: none;"
            )
            cl2 = QVBoxLayout(cell)
            cl2.setContentsMargins(8, 6, 8, 6)
            cl2.setSpacing(1)

            emoji = TOOL_EMOJI.get(tool, '🔧')
            name_lbl = QLabel(f"{emoji} {tool}")
            name_lbl.setStyleSheet(
                f"font-size: 9px; font-weight: bold; "
                f"color: {TEXT}; background: transparent; border: none;"
            )
            cl2.addWidget(name_lbl)

            count = tool_counts.get(tool, 0)
            count_lbl = QLabel(str(count))
            color = '#e94560' if count > 0 else DIM
            count_lbl.setStyleSheet(
                f"font-size: 14px; font-weight: bold; "
                f"color: {color}; background: transparent; border: none;"
            )
            cl2.addWidget(count_lbl)

            run_status = self.tool_runs.get(tool, '')
            if run_status == 'completed':
                status_text = '✓ Done'
                status_color = '#3fb950'
            elif run_status in ['failed', 'timeout', 'error']:
                status_text = '✗ Failed'
                status_color = '#e94560'
            elif count > 0:
                status_text = '✓ Done'
                status_color = '#3fb950'
            else:
                status_text = '— Not run'
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
