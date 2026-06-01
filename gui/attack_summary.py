from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QProgressBar
)
from PyQt6.QtCore import Qt
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}

SEVERITY_BG = {
    'Critical': '#2a0000',
    'High':     '#2a0a10',
    'Medium':   '#2a1800',
    'Low':      '#2a2200',
    'Info':     '#0d1f3c',
}

SEVERITY_ICONS = {
    'Critical': '🔴',
    'High':     '🟠',
    'Medium':   '🟡',
    'Low':      '🟢',
    'Info':     '🔵',
}

ATTACK_PATHS = {
    'telnet': [
        'Attacker on network',
        'Connect to Port 23',
        'Capture plaintext credentials',
        'Full system access'
    ],
    'bindshell': [
        'Attacker on network',
        'Connect to Port 1524',
        'Instant root shell',
        'Complete system compromise'
    ],
    'ftp': [
        'Attacker on network',
        'Connect to Port 21',
        'Brute force or sniff credentials',
        'File system access'
    ],
    'mysql': [
        'Attacker on network',
        'Connect to Port 3306',
        'Default or weak credentials',
        'Full database access'
    ],
    'postgresql': [
        'Attacker on network',
        'Connect to Port 5432',
        'Empty password exploit',
        'Full database access'
    ],
    'vnc': [
        'Attacker on network',
        'Connect to Port 5900',
        'Default password login',
        'Full desktop control'
    ],
    'phpmyadmin': [
        'Attacker finds /phpMyAdmin',
        'Brute force login page',
        'Database admin access',
        'Data exfiltration or RCE'
    ],
    'phpinfo': [
        'Attacker finds phpinfo.php',
        'Reads server configuration',
        'Identifies exploitable versions',
        'Targeted exploitation'
    ],
    'cve-2020-1938': [
        'Attacker reaches AJP port',
        'Exploit Ghostcat (CVE-2020-1938)',
        'Read arbitrary server files',
        'Remote Code Execution'
    ],
    'cve-2012-1823': [
        'Attacker sends crafted HTTP request',
        'Exploit PHP-CGI (CVE-2012-1823)',
        'Remote code execution',
        'Full server compromise'
    ],
    'cve-2011-2523': [
        'Attacker connects to vsftpd',
        'Trigger backdoor (CVE-2011-2523)',
        'Root shell via Port 6200',
        'Complete system compromise'
    ],
    'smb': [
        'Attacker on network',
        'Connect to Port 445',
        'Exploit SMB vulnerability',
        'Lateral movement or RCE'
    ],
    'ssh': [
        'Attacker on network',
        'Connect to Port 22',
        'Brute force weak credentials',
        'Remote shell access'
    ],
    'directory listing': [
        'Attacker browses web server',
        'Finds open directory listing',
        'Enumerates sensitive files',
        'Information disclosure'
    ],
    'directory indexing': [
        'Attacker browses web server',
        'Finds open directory listing',
        'Enumerates sensitive files',
        'Information disclosure'
    ],
    'http trace': [
        'Attacker sends TRACE request',
        'Server reflects headers back',
        'Capture session cookies (XST)',
        'Session hijacking'
    ],
    'multiviews': [
        'Attacker sends crafted requests',
        'Apache MultiViews brute forces files',
        'Discovers hidden resources',
        'Further targeted exploitation'
    ],
    'irc': [
        'Attacker connects to IRC port',
        'Identifies IRC daemon version',
        'Exploit known IRC vulnerabilities',
        'Remote code execution'
    ],
    'java rmi': [
        'Attacker scans for RMI port',
        'Connect to Java RMI service',
        'Exploit deserialization flaw',
        'Remote code execution'
    ],
    'rmi': [
        'Attacker scans for RMI port',
        'Connect to Java RMI service',
        'Exploit deserialization flaw',
        'Remote code execution'
    ],
    'smtp': [
        'Attacker connects to Port 25',
        'Enumerate valid email users',
        'Relay spam or phishing emails',
        'Information disclosure'
    ],
    'nfs': [
        'Attacker scans for NFS port',
        'Mount exposed NFS share',
        'Access sensitive files',
        'Data exfiltration'
    ],
    'wordpress': [
        'Attacker runs WPScan',
        'Discovers vulnerable plugins',
        'Exploit plugin vulnerability',
        'Admin access or RCE'
    ],
    'wp-': [
        'Attacker runs WPScan',
        'Discovers WordPress vulnerability',
        'Exploit vulnerable component',
        'Admin access or RCE'
    ],
    'apache': [
        'Attacker identifies Apache version',
        'Searches for known CVEs',
        'Exploits unpatched vulnerability',
        'Server compromise'
    ],
    'php': [
        'Attacker identifies PHP version',
        'Searches for known CVEs',
        'Exploits PHP vulnerability',
        'Remote code execution'
    ],
    'htaccess': [
        'Attacker finds exposed .htaccess',
        'Reads server configuration rules',
        'Identifies bypass opportunities',
        'Access restricted resources'
    ],
    'htpasswd': [
        'Attacker finds exposed .htpasswd',
        'Downloads password hashes',
        'Cracks hashes offline',
        'Authenticated access'
    ],
    'backup': [
        'Attacker finds backup file',
        'Downloads source code or data',
        'Extracts credentials or secrets',
        'Full application compromise'
    ],
    'config': [
        'Attacker finds config file',
        'Reads database credentials',
        'Connects directly to database',
        'Full data access'
    ],
    'shell': [
        'Attacker finds exposed shell',
        'Executes arbitrary commands',
        'Establishes persistence',
        'Full system compromise'
    ],
    'sql injection': [
        'Attacker injects SQL payload',
        'Extracts database contents',
        'Bypasses authentication',
        'Data exfiltration or RCE'
    ],
    'xss': [
        'Attacker injects script payload',
        'Victim executes malicious script',
        'Session cookies stolen',
        'Account takeover'
    ],
    'path traversal': [
        'Attacker sends traversal payload',
        'Reads files outside web root',
        'Accesses sensitive system files',
        'Credential disclosure'
    ],
}

BG     = '#0d1117'
CARD   = '#161b22'
CARD2  = '#21262d'
BORDER = '#30363d'
TEXT   = '#e6edf3'
DIM    = '#8b949e'


def get_attack_path(title, asset):
    combined = (title + ' ' + asset).lower()
    for keyword, path in ATTACK_PATHS.items():
        if keyword in combined:
            return path
    return None


def calculate_risk_score(findings):
    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    score = (
        counts.get('Critical', 0) * 20 +
        counts.get('High', 0) * 8 +
        counts.get('Medium', 0) * 3 +
        counts.get('Low', 0) * 1
    )
    return min(100, score)


def get_risk_label(score):
    if score >= 80:
        return 'CRITICAL RISK', '#8b0000'
    elif score >= 60:
        return 'HIGH RISK', '#e94560'
    elif score >= 40:
        return 'MEDIUM RISK', '#ff8c00'
    elif score >= 20:
        return 'LOW RISK', '#ffd700'
    else:
        return 'MINIMAL RISK', '#4a9eff'


class CollapsibleSection(QWidget):
    def __init__(self, severity, findings,
                 expanded=True, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.findings = findings
        self.expanded = expanded
        self.color    = SEVERITY_COLORS[severity]
        self.bg       = SEVERITY_BG[severity]
        self.icon     = SEVERITY_ICONS[severity]
        self.init_ui()

    def init_ui(self):
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(0)

        outer = QFrame()
        outer.setStyleSheet(
            f"background: {CARD}; border: 1px solid {BORDER}; "
            f"border-radius: 8px;"
        )
        ol = QVBoxLayout(outer)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.setSpacing(0)

        self.header_btn = QPushButton()
        self.header_btn.setStyleSheet(f"""
            QPushButton {{
                background: {self.bg};
                border: none;
                border-radius: 8px 8px 0 0;
                border-bottom: 1px solid {self.color}44;
                color: {self.color};
                font-size: 13px;
                font-weight: bold;
                padding: 12px 16px;
                text-align: left;
            }}
            QPushButton:hover {{
                background: {self.color}22;
            }}
        """)
        self.header_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header_btn.clicked.connect(self.toggle)
        self.update_header_text()
        ol.addWidget(self.header_btn)

        self.content_widget = QWidget()
        self.content_widget.setStyleSheet(
            f"background: {CARD}; border: none;"
        )
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        for i, f in enumerate(self.findings):
            card = self.build_finding_card(f, i)
            self.content_layout.addWidget(card)

        self.content_widget.setVisible(self.expanded)
        ol.addWidget(self.content_widget)
        self.layout_.addWidget(outer)

    def update_header_text(self):
        arrow = '▾' if self.expanded else '▸'
        self.header_btn.setText(
            f"{self.icon}  {self.severity.upper()} FINDINGS  "
            f"({len(self.findings)})  {arrow}"
        )

    def toggle(self):
        self.expanded = not self.expanded
        self.content_widget.setVisible(self.expanded)
        self.update_header_text()

    def build_finding_card(self, f, index):
        card = QFrame()
        card.setStyleSheet(
            f"background: {CARD}; border: none; "
            f"border-bottom: 1px solid {CARD2};"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 14, 20, 14)
        cl.setSpacing(8)

        title_row = QHBoxLayout()

        num = QLabel(f"{index + 1}.")
        num.setFixedWidth(28)
        num.setStyleSheet(
            f"color: #555; font-size: 12px; font-weight: bold; "
            f"background: transparent; border: none;"
        )
        title_row.addWidget(num)

        title_lbl = QLabel(f['title'])
        title_lbl.setStyleSheet(
            f"color: {TEXT}; font-size: 13px; font-weight: bold; "
            f"background: transparent; border: none;"
        )
        title_lbl.setWordWrap(True)
        title_row.addWidget(title_lbl, 1)

        tool_badge = QLabel(f['tool'])
        tool_badge.setStyleSheet(
            f"color: {DIM}; font-size: 10px; "
            f"background: {CARD2}; border-radius: 4px; "
            f"padding: 2px 8px; border: none;"
        )
        title_row.addWidget(tool_badge)
        cl.addLayout(title_row)

        if f['description']:
            desc_text = f['description']
            if len(desc_text) > 200:
                desc_text = desc_text[:200] + '...'
            desc = QLabel(desc_text)
            desc.setStyleSheet(
                f"color: {DIM}; font-size: 11px; "
                f"background: transparent; border: none;"
            )
            desc.setWordWrap(True)
            cl.addWidget(desc)

        attack_path = get_attack_path(f['title'], f['asset'])
        if attack_path:
            path_frame = QFrame()
            path_frame.setStyleSheet(
                f"background: #0d1117; border-radius: 6px; "
                f"border: 1px solid {self.color}44;"
            )
            pfl = QVBoxLayout(path_frame)
            pfl.setContentsMargins(12, 8, 12, 10)
            pfl.setSpacing(6)

            path_title = QLabel("⚡ Attack Path")
            path_title.setStyleSheet(
                f"color: {self.color}; font-size: 10px; "
                f"font-weight: bold; background: transparent; "
                f"border: none; letter-spacing: 1px;"
            )
            pfl.addWidget(path_title)

            path_row = QHBoxLayout()
            path_row.setSpacing(4)
            for j, step in enumerate(attack_path):
                step_lbl = QLabel(step)
                step_lbl.setStyleSheet(
                    f"color: {TEXT}; font-size: 10px; "
                    f"background: {CARD}; border-radius: 4px; "
                    f"padding: 4px 8px; border: 1px solid {BORDER};"
                )
                path_row.addWidget(step_lbl)
                if j < len(attack_path) - 1:
                    arrow = QLabel("→")
                    arrow.setStyleSheet(
                        f"color: {self.color}; font-size: 12px; "
                        f"background: transparent; border: none;"
                    )
                    path_row.addWidget(arrow)
            path_row.addStretch()
            pfl.addLayout(path_row)
            cl.addWidget(path_frame)

        if f['recommendation']:
            rec_text = f['recommendation']
            if len(rec_text) > 180:
                rec_text = rec_text[:180] + '...'
            rec_frame = QFrame()
            rec_frame.setStyleSheet(
                f"background: #0a1a0a; border-radius: 6px; "
                f"border: 1px solid #1d9e7544;"
            )
            rfl = QHBoxLayout(rec_frame)
            rfl.setContentsMargins(12, 8, 12, 8)
            rfl.setSpacing(8)

            fix_icon = QLabel("✓")
            fix_icon.setFixedWidth(16)
            fix_icon.setStyleSheet(
                f"color: #1d9e75; font-size: 14px; font-weight: bold; "
                f"background: transparent; border: none;"
            )
            rfl.addWidget(fix_icon)

            rec = QLabel(rec_text)
            rec.setStyleSheet(
                f"color: #3fb950; font-size: 11px; "
                f"background: transparent; border: none;"
            )
            rec.setWordWrap(True)
            rfl.addWidget(rec, 1)
            cl.addWidget(rec_frame)

        return card


class AttackSummaryView(QWidget):
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
            SELECT tool, asset, severity, title,
                   description, recommendation
            FROM findings WHERE scan_id=?
            ORDER BY CASE severity
                WHEN "Critical" THEN 0
                WHEN "High"     THEN 1
                WHEN "Medium"   THEN 2
                WHEN "Low"      THEN 3
                WHEN "Info"     THEN 4
                ELSE 5 END
        ''', (self.scan_id,))
        rows = cursor.fetchall()
        self.findings = [
            {
                'tool':           r[0],
                'asset':          r[1],
                'severity':       r[2],
                'title':          r[3],
                'description':    r[4] or '',
                'recommendation': r[5] or '',
            }
            for r in rows
        ]

        cursor.execute(
            'SELECT name, target, profile, created_at '
            'FROM scans WHERE id=?',
            (self.scan_id,)
        )
        row = cursor.fetchone()
        if row:
            self.scan_info = {
                'name':       row[0],
                'target':     row[1],
                'profile':    row[2],
                'created_at': str(row[3])[:16],
            }
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
        layout.setContentsMargins(30, 20, 30, 30)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        layout.addWidget(self.build_header())
        layout.addWidget(self.build_risk_score())
        layout.addWidget(self.build_stats_row())

        critical = [
            f for f in self.findings if f['severity'] == 'Critical'
        ]
        high = [
            f for f in self.findings if f['severity'] == 'High'
        ]
        medium = [
            f for f in self.findings if f['severity'] == 'Medium'
        ]
        low_with_path = [
            f for f in self.findings
            if f['severity'] == 'Low'
            and get_attack_path(f['title'], f['asset'])
        ]
        info_with_path = [
            f for f in self.findings
            if f['severity'] == 'Info'
            and get_attack_path(f['title'], f['asset'])
        ]

        if critical:
            layout.addWidget(
                CollapsibleSection(
                    'Critical', critical, expanded=True
                )
            )
        if high:
            layout.addWidget(
                CollapsibleSection(
                    'High', high, expanded=True
                )
            )
        if medium:
            layout.addWidget(
                CollapsibleSection(
                    'Medium', medium, expanded=False
                )
            )
        if low_with_path:
            layout.addWidget(
                CollapsibleSection(
                    'Low', low_with_path, expanded=False
                )
            )
        if info_with_path:
            layout.addWidget(
                CollapsibleSection(
                    'Info', info_with_path, expanded=False
                )
            )

        layout.addWidget(self.build_recommendations())
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def build_header(self):
        frame = QFrame()
        frame.setObjectName("siemCard")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(20, 16, 20, 16)

        title = QLabel("Attack Surface Summary")
        title.setStyleSheet(
            f"color: #e94560; font-size: 22px; font-weight: bold; "
            f"background: transparent; border: none;"
        )
        fl.addWidget(title)

        target  = self.scan_info.get('target', 'Unknown')
        profile = self.scan_info.get('profile', '')
        date    = self.scan_info.get('created_at', '')
        sub = QLabel(
            f"Target: {target}  ·  Profile: {profile}  ·  "
            f"Scan #{self.scan_id}  ·  {date}"
        )
        sub.setStyleSheet(
            f"color: {DIM}; font-size: 12px; "
            f"background: transparent; border: none;"
        )
        fl.addWidget(sub)
        return frame

    def build_risk_score(self):
        score = calculate_risk_score(self.findings)
        label, color = get_risk_label(score)

        frame = QFrame()
        frame.setObjectName("siemCard")
        fl = QHBoxLayout(frame)
        fl.setContentsMargins(20, 16, 20, 16)
        fl.setSpacing(30)

        left = QVBoxLayout()
        left.setSpacing(4)

        score_lbl = QLabel(f"{score}/100")
        score_lbl.setStyleSheet(
            f"font-size: 42px; font-weight: bold; color: {color}; "
            f"background: transparent; border: none;"
        )
        left.addWidget(score_lbl)

        risk_lbl = QLabel(label)
        risk_lbl.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {color}; "
            f"background: transparent; border: none;"
        )
        left.addWidget(risk_lbl)

        desc = QLabel(
            "Risk score based on finding severity weights"
        )
        desc.setStyleSheet(
            f"font-size: 10px; color: {DIM}; "
            f"background: transparent; border: none;"
        )
        left.addWidget(desc)
        fl.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(6)

        bar = QProgressBar()
        bar.setMaximum(100)
        bar.setValue(score)
        bar.setFixedHeight(20)
        bar.setFixedWidth(380)
        bar.setTextVisible(False)
        bar.setStyleSheet(f"""
            QProgressBar {{
                background: {CARD2};
                border-radius: 6px;
                border: none;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 6px;
            }}
        """)
        right.addWidget(bar)

        formula = QLabel(
            "Critical×20  +  High×8  +  Medium×3  +  Low×1  —  max 100"
        )
        formula.setStyleSheet(
            f"font-size: 10px; color: #444; "
            f"background: transparent; border: none;"
        )
        right.addWidget(formula)
        fl.addLayout(right)
        fl.addStretch()
        return frame

    def build_stats_row(self):
        frame = QFrame()
        frame.setStyleSheet("background: transparent; border: none;")
        fl = QHBoxLayout(frame)
        fl.setSpacing(10)
        fl.setContentsMargins(0, 0, 0, 0)

        counts = {}
        tools  = set()
        for f in self.findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
            tools.add(f['tool'])

        stats = [
            ("Total Findings", str(len(self.findings)),         "#4a9eff"),
            ("Critical",       str(counts.get('Critical', 0)), "#8b0000"),
            ("High",           str(counts.get('High', 0)),     "#e94560"),
            ("Medium",         str(counts.get('Medium', 0)),   "#ff8c00"),
            ("Low",            str(counts.get('Low', 0)),      "#ffd700"),
            ("Info",           str(counts.get('Info', 0)),     "#4a9eff"),
            ("Tools Run",      str(len(tools)),                 "#1d9e75"),
        ]

        for label, value, color in stats:
            card = QFrame()
            card.setObjectName("siemCard")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(10, 8, 10, 8)

            val = QLabel(value)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(
                f"font-size: 20px; font-weight: bold; color: {color}; "
                f"background: transparent; border: none;"
            )
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"font-size: 9px; color: {DIM}; "
                f"background: transparent; border: none;"
            )
            cl.addWidget(val)
            cl.addWidget(lbl)
            fl.addWidget(card)

        return frame

    def build_recommendations(self):
        frame = QFrame()
        frame.setObjectName("siemCard")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(20, 16, 20, 16)
        fl.setSpacing(10)

        title = QLabel("TOP RECOMMENDATIONS")
        title.setStyleSheet(
            f"color: {DIM}; font-size: 11px; font-weight: bold; "
            f"background: transparent; border: none; "
            f"letter-spacing: 1px;"
        )
        fl.addWidget(title)

        crits = [
            f for f in self.findings
            if f['severity'] in ['Critical', 'High']
            and f['recommendation']
        ][:8]

        for i, f in enumerate(crits, 1):
            row = QHBoxLayout()

            num = QLabel(f"{i}.")
            num.setFixedWidth(20)
            num.setStyleSheet(
                f"color: #e94560; font-size: 12px; "
                f"font-weight: bold; background: transparent; "
                f"border: none;"
            )
            row.addWidget(num)

            icon = SEVERITY_ICONS[f['severity']]
            rec  = f['recommendation']
            if len(rec) > 90:
                rec = rec[:90] + '...'
            text = QLabel(f"{icon}  {f['title']}  —  {rec}")
            text.setStyleSheet(
                f"color: {TEXT}; font-size: 12px; "
                f"background: transparent; border: none;"
            )
            text.setWordWrap(True)
            row.addWidget(text, 1)
            fl.addLayout(row)

            if i < len(crits):
                div = QFrame()
                div.setFrameShape(QFrame.Shape.HLine)
                div.setStyleSheet(
                    f"background: {CARD2}; border: none; "
                    f"max-height: 1px;"
                )
                fl.addWidget(div)

        return frame

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
            #siemCard {{
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
