from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTextEdit, QCheckBox,
    QComboBox, QFrame, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt
from backend.scope import validate_target

PROFILES = {
    'Production': 'Safe and slow. Rate limited. Good for live environments.',
    'Standard': 'Balanced speed and coverage. Recommended for most scans.',
    'Deep': 'Aggressive and thorough. Use only on test environments.',
}

TOOLS = {
    'nmap': 'Port scanning and service detection.',
    'subfinder': 'Subdomain discovery via OSINT.',
    'httpx': 'Identifies live web hosts.',
    'whatweb': 'Web technology fingerprinting.',
    'ffuf': 'Directory and endpoint discovery.',
}

class ScanWizard(QWidget):
    def __init__(self, on_scan_start=None):
        super().__init__()
        self.on_scan_start = on_scan_start
        self.current_step = 1
        self.scan_config = {}
        self.tool_checkboxes = {}
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(40, 30, 40, 30)
        self.show_step1()

    def clear_layout(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def add_title(self, text, sub=None):
        title = QLabel(text)
        title.setObjectName("wizardTitle")
        self.layout.addWidget(title)
        if sub:
            subtitle = QLabel(sub)
            subtitle.setObjectName("wizardSub")
            self.layout.addWidget(subtitle)
        self.layout.addSpacing(20)

    def add_nav_buttons(self, back_fn=None, next_fn=None, next_label="Next"):
        self.layout.addStretch()
        nav = QHBoxLayout()
        if back_fn:
            back_btn = QPushButton("Back")
            back_btn.setObjectName("backBtn")
            back_btn.clicked.connect(back_fn)
            nav.addWidget(back_btn)
        nav.addStretch()
        if next_fn:
            next_btn = QPushButton(next_label)
            next_btn.setObjectName("nextBtn")
            next_btn.clicked.connect(next_fn)
            nav.addWidget(next_btn)
        self.layout.addLayout(nav)

    def show_step1(self):
        self.clear_layout()
        self.add_title("Step 1 — Target & Scan Details",
                       "Enter the target you want to scan and give this scan a name.")

        target_label = QLabel("Target (domain, IP, or CIDR):")
        target_label.setObjectName("fieldLabel")
        self.layout.addWidget(target_label)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. scanme.nmap.org or 45.33.32.156")
        self.target_input.setObjectName("inputField")
        self.layout.addWidget(self.target_input)
        self.layout.addSpacing(15)

        name_label = QLabel("Scan Name:")
        name_label.setObjectName("fieldLabel")
        self.layout.addWidget(name_label)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. Q2 External Recon")
        self.name_input.setObjectName("inputField")
        self.layout.addWidget(self.name_input)
        self.layout.addSpacing(15)

        ref_label = QLabel("Approval / Ticket Reference (optional):")
        ref_label.setObjectName("fieldLabel")
        self.layout.addWidget(ref_label)

        self.ref_input = QLineEdit()
        self.ref_input.setPlaceholderText("e.g. JIRA-1234 or email approval ref")
        self.ref_input.setObjectName("inputField")
        self.layout.addWidget(self.ref_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("errorLabel")
        self.layout.addWidget(self.error_label)

        self.add_nav_buttons(next_fn=self.validate_step1)

    def validate_step1(self):
        target = self.target_input.text().strip()
        name = self.name_input.text().strip()

        if not target:
            self.error_label.setText("Target cannot be empty.")
            return
        if not name:
            self.error_label.setText("Scan name cannot be empty.")
            return

        result = validate_target(target)
        if not result['allowed']:
            self.error_label.setText(f"Target blocked: {result['reason']}")
            return

        self.scan_config['target'] = target
        self.scan_config['name'] = name
        self.scan_config['approval_ref'] = self.ref_input.text().strip()
        self.show_step2()

    def show_step2(self):
        self.clear_layout()
        self.add_title("Step 2 — Select Scan Profile",
                       "Choose how aggressive the scan should be.")

        self.profile_buttons = {}
        for profile, description in PROFILES.items():
            btn = QPushButton(f"{profile}\n{description}")
            btn.setObjectName("profileBtn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, p=profile: self.select_profile(p))
            self.layout.addWidget(btn)
            self.layout.addSpacing(8)
            self.profile_buttons[profile] = btn

        self.profile_error = QLabel("")
        self.profile_error.setObjectName("errorLabel")
        self.layout.addWidget(self.profile_error)

        self.add_nav_buttons(back_fn=self.show_step1, next_fn=self.validate_step2)

    def select_profile(self, selected):
        self.scan_config['profile'] = selected
        for profile, btn in self.profile_buttons.items():
            btn.setChecked(profile == selected)
            btn.setObjectName("profileBtnSelected" if profile == selected else "profileBtn")
            btn.setStyleSheet(self.get_stylesheet())

    def validate_step2(self):
        if 'profile' not in self.scan_config:
            self.profile_error.setText("Please select a scan profile.")
            return
        self.show_step3()

    def show_step3(self):
        self.clear_layout()
        self.add_title("Step 3 — Select Tools",
                       "Choose which tools to run in this scan.")

        self.tool_checkboxes = {}
        for tool, description in TOOLS.items():
            cb = QCheckBox(f"{tool}  —  {description}")
            cb.setObjectName("toolCheck")
            cb.setChecked(True)
            self.layout.addWidget(cb)
            self.layout.addSpacing(5)
            self.tool_checkboxes[tool] = cb

        self.tool_error = QLabel("")
        self.tool_error.setObjectName("errorLabel")
        self.layout.addWidget(self.tool_error)

        self.add_nav_buttons(back_fn=self.show_step2, next_fn=self.validate_step3)

    def validate_step3(self):
        selected = [t for t, cb in self.tool_checkboxes.items() if cb.isChecked()]
        if not selected:
            self.tool_error.setText("Please select at least one tool.")
            return
        self.scan_config['tools'] = selected
        self.show_step4()

    def show_step4(self):
        self.clear_layout()
        self.add_title("Step 4 — Confirm & Start Scan",
                       "Review your scan configuration before starting.")

        details = [
            ("Target", self.scan_config.get('target', '')),
            ("Scan Name", self.scan_config.get('name', '')),
            ("Profile", self.scan_config.get('profile', '')),
            ("Tools", ', '.join(self.scan_config.get('tools', []))),
            ("Approval Ref", self.scan_config.get('approval_ref', 'N/A')),
        ]

        for label, value in details:
            row = QHBoxLayout()
            lbl = QLabel(f"{label}:")
            lbl.setObjectName("confirmLabel")
            lbl.setFixedWidth(120)
            val = QLabel(value)
            val.setObjectName("confirmValue")
            val.setWordWrap(True)
            row.addWidget(lbl)
            row.addWidget(val)
            self.layout.addLayout(row)
            self.layout.addSpacing(8)

        self.add_nav_buttons(
            back_fn=self.show_step3,
            next_fn=self.start_scan,
            next_label="Start Scan"
        )

    def start_scan(self):
        if self.on_scan_start:
            self.on_scan_start(self.scan_config)

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #wizardTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #wizardSub {
                color: #888;
                font-size: 12px;
            }
            #fieldLabel {
                color: #aaa;
                font-size: 12px;
                margin-top: 5px;
            }
            #inputField {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 8px;
                font-size: 13px;
            }
            #inputField:focus {
                border: 1px solid #e94560;
            }
            #profileBtn {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 6px;
                padding: 12px;
                text-align: left;
                font-size: 13px;
            }
            #profileBtn:hover {
                border: 1px solid #e94560;
            }
            #profileBtnSelected {
                background-color: #0f3460;
                color: #e94560;
                border: 1px solid #e94560;
                border-radius: 6px;
                padding: 12px;
                text-align: left;
                font-size: 13px;
            }
            #toolCheck {
                color: #e0e0e0;
                font-size: 13px;
                padding: 5px;
            }
            #toolCheck:hover {
                color: #e94560;
            }
            #nextBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: bold;
            }
            #nextBtn:hover {
                background-color: #c73652;
            }
            #backBtn {
                background-color: transparent;
                color: #888;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 10px 24px;
                font-size: 13px;
            }
            #backBtn:hover {
                color: #e0e0e0;
                border: 1px solid #e0e0e0;
            }
            #errorLabel {
                color: #e94560;
                font-size: 12px;
                margin-top: 5px;
            }
            #confirmLabel {
                color: #888;
                font-size: 13px;
            }
            #confirmValue {
                color: #e0e0e0;
                font-size: 13px;
                font-weight: bold;
            }
        """
