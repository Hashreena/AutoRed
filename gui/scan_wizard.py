from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QCheckBox,
    QComboBox, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt
from backend.scope import validate_target

PROFILES = {
    'Production': 'Safe and slow. Rate limited. Good for live environments.',
    'Standard':   'Balanced speed and coverage. Recommended for most scans.',
    'Deep':       'Aggressive and thorough. Use only on test environments.',
}

TOOLS = {
    'nmap':         ('🔍', 'Port scanning and service detection.'),
    'subfinder':    ('🌐', 'Subdomain discovery via OSINT.'),
    'httpx':        ('📡', 'Identifies live web hosts.'),
    'whatweb':      ('🕵️', 'Web technology fingerprinting.'),
    'ffuf':         ('💨', 'Directory and endpoint fuzzing.'),
    'nikto':        ('🎯', 'Web server vulnerability scanner.'),
    'theharvester': ('🌾', 'OSINT email and host harvesting.'),
    'dnsrecon':     ('🔎', 'DNS enumeration and record discovery.'),
    'gobuster':     ('👻', 'Directory and file brute forcing.'),
    'dirsearch':    ('📂', 'Web path discovery with curated wordlists.'),
    'wpscan':       ('🔒', 'WordPress vulnerability scanner.'),
    'nuclei':       ('⚡', 'Template-based CVE vulnerability scanner.'),
}

STEP_LABELS = ['Target', 'Folder', 'Profile', 'Tools', 'Confirm']


class ToolCard(QFrame):
    def __init__(self, tool_name, emoji, description,
                 parent=None):
        super().__init__(parent)
        self.tool_name = tool_name
        self.selected  = True
        self.setObjectName("toolCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(72)
        self.init_ui(emoji, description)
        self.update_style()

    def init_ui(self, emoji, description):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        self.emoji_lbl = QLabel(emoji)
        self.emoji_lbl.setFixedWidth(28)
        self.emoji_lbl.setStyleSheet(
            "font-size: 20px; background: transparent; "
            "border: none;"
        )
        layout.addWidget(self.emoji_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        self.name_lbl = QLabel(self.tool_name)
        self.name_lbl.setStyleSheet(
            "color: #e6edf3; font-size: 13px; "
            "font-weight: bold; "
            "background: transparent; border: none;"
        )
        text_col.addWidget(self.name_lbl)

        self.desc_lbl = QLabel(description)
        self.desc_lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px; "
            "background: transparent; border: none;"
        )
        text_col.addWidget(self.desc_lbl)
        layout.addLayout(text_col)
        layout.addStretch()

        self.check_lbl = QLabel("✓")
        self.check_lbl.setFixedSize(22, 22)
        self.check_lbl.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.check_lbl.setStyleSheet(
            "background: #e94560; color: white; "
            "border-radius: 4px; font-size: 12px; "
            "font-weight: bold; border: none;"
        )
        layout.addWidget(self.check_lbl)

    def update_style(self):
        if self.selected:
            self.setStyleSheet("""
                QFrame#toolCard {
                    background: #161b22;
                    border: 1px solid #e94560;
                    border-radius: 8px;
                }
            """)
            self.check_lbl.setText("✓")
            self.check_lbl.setStyleSheet(
                "background: #e94560; color: white; "
                "border-radius: 4px; font-size: 12px; "
                "font-weight: bold; border: none;"
            )
        else:
            self.setStyleSheet("""
                QFrame#toolCard {
                    background: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                }
                QFrame#toolCard:hover {
                    border: 1px solid #8b949e;
                }
            """)
            self.check_lbl.setText("")
            self.check_lbl.setStyleSheet(
                "background: transparent; "
                "color: transparent; "
                "border-radius: 4px; "
                "border: 1px solid #30363d;"
            )

    def mousePressEvent(self, event):
        self.selected = not self.selected
        self.update_style()
        super().mousePressEvent(event)

    def is_selected(self):
        return self.selected

    def set_selected(self, val):
        self.selected = val
        self.update_style()


class ScanWizard(QWidget):
    def __init__(self, on_scan_start=None):
        super().__init__()
        self.on_scan_start   = on_scan_start
        self.scan_config     = {}
        self.tool_cards      = {}
        self.profile_buttons = {}
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea { border: none; "
            "background: #0d1117; }"
        )

        self.container = QWidget()
        self.container.setStyleSheet(
            "background: #0d1117;"
        )
        self.main_layout = QVBoxLayout(self.container)
        self.main_layout.setContentsMargins(50, 36, 50, 36)
        self.main_layout.setSpacing(0)

        scroll.setWidget(self.container)
        outer.addWidget(scroll)
        self.show_step(1)

    def clear_layout(self):
        while self.main_layout.count():
            item   = self.main_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()
            else:
                layout = item.layout()
                if layout:
                    self.delete_layout(layout)

    def delete_layout(self, layout):
        while layout.count():
            item   = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()
            else:
                sub = item.layout()
                if sub:
                    self.delete_layout(sub)

    def show_step(self, step):
        self.clear_layout()
        self.current_step = step
        if step == 1:
            self.build_step1()
        elif step == 2:
            self.build_step2()
        elif step == 3:
            self.build_step3()
        elif step == 4:
            self.build_step4()
        elif step == 5:
            self.build_step5()

    def add_step_indicator(self, current):
        row = QHBoxLayout()
        row.setSpacing(0)

        for i in range(1, 6):
            col = QVBoxLayout()
            col.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.setSpacing(4)

            dot = QLabel(str(i))
            dot.setFixedSize(30, 30)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            if i <= current:
                dot.setStyleSheet(
                    "background:#e94560;color:white;"
                    "border-radius:15px;font-weight:bold;"
                    "font-size:11px;"
                )
            else:
                dot.setStyleSheet(
                    "background:#21262d;color:#8b949e;"
                    "border-radius:15px;font-size:11px;"
                    "border:1px solid #30363d;"
                )
            col.addWidget(dot)

            lbl = QLabel(STEP_LABELS[i - 1])
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"color:{'#e94560' if i==current else '#555'};"
                "font-size:10px;background:transparent;"
            )
            col.addWidget(lbl)
            row.addLayout(col)

            if i < 5:
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setFixedHeight(1)
                line.setStyleSheet(
                    "background:#e94560;" if i < current
                    else "background:#30363d;"
                )
                row.addWidget(line)

        self.main_layout.addLayout(row)
        self.main_layout.addSpacing(32)

    def add_title(self, text, sub=None):
        title = QLabel(text)
        title.setObjectName("wizardTitle")
        self.main_layout.addWidget(title)
        self.main_layout.addSpacing(6)
        if sub:
            s = QLabel(sub)
            s.setObjectName("wizardSub")
            self.main_layout.addWidget(s)
        self.main_layout.addSpacing(28)

    def add_field_label(self, text, sub=None):
        lbl = QLabel(text)
        lbl.setObjectName("fieldLabel")
        self.main_layout.addWidget(lbl)
        if sub:
            self.main_layout.addSpacing(3)
            s = QLabel(sub)
            s.setObjectName("fieldSub")
            self.main_layout.addWidget(s)
        self.main_layout.addSpacing(8)

    def make_input(self, placeholder='', value=''):
        inp = QLineEdit()
        inp.setPlaceholderText(placeholder)
        inp.setObjectName("inputField")
        if value:
            inp.setText(value)
        return inp

    def add_nav(self, back_step=None, next_fn=None,
                next_label="Next →"):
        self.main_layout.addSpacing(32)
        self.main_layout.addStretch()

        nav = QHBoxLayout()

        RED_BTN = """
            QPushButton {
                background-color: #e94560 !important;
                color: white !important;
                border: none;
                border-radius: 6px;
                padding: 11px 28px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c73652 !important;
            }
        """

        if back_step is not None:
            back_btn = QPushButton("← Back")
            back_btn.setStyleSheet(RED_BTN)
            back_btn.setCursor(
                Qt.CursorShape.PointingHandCursor
            )
            back_btn.clicked.connect(
                lambda: self.show_step(back_step)
            )
            nav.addWidget(back_btn)

        nav.addStretch()

        if next_fn:
            nxt = QPushButton(next_label)
            nxt.setStyleSheet(RED_BTN)
            nxt.setCursor(Qt.CursorShape.PointingHandCursor)
            nxt.clicked.connect(next_fn)
            nav.addWidget(nxt)

        self.main_layout.addLayout(nav)

    # ── Step 1 ───────────────────────────────────────────────
    def build_step1(self):
        self.add_title(
            "Step 1 — Target & Scan Details",
            "Enter the target you want to scan "
            "and give this scan a name."
        )
        self.add_step_indicator(1)

        self.add_field_label(
            "Target",
            "Domain, IP address or CIDR range"
        )
        self.target_input = self.make_input(
            "e.g. scanme.nmap.org or 192.168.112.130",
            self.scan_config.get('target', '')
        )
        self.main_layout.addWidget(self.target_input)

        self.main_layout.addSpacing(28)

        self.add_field_label(
            "Scan Name",
            "Give this scan a descriptive name"
        )
        self.name_input = self.make_input(
            "e.g. Q2 External Recon",
            self.scan_config.get('name', '')
        )
        self.main_layout.addWidget(self.name_input)

        self.main_layout.addSpacing(12)

        self.step1_error = QLabel("")
        self.step1_error.setObjectName("errorLabel")
        self.main_layout.addWidget(self.step1_error)

        self.add_nav(next_fn=self.validate_step1)

    def validate_step1(self):
        target = self.target_input.text().strip()
        name   = self.name_input.text().strip()

        if not target:
            self.step1_error.setText(
                "Target cannot be empty."
            )
            return

        if not name:
            self.step1_error.setText(
                "Scan name cannot be empty."
            )
            return

        result = validate_target(target)
        if not result['allowed']:
            self.step1_error.setText(
                f"Target blocked: {result['reason']}"
            )
            return

        self.scan_config['target'] = target
        self.scan_config['name']   = name
        self.show_step(2)

    # ── Step 2 ───────────────────────────────────────────────
    def build_step2(self):
        self.add_title(
            "Step 2 — Choose Folder",
            "Organise this scan into a folder "
            "by client or project."
        )
        self.add_step_indicator(2)

        self.add_field_label(
            "Select Folder",
            "Pick an existing folder or create a new one below"
        )

        self.folder_combo = QComboBox()
        self.folder_combo.setObjectName("inputField")
        self.folder_combo.addItem(
            "— No folder (unorganised) —", None
        )
        self.load_folders_combo()
        self.main_layout.addWidget(self.folder_combo)

        self.main_layout.addSpacing(28)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFixedHeight(1)
        divider.setStyleSheet("background:#30363d;")
        self.main_layout.addWidget(divider)

        self.main_layout.addSpacing(24)

        new_lbl = QLabel("Create New Folder")
        new_lbl.setObjectName("fieldLabel")
        self.main_layout.addWidget(new_lbl)

        self.main_layout.addSpacing(4)

        new_sub = QLabel(
            "Type a name and click Create — "
            "it will be added to the dropdown above."
        )
        new_sub.setObjectName("fieldSub")
        self.main_layout.addWidget(new_sub)

        self.main_layout.addSpacing(12)

        name_row = QHBoxLayout()
        name_row.setSpacing(10)

        self.new_folder_name = self.make_input(
            "e.g. Client A — VAPT"
        )
        name_row.addWidget(self.new_folder_name)

        create_btn = QPushButton("+ Create Folder")
        create_btn.setObjectName("createFolderBtn")
        create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        create_btn.clicked.connect(self.create_folder_inline)
        name_row.addWidget(create_btn)

        self.main_layout.addLayout(name_row)

        self.main_layout.addSpacing(16)

        self.add_field_label("Description (optional)")
        self.new_folder_desc = self.make_input(
            "e.g. External VAPT for Client A"
        )
        self.main_layout.addWidget(self.new_folder_desc)

        self.main_layout.addSpacing(12)

        self.folder_msg = QLabel("")
        self.folder_msg.setObjectName("successLabel")
        self.main_layout.addWidget(self.folder_msg)

        self.add_nav(back_step=1, next_fn=self.validate_step2)

    def load_folders_combo(self):
        from backend.db import get_folders
        try:
            for folder in get_folders():
                self.folder_combo.addItem(
                    f"📁 {folder['name']}", folder['id']
                )
            saved = self.scan_config.get('folder_id')
            if saved:
                for i in range(self.folder_combo.count()):
                    if self.folder_combo.itemData(i) == saved:
                        self.folder_combo.setCurrentIndex(i)
                        break
        except Exception:
            pass

    def create_folder_inline(self):
        from backend.db import insert_folder
        name = self.new_folder_name.text().strip()
        if not name:
            self.folder_msg.setStyleSheet(
                "color:#e94560;font-size:11px;"
            )
            self.folder_msg.setText(
                "Please enter a folder name."
            )
            return

        desc      = self.new_folder_desc.text().strip()
        folder_id = insert_folder(name, desc)
        self.folder_combo.addItem(f"📁 {name}", folder_id)
        self.folder_combo.setCurrentIndex(
            self.folder_combo.count() - 1
        )
        self.new_folder_name.clear()
        self.new_folder_desc.clear()
        self.folder_msg.setStyleSheet(
            "color:#1d9e75;font-size:11px;"
        )
        self.folder_msg.setText(
            f"✓ Folder '{name}' created and selected!"
        )

    def validate_step2(self):
        self.scan_config['folder_id'] = (
            self.folder_combo.currentData()
        )
        self.show_step(3)

    # ── Step 3 ───────────────────────────────────────────────
    def build_step3(self):
        self.add_title(
            "Step 3 — Select Scan Profile",
            "Choose how aggressive the scan should be."
        )
        self.add_step_indicator(3)

        self.profile_buttons = {}

        for profile, description in PROFILES.items():
            btn = QPushButton(f"{profile}\n{description}")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #161b22;
                    color: #e6edf3;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 14px 16px;
                    text-align: left;
                    font-size: 13px;
                }
                QPushButton:hover {
                    border: 1px solid #e94560;
                    color: #e94560;
                }
            """)
            btn.clicked.connect(
                lambda checked, p=profile:
                self.select_profile(p)
            )
            self.main_layout.addWidget(btn)
            self.main_layout.addSpacing(12)
            self.profile_buttons[profile] = btn

        if 'profile' in self.scan_config:
            self.select_profile(self.scan_config['profile'])

        self.step3_error = QLabel("")
        self.step3_error.setObjectName("errorLabel")
        self.main_layout.addWidget(self.step3_error)

        self.add_nav(back_step=2, next_fn=self.validate_step3)

    def select_profile(self, selected):
        self.scan_config['profile'] = selected
        for profile, btn in self.profile_buttons.items():
            if profile == selected:
                btn.setChecked(True)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #21262d;
                        color: #e94560;
                        border: 2px solid #e94560;
                        border-radius: 6px;
                        padding: 14px 16px;
                        text-align: left;
                        font-size: 13px;
                        font-weight: bold;
                    }
                """)
            else:
                btn.setChecked(False)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #161b22;
                        color: #e6edf3;
                        border: 1px solid #30363d;
                        border-radius: 6px;
                        padding: 14px 16px;
                        text-align: left;
                        font-size: 13px;
                    }
                    QPushButton:hover {
                        border: 1px solid #e94560;
                        color: #e94560;
                    }
                """)

    def validate_step3(self):
        if 'profile' not in self.scan_config:
            self.step3_error.setText(
                "Please select a scan profile."
            )
            return
        self.show_step(4)

    # ── Step 4 ───────────────────────────────────────────────
    def build_step4(self):
        self.add_title(
            "Step 4 — Select Tools",
            "Click a card to select or deselect a tool."
        )
        self.add_step_indicator(4)

        action_row = QHBoxLayout()

        select_all_btn = QPushButton("Select All")
        select_all_btn.setObjectName("smallBtn")
        select_all_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        select_all_btn.clicked.connect(self.select_all_tools)
        action_row.addWidget(select_all_btn)

        clear_btn = QPushButton("Clear All")
        clear_btn.setObjectName("smallBtn")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_all_tools)
        action_row.addWidget(clear_btn)

        action_row.addStretch()

        self.tool_count_lbl = QLabel("12 of 12 tools selected")
        self.tool_count_lbl.setObjectName("fieldSub")
        action_row.addWidget(self.tool_count_lbl)

        self.main_layout.addLayout(action_row)
        self.main_layout.addSpacing(12)

        self.tool_cards = {}
        tools_list      = list(TOOLS.items())

        for i in range(0, len(tools_list), 2):
            row = QHBoxLayout()
            row.setSpacing(10)

            tool1, (emoji1, desc1) = tools_list[i]
            card1 = ToolCard(tool1, emoji1, desc1)
            card1.mousePressEvent = (
                lambda e, c=card1: self.on_card_click(c, e)
            )
            row.addWidget(card1)
            self.tool_cards[tool1] = card1

            if i + 1 < len(tools_list):
                tool2, (emoji2, desc2) = tools_list[i + 1]
                card2 = ToolCard(tool2, emoji2, desc2)
                card2.mousePressEvent = (
                    lambda e, c=card2: self.on_card_click(c, e)
                )
                row.addWidget(card2)
                self.tool_cards[tool2] = card2

            self.main_layout.addLayout(row)
            self.main_layout.addSpacing(10)

        self.step4_error = QLabel("")
        self.step4_error.setObjectName("errorLabel")
        self.main_layout.addWidget(self.step4_error)

        self.add_nav(back_step=3, next_fn=self.validate_step4)

    def on_card_click(self, card, event):
        card.selected = not card.selected
        card.update_style()
        self.update_tool_count()

    def update_tool_count(self):
        selected = sum(
            1 for c in self.tool_cards.values()
            if c.is_selected()
        )
        total = len(self.tool_cards)
        self.tool_count_lbl.setText(
            f"{selected} of {total} tools selected"
        )

    def select_all_tools(self):
        for card in self.tool_cards.values():
            card.set_selected(True)
        self.update_tool_count()

    def clear_all_tools(self):
        for card in self.tool_cards.values():
            card.set_selected(False)
        self.update_tool_count()

    def validate_step4(self):
        selected = [
            t for t, c in self.tool_cards.items()
            if c.is_selected()
        ]
        if not selected:
            self.step4_error.setText(
                "Please select at least one tool."
            )
            return
        self.scan_config['tools'] = selected
        self.show_step(5)

    # ── Step 5 ───────────────────────────────────────────────
    def build_step5(self):
        self.add_title(
            "Step 5 — Confirm & Start Scan",
            "Review your scan configuration before starting."
        )
        self.add_step_indicator(5)

        folder_id   = self.scan_config.get('folder_id')
        folder_name = '— No folder —'
        if folder_id:
            from backend.db import get_folders
            for f in get_folders():
                if f['id'] == folder_id:
                    folder_name = f['name']
                    break

        details = [
            ("Target",    self.scan_config.get('target', '')),
            ("Scan Name", self.scan_config.get('name', '')),
            ("Folder",    folder_name),
            ("Profile",   self.scan_config.get('profile', '')),
            ("Tools",     ', '.join(
                self.scan_config.get('tools', [])
            )),
        ]

        for label, value in details:
            row = QHBoxLayout()
            lbl = QLabel(f"{label}:")
            lbl.setObjectName("confirmLabel")
            lbl.setFixedWidth(130)
            val = QLabel(value)
            val.setObjectName("confirmValue")
            val.setWordWrap(True)
            row.addWidget(lbl)
            row.addWidget(val)
            self.main_layout.addLayout(row)
            self.main_layout.addSpacing(14)

        self.add_nav(
            back_step=4,
            next_fn=self.start_scan,
            next_label="Start Scan ↗"
        )

    def start_scan(self):
        if self.on_scan_start:
            self.on_scan_start(self.scan_config)

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            QScrollArea { border: none; }
            #wizardTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #wizardSub { color: #8b949e; font-size: 12px; }
            #fieldLabel {
                color: #e6edf3;
                font-size: 13px;
                font-weight: bold;
            }
            #fieldSub { color: #8b949e; font-size: 11px; }
            #inputField {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px 14px;
                font-size: 13px;
                min-height: 20px;
            }
            #inputField:focus { border: 1px solid #e94560; }
            QComboBox {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px 14px;
                font-size: 13px;
                min-height: 20px;
            }
            QComboBox:focus { border: 1px solid #e94560; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #30363d;
                selection-background-color: #21262d;
                selection-color: #e94560;
            }
            #createFolderBtn {
                background-color: #21262d;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px 18px;
                font-size: 12px;
                font-weight: bold;
                min-height: 20px;
            }
            #createFolderBtn:hover {
                border-color: #e94560;
                color: #e94560;
            }
            #smallBtn {
                background-color: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 11px;
            }
            #smallBtn:hover {
                border-color: #e94560;
                color: #e94560;
            }
            #errorLabel {
                color: #e94560;
                font-size: 12px;
                margin-top: 4px;
            }
            #successLabel {
                color: #1d9e75;
                font-size: 12px;
                margin-top: 4px;
            }
            #confirmLabel {
                color: #8b949e;
                font-size: 13px;
            }
            #confirmValue {
                color: #e6edf3;
                font-size: 13px;
                font-weight: bold;
            }
        """
