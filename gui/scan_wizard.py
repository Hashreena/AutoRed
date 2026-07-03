from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QCheckBox,
    QComboBox, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt
from backend.scope import validate_target
from gui.preferences import load_prefs, get_theme
# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def rgba_from_hex(hex_color, alpha):
    color = hex_color.strip().lstrip("#")
    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"
    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)
    return f"rgba({red}, {green}, {blue}, {alpha})"
def theme_value(theme, key, fallback):
    return theme.get(key, fallback)
PROFILES = {
    "Production": "Safe and slow. Rate limited. Good for live environments.",
    "Standard": "Balanced speed and coverage. Recommended for most scans.",
    "Deep": "Aggressive and thorough. Use only on test environments.",
}
TOOLS = {
    "nmap": ("🔍", "Port scanning and service detection."),
    "subfinder": ("🌐", "Subdomain discovery via OSINT."),
    "httpx": ("📡", "Identifies live web hosts."),
    "whatweb": ("🕵️", "Web technology fingerprinting."),
    "ffuf": ("💨", "Directory and endpoint fuzzing."),
    "nikto": ("🎯", "Web server vulnerability scanner."),
    "theharvester": ("🌾", "OSINT email and host harvesting."),
    "dnsrecon": ("🔎", "DNS enumeration and record discovery."),
    "gobuster": ("👻", "Directory and file brute forcing."),
    "dirsearch": ("📂", "Web path discovery with curated wordlists."),
    "wpscan": ("🔒", "WordPress vulnerability scanner."),
    "nuclei": ("⚡", "Template-based CVE vulnerability scanner."),
}
STEP_LABELS = [
    "Target",
    "Folder",
    "Profile",
    "Tools",
    "Confirm",
]
class ToolCard(QFrame):
    def __init__(
        self,
        tool_name,
        emoji,
        description,
        theme=None,
        font_size=13,
        parent=None,
    ):
        super().__init__(parent)
        self.tool_name = tool_name
        self.selected = True
        self.t = theme or get_theme(True)
        self.fs = font_size
        self.setObjectName("toolCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(72)
        self.init_ui(emoji, description)
        self.update_style()
    def set_theme(self, theme, font_size=None):
        self.t = theme
        if font_size is not None:
            self.fs = font_size
        self.apply_text_styles()
        self.update_style()
    def init_ui(self, emoji, description):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        self.emoji_lbl = QLabel(emoji)
        self.emoji_lbl.setFixedWidth(28)
        self.emoji_lbl.setStyleSheet(
            """
            font-size: 20px;
            background: transparent;
            border: none;
            """
        )
        layout.addWidget(self.emoji_lbl)
        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        self.name_lbl = QLabel(self.tool_name)
        text_col.addWidget(self.name_lbl)
        self.desc_lbl = QLabel(description)
        text_col.addWidget(self.desc_lbl)
        layout.addLayout(text_col)
        layout.addStretch()
        self.check_lbl = QLabel("✓")
        self.check_lbl.setFixedSize(22, 22)
        self.check_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.check_lbl)
        self.apply_text_styles()
    def apply_text_styles(self):
        self.name_lbl.setStyleSheet(
            f"""
            color: {self.t["text"]};
            font-size: {self.fs}px;
            font-weight: 800;
            background: transparent;
            border: none;
            """
        )
        self.desc_lbl.setStyleSheet(
            f"""
            color: {self.t["text_muted"]};
            font-size: {self.fs - 2}px;
            background: transparent;
            border: none;
            """
        )
    def update_style(self):
        accent = self.t["accent"]
        accent_hover = self.t["accent_hover"]
        card_bg = self.t["card_bg"]
        card_bg_2 = self.t["card_bg_2"]
        border = self.t["border"]
        border_soft = self.t["border_soft"]
        hover = self.t.get("hover", rgba_from_hex(accent, 18))
        if self.selected:
            self.setStyleSheet(
                f"""
                QFrame#toolCard {{
                    background-color: {card_bg};
                    border: 1px solid {accent};
                    border-radius: 9px;
                }}
                QFrame#toolCard:hover {{
                    background-color: {card_bg_2};
                    border: 1px solid {accent_hover};
                }}
                """
            )
            self.check_lbl.setText("✓")
            self.check_lbl.setStyleSheet(
                f"""
                background-color: {accent};
                color: white;
                border-radius: 5px;
                font-size: {self.fs - 1}px;
                font-weight: 900;
                border: none;
                """
            )
        else:
            self.setStyleSheet(
                f"""
                QFrame#toolCard {{
                    background-color: {card_bg};
                    border: 1px solid {border};
                    border-radius: 9px;
                }}
                QFrame#toolCard:hover {{
                    border: 1px solid {accent};
                    background-color: {hover};
                }}
                """
            )
            self.check_lbl.setText("")
            self.check_lbl.setStyleSheet(
                f"""
                background: transparent;
                color: transparent;
                border-radius: 5px;
                border: 1px solid {border_soft};
                """
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
    def __init__(self, on_scan_start=None, prefs=None):
        super().__init__()
        self.on_scan_start = on_scan_start
        self.scan_config = {}
        self.tool_cards = {}
        self.profile_buttons = {}
        self.current_step = 1
        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────
    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        self.setStyleSheet(self.get_stylesheet())
        if hasattr(self, "scroll"):
            self.scroll.setStyleSheet(
                f"""
                QScrollArea {{
                    border: none;
                    background: {self.t["bg"]};
                }}
                """
            )
        if hasattr(self, "container"):
            self.container.setStyleSheet(
                f"""
                background-color: {self.t["bg"]};
                """
            )
        self._capture_current_inputs()
        self.show_step(self.current_step)
    def _capture_current_inputs(self):
        step = getattr(self, "current_step", 1)
        try:
            if step == 1:
                if hasattr(self, "target_input"):
                    self.scan_config["target"] = (
                        self.target_input.text().strip()
                    )
                if hasattr(self, "name_input"):
                    self.scan_config["name"] = (
                        self.name_input.text().strip()
                    )
            elif step == 2:
                if hasattr(self, "folder_combo"):
                    self.scan_config["folder_id"] = (
                        self.folder_combo.currentData()
                    )
            elif step == 4:
                if self.tool_cards:
                    self.scan_config["tools"] = [
                        tool_name
                        for tool_name, card in self.tool_cards.items()
                        if card.is_selected()
                    ]
        except Exception:
            pass
    # ─────────────────────────────────────────────
    # Base UI
    # ─────────────────────────────────────────────
    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet(
            f"""
            QScrollArea {{
                border: none;
                background: {self.t["bg"]};
            }}
            """
        )
        self.container = QWidget()
        self.container.setStyleSheet(
            f"""
            background-color: {self.t["bg"]};
            """
        )
        self.main_layout = QVBoxLayout(self.container)
        self.main_layout.setContentsMargins(50, 36, 50, 36)
        self.main_layout.setSpacing(0)
        self.scroll.setWidget(self.container)
        outer.addWidget(self.scroll)
        self.show_step(1)
    def clear_layout(self):
        while self.main_layout.count():
            item = self.main_layout.takeAt(0)
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
            item = layout.takeAt(0)
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
    # ─────────────────────────────────────────────
    # Shared builders
    # ─────────────────────────────────────────────
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
                    f"""
                    background-color: {self.t["accent"]};
                    color: white;
                    border-radius: 15px;
                    font-weight: 900;
                    font-size: {self.fs - 2}px;
                    border: 1px solid {self.t["accent_hover"]};
                    """
                )
            else:
                dot.setStyleSheet(
                    f"""
                    background-color: {self.t["card_bg"]};
                    color: {self.t["text_muted"]};
                    border-radius: 15px;
                    font-size: {self.fs - 2}px;
                    border: 1px solid {self.t["border"]};
                    """
                )
            col.addWidget(dot)
            lbl = QLabel(STEP_LABELS[i - 1])
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"""
                color: {self.t["accent"] if i == current else self.t["text_muted"]};
                font-size: {self.fs - 3}px;
                font-weight: {"800" if i == current else "600"};
                background: transparent;
                border: none;
                """
            )
            col.addWidget(lbl)
            row.addLayout(col)
            if i < 5:
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setFixedHeight(1)
                if i < current:
                    line.setStyleSheet(
                        f"""
                        background-color: {self.t["accent"]};
                        border: none;
                        """
                    )
                else:
                    line.setStyleSheet(
                        f"""
                        background-color: {self.t["border"]};
                        border: none;
                        """
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
            subtitle = QLabel(sub)
            subtitle.setObjectName("wizardSub")
            self.main_layout.addWidget(subtitle)
        self.main_layout.addSpacing(28)
    def add_field_label(self, text, sub=None):
        lbl = QLabel(text)
        lbl.setObjectName("fieldLabel")
        self.main_layout.addWidget(lbl)
        if sub:
            self.main_layout.addSpacing(3)
            sub_lbl = QLabel(sub)
            sub_lbl.setObjectName("fieldSub")
            self.main_layout.addWidget(sub_lbl)
        self.main_layout.addSpacing(8)
    def make_input(self, placeholder="", value=""):
        inp = QLineEdit()
        inp.setPlaceholderText(placeholder)
        inp.setObjectName("inputField")
        if value:
            inp.setText(value)
        return inp
    def add_nav(
        self,
        back_step=None,
        next_fn=None,
        next_label="Next →",
    ):
        self.main_layout.addSpacing(32)
        self.main_layout.addStretch()
        nav = QHBoxLayout()
        primary_btn_style = f"""
            QPushButton {{
                background-color: {self.t["accent"]};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 11px 28px;
                font-size: {self.fs}px;
                font-weight: 900;
            }}
            QPushButton:hover {{
                background-color: {self.t["accent_hover"]};
            }}
            QPushButton:pressed {{
                background-color: {self.t["accent_dark"]};
            }}
        """
        secondary_btn_style = f"""
            QPushButton {{
                background-color: {self.t.get("button_soft", self.t["card_bg"])};
                color: {self.t["text"]};
                border: 1px solid {self.t["border"]};
                border-radius: 8px;
                padding: 11px 28px;
                font-size: {self.fs}px;
                font-weight: 800;
            }}
            QPushButton:hover {{
                border-color: {self.t["accent"]};
                color: {self.t["accent"]};
                background-color: {self.t.get("hover", rgba_from_hex(self.t["accent"], 22))};
            }}
            QPushButton:pressed {{
                background-color: {rgba_from_hex(self.t["accent_dark"], 85)};
            }}
        """
        if back_step is not None:
            back_btn = QPushButton("← Back")
            back_btn.setStyleSheet(secondary_btn_style)
            back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            back_btn.clicked.connect(
                lambda: self.show_step(back_step)
            )
            nav.addWidget(back_btn)
        nav.addStretch()
        if next_fn:
            nxt = QPushButton(next_label)
            nxt.setStyleSheet(primary_btn_style)
            nxt.setCursor(Qt.CursorShape.PointingHandCursor)
            nxt.clicked.connect(next_fn)
            nav.addWidget(nxt)
        self.main_layout.addLayout(nav)
    # ─────────────────────────────────────────────
    # Step 1
    # ─────────────────────────────────────────────
    def build_step1(self):
        self.add_title(
            "Step 1 — Target & Scan Details",
            "Enter the target you want to scan and give this scan a name."
        )
        self.add_step_indicator(1)
        self.add_field_label(
            "Target",
            "Domain, IP address or CIDR range"
        )
        self.target_input = self.make_input(
            "e.g. scanme.nmap.org or 192.168.112.130",
            self.scan_config.get("target", "")
        )
        self.main_layout.addWidget(self.target_input)
        self.main_layout.addSpacing(28)
        self.add_field_label(
            "Scan Name",
            "Give this scan a descriptive name"
        )
        self.name_input = self.make_input(
            "e.g. Q2 External Recon",
            self.scan_config.get("name", "")
        )
        self.main_layout.addWidget(self.name_input)
        self.main_layout.addSpacing(12)
        # ── Error / info label ──
        self.step1_error = QLabel("")
        self.step1_error.setObjectName("errorLabel")
        self.step1_error.setWordWrap(True)
        self.main_layout.addWidget(self.step1_error)
        # ── Category label (shown when blocked) ──
        self.step1_category = QLabel("")
        self.step1_category.setObjectName("categoryLabel")
        self.step1_category.setWordWrap(True)
        self.main_layout.addWidget(self.step1_category)
        # ── Action label (tells user what to do) ──
        self.step1_action = QLabel("")
        self.step1_action.setObjectName("actionLabel")
        self.step1_action.setWordWrap(True)
        self.main_layout.addWidget(self.step1_action)
        self.add_nav(next_fn=self.validate_step1)
    def validate_step1(self):
        target = self.target_input.text().strip()
        name   = self.name_input.text().strip()
        # Reset all labels
        self.step1_error.setText("")
        self.step1_category.setText("")
        self.step1_action.setText("")
        if not target:
            self.step1_error.setText("⛔  Target cannot be empty.")
            return
        if not name:
            self.step1_error.setText("⛔  Scan name cannot be empty.")
            return
        result = validate_target(target)
        if not result["allowed"]:
            # ── Main error: why it is blocked ──
            self.step1_error.setStyleSheet(
                f"""
                color: {self.t["brand_red"]};
                font-size: {self.fs - 1}px;
                font-weight: 700;
                background: transparent;
                border: none;
                margin-top: 6px;
                """
            )
            self.step1_error.setText(
                f"⛔  Target Blocked: {result['reason']}"
            )
            # ── Category badge ──
            category = result.get("category", "")
            if category:
                self.step1_category.setStyleSheet(
                    f"""
                    color: {self.t["warning"] if hasattr(self.t, "warning") else "#CA8A04"};
                    font-size: {self.fs - 2}px;
                    font-weight: 800;
                    background: transparent;
                    border: none;
                    margin-top: 4px;
                    """
                )
                self.step1_category.setText(
                    f"Category: {category}"
                )
            # ── Action: what the user should do ──
            action = result.get("action", "")
            if action:
                self.step1_action.setStyleSheet(
                    f"""
                    color: {self.t["text_muted"]};
                    font-size: {self.fs - 2}px;
                    background: transparent;
                    border: none;
                    margin-top: 4px;
                    """
                )
                self.step1_action.setText(
                    f"What to do: {action}\n\n"
                    f"Go to Authorised Targets Manager to "
                    f"request authorization for this target."
                )
            return
        # ── Authorized override (on blocklist but approved) ──
        if result.get("authorized"):
            self.step1_error.setStyleSheet(
                f"""
                color: {self.t["success"]};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
                """
            )
            self.step1_error.setText(
                "✓  Authorized target — proceeding with scan."
            )
        self.scan_config["target"] = target
        self.scan_config["name"]   = name
        self.show_step(2)
    # ─────────────────────────────────────────────
    # Step 2
    # ─────────────────────────────────────────────
    def build_step2(self):
        self.add_title(
            "Step 2 — Choose Folder",
            "Organise this scan into a folder by client or project."
        )
        self.add_step_indicator(2)
        self.add_field_label(
            "Select Folder",
            "Pick an existing folder or create a new one below"
        )
        self.folder_combo = QComboBox()
        self.folder_combo.setObjectName("inputField")
        self.folder_combo.addItem(
            "— No folder (unorganised) —",
            None
        )
        self.load_folders_combo()
        self.main_layout.addWidget(self.folder_combo)
        self.main_layout.addSpacing(28)
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFixedHeight(1)
        divider.setStyleSheet(
            f"""
            background-color: {self.t["border"]};
            border: none;
            """
        )
        self.main_layout.addWidget(divider)
        self.main_layout.addSpacing(24)
        new_lbl = QLabel("Create New Folder")
        new_lbl.setObjectName("fieldLabel")
        self.main_layout.addWidget(new_lbl)
        self.main_layout.addSpacing(4)
        new_sub = QLabel(
            "Type a name and click Create — it will be added to the dropdown above."
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
        self.add_nav(
            back_step=1,
            next_fn=self.validate_step2
        )
    def load_folders_combo(self):
        from backend.db import get_folders
        try:
            for folder in get_folders():
                self.folder_combo.addItem(
                    f"📁 {folder['name']}",
                    folder["id"]
                )
            saved = self.scan_config.get("folder_id")
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
                f"""
                color: {self.t["brand_red"]};
                font-size: {self.fs - 2}px;
                background: transparent;
                border: none;
                """
            )
            self.folder_msg.setText("Please enter a folder name.")
            return
        desc = self.new_folder_desc.text().strip()
        folder_id = insert_folder(name, desc)
        self.folder_combo.addItem(f"📁 {name}", folder_id)
        self.folder_combo.setCurrentIndex(
            self.folder_combo.count() - 1
        )
        self.new_folder_name.clear()
        self.new_folder_desc.clear()
        self.folder_msg.setStyleSheet(
            f"""
            color: {self.t["success"]};
            font-size: {self.fs - 2}px;
            background: transparent;
            border: none;
            """
        )
        self.folder_msg.setText(
            f"✓ Folder '{name}' created and selected!"
        )
    def validate_step2(self):
        self.scan_config["folder_id"] = (
            self.folder_combo.currentData()
        )
        self.show_step(3)
    # ─────────────────────────────────────────────
    # Step 3
    # ─────────────────────────────────────────────
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
            btn.setStyleSheet(self.profile_button_style(active=False))
            btn.clicked.connect(
                lambda checked, p=profile: self.select_profile(p)
            )
            self.main_layout.addWidget(btn)
            self.main_layout.addSpacing(12)
            self.profile_buttons[profile] = btn
        if "profile" in self.scan_config:
            self.select_profile(self.scan_config["profile"])
        self.step3_error = QLabel("")
        self.step3_error.setObjectName("errorLabel")
        self.main_layout.addWidget(self.step3_error)
        self.add_nav(
            back_step=2,
            next_fn=self.validate_step3
        )
    def profile_button_style(self, active=False):
        if active:
            return f"""
                QPushButton {{
                    background-color: {self.t.get("hover", rgba_from_hex(self.t["accent"], 24))};
                    color: {self.t["accent"]};
                    border: 2px solid {self.t["accent"]};
                    border-radius: 8px;
                    padding: 14px 16px;
                    text-align: left;
                    font-size: {self.fs}px;
                    font-weight: 900;
                }}
            """
        return f"""
            QPushButton {{
                background-color: {self.t["card_bg"]};
                color: {self.t["text"]};
                border: 1px solid {self.t["border"]};
                border-radius: 8px;
                padding: 14px 16px;
                text-align: left;
                font-size: {self.fs}px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                border: 1px solid {self.t["accent"]};
                color: {self.t["accent"]};
                background-color: {self.t.get("hover", rgba_from_hex(self.t["accent"], 18))};
            }}
        """
    def select_profile(self, selected):
        self.scan_config["profile"] = selected
        for profile, btn in self.profile_buttons.items():
            if profile == selected:
                btn.setChecked(True)
                btn.setStyleSheet(
                    self.profile_button_style(active=True)
                )
            else:
                btn.setChecked(False)
                btn.setStyleSheet(
                    self.profile_button_style(active=False)
                )
    def validate_step3(self):
        if "profile" not in self.scan_config:
            self.step3_error.setText(
                "Please select a scan profile."
            )
            return
        self.show_step(4)
    # ─────────────────────────────────────────────
    # Step 4
    # ─────────────────────────────────────────────
    def build_step4(self):
        self.add_title(
            "Step 4 — Select Tools",
            "Click a card to select or deselect a tool."
        )
        self.add_step_indicator(4)
        action_row = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.setObjectName("smallBtn")
        select_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
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
        tools_list = list(TOOLS.items())
        prev_selection = self.scan_config.get("tools")
        for i in range(0, len(tools_list), 2):
            row = QHBoxLayout()
            row.setSpacing(10)
            tool1, (emoji1, desc1) = tools_list[i]
            card1 = ToolCard(
                tool1,
                emoji1,
                desc1,
                theme=self.t,
                font_size=self.fs
            )
            card1.mousePressEvent = (
                lambda event, c=card1: self.on_card_click(c, event)
            )
            if prev_selection is not None:
                card1.set_selected(tool1 in prev_selection)
            row.addWidget(card1)
            self.tool_cards[tool1] = card1
            if i + 1 < len(tools_list):
                tool2, (emoji2, desc2) = tools_list[i + 1]
                card2 = ToolCard(
                    tool2,
                    emoji2,
                    desc2,
                    theme=self.t,
                    font_size=self.fs
                )
                card2.mousePressEvent = (
                    lambda event, c=card2: self.on_card_click(c, event)
                )
                if prev_selection is not None:
                    card2.set_selected(tool2 in prev_selection)
                row.addWidget(card2)
                self.tool_cards[tool2] = card2
            self.main_layout.addLayout(row)
            self.main_layout.addSpacing(10)
        self.step4_error = QLabel("")
        self.step4_error.setObjectName("errorLabel")
        self.main_layout.addWidget(self.step4_error)
        self.update_tool_count()
        self.add_nav(
            back_step=3,
            next_fn=self.validate_step4
        )
    def on_card_click(self, card, event):
        card.selected = not card.selected
        card.update_style()
        self.update_tool_count()
    def update_tool_count(self):
        selected = sum(
            1
            for card in self.tool_cards.values()
            if card.is_selected()
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
            tool_name
            for tool_name, card in self.tool_cards.items()
            if card.is_selected()
        ]
        if not selected:
            self.step4_error.setText(
                "Please select at least one tool."
            )
            return
        self.scan_config["tools"] = selected
        self.show_step(5)
    # ─────────────────────────────────────────────
    # Step 5
    # ─────────────────────────────────────────────
    def build_step5(self):
        self.add_title(
            "Step 5 — Confirm & Start Scan",
            "Review your scan configuration before starting."
        )
        self.add_step_indicator(5)
        folder_id = self.scan_config.get("folder_id")
        folder_name = "— No folder —"
        if folder_id:
            from backend.db import get_folders
            for folder in get_folders():
                if folder["id"] == folder_id:
                    folder_name = folder["name"]
                    break
        details = [
            ("Target", self.scan_config.get("target", "")),
            ("Scan Name", self.scan_config.get("name", "")),
            ("Folder", folder_name),
            ("Profile", self.scan_config.get("profile", "")),
            ("Tools", ", ".join(self.scan_config.get("tools", []))),
        ]
        summary_card = QFrame()
        summary_card.setObjectName("confirmCard")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(18, 16, 18, 16)
        summary_layout.setSpacing(14)
        for label, value in details:
            row = QHBoxLayout()
            lbl = QLabel(f"{label}:")
            lbl.setObjectName("confirmLabel")
            lbl.setFixedWidth(130)
            val = QLabel(value)
            val.setObjectName("confirmValue")
            val.setWordWrap(True)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            summary_layout.addLayout(row)
        self.main_layout.addWidget(summary_card)
        self.add_nav(
            back_step=4,
            next_fn=self.start_scan,
            next_label="Start Scan ↗"
        )
    def start_scan(self):
        if self.on_scan_start:
            self.on_scan_start(self.scan_config)
    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────
    def get_stylesheet(self):
        fs = self.fs
        t = self.t
        bg = t["bg"]
        bg_deep = t.get("bg_deep", bg)
        card_bg = t["card_bg"]
        card_bg_2 = t["card_bg_2"]
        border = t["border"]
        border_soft = t["border_soft"]
        text = t["text"]
        text_muted = t["text_muted"]
        text_soft = t["text_soft"]
        accent = t["accent"]
        accent_hover = t["accent_hover"]
        accent_dark = t["accent_dark"]
        brand_red = t["brand_red"]
        success = t["success"]
        hover = t.get("hover", rgba_from_hex(accent, 22))
        button_soft = t.get("button_soft", card_bg)
        selection_bg = t.get(
            "selection_bg",
            rgba_from_hex(accent, 35)
        )
        selection_text = t.get(
            "selection_text",
            "#FEE2E2"
        )
        card_hover = t.get(
            "card_hover",
            rgba_from_hex(accent, 80)
        )
        return f"""
            QWidget {{
                background-color: {bg};
                color: {text};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}
            QScrollArea {{
                border: none;
                background: {bg};
            }}
            QScrollBar:vertical {{
                background: {bg};
                width: 10px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {border_soft};
                border-radius: 5px;
                min-height: 28px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {accent};
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            #wizardTitle {{
                color: {accent};
                font-size: {fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
            #wizardSub {{
                color: {text_muted};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}
            #fieldLabel {{
                color: {text};
                font-size: {fs}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}
            #fieldSub {{
                color: {text_muted};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
            }}
            #inputField {{
                background-color: {card_bg};
                color: {text};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 12px 14px;
                font-size: {fs}px;
                min-height: 20px;
                selection-background-color: {accent};
                selection-color: white;
            }}
            #inputField:focus {{
                border: 1px solid {accent};
                background-color: {card_bg_2};
            }}
            QLineEdit {{
                background-color: {card_bg};
                color: {text};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 12px 14px;
                font-size: {fs}px;
                min-height: 20px;
                selection-background-color: {accent};
                selection-color: white;
            }}
            QLineEdit:focus {{
                border: 1px solid {accent};
                background-color: {card_bg_2};
            }}
            QLineEdit::placeholder {{
                color: {text_soft};
            }}
            QComboBox {{
                background-color: {card_bg};
                color: {text};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 12px 14px;
                font-size: {fs}px;
                min-height: 20px;
                selection-background-color: {accent};
                selection-color: white;
            }}
            QComboBox:focus {{
                border: 1px solid {accent};
                background-color: {card_bg_2};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 28px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {card_bg};
                color: {text};
                border: 1px solid {border};
                selection-background-color: {selection_bg};
                selection-color: {selection_text};
                outline: none;
            }}
            #createFolderBtn {{
                background-color: {button_soft};
                color: {text};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 12px 18px;
                font-size: {fs - 1}px;
                font-weight: 800;
                min-height: 20px;
            }}
            #createFolderBtn:hover {{
                border-color: {accent};
                color: {accent};
                background-color: {hover};
            }}
            #smallBtn {{
                background-color: {button_soft};
                color: {text_muted};
                border: 1px solid {border};
                border-radius: 7px;
                padding: 6px 14px;
                font-size: {fs - 2}px;
                font-weight: 700;
            }}
            #smallBtn:hover {{
                border-color: {accent};
                color: {accent};
                background-color: {hover};
            }}
            #errorLabel {{
                color: {brand_red};
                font-size: {fs - 1}px;
                font-weight: 700;
                background: transparent;
                border: none;
                margin-top: 4px;
            }}
            #categoryLabel {{
                color: #CA8A04;
                font-size: {fs - 2}px;
                font-weight: 800;
                background: transparent;
                border: none;
                margin-top: 4px;
            }}
            #actionLabel {{
                color: {text_muted};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
                margin-top: 4px;
            }}
            #successLabel {{
                color: {success};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
                margin-top: 4px;
            }}
            #confirmCard {{
                background-color: {card_bg};
                border: 1px solid {border};
                border-radius: 10px;
            }}
            #confirmCard:hover {{
                border: 1px solid {card_hover};
            }}
            #confirmLabel {{
                color: {text_muted};
                font-size: {fs}px;
                background: transparent;
                border: none;
            }}
            #confirmValue {{
                color: {text};
                font-size: {fs}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}
        """
