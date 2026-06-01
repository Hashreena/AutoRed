from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QComboBox,
    QCheckBox, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QApplication
import json
import os
import sys
import subprocess

SETTINGS_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'storage', 'settings.json'
)

PROJECT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)

PYTHON = sys.executable

DEFAULT_SETTINGS = {
    'theme':              'Dark',
    'default_severity':   'All',
    'auto_open_findings': True,
    'scan_notifications': True,
}

THEMES = {
    'Dark': {
        'bg':      '#0d1117',
        'card':    '#161b22',
        'card2':   '#21262d',
        'border':  '#30363d',
        'text':    '#e6edf3',
        'dim':     '#8b949e',
        'accent':  '#e94560',
        'sidebar': '#161b22',
    },
    'Light': {
        'bg':      '#f6f8fa',
        'card':    '#ffffff',
        'card2':   '#f0f2f5',
        'border':  '#d0d7de',
        'text':    '#1f2328',
        'dim':     '#57606a',
        'accent':  '#e94560',
        'sidebar': '#f6f8fa',
    },
    'Midnight Blue': {
        'bg':      '#0a0e1a',
        'card':    '#0f1729',
        'card2':   '#162040',
        'border':  '#1e3a5f',
        'text':    '#cdd9e5',
        'dim':     '#768390',
        'accent':  '#4a9eff',
        'sidebar': '#0f1729',
    },
    'Hacker Green': {
        'bg':      '#0a0f0a',
        'card':    '#0f1a0f',
        'card2':   '#152415',
        'border':  '#1e3d1e',
        'text':    '#b5e5b5',
        'dim':     '#6a9e6a',
        'accent':  '#3fb950',
        'sidebar': '#0f1a0f',
    },
}

BG     = '#0d1117'
CARD   = '#161b22'
CARD2  = '#21262d'
BORDER = '#30363d'
TEXT   = '#e6edf3'
DIM    = '#8b949e'
RED    = '#e94560'


def load_settings():
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, 'r') as f:
                saved = json.load(f)
                return {**DEFAULT_SETTINGS, **saved}
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)


def save_settings(settings):
    try:
        os.makedirs(
            os.path.dirname(SETTINGS_PATH), exist_ok=True
        )
        with open(SETTINGS_PATH, 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        print(f"[!] Failed to save settings: {e}")
        return False


def get_theme():
    s = load_settings()
    return THEMES.get(s.get('theme', 'Dark'), THEMES['Dark'])


def restart_app():
    env = dict(os.environ)
    env['VIRTUAL_ENV'] = os.path.dirname(os.path.dirname(PYTHON))
    env['PATH'] = (
        os.path.dirname(PYTHON) + ':' + env.get('PATH', '')
    )
    subprocess.Popen(
        [PYTHON, '-m', 'gui.main_window'],
        cwd=PROJECT_DIR,
        env=env
    )
    QApplication.instance().quit()


class ThemeCard(QFrame):
    def __init__(self, theme_name, theme_data,
                 selected=False, on_select=None, parent=None):
        super().__init__(parent)
        self.theme_name = theme_name
        self.on_select  = on_select
        self.selected   = selected
        self.theme_data = theme_data
        self.setFixedSize(140, 90)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.init_ui()
        self.update_style()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        preview = QFrame()
        preview.setFixedHeight(36)
        bg     = self.theme_data['bg']
        card   = self.theme_data['card']
        accent = self.theme_data['accent']
        preview.setStyleSheet(
            f"background: {bg}; border-radius: 4px; border: none;"
        )
        pl = QHBoxLayout(preview)
        pl.setContentsMargins(4, 4, 4, 4)
        pl.setSpacing(4)

        sidebar_prev = QFrame()
        sidebar_prev.setFixedWidth(24)
        sidebar_prev.setStyleSheet(
            f"background: {card}; border-radius: 3px; border: none;"
        )
        pl.addWidget(sidebar_prev)

        content_prev = QFrame()
        content_prev.setStyleSheet(
            f"background: {bg}; border-radius: 3px; border: none;"
        )
        pl.addWidget(content_prev)

        dot = QFrame()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(
            f"background: {accent}; border-radius: 4px; border: none;"
        )
        pl.addWidget(dot)
        layout.addWidget(preview)

        name_lbl = QLabel(self.theme_name)
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet(
            "font-size: 11px; font-weight: bold; "
            "background: transparent; border: none;"
        )
        layout.addWidget(name_lbl)

    def update_style(self):
        accent = self.theme_data['accent']
        if self.selected:
            self.setStyleSheet(f"""
                QFrame {{
                    background: {CARD};
                    border: 2px solid {accent};
                    border-radius: 8px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QFrame {{
                    background: {CARD};
                    border: 1px solid {BORDER};
                    border-radius: 8px;
                }}
                QFrame:hover {{
                    border: 1px solid {accent};
                }}
            """)

    def mousePressEvent(self, event):
        if self.on_select:
            self.on_select(self.theme_name)
        super().mousePressEvent(event)

    def set_selected(self, val):
        self.selected = val
        self.update_style()


class SettingsScreen(QWidget):
    def __init__(self, on_close=None, app=None):
        super().__init__()
        self.on_close    = on_close
        self.app         = app or QApplication.instance()
        self.settings    = load_settings()
        self.fields      = {}
        self.theme_cards = {}
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

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
        layout.setSpacing(16)

        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        sub = QLabel(
            "Customise AutoRed appearance, "
            "scan behaviour and manage data."
        )
        sub.setObjectName("pageSub")
        layout.addWidget(sub)
        layout.addSpacing(4)

        layout.addWidget(self.build_theme_section())
        layout.addWidget(self.build_scan_section())
        layout.addWidget(self.build_data_section())
        layout.addWidget(self.build_about_section())

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        save_btn = QPushButton("Save & Apply")
        save_btn.setObjectName("saveBtn")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self.save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("Reset Defaults")
        reset_btn.setObjectName("resetBtn")
        reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reset_btn.clicked.connect(self.reset_defaults)
        btn_row.addWidget(reset_btn)

        layout.addLayout(btn_row)

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def make_section(self, title, subtitle=None):
        frame = QFrame()
        frame.setObjectName("settingsCard")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(20, 16, 20, 20)
        fl.setSpacing(12)

        t = QLabel(title)
        t.setObjectName("sectionTitle")
        fl.addWidget(t)

        if subtitle:
            s = QLabel(subtitle)
            s.setObjectName("sectionSub")
            fl.addWidget(s)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(
            f"background: {BORDER}; border: none; max-height: 1px;"
        )
        fl.addWidget(divider)

        return frame, fl

    def make_checkbox(self, layout, label, key):
        cb = QCheckBox(label)
        cb.setObjectName("settingsCheck")
        cb.setChecked(bool(self.settings.get(key, False)))
        self.fields[key] = cb
        layout.addWidget(cb)
        return cb

    def make_combo(self, layout, label, key, options):
        col = QVBoxLayout()
        col.setSpacing(4)

        lbl = QLabel(label)
        lbl.setObjectName("fieldLabel")
        col.addWidget(lbl)

        combo = QComboBox()
        combo.setObjectName("inputField")
        for opt in options:
            combo.addItem(opt)
        current = self.settings.get(key, options[0])
        idx = combo.findText(str(current))
        if idx >= 0:
            combo.setCurrentIndex(idx)
        self.fields[key] = combo
        col.addWidget(combo)
        layout.addLayout(col)
        return combo

    def build_theme_section(self):
        frame, fl = self.make_section(
            "🎨  Appearance",
            "Choose a colour theme. "
            "Click Save & Apply — AutoRed will restart with the new theme."
        )

        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        cards_row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        current_theme = self.settings.get('theme', 'Dark')

        for theme_name, theme_data in THEMES.items():
            card = ThemeCard(
                theme_name, theme_data,
                selected=(theme_name == current_theme),
                on_select=self.select_theme,
                parent=self
            )
            cards_row.addWidget(card)
            self.theme_cards[theme_name] = card

        cards_row.addStretch()
        fl.addLayout(cards_row)

        self.selected_theme_lbl = QLabel(
            f"Selected: {current_theme}"
        )
        self.selected_theme_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 11px; "
            f"background: transparent; border: none;"
        )
        fl.addWidget(self.selected_theme_lbl)

        note = QLabel(
            "⚠  AutoRed will restart automatically to apply the theme."
        )
        note.setStyleSheet(
            f"color: #ff8c00; font-size: 11px; "
            f"background: transparent; border: none;"
        )
        fl.addWidget(note)

        return frame

    def select_theme(self, theme_name):
        self.settings['theme'] = theme_name
        for name, card in self.theme_cards.items():
            card.set_selected(name == theme_name)
        self.selected_theme_lbl.setText(
            f"Selected: {theme_name}"
        )

    def build_scan_section(self):
        frame, fl = self.make_section(
            "⚙️  Scan Preferences",
            "Configure default behaviour when running "
            "and viewing scans."
        )

        self.make_combo(
            fl,
            "Default Severity Filter (when opening findings)",
            'default_severity',
            ['All', 'Critical', 'High', 'Medium', 'Low', 'Info']
        )

        fl.addSpacing(4)

        self.make_checkbox(
            fl,
            "Automatically open findings when scan completes",
            'auto_open_findings'
        )
        self.make_checkbox(
            fl,
            "Show notification when scan finishes",
            'scan_notifications'
        )

        return frame

    def build_data_section(self):
        frame, fl = self.make_section(
            "🗑️  Data Management",
            "Clear scan history and findings. "
            "Useful for resetting before a demo."
        )

        warn = QLabel(
            "⚠  These actions are irreversible. "
            "Export any reports you need first."
        )
        warn.setStyleSheet(
            f"color: #ff8c00; font-size: 11px; "
            f"background: transparent; border: none;"
        )
        warn.setWordWrap(True)
        fl.addWidget(warn)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        for label, handler in [
            ("🗑  Clear All Findings", self.clear_findings),
            ("🗑  Clear All Scans",    self.clear_scans),
            ("🗑  Clear All Folders",  self.clear_folders),
        ]:
            btn = QPushButton(label)
            btn.setObjectName("dangerBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)

        btn_row.addStretch()
        fl.addLayout(btn_row)

        try:
            from backend.db import get_connection
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM scans')
            sc = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM findings')
            fc = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM folders')
            foc = cursor.fetchone()[0]
            conn.close()
            stats = QLabel(
                f"Database: {sc} scans  ·  "
                f"{fc} findings  ·  {foc} folders"
            )
            stats.setStyleSheet(
                f"color: {DIM}; font-size: 11px; "
                f"background: transparent; border: none;"
            )
            fl.addWidget(stats)
        except Exception:
            pass

        return frame

    def clear_findings(self):
        if self._confirm(
            "Delete ALL findings? Cannot be undone."
        ):
            try:
                from backend.db import get_connection
                conn = get_connection()
                conn.execute('DELETE FROM findings')
                conn.commit()
                conn.close()
                self.show_msg("Done", "All findings deleted.")
            except Exception as e:
                self.show_msg("Error", str(e))

    def clear_scans(self):
        if self._confirm(
            "Delete ALL scans and findings? Cannot be undone."
        ):
            try:
                from backend.db import get_connection
                conn = get_connection()
                conn.execute('DELETE FROM findings')
                conn.execute('DELETE FROM tool_runs')
                conn.execute('DELETE FROM audit_logs')
                conn.execute('DELETE FROM scans')
                conn.commit()
                conn.close()
                self.show_msg("Done", "All scans deleted.")
            except Exception as e:
                self.show_msg("Error", str(e))

    def clear_folders(self):
        if self._confirm(
            "Delete ALL folders?\n"
            "Scans will be kept but unassigned."
        ):
            try:
                from backend.db import get_connection
                conn = get_connection()
                conn.execute('UPDATE scans SET folder_id=NULL')
                conn.execute('DELETE FROM folders')
                conn.commit()
                conn.close()
                self.show_msg("Done", "All folders deleted.")
            except Exception as e:
                self.show_msg("Error", str(e))

    def _confirm(self, message):
        reply = QMessageBox.question(
            self, "Confirm", message,
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )
        return reply == QMessageBox.StandardButton.Yes

    def show_msg(self, title, text):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setStyleSheet(f"""
            QMessageBox {{ background: {CARD}; }}
            QLabel {{
                color: {TEXT};
                font-size: 12px;
                background: transparent;
            }}
            QPushButton {{
                background: {RED};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                min-width: 60px;
            }}
        """)
        msg.exec()

    def build_about_section(self):
        frame, fl = self.make_section("ℹ️  About AutoRed")

        about_row = QHBoxLayout()
        about_row.setSpacing(24)

        left = QVBoxLayout()
        left.setSpacing(8)

        info_items = [
            ("Platform",    "AutoRed v1.0"),
            ("Type",        "Recon Automation Platform"),
            ("Author",      "Hashreena Kaur"),
            ("Student ID",  "TP071939"),
            ("Institution", "Asia Pacific University (APU)"),
            ("Programme",   "B.Sc. (Hons) CS in Cybersecurity"),
            ("Year",        "2026"),
        ]
        for key, value in info_items:
            row = QHBoxLayout()
            k = QLabel(f"{key}:")
            k.setFixedWidth(100)
            k.setStyleSheet(
                f"color: {DIM}; font-size: 12px; "
                f"font-weight: bold; background: transparent; "
                f"border: none;"
            )
            v = QLabel(value)
            v.setStyleSheet(
                f"color: {TEXT}; font-size: 12px; "
                f"background: transparent; border: none;"
            )
            row.addWidget(k)
            row.addWidget(v)
            row.addStretch()
            left.addLayout(row)

        about_row.addLayout(left, 2)

        right = QVBoxLayout()
        right.setSpacing(6)
        right.setAlignment(Qt.AlignmentFlag.AlignTop)

        tools_lbl = QLabel("Integrated Tools (12)")
        tools_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 11px; font-weight: bold; "
            f"background: transparent; border: none;"
        )
        right.addWidget(tools_lbl)

        tools = [
            ("🔍", "Nmap"),         ("🌐", "Subfinder"),
            ("📡", "httpx"),        ("🕵️", "WhatWeb"),
            ("💨", "ffuf"),         ("🎯", "Nikto"),
            ("🌾", "theHarvester"), ("🔎", "DNSrecon"),
            ("👻", "Gobuster"),     ("📂", "Dirsearch"),
            ("🔒", "WPScan"),       ("⚡", "Nuclei"),
        ]

        tools_grid = QHBoxLayout()
        col1 = QVBoxLayout()
        col2 = QVBoxLayout()
        for i, (emoji, name) in enumerate(tools):
            lbl = QLabel(f"{emoji} {name}")
            lbl.setStyleSheet(
                f"color: {TEXT}; font-size: 11px; "
                f"background: transparent; border: none;"
            )
            if i < 6:
                col1.addWidget(lbl)
            else:
                col2.addWidget(lbl)
        tools_grid.addLayout(col1)
        tools_grid.addLayout(col2)
        right.addLayout(tools_grid)
        about_row.addLayout(right, 1)
        fl.addLayout(about_row)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(
            f"background: {BORDER}; border: none; max-height: 1px;"
        )
        fl.addWidget(div)

        link_row = QHBoxLayout()

        github_btn = QPushButton("🔗  View on GitHub")
        github_btn.setObjectName("linkBtn")
        github_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        github_btn.clicked.connect(
            lambda: QDesktopServices.openUrl(
                QUrl("https://github.com/Hashreena/AutoRed")
            )
        )
        link_row.addWidget(github_btn)

        bench_btn = QPushButton("📊  Benchmark Results")
        bench_btn.setObjectName("linkBtn")
        bench_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        bench_btn.clicked.connect(self.show_benchmark)
        link_row.addWidget(bench_btn)

        link_row.addStretch()

        disc = QLabel(
            "For authorized security assessment "
            "and educational purposes only."
        )
        disc.setStyleSheet(
            f"color: {DIM}; font-size: 10px; "
            f"background: transparent; border: none;"
        )
        link_row.addWidget(disc)
        fl.addLayout(link_row)

        return frame

    def show_benchmark(self):
        bench_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'storage', 'benchmark_results.txt'
        )
        try:
            with open(bench_path, 'r') as f:
                content = f.read()
        except Exception:
            content = (
                "Benchmark results not found.\n"
                "Run a full scan to generate results."
            )
        msg = QMessageBox(self)
        msg.setWindowTitle("Benchmark Results")
        msg.setText(content[:800])
        msg.setStyleSheet(f"""
            QMessageBox {{ background: {CARD}; }}
            QLabel {{
                color: {TEXT}; font-size: 11px;
                font-family: Courier;
                background: transparent;
            }}
            QPushButton {{
                background: {RED}; color: white;
                border: none; border-radius: 4px;
                padding: 6px 16px;
            }}
        """)
        msg.exec()

    def save(self):
        for key, widget in self.fields.items():
            if isinstance(widget, QComboBox):
                self.settings[key] = widget.currentText()
            elif isinstance(widget, QCheckBox):
                self.settings[key] = widget.isChecked()

        if not save_settings(self.settings):
            self.show_msg("Error", "Failed to save settings.")
            return

        theme_name = self.settings.get('theme', 'Dark')
        current_theme = load_settings().get('theme', 'Dark')

        reply = QMessageBox.question(
            self,
            "Save & Apply",
            f"Settings saved!\n\n"
            f"Theme: {theme_name}\n\n"
            f"AutoRed will restart to apply the theme.\n"
            f"Restart now?",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            env = dict(os.environ)
            env['VIRTUAL_ENV'] = os.path.dirname(
                os.path.dirname(PYTHON)
            )
            env['PATH'] = (
                os.path.dirname(PYTHON) + ':' +
                env.get('PATH', '')
            )
            subprocess.Popen(
                [PYTHON, '-m', 'gui.main_window'],
                cwd=PROJECT_DIR,
                env=env
            )
            QApplication.instance().quit()

    def reset_defaults(self):
        self.settings = dict(DEFAULT_SETTINGS)
        for key, widget in self.fields.items():
            val = DEFAULT_SETTINGS.get(key, '')
            if isinstance(widget, QComboBox):
                idx = widget.findText(str(val))
                if idx >= 0:
                    widget.setCurrentIndex(idx)
            elif isinstance(widget, QCheckBox):
                widget.setChecked(bool(val))
        default_theme = DEFAULT_SETTINGS.get('theme', 'Dark')
        self.select_theme(default_theme)

    def get_stylesheet(self):
        return f"""
            QWidget {{
                background-color: {BG};
                color: {TEXT};
                font-family: Arial;
                font-size: 13px;
            }}
            QScrollArea {{ border: none; }}
            #pageTitle {{
                color: {RED};
                font-size: 22px;
                font-weight: bold;
                background: transparent;
                border: none;
            }}
            #pageSub {{
                color: {DIM};
                font-size: 12px;
                background: transparent;
                border: none;
            }}
            #settingsCard {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            #sectionTitle {{
                color: {RED};
                font-size: 14px;
                font-weight: bold;
                background: transparent;
                border: none;
            }}
            #sectionSub {{
                color: {DIM};
                font-size: 11px;
                background: transparent;
                border: none;
            }}
            #fieldLabel {{
                color: {TEXT};
                font-size: 12px;
                font-weight: bold;
                background: transparent;
                border: none;
            }}
            #inputField {{
                background: {CARD2};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }}
            #inputField:focus {{ border-color: {RED}; }}
            QComboBox {{
                background: {CARD2};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }}
            QComboBox:focus {{ border-color: {RED}; }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox QAbstractItemView {{
                background: {CARD2};
                color: {TEXT};
                border: 1px solid {BORDER};
                selection-background-color: {CARD};
                selection-color: {RED};
            }}
            #settingsCheck {{
                color: {TEXT};
                font-size: 12px;
                padding: 4px;
            }}
            #settingsCheck:hover {{ color: {RED}; }}
            #saveBtn {{
                background: {RED};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: bold;
            }}
            #saveBtn:hover {{ background: #c73652; }}
            #resetBtn {{
                background: transparent;
                color: {DIM};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 10px 24px;
                font-size: 13px;
            }}
            #resetBtn:hover {{
                color: {TEXT};
                border-color: {TEXT};
            }}
            #dangerBtn {{
                background: transparent;
                color: {RED};
                border: 1px solid {RED}44;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
            }}
            #dangerBtn:hover {{
                background: {RED}22;
                border-color: {RED};
            }}
            #linkBtn {{
                background: transparent;
                color: #4a9eff;
                border: 1px solid #4a9eff44;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 12px;
            }}
            #linkBtn:hover {{
                background: #4a9eff22;
                border-color: #4a9eff;
            }}
        """
