import sys
import math
import random
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import (
    QPainter, QColor, QPen,
    QLinearGradient, QRadialGradient, QBrush
)
from gui.preferences import (
    load_prefs,
    get_theme,
    build_stylesheet,
)
# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def qcolor(hex_color, alpha=None):
    color = QColor(hex_color)
    if alpha is not None:
        color.setAlpha(alpha)
    return color
def rgba_from_hex(hex_color, alpha):
    color = QColor(hex_color)
    return (
        f"rgba({color.red()}, {color.green()}, "
        f"{color.blue()}, {alpha})"
    )
def is_dark_theme(prefs):
    return prefs.get("dark_mode", True)
# ─────────────────────────────────────────────
# Floating Tool Chips
# ─────────────────────────────────────────────
class FloatingTool(QLabel):
    def __init__(self, text, theme, parent=None):
        super().__init__(text, parent)
        self.t = theme
        self.set_theme(theme)
        self.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents
        )
        self.dx = 0
        self.dy = 0
        self.elapsed = 0
        self.duration = 6000
        self.max_opacity = 0.34
        self.start_x = 0
        self.start_y = 0
    def set_theme(self, theme):
        self.t = theme
        self.setStyleSheet(f"""
            QLabel {{
                color: {self.t["accent"]};
                background-color: {rgba_from_hex(self.t["card_bg"], 215)};
                border: 1px solid {rgba_from_hex(self.t["accent"], 95)};
                border-radius: 10px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: bold;
            }}
        """)
# ─────────────────────────────────────────────
# Welcome Screen
# ─────────────────────────────────────────────
class WelcomeScreen(QWidget):
    def __init__(
        self,
        on_new_scan=None,
        on_open_scan=None,
        on_authorized_targets=None,
        prefs=None,
    ):
        super().__init__()
        self.on_new_scan = on_new_scan
        self.on_open_scan = on_open_scan
        self.on_authorized_targets = on_authorized_targets
        self.prefs = prefs or load_prefs()
        self.dark = is_dark_theme(self.prefs)
        self.t = get_theme(self.dark)
        self.tools = [
            "Nmap", "Subfinder", "httpx", "WhatWeb",
            "ffuf", "Nikto", "theHarvester", "DNSrecon",
            "Gobuster", "Dirsearch", "WPScan", "Nuclei"
        ]
        self.floating_labels = []
        self.phrases = [
            "Automating reconnaissance workflows...",
            "12 integrated recon tools...",
            "From scan to report in minutes...",
            "Built for pentesters and security teams...",
            "Powered by Nmap, Nuclei, Nikto and more..."
        ]
        self.phrase_index = 0
        self.char_index = 0
        self.deleting = False
        self.typing_paused = False
        self.bg_phase = 0
        self.setStyleSheet("background: transparent;")
        self.init_ui()
        self.start_animations()
    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────
    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = is_dark_theme(self.prefs)
        self.t = get_theme(self.dark)
        self._apply_widget_styles()
        for tool in self.floating_labels:
            tool.set_theme(self.t)
        self.update()
    def _apply_widget_styles(self):
        t = self.t
        self.center_widget.setStyleSheet(
            "background: transparent;"
        )
        self.logo_label.setStyleSheet(f"""
            QLabel {{
                color: {t["accent"]};
                font-size: 54px;
                font-weight: 900;
                letter-spacing: 4px;
                background: transparent;
                border: none;
            }}
        """)
        self.sub_label.setStyleSheet(f"""
            QLabel {{
                color: {t["text_muted"]};
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 5px;
                background: transparent;
                border: none;
                margin-top: 2px;
            }}
        """)
        self.typing_label.setStyleSheet(f"""
            QLabel {{
                color: {t["text"]};
                font-size: 13px;
                background: transparent;
                border: none;
                min-height: 22px;
            }}
        """)
        self.new_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t["accent"]};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: 900;
            }}
            QPushButton:hover {{
                background-color: {t["accent_hover"]};
            }}
            QPushButton:pressed {{
                background-color: {t["accent_dark"]};
            }}
        """)
        self.open_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t["button_soft"]};
                color: {t["text"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: 900;
            }}
            QPushButton:hover {{
                border-color: {t["accent"]};
                color: {t["accent"]};
                background-color: {t["hover"]};
            }}
            QPushButton:pressed {{
                background-color: {rgba_from_hex(t["accent_dark"], 80)};
            }}
        """)
        self.auth_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {rgba_from_hex(t["card_bg"], 210)};
                color: {t["success"]};
                border: 1px solid {rgba_from_hex(t["success"], 120)};
                border-radius: 8px;
                padding: 6px 20px;
                font-size: 12px;
                font-weight: 900;
            }}
            QPushButton:hover {{
                background-color: {rgba_from_hex(t["success"], 22)};
                color: {t["success"]};
                border-color: {t["success"]};
            }}
            QPushButton:pressed {{
                background-color: {rgba_from_hex(t["success"], 60)};
            }}
        """)
        self.tagline.setStyleSheet(f"""
            QLabel {{
                color: {t["text_soft"]};
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 1px;
                background: transparent;
                border: none;
            }}
        """)
    # ─────────────────────────────────────────────
    # Animated background
    # ─────────────────────────────────────────────
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        h = self.height()
        t = self.t
        bg = QLinearGradient(0, 0, w, h)
        if self.dark:
            bg.setColorAt(0.0, QColor(t["bg"]))
            bg.setColorAt(0.42, QColor("#07111F"))
            bg.setColorAt(1.0, QColor(t["bg_deep"]))
        else:
            bg.setColorAt(0.0, QColor("#F8FAFC"))
            bg.setColorAt(0.45, QColor("#EEF2F7"))
            bg.setColorAt(1.0, QColor("#E2E8F0"))
        painter.fillRect(self.rect(), bg)
        red_glow = QRadialGradient(
            int(w * 0.28),
            int(h * 0.25),
            int(max(w, h) * 0.58)
        )
        if self.dark:
            red_glow.setColorAt(0.0, QColor(239, 68, 68, 44))
            red_glow.setColorAt(0.32, QColor(239, 68, 68, 18))
            red_glow.setColorAt(1.0, QColor(239, 68, 68, 0))
        else:
            red_glow.setColorAt(0.0, QColor(239, 68, 68, 30))
            red_glow.setColorAt(0.35, QColor(239, 68, 68, 12))
            red_glow.setColorAt(1.0, QColor(239, 68, 68, 0))
        painter.fillRect(self.rect(), QBrush(red_glow))
        secondary_glow = QRadialGradient(
            int(w * 0.78),
            int(h * 0.72),
            int(max(w, h) * 0.52)
        )
        if self.dark:
            secondary_glow.setColorAt(0.0, QColor(7, 17, 31, 120))
            secondary_glow.setColorAt(0.42, QColor(15, 23, 42, 70))
            secondary_glow.setColorAt(1.0, QColor(2, 6, 23, 0))
        else:
            secondary_glow.setColorAt(0.0, QColor(96, 165, 250, 35))
            secondary_glow.setColorAt(0.42, QColor(203, 213, 225, 40))
            secondary_glow.setColorAt(1.0, QColor(248, 250, 252, 0))
        painter.fillRect(self.rect(), QBrush(secondary_glow))
        corner_glow = QRadialGradient(
            int(w * 0.84),
            int(h * 0.22),
            int(max(w, h) * 0.42)
        )
        corner_glow.setColorAt(0.0, QColor(220, 38, 38, 24))
        corner_glow.setColorAt(0.38, QColor(220, 38, 38, 8))
        corner_glow.setColorAt(1.0, QColor(220, 38, 38, 0))
        painter.fillRect(self.rect(), QBrush(corner_glow))
        grid_alpha = 72 if self.dark else 80
        grid_pen = QPen(qcolor(t["border"], grid_alpha))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)
        grid_size = 48
        shift = int(math.sin(self.bg_phase / 80) * 8)
        for x in range(-grid_size, w + grid_size, grid_size):
            painter.drawLine(x + shift, 0, x + shift, h)
        for y in range(-grid_size, h + grid_size, grid_size):
            painter.drawLine(0, y - shift, w, y - shift)
        dot_pen = QPen(QColor(239, 68, 68, 58 if self.dark else 42))
        dot_pen.setWidth(2)
        painter.setPen(dot_pen)
        for x in range(24, w, 96):
            for y in range(24, h, 96):
                painter.drawPoint(x + shift, y - shift)
        sweep_y = int((self.bg_phase / 1000) * h)
        sweep_pen = QPen(QColor(239, 68, 68, 78 if self.dark else 55))
        sweep_pen.setWidth(2)
        painter.setPen(sweep_pen)
        painter.drawLine(0, sweep_y, w, sweep_y)
        sweep_glow_pen = QPen(QColor(239, 68, 68, 25 if self.dark else 18))
        sweep_glow_pen.setWidth(8)
        painter.setPen(sweep_glow_pen)
        painter.drawLine(0, sweep_y, w, sweep_y)
        cx = int(w * 0.76)
        cy = int(h * 0.62)
        radius = int(min(w, h) * 0.22)
        radar_pen = QPen(qcolor(t["accent"], 38 if self.dark else 45))
        radar_pen.setWidth(1)
        painter.setPen(radar_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(cx - radius, cy - radius, radius * 2, radius * 2)
        painter.drawEllipse(
            cx - int(radius * 0.62),
            cy - int(radius * 0.62),
            int(radius * 1.24),
            int(radius * 1.24)
        )
        angle = self.bg_phase / 70
        x2 = cx + int(math.cos(angle) * radius)
        y2 = cy + int(math.sin(angle) * radius)
        radar_line = QPen(qcolor(t["accent"], 58 if self.dark else 48))
        radar_line.setWidth(2)
        painter.setPen(radar_line)
        painter.drawLine(cx, cy, x2, y2)
        bottom = QLinearGradient(0, int(h * 0.62), 0, h)
        if self.dark:
            bottom.setColorAt(0.0, QColor(2, 6, 23, 0))
            bottom.setColorAt(1.0, QColor(2, 6, 23, 200))
        else:
            bottom.setColorAt(0.0, QColor(248, 250, 252, 0))
            bottom.setColorAt(1.0, QColor(226, 232, 240, 140))
        painter.fillRect(self.rect(), QBrush(bottom))
    def animate_background(self):
        self.bg_phase = (self.bg_phase + 4) % 1000
        self.update()
    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────
    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.center_widget = QWidget(self)
        self.center_widget.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents,
            False
        )
        layout = QVBoxLayout(self.center_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)
        outer.addWidget(self.center_widget)
        layout.addStretch()
        self.logo_label = QLabel("AutoRed")
        self.logo_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        layout.addWidget(self.logo_label)
        self.sub_label = QLabel(
            "RECON AUTOMATION PLATFORM"
        )
        self.sub_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        layout.addWidget(self.sub_label)
        layout.addSpacing(30)
        self.typing_label = QLabel("")
        self.typing_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        layout.addWidget(self.typing_label)
        layout.addSpacing(30)
        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_row.setSpacing(12)
        self.new_btn = QPushButton("+ New Scan")
        self.new_btn.setFixedHeight(38)
        self.new_btn.setMinimumWidth(120)
        self.new_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        if self.on_new_scan:
            self.new_btn.clicked.connect(self.on_new_scan)
        btn_row.addWidget(self.new_btn)
        self.open_btn = QPushButton("Open Scan")
        self.open_btn.setFixedHeight(38)
        self.open_btn.setMinimumWidth(105)
        self.open_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        if self.on_open_scan:
            self.open_btn.clicked.connect(self.on_open_scan)
        btn_row.addWidget(self.open_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(10)
        auth_row = QHBoxLayout()
        auth_row.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.auth_btn = QPushButton(
            "🛡️  Authorized Targets Manager"
        )
        self.auth_btn.setFixedHeight(36)
        self.auth_btn.setMinimumWidth(230)
        self.auth_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        if self.on_authorized_targets:
            self.auth_btn.clicked.connect(
                self.on_authorized_targets
            )
        auth_row.addWidget(self.auth_btn)
        layout.addLayout(auth_row)
        layout.addSpacing(16)
        self.tagline = QLabel(
            "12 tools  ·  automated  ·  "
            "professional reports  ·  APU FYP 2026"
        )
        self.tagline.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        layout.addWidget(self.tagline)
        layout.addStretch()
        self._apply_widget_styles()
    # ─────────────────────────────────────────────
    # Animations
    # ─────────────────────────────────────────────
    def start_animations(self):
        self.bg_timer = QTimer(self)
        self.bg_timer.timeout.connect(self.animate_background)
        self.bg_timer.start(35)
        self.spawn_timer = QTimer(self)
        self.spawn_timer.timeout.connect(self.spawn_tool)
        self.spawn_timer.start(600)
        self.float_timer = QTimer(self)
        self.float_timer.timeout.connect(
            self.update_floats
        )
        self.float_timer.start(30)
        self.type_timer = QTimer(self)
        self.type_timer.timeout.connect(
            self.update_typing
        )
        self.type_timer.start(70)
        for i in range(6):
            QTimer.singleShot(
                i * 300,
                self.spawn_tool
            )
    def spawn_tool(self):
        if not self.isVisible():
            return
        w = self.width() or 900
        h = self.height() or 650
        tool = FloatingTool(
            random.choice(self.tools),
            self.t,
            self
        )
        tool.adjustSize()
        zone = random.choice(
            ["top", "bottom", "left", "right"]
        )
        if zone == "top":
            start_x = random.randint(
                20,
                max(20, w - 120)
            )
            start_y = random.randint(
                10,
                int(h * 0.18)
            )
        elif zone == "bottom":
            start_x = random.randint(
                20,
                max(20, w - 120)
            )
            start_y = random.randint(
                int(h * 0.82),
                max(int(h * 0.82), h - 40)
            )
        elif zone == "left":
            start_x = random.randint(
                10,
                int(w * 0.18)
            )
            start_y = random.randint(
                20,
                max(20, h - 40)
            )
        else:
            start_x = random.randint(
                int(w * 0.82),
                max(int(w * 0.82), w - 120)
            )
            start_y = random.randint(
                20,
                max(20, h - 40)
            )
        angle = random.uniform(0, math.pi * 2)
        speed = random.uniform(20, 50)
        tool.dx = math.cos(angle) * speed
        tool.dy = math.sin(angle) * speed
        tool.start_x = start_x
        tool.start_y = start_y
        tool.elapsed = 0
        tool.duration = random.randint(5000, 9000)
        tool.max_opacity = random.uniform(0.26, 0.42)
        tool.move(start_x, start_y)
        tool.show()
        tool.lower()
        self.floating_labels.append(tool)
        if hasattr(self, "center_widget"):
            self.center_widget.raise_()
    def update_floats(self):
        dt = 30
        to_remove = []
        for tool in self.floating_labels:
            tool.elapsed += dt
            t = tool.elapsed / tool.duration
            if t >= 1:
                to_remove.append(tool)
                continue
            if t < 0.15:
                ease = t / 0.15
            elif t > 0.85:
                ease = (1 - t) / 0.15
            else:
                ease = 1.0
            opacity = ease * tool.max_opacity
            tool.setWindowOpacity(opacity)
            x = tool.start_x + tool.dx * t
            y = tool.start_y + tool.dy * t
            tool.move(int(x), int(y))
            tool.lower()
        for tool in to_remove:
            self.floating_labels.remove(tool)
            tool.deleteLater()
        if hasattr(self, "center_widget"):
            self.center_widget.raise_()
    def update_typing(self):
        if self.typing_paused:
            return
        phrase = self.phrases[self.phrase_index]
        if not self.deleting:
            self.char_index += 1
            self.typing_label.setText(
                phrase[:self.char_index] + "|"
            )
            if self.char_index >= len(phrase):
                self.deleting = True
                self.typing_paused = True
                QTimer.singleShot(
                    1500,
                    self.resume_typing
                )
        else:
            self.char_index -= 1
            self.typing_label.setText(
                phrase[:self.char_index] + "|"
            )
            if self.char_index <= 0:
                self.deleting = False
                self.phrase_index = (
                    self.phrase_index + 1
                ) % len(self.phrases)
        speed = 35 if self.deleting else 70
        self.type_timer.setInterval(speed)
    def resume_typing(self):
        self.typing_paused = False
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "center_widget"):
            self.center_widget.setGeometry(
                0,
                0,
                self.width(),
                self.height()
            )
            self.center_widget.raise_()
    def stop_animations(self):
        if hasattr(self, "bg_timer"):
            self.bg_timer.stop()
        if hasattr(self, "spawn_timer"):
            self.spawn_timer.stop()
        if hasattr(self, "float_timer"):
            self.float_timer.stop()
        if hasattr(self, "type_timer"):
            self.type_timer.stop()
        for tool in self.floating_labels:
            tool.deleteLater()
        self.floating_labels.clear()
# ─────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "AutoRed — Recon Automation Platform"
        )
        self.setMinimumSize(1000, 650)
        self.current_scan_id = None
        self.welcome_screen = None
        self.chat_btn = None
        self.auth_manager = None
        self.login_screen = None
        self.prefs = load_prefs()
        self._apply_prefs()
        # ── UAT MODE: login disabled ──
        # A dummy user is set so all parts of the app
        # that reference current_user work correctly.
        self.current_user = {
            "id": 1,
            "username": "UAT Tester",
            "email": "uat@autored.local"
        }
        self.init_ui()
    def _theme(self):
        return get_theme(
            self.prefs.get(
                "dark_mode",
                True
            )
        )
    def _apply_prefs(self):
        sheet = self.get_app_stylesheet()
        QApplication.instance().setStyleSheet(sheet)
        self.setStyleSheet(sheet)
    def get_app_stylesheet(self):
        t = self._theme()
        base = build_stylesheet(
            dark_mode=self.prefs.get(
                "dark_mode",
                True
            ),
            font_size=self.prefs.get(
                "font_size",
                13
            ),
        )
        extra = f"""
            #mainRoot,
            #mainWrapper {{
                background-color: {t["bg"]};
            }}
            #sidebarUserRow {{
                background: transparent;
                border: none;
            }}
            #sidebarUserLabel {{
                color: {t["text_muted"]};
                font-size: 12px;
                background: transparent;
                border: none;
                font-weight: 700;
            }}
            #logoutIconBtn {{
                background: transparent;
                color: {t["accent"]};
                border: 1px solid transparent;
                border-radius: 7px;
                font-size: 15px;
                font-weight: 900;
            }}
            #logoutIconBtn:hover {{
                background: {t["hover"]};
                color: {t["accent"]};
                border-color: {t["accent"]};
            }}
            #logoutIconBtn:pressed {{
                background: {rgba_from_hex(t["accent_dark"], 80)};
                color: white;
            }}
            QToolTip {{
                background-color: {t["card_bg"]};
                color: {t["text"]};
                border: 1px solid {t["border"]};
                border-radius: 6px;
                padding: 5px 8px;
                font-size: 12px;
            }}
            #logoutBtn {{
                background: transparent;
                color: {t["accent"]};
                border: none;
                text-align: left;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: bold;
            }}
            #logoutBtn:hover {{
                background: {t["hover"]};
                color: {t["accent"]};
            }}
        """
        return base + extra
    def open_preferences(self):
        from gui.preferences import PreferencesDialog
        dialog = PreferencesDialog(
            parent=self,
            current_prefs=self.prefs,
        )
        dialog.prefs_changed.connect(
            self._on_prefs_changed
        )
        dialog.exec()
    def _on_prefs_changed(self, new_prefs):
        self.prefs = new_prefs
        self._apply_prefs()
        if hasattr(self, "central") and self.central:
            self.central.setStyleSheet(
                f"background-color: {self._theme()['bg']};"
            )
        self._retheme_current_page()
    def _retheme_current_page(self):
        if self.welcome_screen and hasattr(
            self.welcome_screen,
            "apply_theme"
        ):
            try:
                self.welcome_screen.apply_theme(self.prefs)
            except Exception as e:
                print(f"[!] welcome apply_theme failed: {e}")
        if self.login_screen and hasattr(
            self.login_screen,
            "apply_theme"
        ):
            try:
                self.login_screen.apply_theme(self.prefs)
            except Exception as e:
                print(f"[!] login apply_theme failed: {e}")
        if hasattr(self, "content_layout"):
            try:
                count = self.content_layout.count()
            except RuntimeError:
                count = 0
            for i in range(count):
                try:
                    item = self.content_layout.itemAt(i)
                    widget = item.widget() if item else None
                except RuntimeError:
                    break
                if widget and hasattr(widget, "apply_theme"):
                    try:
                        widget.apply_theme(self.prefs)
                    except Exception as e:
                        print(f"[!] apply_theme failed: {e}")
        if self.chat_btn and hasattr(self.chat_btn, "apply_theme"):
            try:
                self.chat_btn.apply_theme(self.prefs)
            except Exception as e:
                print(f"[!] chat apply_theme failed: {e}")
        if (
            self.auth_manager and
            hasattr(self.auth_manager, "apply_theme")
        ):
            try:
                self.auth_manager.apply_theme(self.prefs)
            except Exception as e:
                print(f"[!] auth apply_theme failed: {e}")
    def init_ui(self):
        self.central = QWidget()
        self.central.setObjectName("mainRoot")
        self.central.setStyleSheet(
            f"background-color: {self._theme()['bg']};"
        )
        self.setCentralWidget(self.central)
        self.main_layout = QVBoxLayout(self.central)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        # ── UAT MODE: skip login, go straight to welcome ──
        self.show_welcome()
    def logout(self):
        # ── UAT MODE: logout returns to welcome screen ──
        # No token revocation needed since login is disabled
        self.show_welcome()
    def add_chat_button(self):
        from gui.ai_chat import AIChatButton
        if self.chat_btn:
            try:
                if hasattr(self.chat_btn, "cleanup"):
                    self.chat_btn.cleanup()
                self.chat_btn.deleteLater()
            except Exception:
                pass
        self.chat_btn = AIChatButton(
            self.central,
            prefs=self.prefs
        )
        self.chat_btn.hide()
    def toggle_chat_from_sidebar(self):
        if not self.chat_btn:
            self.add_chat_button()
        self.chat_btn.toggle_chat()
    def resizeEvent(self, event):
        super().resizeEvent(event)
    def show_welcome(self):
        self.clear_content()
        self._apply_prefs()
        self.welcome_screen = WelcomeScreen(
            on_new_scan=self.open_new_scan,
            on_open_scan=self.open_existing_scan,
            on_authorized_targets=self.open_authorized_targets,
            prefs=self.prefs,
        )
        self.main_layout.addWidget(self.welcome_screen)
        QTimer.singleShot(100, self.add_chat_button)
    def stop_welcome(self):
        if self.welcome_screen:
            self.welcome_screen.stop_animations()
            self.welcome_screen = None
    def _stop_page_workers(self):
        if not hasattr(self, "content_layout"):
            return
        try:
            count = self.content_layout.count()
        except RuntimeError:
            return
        for i in range(count):
            try:
                item = self.content_layout.itemAt(i)
                widget = item.widget() if item else None
            except RuntimeError:
                return
            if widget and hasattr(widget, "cleanup"):
                try:
                    widget.cleanup()
                except Exception as e:
                    print(f"[!] worker cleanup failed: {e}")
    def clear_content(self):
        self._stop_page_workers()
        self.stop_welcome()
        while self.main_layout.count():
            child = self.main_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    def show_main_layout(self):
        self.clear_content()
        self._apply_prefs()
        wrapper = QWidget()
        wrapper.setObjectName("mainWrapper")
        wrapper_layout = QHBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)
        sidebar = self.create_sidebar()
        wrapper_layout.addWidget(sidebar)
        self.content_area = QWidget()
        self.content_area.setObjectName("contentArea")
        self.content_layout = QVBoxLayout(
            self.content_area
        )
        self.content_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )
        self.content_layout.setAlignment(
            Qt.AlignmentFlag.AlignTop
        )
        wrapper_layout.addWidget(self.content_area)
        self.main_layout.addWidget(wrapper)
        QTimer.singleShot(100, self.add_chat_button)
    def create_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        title = QLabel("AutoRed")
        title.setObjectName("sidebarTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFixedHeight(70)
        layout.addWidget(title)
        subtitle = QLabel("Recon Automation")
        subtitle.setObjectName("sidebarSubtitle")
        subtitle.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        layout.addWidget(subtitle)
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setObjectName("divider")
        layout.addWidget(divider)
        layout.addSpacing(20)
        buttons = [
            ("New Scan", self.open_new_scan),
            ("Open Existing Scan", self.open_existing_scan),
            ("Home", self.show_welcome),
            ("Preferences", self.open_preferences),
        ]
        for label, handler in buttons:
            btn = QPushButton(label)
            btn.setObjectName("sidebarBtn")
            btn.setCursor(
                Qt.CursorShape.PointingHandCursor
            )
            btn.clicked.connect(handler)
            layout.addWidget(btn)
            layout.addSpacing(5)
        layout.addSpacing(10)
        auth_btn = QPushButton("🛡️  Authorized Targets")
        auth_btn.setObjectName("authSideBtn")
        auth_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        auth_btn.clicked.connect(
            self.open_authorized_targets
        )
        layout.addWidget(auth_btn)
        layout.addSpacing(5)
        layout.addStretch()

        chat_btn = QPushButton("🤖  AI Assistant")
        chat_btn.setObjectName("chatSideBtn")
        chat_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        chat_btn.clicked.connect(
            self.toggle_chat_from_sidebar
        )
        layout.addWidget(chat_btn)
        return sidebar
    def open_authorized_targets(self):
        from gui.authorized_targets import (
            AuthorizedTargetsManager
        )
        self.auth_manager = AuthorizedTargetsManager(
            prefs=self.prefs
        )
        self.auth_manager.setMinimumSize(700, 580)
        self.auth_manager.show()
        self.auth_manager.raise_()
        self.auth_manager.activateWindow()
    def clear_content_area(self):
        self._stop_page_workers()

        if hasattr(self, "content_layout"):
            while self.content_layout.count():
                child = self.content_layout.takeAt(0)
                widget = child.widget()

                if widget:
                    if hasattr(widget, "cleanup"):
                        try:
                            widget.cleanup()
                        except Exception:
                            pass

                    widget.deleteLater()
    def open_new_scan(self):
        self.show_main_layout()
        from gui.scan_wizard import ScanWizard
        self.content_layout.setAlignment(
            Qt.AlignmentFlag.AlignTop
        )
        wizard = ScanWizard(
            on_scan_start=self.handle_scan_start,
            prefs=self.prefs,
        )
        self.content_layout.addWidget(wizard)
    def handle_scan_start(self, config):
        from gui.scan_progress import ScanProgressScreen
        self.clear_content_area()
        progress = ScanProgressScreen(
            config,
            on_finished=self.view_findings,
            prefs=self.prefs,
        )
        self.content_layout.addWidget(progress)
    def open_existing_scan(self):
        self.show_main_layout()
        from gui.open_scan import OpenScanScreen
        open_screen = OpenScanScreen(
            on_scan_select=self.view_findings,
            on_diff=self.show_scan_diff,
            prefs=self.prefs,
        )
        self.content_layout.addWidget(open_screen)
    def view_findings(self, scan_id):
        from gui.findings_dashboard import (
            FindingsDashboard
        )
        self.current_scan_id = scan_id
        if not hasattr(self, "content_layout"):
            self.show_main_layout()
        self.clear_content_area()
        dashboard = FindingsDashboard(
            scan_id=scan_id,
            on_finding_click=self.show_finding_detail,
            on_audit_click=self.show_audit_log,
            on_charts_click=self.show_charts,
            on_graph_click=self.show_network_graph,
            on_back=self.open_existing_scan,
            prefs=self.prefs,
        )
        self.content_layout.addWidget(dashboard)
    def show_finding_detail(
        self,
        finding,
        cached_data=None
    ):
        from gui.finding_loading import FindingLoadingScreen

        self.clear_content_area()

        loading = FindingLoadingScreen(
            finding=finding,
            cached_data=cached_data,
            on_loaded=self.show_finding_detail_loaded,
            on_back=lambda: self.view_findings(
                self.current_scan_id
            ),
            prefs=self.prefs,
        )

        self.content_layout.addWidget(loading)

    def show_finding_detail_loaded(
        self,
        finding,
        enriched_data=None
    ):
        from gui.finding_detail import FindingDetail

        self.clear_content_area()

        detail = FindingDetail(
            finding=finding,
            on_close=lambda: self.view_findings(
                self.current_scan_id
            ),
            on_status_change=lambda status: print(
                f"[+] Status updated to {status}"
            ),
            cached_data=enriched_data,
            prefs=self.prefs,
            on_audit_log=self.show_audit_log,
            on_visualize=self.show_charts,
        )

        self.content_layout.addWidget(detail)
    def show_scan_diff(self, scan_a_id, scan_b_id):
        from gui.scan_diff import ScanDiffScreen
        self.clear_content_area()
        diff = ScanDiffScreen(
            scan_a_id=scan_a_id,
            scan_b_id=scan_b_id,
            on_close=self.open_existing_scan,
            on_finding_click=lambda finding:
                self.show_finding_detail_from_diff(
                    finding,
                    scan_a_id,
                    scan_b_id
                ),
            prefs=self.prefs,
        )
        self.content_layout.addWidget(diff)
    def show_finding_detail_from_diff(
        self,
        finding,
        scan_a_id,
        scan_b_id
    ):
        from gui.finding_loading import FindingLoadingScreen

        self.clear_content_area()

        loading = FindingLoadingScreen(
            finding=finding,
            cached_data=None,
            on_loaded=lambda f, data:
                self.show_finding_detail_from_diff_loaded(
                    f,
                    data,
                    scan_a_id,
                    scan_b_id
                ),
            on_back=lambda:
                self.show_scan_diff(scan_a_id, scan_b_id),
            prefs=self.prefs,
        )

        self.content_layout.addWidget(loading)

    def show_finding_detail_from_diff_loaded(
        self,
        finding,
        enriched_data,
        scan_a_id,
        scan_b_id
    ):
        from gui.finding_detail import FindingDetail

        self.clear_content_area()

        detail = FindingDetail(
            finding=finding,
            on_close=lambda:
                self.show_scan_diff(scan_a_id, scan_b_id),
            on_status_change=lambda status: print(
                f"[+] Status updated to {status}"
            ),
            cached_data=enriched_data,
            prefs=self.prefs,
            on_audit_log=self.show_audit_log,
            on_visualize=self.show_charts,
        )

        self.content_layout.addWidget(detail)
    def show_audit_log(self, scan_id):
        from gui.audit_log import AuditLogViewer
        self.clear_content_area()
        audit = AuditLogViewer(
            scan_id=scan_id,
            on_close=lambda: self.view_findings(
                scan_id
            ),
            prefs=self.prefs,
        )
        self.content_layout.addWidget(audit)
    def show_charts(self, scan_id):
        from gui.charts_view import ChartsView
        self.clear_content_area()
        charts = ChartsView(
            scan_id=scan_id,
            on_close=lambda: self.view_findings(
                scan_id
            ),
            prefs=self.prefs,
        )
        self.content_layout.addWidget(charts)
    def show_network_graph(self, scan_id):
        from gui.attack_summary import AttackSummaryView
        self.clear_content_area()
        graph = AttackSummaryView(
            scan_id=scan_id,
            on_close=lambda: self.view_findings(
                scan_id
            ),
            prefs=self.prefs,
        )
        self.content_layout.addWidget(graph)
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
