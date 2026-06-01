import sys
import math
import random
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont


class FloatingTool(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QLabel {
                color: #3d5a7a;
                background-color: #0d1117;
                border: 1px solid #1c2733;
                border-radius: 10px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        self.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents
        )
        self.dx           = 0
        self.dy           = 0
        self.elapsed      = 0
        self.duration     = 6000
        self.max_opacity  = 0.3
        self.start_x      = 0
        self.start_y      = 0


class WelcomeScreen(QWidget):
    def __init__(self, on_new_scan=None, on_open_scan=None,
                 on_authorized_targets=None):
        super().__init__()
        self.on_new_scan            = on_new_scan
        self.on_open_scan           = on_open_scan
        self.on_authorized_targets  = on_authorized_targets
        self.tools = [
            'Nmap', 'Subfinder', 'httpx', 'WhatWeb', 'ffuf',
            'Nikto', 'theHarvester', 'DNSrecon', 'Gobuster',
            'Dirsearch', 'WPScan', 'Nuclei'
        ]
        self.floating_labels = []
        self.phrases = [
            "Automating reconnaissance workflows...",
            "12 integrated recon tools...",
            "From scan to report in minutes...",
            "Built for pentesters and security teams...",
            "Powered by Nmap, Nuclei, Nikto and more..."
        ]
        self.phrase_index  = 0
        self.char_index    = 0
        self.deleting      = False
        self.typing_paused = False
        self.setStyleSheet("background-color: #0d1117;")
        self.init_ui()
        self.start_animations()

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self.center_widget = QWidget(self)
        self.center_widget.setStyleSheet(
            "background: transparent;"
        )
        self.center_widget.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents,
            False
        )

        layout = QVBoxLayout(self.center_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)
        outer.addWidget(self.center_widget)

        layout.addStretch()

        # ── Logo ─────────────────────────────────────────
        self.logo_label = QLabel("AutoRed")
        self.logo_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.logo_label.setStyleSheet(
            "color: #e94560; font-size: 52px; "
            "font-weight: bold; letter-spacing: 4px; "
            "background: transparent;"
        )
        layout.addWidget(self.logo_label)

        self.sub_label = QLabel("RECON AUTOMATION PLATFORM")
        self.sub_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.sub_label.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "font-weight: bold; letter-spacing: 5px; "
            "background: transparent; margin-top: 2px;"
        )
        layout.addWidget(self.sub_label)

        layout.addSpacing(30)

        # ── Typing animation ──────────────────────────────
        self.typing_label = QLabel("")
        self.typing_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.typing_label.setStyleSheet(
            "color: #8b949e; font-size: 13px; "
            "background: transparent; min-height: 22px;"
        )
        layout.addWidget(self.typing_label)

        layout.addSpacing(30)

        # ── Buttons row 1 — New Scan + Open Scan ─────────
        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_row.setSpacing(12)

        new_btn = QPushButton("+ New Scan")
        new_btn.setFixedHeight(38)
        new_btn.setMinimumWidth(120)
        new_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        new_btn.setStyleSheet("""
            QPushButton {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #c73652; }
            QPushButton:pressed { background-color: #a02940; }
        """)
        new_btn.clicked.connect(self.on_new_scan)
        btn_row.addWidget(new_btn)

        open_btn = QPushButton("Open Scan")
        open_btn.setFixedHeight(38)
        open_btn.setMinimumWidth(100)
        open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 13px;
            }
            QPushButton:hover {
                border-color: #e94560;
                color: #e94560;
            }
            QPushButton:pressed {
                background-color: #161b22;
            }
        """)
        open_btn.clicked.connect(self.on_open_scan)
        btn_row.addWidget(open_btn)

        layout.addLayout(btn_row)

        layout.addSpacing(10)

        # ── Buttons row 2 — Authorized Targets ───────────
        auth_row = QHBoxLayout()
        auth_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        auth_btn = QPushButton("🛡️  Authorized Targets Manager")
        auth_btn.setFixedHeight(36)
        auth_btn.setMinimumWidth(220)
        auth_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        auth_btn.setStyleSheet("""
            QPushButton {
                background-color: #1d9e75;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 6px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #178a64; }
            QPushButton:pressed { background-color: #126b4e; }
        """)
        if self.on_authorized_targets:
            auth_btn.clicked.connect(
                self.on_authorized_targets
            )
        auth_row.addWidget(auth_btn)
        layout.addLayout(auth_row)

        layout.addSpacing(16)

        # ── Tagline ───────────────────────────────────────
        tagline = QLabel(
            "12 tools  ·  automated  ·  "
            "professional reports  ·  APU FYP 2026"
        )
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline.setStyleSheet(
            "color: #8b949e; font-size: 10px; "
            "font-weight: bold; letter-spacing: 1px; "
            "background: transparent;"
        )
        layout.addWidget(tagline)

        layout.addStretch()

    def start_animations(self):
        self.spawn_timer = QTimer(self)
        self.spawn_timer.timeout.connect(self.spawn_tool)
        self.spawn_timer.start(600)

        self.float_timer = QTimer(self)
        self.float_timer.timeout.connect(self.update_floats)
        self.float_timer.start(30)

        self.type_timer = QTimer(self)
        self.type_timer.timeout.connect(self.update_typing)
        self.type_timer.start(70)

        for i in range(6):
            QTimer.singleShot(i * 300, self.spawn_tool)

    def spawn_tool(self):
        if not self.isVisible():
            return
        w    = self.width() or 900
        h    = self.height() or 650
        tool = FloatingTool(
            random.choice(self.tools), self
        )
        tool.adjustSize()

        zone = random.choice(
            ['top', 'bottom', 'left', 'right']
        )
        if zone == 'top':
            start_x = random.randint(20, max(20, w - 120))
            start_y = random.randint(10, int(h * 0.18))
        elif zone == 'bottom':
            start_x = random.randint(20, max(20, w - 120))
            start_y = random.randint(
                int(h * 0.82), max(int(h * 0.82), h - 40)
            )
        elif zone == 'left':
            start_x = random.randint(10, int(w * 0.18))
            start_y = random.randint(20, max(20, h - 40))
        else:
            start_x = random.randint(
                int(w * 0.82), max(int(w * 0.82), w - 120)
            )
            start_y = random.randint(20, max(20, h - 40))

        angle        = random.uniform(0, math.pi * 2)
        speed        = random.uniform(20, 50)
        tool.dx          = math.cos(angle) * speed
        tool.dy          = math.sin(angle) * speed
        tool.start_x     = start_x
        tool.start_y     = start_y
        tool.elapsed     = 0
        tool.duration    = random.randint(5000, 9000)
        tool.max_opacity = random.uniform(0.25, 0.40)
        tool.move(start_x, start_y)
        tool.show()
        tool.lower()
        self.floating_labels.append(tool)

        if hasattr(self, 'center_widget'):
            self.center_widget.raise_()

    def update_floats(self):
        dt        = 30
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

        if hasattr(self, 'center_widget'):
            self.center_widget.raise_()

    def update_typing(self):
        if self.typing_paused:
            return

        phrase = self.phrases[self.phrase_index]

        if not self.deleting:
            self.char_index += 1
            self.typing_label.setText(
                phrase[:self.char_index] + '|'
            )
            if self.char_index >= len(phrase):
                self.deleting      = True
                self.typing_paused = True
                QTimer.singleShot(1500, self.resume_typing)
        else:
            self.char_index -= 1
            self.typing_label.setText(
                phrase[:self.char_index] + '|'
            )
            if self.char_index <= 0:
                self.deleting     = False
                self.phrase_index = (
                    self.phrase_index + 1
                ) % len(self.phrases)

        speed = 35 if self.deleting else 70
        self.type_timer.setInterval(speed)

    def resume_typing(self):
        self.typing_paused = False

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'center_widget'):
            self.center_widget.setGeometry(
                0, 0, self.width(), self.height()
            )
            self.center_widget.raise_()

    def stop_animations(self):
        if hasattr(self, 'spawn_timer'):
            self.spawn_timer.stop()
        if hasattr(self, 'float_timer'):
            self.float_timer.stop()
        if hasattr(self, 'type_timer'):
            self.type_timer.stop()
        for tool in self.floating_labels:
            tool.deleteLater()
        self.floating_labels.clear()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "AutoRed — Recon Automation Platform"
        )
        self.setMinimumSize(1000, 650)
        self.current_scan_id = None
        self.welcome_screen  = None
        self.chat_btn        = None
        self.auth_manager    = None
        self.setStyleSheet("background-color: #0d1117;")
        self.init_ui()

    def init_ui(self):
        self.central = QWidget()
        self.setCentralWidget(self.central)
        self.main_layout = QVBoxLayout(self.central)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.show_welcome()

    def add_chat_button(self):
        from gui.ai_chat import AIChatButton
        if self.chat_btn:
            try:
                self.chat_btn.deleteLater()
            except Exception:
                pass
        self.chat_btn = AIChatButton(self.central)
        self.chat_btn.hide()

    def toggle_chat_from_sidebar(self):
        if not self.chat_btn:
            self.add_chat_button()
        self.chat_btn.toggle_chat()

    def resizeEvent(self, event):
        super().resizeEvent(event)

    def show_welcome(self):
        self.clear_content()
        self.setStyleSheet("background-color: #0d1117;")
        self.welcome_screen = WelcomeScreen(
            on_new_scan           = self.open_new_scan,
            on_open_scan          = self.open_existing_scan,
            on_authorized_targets = self.open_authorized_targets,
        )
        self.main_layout.addWidget(self.welcome_screen)
        QTimer.singleShot(100, self.add_chat_button)

    def stop_welcome(self):
        if self.welcome_screen:
            self.welcome_screen.stop_animations()
            self.welcome_screen = None

    def clear_content(self):
        self.stop_welcome()
        while self.main_layout.count():
            child = self.main_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def get_app_stylesheet(self):
        return """
            QMainWindow { background-color: #0d1117; }
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            #sidebar {
                background-color: #161b22;
                border-right: 1px solid #30363d;
            }
            #sidebarTitle {
                color: #e94560;
                font-size: 22px;
                font-weight: bold;
                padding: 10px;
            }
            #sidebarSubtitle {
                color: #8b949e;
                font-size: 11px;
                padding-bottom: 10px;
            }
            #divider { color: #30363d; margin: 0 15px; }
            #sidebarBtn {
                background-color: transparent;
                color: #e6edf3;
                border: none;
                border-left: 3px solid transparent;
                padding: 12px 20px;
                text-align: left;
                font-size: 13px;
            }
            #sidebarBtn:hover {
                background-color: #21262d;
                color: #e94560;
                border-left: 3px solid #e94560;
            }
            #authSideBtn {
                background-color: #1d9e7533;
                color: #1d9e75;
                border: none;
                border-left: 3px solid #1d9e75;
                padding: 12px 20px;
                text-align: left;
                font-size: 13px;
                font-weight: bold;
            }
            #authSideBtn:hover {
                background-color: #1d9e7555;
            }
            #chatSideBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-top: 1px solid #c73652;
                padding: 14px 20px;
                text-align: left;
                font-size: 13px;
                font-weight: bold;
            }
            #chatSideBtn:hover { background-color: #c73652; }
            #contentArea { background-color: #0d1117; }
        """

    def show_main_layout(self):
        self.clear_content()
        self.setStyleSheet(self.get_app_stylesheet())

        wrapper        = QWidget()
        wrapper_layout = QHBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        sidebar = self.create_sidebar()
        wrapper_layout.addWidget(sidebar)

        self.content_area = QWidget()
        self.content_area.setObjectName("contentArea")
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
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
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setObjectName("divider")
        layout.addWidget(divider)

        layout.addSpacing(20)

        buttons = [
            ("New Scan",           self.open_new_scan),
            ("Open Existing Scan", self.open_existing_scan),
            ("Home",               self.show_welcome),
        ]

        for label, handler in buttons:
            btn = QPushButton(label)
            btn.setObjectName("sidebarBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(handler)
            layout.addWidget(btn)
            layout.addSpacing(5)

        layout.addSpacing(10)

        # ── Authorized Targets button in sidebar ──────────
        auth_btn = QPushButton("🛡️  Authorized Targets")
        auth_btn.setObjectName("authSideBtn")
        auth_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        auth_btn.clicked.connect(self.open_authorized_targets)
        layout.addWidget(auth_btn)
        layout.addSpacing(5)

        layout.addStretch()

        chat_btn = QPushButton("🤖  AI Assistant")
        chat_btn.setObjectName("chatSideBtn")
        chat_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        chat_btn.clicked.connect(self.toggle_chat_from_sidebar)
        layout.addWidget(chat_btn)

        return sidebar

    def open_authorized_targets(self):
        from gui.authorized_targets import (
            AuthorizedTargetsManager
        )
        self.auth_manager = AuthorizedTargetsManager()
        self.auth_manager.setMinimumSize(700, 580)
        self.auth_manager.show()
        self.auth_manager.raise_()
        self.auth_manager.activateWindow()

    def clear_content_area(self):
        if hasattr(self, 'content_layout'):
            while self.content_layout.count():
                child = self.content_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

    def open_new_scan(self):
        self.show_main_layout()
        from gui.scan_wizard import ScanWizard
        self.content_layout.setAlignment(
            Qt.AlignmentFlag.AlignTop
        )
        wizard = ScanWizard(
            on_scan_start=self.handle_scan_start
        )
        self.content_layout.addWidget(wizard)

    def handle_scan_start(self, config):
        from gui.scan_progress import ScanProgressScreen
        self.clear_content_area()
        progress = ScanProgressScreen(
            config, on_finished=self.view_findings
        )
        self.content_layout.addWidget(progress)

    def open_existing_scan(self):
        self.show_main_layout()
        from gui.open_scan import OpenScanScreen
        open_screen = OpenScanScreen(
            on_scan_select=self.view_findings
        )
        self.content_layout.addWidget(open_screen)

    def view_findings(self, scan_id):
        from gui.findings_dashboard import FindingsDashboard
        self.current_scan_id = scan_id
        if not hasattr(self, 'content_layout'):
            self.show_main_layout()
        self.clear_content_area()
        dashboard = FindingsDashboard(
            scan_id          = scan_id,
            on_finding_click = self.show_finding_detail,
            on_audit_click   = self.show_audit_log,
            on_charts_click  = self.show_charts,
            on_graph_click   = self.show_network_graph,
        )
        self.content_layout.addWidget(dashboard)

    def show_finding_detail(self, finding, cached_data=None):
        from gui.finding_detail import FindingDetail
        self.clear_content_area()
        detail = FindingDetail(
            finding          = finding,
            on_close         = lambda: self.view_findings(
                self.current_scan_id
            ),
            on_status_change = lambda status: print(
                f"[+] Status updated to {status}"
            ),
            cached_data      = cached_data,
        )
        self.content_layout.addWidget(detail)

    def show_audit_log(self, scan_id):
        from gui.audit_log import AuditLogViewer
        self.clear_content_area()
        audit = AuditLogViewer(
            scan_id  = scan_id,
            on_close = lambda: self.view_findings(scan_id)
        )
        self.content_layout.addWidget(audit)

    def show_charts(self, scan_id):
        from gui.charts_view import ChartsView
        self.clear_content_area()
        charts = ChartsView(
            scan_id  = scan_id,
            on_close = lambda: self.view_findings(scan_id)
        )
        self.content_layout.addWidget(charts)

    def show_network_graph(self, scan_id):
        from gui.attack_summary import AttackSummaryView
        self.clear_content_area()
        graph = AttackSummaryView(
            scan_id  = scan_id,
            on_close = lambda: self.view_findings(scan_id)
        )
        self.content_layout.addWidget(graph)


def main():
    app    = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
