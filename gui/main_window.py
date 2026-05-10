import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoRed — Recon Automation Platform")
        self.setMinimumSize(1000, 650)
        self.current_scan_id = None
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)

        self.content_area = QWidget()
        self.content_area.setObjectName("contentArea")
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_layout.setContentsMargins(0, 0, 0, 0)

        self.show_welcome()
        main_layout.addWidget(self.content_area)

    def show_welcome(self):
        self.clear_content()
        welcome = QWidget()
        welcome_layout = QVBoxLayout(welcome)
        welcome_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Welcome to AutoRed")
        title.setObjectName("welcomeLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sub = QLabel("Select an option from the menu to get started.")
        sub.setObjectName("subLabel")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        version = QLabel("v1.0  —  FYP 2026  —  APU")
        version.setObjectName("versionWelcome")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)

        stats_row = QHBoxLayout()
        stats_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stats = [
            ("New Scan",     "Start a new recon scan"),
            ("Open Scan",    "View past scan results"),
            ("Reports",      "Export PDF or Word"),
        ]
        for label, desc in stats:
            card = self.make_welcome_card(label, desc)
            stats_row.addWidget(card)

        welcome_layout.addStretch()
        welcome_layout.addWidget(title)
        welcome_layout.addWidget(sub)
        welcome_layout.addSpacing(30)
        welcome_layout.addLayout(stats_row)
        welcome_layout.addSpacing(20)
        welcome_layout.addWidget(version)
        welcome_layout.addStretch()

        self.content_layout.addWidget(welcome)

    def make_welcome_card(self, label, desc):
        card = QFrame()
        card.setObjectName("welcomeCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 15, 20, 15)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            "font-size: 15px; font-weight: bold; "
            "color: #e94560; border: none;"
        )
        desc_lbl = QLabel(desc)
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_lbl.setStyleSheet(
            "font-size: 11px; color: #888; border: none;"
        )
        card_layout.addWidget(lbl)
        card_layout.addWidget(desc_lbl)
        return card

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
            ("New Scan",          self.open_new_scan),
            ("Open Existing Scan",self.open_existing_scan),
            ("Reports",           self.open_reports),
            ("Settings",          self.open_settings),
        ]

        for label, handler in buttons:
            btn = QPushButton(label)
            btn.setObjectName("sidebarBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(handler)
            layout.addWidget(btn)
            layout.addSpacing(5)

        layout.addStretch()

        version = QLabel("v1.0 — FYP 2026")
        version.setObjectName("versionLabel")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        layout.addSpacing(10)

        return sidebar

    def clear_content(self):
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def open_new_scan(self):
        from gui.scan_wizard import ScanWizard
        self.clear_content()
        wizard = ScanWizard(on_scan_start=self.handle_scan_start)
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.content_layout.addWidget(wizard)

    def handle_scan_start(self, config):
        from gui.scan_progress import ScanProgressScreen
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        progress = ScanProgressScreen(
            config,
            on_finished=self.view_findings
        )
        self.content_layout.addWidget(progress)

    def open_existing_scan(self):
        from gui.open_scan import OpenScanScreen
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        open_screen = OpenScanScreen(
            on_scan_select=self.view_findings
        )
        self.content_layout.addWidget(open_screen)

    def view_findings(self, scan_id):
        from gui.findings_dashboard import FindingsDashboard
        self.current_scan_id = scan_id
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        dashboard = FindingsDashboard(
            scan_id=scan_id,
            on_finding_click=self.show_finding_detail,
            on_audit_click=self.show_audit_log
        )
        self.content_layout.addWidget(dashboard)

    def show_finding_detail(self, finding):
        from gui.finding_detail import FindingDetail
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        detail = FindingDetail(
            finding=finding,
            on_close=lambda: self.view_findings(self.current_scan_id),
            on_status_change=lambda status: print(
                f"[+] Status updated to {status}"
            )
        )
        self.content_layout.addWidget(detail)

    def show_audit_log(self, scan_id):
        from gui.audit_log import AuditLogViewer
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        audit = AuditLogViewer(
            scan_id=scan_id,
            on_close=lambda: self.view_findings(scan_id)
        )
        self.content_layout.addWidget(audit)

    def open_reports(self):
        from gui.open_scan import OpenScanScreen
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        open_screen = OpenScanScreen(
            on_scan_select=self.view_findings
        )
        self.content_layout.addWidget(open_screen)

    def open_settings(self):
        self.clear_content()
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel("Settings coming soon.")
        lbl.setObjectName("subLabel")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addWidget(lbl)

    def get_stylesheet(self):
        return """
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #sidebar {
                background-color: #16213e;
                border-right: 1px solid #0f3460;
            }
            #sidebarTitle {
                color: #e94560;
                font-size: 22px;
                font-weight: bold;
                padding: 10px;
            }
            #sidebarSubtitle {
                color: #888;
                font-size: 11px;
                padding-bottom: 10px;
            }
            #divider {
                color: #0f3460;
                margin: 0 15px;
            }
            #sidebarBtn {
                background-color: transparent;
                color: #e0e0e0;
                border: none;
                border-left: 3px solid transparent;
                padding: 12px 20px;
                text-align: left;
                font-size: 13px;
            }
            #sidebarBtn:hover {
                background-color: #0f3460;
                color: #e94560;
                border-left: 3px solid #e94560;
            }
            #contentArea {
                background-color: #1a1a2e;
            }
            #welcomeLabel {
                color: #e94560;
                font-size: 28px;
                font-weight: bold;
            }
            #subLabel {
                color: #888;
                font-size: 14px;
                margin-top: 10px;
            }
            #versionWelcome {
                color: #444;
                font-size: 11px;
                margin-top: 10px;
            }
            #versionLabel {
                color: #444;
                font-size: 10px;
            }
            #welcomeCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                min-width: 150px;
                max-width: 200px;
                margin: 0 8px;
            }
        """

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
