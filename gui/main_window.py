import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.scan_wizard import ScanWizard

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoRed — Recon Automation Platform")
        self.setMinimumSize(900, 600)
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
        content_layout = QVBoxLayout(self.content_area)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.content_label = QLabel("Welcome to AutoRed")
        self.content_label.setObjectName("welcomeLabel")
        self.content_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.content_sub = QLabel("Select an option from the menu to get started.")
        self.content_sub.setObjectName("subLabel")
        self.content_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        content_layout.addWidget(self.content_label)
        content_layout.addWidget(self.content_sub)

        main_layout.addWidget(self.content_area)

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
            ("New Scan", self.open_new_scan),
            ("Open Existing Scan", self.open_existing_scan),
            ("Reports", self.open_reports),
            ("Settings", self.open_settings),
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

    def open_new_scan(self):
        wizard = ScanWizard(on_scan_start=self.handle_scan_start)
        self.content_area.layout().addWidget(wizard)
        old_label = self.content_area.findChild(QLabel, "welcomeLabel")
        old_sub = self.content_area.findChild(QLabel, "subLabel")
        if old_label:
           old_label.hide()
        if old_sub:
           old_sub.hide()

    def handle_scan_start(self, config):
        from gui.scan_progress import ScanProgressScreen
        self.clear_content()
        progress = ScanProgressScreen(config, on_finished=self.view_findings)
        self.content_area.layout().addWidget(progress)

    def view_findings(self, scan_id):
        from PyQt6.QtWidgets import QMessageBox
        msg = QMessageBox()
        msg.setWindowTitle("Scan Complete")
        msg.setText(f"Scan {scan_id} complete! Findings dashboard coming in Day 13.")
        msg.exec()

    def clear_content(self):
        layout = self.content_area.layout()
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def open_existing_scan(self):
        self.content_label.setText("Open Existing Scan")
        self.content_sub.setText("Scan history coming soon...")

    def open_reports(self):
        self.content_label.setText("Reports")
        self.content_sub.setText("Report builder coming soon...")

    def open_settings(self):
        self.content_label.setText("Settings")
        self.content_sub.setText("Settings coming soon...")

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
                padding: 12px 20px;
                text-align: left;
                font-size: 13px;
            }
            #sidebarBtn:hover {
                background-color: #0f3460;
                color: #e94560;
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
            #versionLabel {
                color: #444;
                font-size: 10px;
            }
        """

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
