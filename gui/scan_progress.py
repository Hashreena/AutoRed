from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QProgressBar, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.db import init_db, insert_scan
from backend.job_queue import run_scan

class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    tool_done_signal = pyqtSignal(str, str)
    scan_done_signal = pyqtSignal()

    def __init__(self, scan_id, config):
        super().__init__()
        self.scan_id = scan_id
        self.config = config
        self._stop = False

    def run(self):
        target = self.config['target']
        profile = self.config['profile']
        tools = self.config['tools']
        presets = {t: 'quick' for t in tools}

        self.log_signal.emit(f"[*] Scan started for target: {target}")
        self.log_signal.emit(f"[*] Profile: {profile}")
        self.log_signal.emit(f"[*] Tools: {', '.join(tools)}")
        self.log_signal.emit("-" * 50)

        from backend.command_builder import build_command
        from backend.runner import run_tool
        from backend.db import insert_audit_log
        import os

        output_base = os.path.join('storage', str(self.scan_id))
        os.makedirs(output_base, exist_ok=True)

        for tool in tools:
            if self._stop:
                self.log_signal.emit("[!] Scan stopped by user.")
                break

            preset = presets.get(tool, 'quick')
            command = build_command(tool, target, profile, preset)

            self.log_signal.emit(f"\n[*] Running {tool}...")
            self.log_signal.emit(f"[*] Command: {command}")

            output_dir = os.path.join(output_base, tool)
            result = run_tool(self.scan_id, tool, command, output_dir)

            status = result['status']
            if status == 'completed':
                self.log_signal.emit(f"[+] {tool} finished successfully")
                self.tool_done_signal.emit(tool, 'completed')
            else:
                self.log_signal.emit(f"[-] {tool} failed — {status}")
                self.tool_done_signal.emit(tool, 'failed')

        self.log_signal.emit("\n[+] All tools finished.")
        self.scan_done_signal.emit()

    def stop(self):
        self._stop = True


class ScanProgressScreen(QWidget):
    def __init__(self, config, on_finished=None):
        super().__init__()
        self.config = config
        self.on_finished = on_finished
        self.tool_labels = {}
        self.completed_tools = 0
        self.total_tools = len(config.get('tools', []))
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.start_scan()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)

        title = QLabel(f"Scanning: {self.config.get('target', '')}")
        title.setObjectName("scanTitle")
        layout.addWidget(title)

        profile_lbl = QLabel(f"Profile: {self.config.get('profile', '')}  |  Tools: {', '.join(self.config.get('tools', []))}")
        profile_lbl.setObjectName("scanSub")
        layout.addWidget(profile_lbl)
        layout.addSpacing(20)

        layout.addWidget(QLabel("Overall Progress:"))
        self.overall_progress = QProgressBar()
        self.overall_progress.setMaximum(self.total_tools)
        self.overall_progress.setValue(0)
        self.overall_progress.setObjectName("overallBar")
        layout.addWidget(self.overall_progress)
        layout.addSpacing(15)

        layout.addWidget(QLabel("Tool Status:"))
        for tool in self.config.get('tools', []):
            row = QHBoxLayout()
            lbl = QLabel(f"  {tool}")
            lbl.setFixedWidth(120)
            status = QLabel("Queued")
            status.setObjectName("statusQueued")
            self.tool_labels[tool] = status
            row.addWidget(lbl)
            row.addWidget(status)
            row.addStretch()
            layout.addLayout(row)

        layout.addSpacing(20)
        layout.addWidget(QLabel("Live Output:"))

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setObjectName("logOutput")
        layout.addWidget(self.log_output)

        btn_row = QHBoxLayout()
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_scan)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()

        self.done_btn = QPushButton("View Findings")
        self.done_btn.setObjectName("doneBtn")
        self.done_btn.setEnabled(False)
        self.done_btn.clicked.connect(self.view_findings)
        btn_row.addWidget(self.done_btn)
        layout.addLayout(btn_row)

    def start_scan(self):
        init_db()
        self.scan_id = insert_scan(
            name=self.config.get('name', 'Unnamed Scan'),
            target=self.config.get('target', ''),
            profile=self.config.get('profile', 'Standard'),
            approval_ref=self.config.get('approval_ref', '')
        )

        self.worker = ScanWorker(self.scan_id, self.config)
        self.worker.log_signal.connect(self.append_log)
        self.worker.tool_done_signal.connect(self.update_tool_status)
        self.worker.scan_done_signal.connect(self.scan_finished)
        self.worker.start()

    def append_log(self, message):
        self.log_output.append(message)

    def update_tool_status(self, tool, status):
        if tool in self.tool_labels:
            lbl = self.tool_labels[tool]
            if status == 'completed':
                lbl.setText("Done")
                lbl.setObjectName("statusDone")
            else:
                lbl.setText("Failed")
                lbl.setObjectName("statusFailed")
            lbl.setStyleSheet(self.get_stylesheet())
        self.completed_tools += 1
        self.overall_progress.setValue(self.completed_tools)

    def scan_finished(self):
        self.stop_btn.setEnabled(False)
        self.done_btn.setEnabled(True)
        self.append_log("\n[+] Scan complete! Click 'View Findings' to see results.")

    def stop_scan(self):
        if hasattr(self, 'worker'):
            self.worker.stop()
            self.append_log("[!] Stopping scan...")

    def view_findings(self):
        if self.on_finished:
            self.on_finished(self.scan_id)

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #scanTitle {
                color: #e94560;
                font-size: 18px;
                font-weight: bold;
            }
            #scanSub {
                color: #888;
                font-size: 12px;
            }
            #overallBar {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 4px;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #e94560;
                border-radius: 4px;
            }
            #logOutput {
                background-color: #0d0d1a;
                color: #00ff41;
                font-family: Courier;
                font-size: 12px;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 8px;
            }
            #statusQueued { color: #888; }
            #statusDone { color: #00ff41; font-weight: bold; }
            #statusFailed { color: #e94560; font-weight: bold; }
            #stopBtn {
                background-color: transparent;
                color: #e94560;
                border: 1px solid #e94560;
                border-radius: 4px;
                padding: 8px 20px;
            }
            #stopBtn:hover { background-color: #e94560; color: white; }
            #doneBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 20px;
                font-weight: bold;
            }
            #doneBtn:disabled { background-color: #444; color: #888; }
            #doneBtn:hover { background-color: #c73652; }
        """


if __name__ == '__main__':
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    config = {
        'name': 'Day 12 Test',
        'target': 'scanme.nmap.org',
        'profile': 'Standard',
        'tools': ['nmap', 'subfinder'],
        'approval_ref': 'TEST-001'
    }

    screen = ScanProgressScreen(config)
    screen.resize(900, 600)
    screen.show()
    sys.exit(app.exec())
