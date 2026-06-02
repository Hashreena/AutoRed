from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QProgressBar, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import sys
import os
sys.path.insert(
    0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    )
)
from backend.db import init_db, insert_scan


class ScanWorker(QThread):
    log_signal       = pyqtSignal(str)
    tool_done_signal = pyqtSignal(str, str)
    scan_done_signal = pyqtSignal()

    def __init__(self, scan_id, config):
        super().__init__()
        self.scan_id = scan_id
        self.config  = config
        self._stop   = False

    def run(self):
        target  = self.config['target']
        profile = self.config['profile']
        tools   = self.config['tools']
        presets = {t: 'quick' for t in tools}

        self.log_signal.emit(
            f"[*] Scan started for target: {target}"
        )
        self.log_signal.emit(f"[*] Profile: {profile}")
        self.log_signal.emit(
            f"[*] Tools: {', '.join(tools)}"
        )
        self.log_signal.emit("-" * 50)

        from backend.command_builder import build_command
        from backend.runner import run_tool

        output_base = os.path.join(
            'storage', str(self.scan_id)
        )
        os.makedirs(output_base, exist_ok=True)

        for tool in tools:
            if self._stop:
                self.log_signal.emit(
                    "[!] Scan stopped by user."
                )
                break

            preset  = presets.get(tool, 'quick')
            command = build_command(
                tool, target, profile, preset
            )
            self.log_signal.emit(
                f"\n[*] Running {tool}..."
            )
            self.log_signal.emit(
                f"[*] Command: {command}"
            )

            output_dir = os.path.join(output_base, tool)
            result     = run_tool(
                self.scan_id, tool, command, output_dir
            )
            status = result['status']

            if status == 'completed':
                self.log_signal.emit(
                    f"[+] {tool} finished successfully"
                )
                self.tool_done_signal.emit(
                    tool, 'completed'
                )
                from backend.job_queue import (
                    parse_tool_output
                )
                parse_tool_output(
                    self.scan_id, tool,
                    result['stdout'], target
                )
                self.log_signal.emit(
                    f"[+] {tool} findings parsed and saved"
                )
            else:
                self.log_signal.emit(
                    f"[-] {tool} failed — {status}"
                )
                self.tool_done_signal.emit(tool, status)

        from backend.db import get_connection
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scans SET status='completed' "
            "WHERE id=?",
            (self.scan_id,)
        )
        conn.commit()
        conn.close()

        self.log_signal.emit("\n[+] All tools finished.")
        self.scan_done_signal.emit()

    def stop(self):
        self._stop = True


class ScanProgressScreen(QWidget):
    def __init__(self, config, on_finished=None):
        super().__init__()
        self.config          = config
        self.on_finished     = on_finished
        self.tool_labels     = {}
        self.completed_tools = 0
        self.total_tools     = len(
            config.get('tools', [])
        )
        self.scan_id         = None
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.start_scan()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(0)

        title = QLabel(
            f"Scanning: {self.config.get('target', '')}"
        )
        title.setObjectName("scanTitle")
        layout.addWidget(title)
        layout.addSpacing(6)

        tools_str   = ', '.join(
            self.config.get('tools', [])
        )
        profile_lbl = QLabel(
            f"Profile: {self.config.get('profile', '')} "
            f" |  Tools: {tools_str}"
        )
        profile_lbl.setObjectName("scanSub")
        profile_lbl.setWordWrap(True)
        layout.addWidget(profile_lbl)
        layout.addSpacing(24)

        prog_lbl = QLabel("Overall Progress:")
        prog_lbl.setObjectName("sectionLbl")
        layout.addWidget(prog_lbl)
        layout.addSpacing(6)

        self.overall_progress = QProgressBar()
        self.overall_progress.setMaximum(self.total_tools)
        self.overall_progress.setValue(0)
        self.overall_progress.setObjectName("overallBar")
        self.overall_progress.setFixedHeight(22)
        layout.addWidget(self.overall_progress)
        layout.addSpacing(20)

        status_lbl = QLabel("Tool Status:")
        status_lbl.setObjectName("sectionLbl")
        layout.addWidget(status_lbl)
        layout.addSpacing(8)

        for tool in self.config.get('tools', []):
            row = QHBoxLayout()
            row.setSpacing(0)

            lbl = QLabel(f"  {tool}")
            lbl.setFixedWidth(160)
            lbl.setStyleSheet(
                "color: #8b949e; font-size: 12px; "
                "background: transparent;"
            )
            status = QLabel("Queued")
            status.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent;"
            )
            self.tool_labels[tool] = status
            row.addWidget(lbl)
            row.addWidget(status)
            row.addStretch()
            layout.addLayout(row)
            layout.addSpacing(4)

        layout.addSpacing(20)

        log_lbl = QLabel("Live Output:")
        log_lbl.setObjectName("sectionLbl")
        layout.addWidget(log_lbl)
        layout.addSpacing(6)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setObjectName("logOutput")
        layout.addWidget(self.log_output)
        layout.addSpacing(12)

        btn_row = QHBoxLayout()

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.stop_btn.clicked.connect(self.stop_scan)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()

        self.done_btn = QPushButton("View Findings →")
        self.done_btn.setObjectName("doneBtn")
        self.done_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.done_btn.setEnabled(False)
        self.done_btn.clicked.connect(self.view_findings)
        btn_row.addWidget(self.done_btn)

        layout.addLayout(btn_row)

    def start_scan(self):
        init_db()
        self.scan_id = insert_scan(
            name         = self.config.get(
                'name', 'Unnamed Scan'
            ),
            target       = self.config.get('target', ''),
            profile      = self.config.get(
                'profile', 'Standard'
            ),
            approval_ref = self.config.get(
                'approval_ref', ''
            ),
            folder_id    = self.config.get(
                'folder_id', None
            )
        )
        self.worker = ScanWorker(self.scan_id, self.config)
        self.worker.log_signal.connect(self.append_log)
        self.worker.tool_done_signal.connect(
            self.update_tool_status
        )
        self.worker.scan_done_signal.connect(
            self.scan_finished
        )
        self.worker.start()

    def append_log(self, message):
        self.log_output.append(message)

    def update_tool_status(self, tool, status):
        if tool in self.tool_labels:
            lbl = self.tool_labels[tool]
            if status == 'completed':
                lbl.setText("Done")
                lbl.setStyleSheet(
                    "color: #3fb950; font-weight: bold; "
                    "font-size: 12px; "
                    "background: transparent;"
                )
            elif status in ['failed', 'timeout', 'error']:
                lbl.setText("Failed")
                lbl.setStyleSheet(
                    "color: #e94560; font-weight: bold; "
                    "font-size: 12px; "
                    "background: transparent;"
                )
            else:
                lbl.setText("Running...")
                lbl.setStyleSheet(
                    "color: #ff8c00; font-weight: bold; "
                    "font-size: 12px; "
                    "background: transparent;"
                )
        self.completed_tools += 1
        self.overall_progress.setValue(self.completed_tools)

    def scan_finished(self):
        self.stop_btn.setEnabled(False)
        self.done_btn.setEnabled(True)
        self.append_log(
            "\n[+] Scan complete! "
            "Click 'View Findings' to see results."
        )
        self.send_telegram_notification()

    def send_telegram_notification(self):
        try:
            from backend.db import get_connection
            from backend.notifier import (
                notify_scan_complete
            )
            conn   = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM findings WHERE scan_id=?',
                (self.scan_id,)
            )
            findings = [
                dict(row) for row in cursor.fetchall()
            ]
            conn.close()

            critical = sum(
                1 for f in findings
                if f.get('severity') == 'Critical'
            )
            high = sum(
                1 for f in findings
                if f.get('severity') == 'High'
            )

            if critical > 0 or high > 0:
                self.append_log(
                    f"\n[*] Sending Telegram alert — "
                    f"{critical} Critical, "
                    f"{high} High findings..."
                )
                scan_name = self.config.get(
                    'name', 'AutoRed Scan'
                )
                target = self.config.get(
                    'target', 'Unknown'
                )
                notify_scan_complete(
                    scan_name, target, findings
                )
                self.append_log(
                    "[+] Telegram notification sent!"
                )
            else:
                self.append_log(
                    "[*] No Critical/High findings — "
                    "Telegram notification skipped."
                )
        except Exception as e:
            self.append_log(
                f"[!] Telegram notification failed: {e}"
            )

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
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            #scanTitle {
                color: #e94560;
                font-size: 18px;
                font-weight: bold;
            }
            #scanSub {
                color: #8b949e;
                font-size: 12px;
            }
            #sectionLbl {
                color: #e6edf3;
                font-size: 12px;
                font-weight: bold;
            }
            #overallBar {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #e94560;
                border-radius: 4px;
            }
            #logOutput {
                background-color: #010409;
                color: #3fb950;
                font-family: Courier;
                font-size: 12px;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
            #stopBtn {
                background-color: transparent;
                color: #e94560;
                border: 1px solid #e94560;
                border-radius: 6px;
                padding: 9px 22px;
                font-size: 12px;
                font-weight: bold;
            }
            #stopBtn:hover {
                background-color: #e94560;
                color: white;
            }
            #stopBtn:disabled {
                color: #555;
                border-color: #333;
            }
            #doneBtn {
                background-color: #e94560;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 9px 22px;
                font-size: 12px;
                font-weight: bold;
            }
            #doneBtn:disabled {
                background-color: #21262d;
                color: #555;
            }
            #doneBtn:hover {
                background-color: #c73652;
            }
        """
