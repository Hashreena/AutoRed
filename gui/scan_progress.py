from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QProgressBar, QTextEdit, QFrame,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

import sys
import os

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from backend.db import init_db, insert_scan
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


class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    tool_started_signal = pyqtSignal(str)
    tool_done_signal = pyqtSignal(str, str)
    scan_done_signal = pyqtSignal()

    def __init__(self, scan_id, config):
        super().__init__()

        self.scan_id = scan_id
        self.config = config
        self._stop = False

    def run(self):
        target = self.config["target"]
        profile = self.config["profile"]
        tools = self.config["tools"]
        presets = {tool: "quick" for tool in tools}

        self.log_signal.emit(f"[*] Scan started for target: {target}")
        self.log_signal.emit(f"[*] Profile: {profile}")
        self.log_signal.emit(f"[*] Tools: {', '.join(tools)}")
        self.log_signal.emit("-" * 60)

        from backend.command_builder import build_command
        from backend.runner import run_tool

        output_base = os.path.join(
            "storage",
            str(self.scan_id)
        )
        os.makedirs(output_base, exist_ok=True)

        for tool in tools:
            if self._stop:
                self.log_signal.emit("[!] Scan stopped by user.")
                break

            preset = presets.get(tool, "quick")

            command = build_command(
                tool,
                target,
                profile,
                preset
            )

            self.tool_started_signal.emit(tool)

            self.log_signal.emit("")
            self.log_signal.emit(f"[*] Running {tool}...")
            self.log_signal.emit(f"[*] Command: {command}")

            output_dir = os.path.join(output_base, tool)

            result = run_tool(
                self.scan_id,
                tool,
                command,
                output_dir
            )

            status = result["status"]

            if status == "completed":
                self.log_signal.emit(f"[+] {tool} finished successfully")

                self.tool_done_signal.emit(
                    tool,
                    "completed"
                )

                from backend.job_queue import parse_tool_output

                parse_tool_output(
                    self.scan_id,
                    tool,
                    result["stdout"],
                    target
                )

                self.log_signal.emit(f"[+] {tool} findings parsed and saved")

            else:
                self.log_signal.emit(f"[-] {tool} failed — {status}")

                self.tool_done_signal.emit(
                    tool,
                    status
                )

        from backend.db import get_connection

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE scans SET status='completed' WHERE id=?",
            (self.scan_id,)
        )

        conn.commit()
        conn.close()

        self.log_signal.emit("")
        self.log_signal.emit("[+] All tools finished.")
        self.scan_done_signal.emit()

    def stop(self):
        self._stop = True


class ScanProgressScreen(QWidget):
    def __init__(self, config, on_finished=None, prefs=None):
        super().__init__()

        self.config = config
        self.on_finished = on_finished

        self.tool_labels = {}
        self.tool_name_labels = {}
        self.tool_row_frames = {}
        self.tool_status_state = {}

        self.completed_tools = 0
        self.total_tools = len(config.get("tools", []))
        self.scan_id = None
        self.worker = None

        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self._set_terminal_colors()

        self.setStyleSheet(self.get_stylesheet())

        self.init_ui()
        self.start_scan()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_terminal_colors(self):
        if self.dark:
            self.term_bg = "#010409"
            self.term_fg = "#86EFAC"
            self.term_border = self.t["border"]
        else:
            self.term_bg = "#FFFFFF"
            self.term_fg = "#166534"
            self.term_border = self.t["border"]

    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self._set_terminal_colors()
        self.setStyleSheet(self.get_stylesheet())

        for tool, lbl in self.tool_name_labels.items():
            lbl.setStyleSheet(
                f"""
                color: {self.t["text"]};
                font-size: {self.fs}px;
                font-weight: 800;
                background: transparent;
                border: none;
                """
            )

        for tool, lbl in self.tool_labels.items():
            state = self.tool_status_state.get(tool, "queued")
            self._style_status_label(lbl, state)

        for tool, row in self.tool_row_frames.items():
            state = self.tool_status_state.get(tool, "queued")
            self._style_tool_row(row, state)

    def _status_color(self, state):
        if state == "completed":
            return self.t["success"]

        if state in ("failed", "timeout", "error", "stopped"):
            return self.t["brand_red"]

        if state == "running":
            return self.t["accent"]

        return self.t["text_muted"]

    def _status_text(self, state):
        if state == "completed":
            return "Done"

        if state in ("failed", "timeout", "error"):
            return "Failed"

        if state == "stopped":
            return "Stopped"

        if state == "running":
            return "Running..."

        return "Queued"

    def _style_status_label(self, lbl, state):
        color = self._status_color(state)

        lbl.setStyleSheet(
            f"""
            color: {color};
            font-weight: 900;
            font-size: {self.fs}px;
            background: transparent;
            border: none;
            """
        )

    def _style_tool_row(self, row, state):
        if state == "running":
            bg = rgba_from_hex(self.t["accent"], 22)
            border = self.t["accent"]

        elif state == "completed":
            bg = rgba_from_hex(self.t["success"], 18)
            border = rgba_from_hex(self.t["success"], 110)

        elif state in ("failed", "timeout", "error", "stopped"):
            bg = rgba_from_hex(self.t["brand_red"], 18)
            border = rgba_from_hex(self.t["brand_red"], 130)

        else:
            bg = self.t.get("card_bg_2", self.t["card_bg"])
            border = self.t["border"]

        row.setStyleSheet(
            f"""
            QFrame#toolRow {{
                background-color: {bg};
                border: 1px solid {border};
                border-radius: 8px;
            }}
            """
        )

    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 22, 30, 22)
        layout.setSpacing(10)

        header_card = QFrame()
        header_card.setObjectName("headerCard")

        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(8)

        title = QLabel(
            f"Scanning: {self.config.get('target', '')}"
        )
        title.setObjectName("scanTitle")
        header_layout.addWidget(title)

        tools_str = ", ".join(
            self.config.get("tools", [])
        )

        profile_lbl = QLabel(
            f"Profile: {self.config.get('profile', '')}  •  Tools: {tools_str}"
        )
        profile_lbl.setObjectName("scanSub")
        profile_lbl.setWordWrap(True)
        header_layout.addWidget(profile_lbl)

        layout.addWidget(header_card)

        progress_card = QFrame()
        progress_card.setObjectName("siemCard")

        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(18, 16, 18, 16)
        progress_layout.setSpacing(10)

        progress_top = QHBoxLayout()

        prog_lbl = QLabel("OVERALL PROGRESS")
        prog_lbl.setObjectName("sectionLbl")

        self.progress_count_lbl = QLabel(
            f"0 / {self.total_tools} tools completed"
        )
        self.progress_count_lbl.setObjectName("mutedLbl")
        self.progress_count_lbl.setAlignment(
            Qt.AlignmentFlag.AlignRight
        )

        progress_top.addWidget(prog_lbl)
        progress_top.addWidget(self.progress_count_lbl)

        progress_layout.addLayout(progress_top)

        self.overall_progress = QProgressBar()
        self.overall_progress.setMaximum(self.total_tools)
        self.overall_progress.setValue(0)
        self.overall_progress.setObjectName("overallBar")
        self.overall_progress.setFixedHeight(22)
        self.overall_progress.setTextVisible(True)

        progress_layout.addWidget(self.overall_progress)

        layout.addWidget(progress_card)

        status_card = QFrame()
        status_card.setObjectName("siemCard")
        status_card.setMaximumHeight(340)

        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(18, 14, 18, 14)
        status_layout.setSpacing(8)

        status_lbl = QLabel("TOOL EXECUTION STATUS")
        status_lbl.setObjectName("sectionLbl")
        status_layout.addWidget(status_lbl)

        tools = self.config.get("tools", [])
        split_index = (len(tools) + 1) // 2

        tool_columns = QHBoxLayout()
        tool_columns.setContentsMargins(0, 0, 0, 0)
        tool_columns.setSpacing(12)

        left_col = QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(6)

        right_col = QVBoxLayout()
        right_col.setContentsMargins(0, 0, 0, 0)
        right_col.setSpacing(6)

        for index, tool in enumerate(tools):
            row_frame = QFrame()
            row_frame.setObjectName("toolRow")
            row_frame.setFixedHeight(34)

            row_layout = QHBoxLayout(row_frame)
            row_layout.setContentsMargins(12, 5, 12, 5)
            row_layout.setSpacing(10)

            tool_name = QLabel(tool)
            tool_name.setMinimumWidth(130)
            tool_name.setStyleSheet(
                f"""
                color: {self.t["text"]};
                font-size: {self.fs}px;
                font-weight: 800;
                background: transparent;
                border: none;
                """
            )

            status = QLabel("Queued")
            status.setMinimumWidth(92)
            status.setAlignment(
                Qt.AlignmentFlag.AlignRight |
                Qt.AlignmentFlag.AlignVCenter
            )

            self.tool_status_state[tool] = "queued"
            self._style_status_label(status, "queued")
            self._style_tool_row(row_frame, "queued")

            self.tool_name_labels[tool] = tool_name
            self.tool_labels[tool] = status
            self.tool_row_frames[tool] = row_frame

            row_layout.addWidget(tool_name)
            row_layout.addStretch()
            row_layout.addWidget(status)

            if index < split_index:
                left_col.addWidget(row_frame)
            else:
                right_col.addWidget(row_frame)

        left_col.addStretch()
        right_col.addStretch()

        tool_columns.addLayout(left_col, 1)
        tool_columns.addLayout(right_col, 1)

        status_layout.addLayout(tool_columns)

        layout.addWidget(status_card, 1)

        log_header_row = QHBoxLayout()

        log_lbl = QLabel("LIVE OUTPUT")
        log_lbl.setObjectName("sectionLbl")

        log_hint = QLabel("Real-time scanner output and parser status")
        log_hint.setObjectName("mutedLbl")
        log_hint.setAlignment(Qt.AlignmentFlag.AlignRight)

        log_header_row.addWidget(log_lbl)
        log_header_row.addWidget(log_hint)

        layout.addLayout(log_header_row)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setObjectName("logOutput")
        self.log_output.setMinimumHeight(330)
        layout.addWidget(self.log_output, 3)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

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

    # ─────────────────────────────────────────────
    # Scan lifecycle
    # ─────────────────────────────────────────────

    def start_scan(self):
        init_db()

        self.scan_id = insert_scan(
            name=self.config.get("name", "Unnamed Scan"),
            target=self.config.get("target", ""),
            profile=self.config.get("profile", "Standard"),
            approval_ref=self.config.get("approval_ref", ""),
            folder_id=self.config.get("folder_id", None)
        )

        self.worker = ScanWorker(
            self.scan_id,
            self.config
        )

        self.worker.log_signal.connect(self.append_log)
        self.worker.tool_started_signal.connect(
            self.mark_tool_running
        )
        self.worker.tool_done_signal.connect(
            self.update_tool_status
        )
        self.worker.scan_done_signal.connect(
            self.scan_finished
        )

        self.worker.start()

    def append_log(self, message):
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )

    def mark_tool_running(self, tool):
        if tool in self.tool_labels:
            self.tool_status_state[tool] = "running"

            lbl = self.tool_labels[tool]
            lbl.setText("Running...")
            self._style_status_label(lbl, "running")

            row = self.tool_row_frames.get(tool)

            if row:
                self._style_tool_row(row, "running")

    def update_tool_status(self, tool, status):
        if status == "completed":
            state = "completed"

        elif status in ("failed", "timeout", "error"):
            state = "failed"

        else:
            state = "failed"

        if tool in self.tool_labels:
            self.tool_status_state[tool] = state

            lbl = self.tool_labels[tool]
            lbl.setText(self._status_text(state))
            self._style_status_label(lbl, state)

            row = self.tool_row_frames.get(tool)

            if row:
                self._style_tool_row(row, state)

        self.completed_tools += 1
        self.overall_progress.setValue(self.completed_tools)

        self.progress_count_lbl.setText(
            f"{self.completed_tools} / {self.total_tools} tools completed"
        )

    def scan_finished(self):
        self.stop_btn.setEnabled(False)
        self.done_btn.setEnabled(True)

        self.append_log("")
        self.append_log(
            "[+] Scan complete! Click 'View Findings' to see results."
        )

        self.send_completion_notifications()

    def send_completion_notifications(self):
        try:
            self.append_log("")
            self.append_log(
                "[*] Sending scan report to sitinorziah25@gmail.com ..."
            )

            from backend.notifier import send_notifications

            send_notifications(self.scan_id)

            self.append_log("[+] Scan report sent successfully!")

        except Exception as e:
            self.append_log(f"[!] Notification failed: {e}")

    def stop_scan(self):
        if hasattr(self, "worker") and self.worker:
            self.worker.stop()
            self.append_log("[!] Stopping scan...")

            self.stop_btn.setEnabled(False)

            for tool, state in list(self.tool_status_state.items()):
                if state in ("queued", "running"):
                    self.tool_status_state[tool] = "stopped"

                    if tool in self.tool_labels:
                        lbl = self.tool_labels[tool]
                        lbl.setText("Stopped")
                        self._style_status_label(lbl, "stopped")

                    row = self.tool_row_frames.get(tool)

                    if row:
                        self._style_tool_row(row, "stopped")

    def view_findings(self):
        if self.on_finished:
            self.on_finished(self.scan_id)

    def cleanup(self):
        if self.worker and self.worker.isRunning():
            try:
                self.worker.stop()
            except Exception:
                pass

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
        card_hover = t.get(
            "card_hover",
            rgba_from_hex(accent, 75)
        )

        return f"""
            QWidget {{
                background-color: {bg};
                color: {text};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}

            #headerCard {{
                background-color: {card_bg};
                border: 1px solid {border};
                border-radius: 12px;
            }}

            #headerCard:hover {{
                border: 1px solid {card_hover};
            }}

            #siemCard {{
                background-color: {card_bg};
                border: 1px solid {border};
                border-radius: 12px;
            }}

            #siemCard:hover {{
                border: 1px solid {card_hover};
            }}

            #scanTitle {{
                color: {accent};
                font-size: {fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #scanSub {{
                color: {text_muted};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}

            #sectionLbl {{
                color: {text};
                font-size: {fs - 1}px;
                font-weight: 900;
                letter-spacing: 1px;
                background: transparent;
                border: none;
            }}

            #mutedLbl {{
                color: {text_muted};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
            }}

            #overallBar {{
                background-color: {bg_deep};
                border: 1px solid {border};
                border-radius: 7px;
                color: {text};
                text-align: center;
                font-weight: 900;
            }}

            QProgressBar::chunk {{
                background-color: {accent};
                border-radius: 7px;
            }}


            #toolScroll {{
                background: transparent;
                border: none;
            }}

            #toolContainer {{
                background: transparent;
                border: none;
            }}

            #logOutput {{
                background-color: {self.term_bg};
                color: {self.term_fg};
                font-family: "Courier New", monospace;
                font-size: {fs}px;
                border: 1px solid {self.term_border};
                border-radius: 10px;
                padding: 12px;
                selection-background-color: {accent};
                selection-color: white;
            }}

            #logOutput:focus {{
                border: 1px solid {rgba_from_hex(accent, 90)};
            }}

            #stopBtn {{
                background-color: transparent;
                color: {brand_red};
                border: 1px solid {brand_red};
                border-radius: 8px;
                padding: 10px 24px;
                font-size: {fs - 1}px;
                font-weight: 900;
            }}

            #stopBtn:hover {{
                background-color: {rgba_from_hex(brand_red, 30)};
                color: {brand_red};
            }}

            #stopBtn:pressed {{
                background-color: {rgba_from_hex(brand_red, 60)};
            }}

            #stopBtn:disabled {{
                color: {text_soft};
                border-color: {border};
                background-color: transparent;
            }}

            #doneBtn {{
                background-color: {accent};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 24px;
                font-size: {fs - 1}px;
                font-weight: 900;
            }}

            #doneBtn:hover {{
                background-color: {accent_hover};
            }}

            #doneBtn:pressed {{
                background-color: {accent_dark};
            }}

            #doneBtn:disabled {{
                background-color: {card_bg_2};
                color: {text_soft};
                border: 1px solid {border};
            }}

            QScrollBar:vertical {{
                background: {bg};
                width: 10px;
                margin: 0px;
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
        """
