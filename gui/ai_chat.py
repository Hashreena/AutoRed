from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFrame,
    QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer

import json
import urllib.request
import urllib.error
import os
import re

from gui.preferences import load_prefs, get_theme


# ─────────────────────────────────────────────
# AutoRed AI Chat Theme Helpers
# Supports Dark Theme + Light Theme
# ─────────────────────────────────────────────

def rgba_from_hex(hex_color, alpha):
    color = str(hex_color).strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


# Detached AI request threads live here until they finish, so a
# QThread is never destroyed while still running.
_ACTIVE_WORKERS = []


SYSTEM_PROMPT = """You are AutoRed AI Assistant — an expert cybersecurity analyst embedded in AutoRed, a reconnaissance automation platform built as a Final Year Project at Asia Pacific University (APU).

Your role is to help security analysts:
1. Understand vulnerability findings from recon scans
2. Recommend appropriate tools for different scan targets
3. Explain what findings mean in plain English
4. Provide step-by-step remediation guidance
5. Answer general cybersecurity and pentesting questions
6. Help users understand CVSS scores and severity ratings

AutoRed integrates these 12 tools:
- Nmap: Port scanning and service detection
- Subfinder: Subdomain discovery via OSINT
- httpx: HTTP probing to identify live web hosts
- WhatWeb: Web technology fingerprinting
- ffuf: Fast directory and endpoint fuzzing
- Nikto: Web server vulnerability scanning
- theHarvester: OSINT email and host harvesting
- DNSrecon: DNS enumeration and zone analysis
- Gobuster: Directory and file brute forcing
- Dirsearch: Web path discovery with curated wordlists
- WPScan: WordPress vulnerability scanning
- Nuclei: Template-based CVE vulnerability detection

IMPORTANT FORMATTING RULES:
- Never use markdown formatting like #, ##, **, *, `, or ```
- Never use headers or bold text
- Use plain text only
- Use bullet points with the • character for lists
- Keep responses concise and easy to read
- Be friendly and professional"""


def load_api_key():
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if api_key:
        return api_key

    env_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        ".env"
    )

    if os.path.exists(env_path):
        with open(env_path) as file:
            for line in file:
                line = line.strip()

                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip()

    return ""


def clean_markdown(text):
    text = re.sub(r"#{1,6}\s*", "", text)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*", r"\1", text)
    text = re.sub(r"`{3}[\s\S]*?`{3}", "", text)
    text = re.sub(r"`(.*?)`", r"\1", text)
    text = re.sub(
        r"^\s*[-*+]\s+",
        "• ",
        text,
        flags=re.MULTILINE
    )
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


class AIWorker(QThread):
    response_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, messages):
        super().__init__()

        self.messages = messages

    def run(self):
        try:
            api_key = load_api_key()

            if not api_key:
                self.error_signal.emit(
                    "No API key found.\n\n"
                    "Add your key to /home/kali/AutoRed/.env:\n"
                    "ANTHROPIC_API_KEY=sk-ant-your-key-here"
                )
                return

            payload = json.dumps(
                {
                    "model": "claude-sonnet-4-5-20250929",
                    "max_tokens": 1000,
                    "system": SYSTEM_PROMPT,
                    "messages": self.messages,
                }
            ).encode("utf-8")

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key": api_key,
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["content"][0]["text"]
                self.response_signal.emit(text)

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")

            try:
                err = json.loads(body)
                msg = err.get("error", {}).get("message", str(e))
            except Exception:
                msg = str(e)

            self.error_signal.emit(f"API Error: {msg}")

        except urllib.error.URLError as e:
            self.error_signal.emit(
                f"Connection failed: {str(e)}\n"
                f"Check your internet connection."
            )

        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")

        finally:
            self.finished_signal.emit()


class MessageBubble(QFrame):
    def __init__(
        self,
        text,
        is_user=True,
        theme=None,
        dark_mode=True,
        font_size=12,
        parent=None
    ):
        super().__init__(parent)

        self.text = text
        self.is_user = is_user
        self.t = theme or get_theme(True)
        self.dark = dark_mode
        self.fs = font_size

        self.setObjectName("messageBubbleFrame")
        self.setStyleSheet(
            """
            QFrame#messageBubbleFrame {
                border: none;
                background: transparent;
            }
            """
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(6)

        bubble = QLabel(text)
        bubble.setWordWrap(True)
        bubble.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        bubble.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Minimum
        )
        bubble.setMaximumWidth(340)

        if is_user:
            user_bg = self.t["accent"]
            user_border = self.t["accent_hover"]
            user_text = "white"

            bubble.setStyleSheet(
                f"""
                QLabel {{
                    background-color: {user_bg};
                    color: {user_text};
                    border: 1px solid {user_border};
                    border-radius: 13px;
                    padding: 9px 12px;
                    font-size: {self.fs}px;
                    font-weight: 800;
                }}
                """
            )

            layout.addStretch()
            layout.addWidget(bubble)

        else:
            assistant_bg = (
                self.t["card_bg"]
                if self.dark
                else self.t["card_bg"]
            )

            bubble.setStyleSheet(
                f"""
                QLabel {{
                    background-color: {assistant_bg};
                    color: {self.t["text"]};
                    border: 1px solid {self.t["border"]};
                    border-radius: 13px;
                    padding: 9px 12px;
                    font-size: {self.fs}px;
                }}
                """
            )

            layout.addWidget(bubble)
            layout.addStretch()


class AIChatPanel(QWidget):
    WELCOME = (
        "Hi! I am your AutoRed AI Assistant.\n\n"
        "I can help you:\n"
        "• Understand scan findings\n"
        "• Recommend tools for your target\n"
        "• Explain vulnerabilities in plain English\n"
        "• Provide remediation guidance\n\n"
        "What would you like to know?"
    )

    def __init__(self, parent=None, prefs=None):
        super().__init__(parent)

        self.messages = []
        self.worker = None
        self.is_thinking = False

        self.prefs = prefs or load_prefs()
        self._set_theme_colors()

        self.setFixedSize(390, 530)
        self.setObjectName("aiChatPanel")

        self.init_ui()
        self._style_chrome()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self.BG = self.t["bg"]
        self.BG_DEEP = self.t.get("bg_deep", self.BG)

        self.CARD = self.t["card_bg"]
        self.CARD2 = self.t["card_bg_2"]

        self.BORDER = self.t["border"]
        self.BORDER_SOFT = self.t["border_soft"]

        self.TEXT = self.t["text"]
        self.DIM = self.t["text_muted"]
        self.SOFT = self.t["text_soft"]

        self.ACCENT = self.t["accent"]
        self.ACCENT_HOVER = self.t["accent_hover"]
        self.ACCENT_DARK = self.t["accent_dark"]

        self.SUCCESS = self.t["success"]
        self.WARNING = self.t["warning"]
        self.INFO = self.t["info"]
        self.PURPLE = self.t["purple"]

        self.HOVER = self.t.get(
            "hover",
            rgba_from_hex(self.ACCENT, 18 if not self.dark else 25)
        )

        self.SELECTION_BG = self.t.get(
            "selection_bg",
            rgba_from_hex(self.ACCENT, 28 if not self.dark else 35)
        )

        self.SELECTION_TEXT = self.t.get(
            "selection_text",
            "#7F1D1D" if not self.dark else "#FEE2E2"
        )

        self.BUTTON_SOFT = self.t.get(
            "button_soft",
            "#FFFFFF" if not self.dark else "rgba(15, 23, 42, 185)"
        )

        self.CARD_HOVER = self.t.get(
            "card_hover",
            rgba_from_hex(self.ACCENT, 55 if not self.dark else 90)
        )

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()

        self._style_chrome()
        self._rerender_bubbles()

    def _style_chrome(self):
        header_bg = self.ACCENT
        header_border = self.ACCENT_HOVER

        self.setStyleSheet(
            f"""
            QWidget#aiChatPanel {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 14px;
                font-family: "Segoe UI", Arial, sans-serif;
            }}

            QWidget#aiChatPanel:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}

            QFrame#chatHeader {{
                background-color: {header_bg};
                border: none;
                border-radius: 14px 14px 0 0;
                border-bottom: 1px solid {header_border};
            }}

            QLabel#chatIcon {{
                font-size: 18px;
                background: transparent;
                border: none;
                color: white;
            }}

            QLabel#chatTitle {{
                color: white;
                font-size: 12px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            QLabel#chatSub {{
                color: rgba(255, 255, 255, 0.86);
                font-size: 9px;
                background: transparent;
                border: none;
            }}

            QPushButton#clearChatBtn {{
                background: rgba(255, 255, 255, 0.16);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.25);
                border-radius: 7px;
                font-size: 11px;
                font-weight: 800;
            }}

            QPushButton#clearChatBtn:hover {{
                background: rgba(255, 255, 255, 0.28);
            }}

            QScrollArea#chatScroll {{
                border: none;
                background: {self.BG_DEEP};
            }}

            QScrollArea#chatScroll QScrollBar:vertical {{
                background: {self.BG_DEEP};
                width: 8px;
                margin: 0;
            }}

            QScrollArea#chatScroll QScrollBar::handle:vertical {{
                background: {self.BORDER_SOFT};
                border-radius: 4px;
                min-height: 24px;
            }}

            QScrollArea#chatScroll QScrollBar::handle:vertical:hover {{
                background: {self.ACCENT};
            }}

            QScrollArea#chatScroll QScrollBar::add-line:vertical,
            QScrollArea#chatScroll QScrollBar::sub-line:vertical {{
                height: 0px;
            }}

            QWidget#chatContent {{
                background-color: {self.BG_DEEP};
                border: none;
            }}

            QFrame#inputFrame {{
                background-color: {self.CARD};
                border-top: 1px solid {self.BORDER};
                border-radius: 0 0 14px 14px;
                border-left: none;
                border-right: none;
                border-bottom: none;
            }}

            QLineEdit#chatInput {{
                background-color: {self.BG_DEEP};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 18px;
                padding: 8px 14px;
                font-size: {max(11, self.fs - 1)}px;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}

            QLineEdit#chatInput:focus {{
                border-color: {self.ACCENT};
                background-color: {self.CARD2};
            }}

            QLineEdit#chatInput::placeholder {{
                color: {self.SOFT};
            }}

            QPushButton#sendBtn {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 18px;
                font-size: 16px;
                font-weight: 900;
            }}

            QPushButton#sendBtn:hover {{
                background-color: {self.ACCENT_HOVER};
            }}

            QPushButton#sendBtn:pressed {{
                background-color: {self.ACCENT_DARK};
            }}

            QPushButton#sendBtn:disabled {{
                background-color: {self.CARD2};
                color: {self.SOFT};
                border: 1px solid {self.BORDER};
            }}
            """
        )

    def _rerender_bubbles(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()

        self.add_bubble(self.WELCOME, is_user=False)

        for message in self.messages:
            self.add_bubble(
                clean_markdown(message["content"])
                if message["role"] == "assistant"
                else message["content"],
                is_user=(message["role"] == "user")
            )

    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.header = QFrame()
        self.header.setObjectName("chatHeader")
        self.header.setFixedHeight(56)

        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(14, 0, 14, 0)
        header_layout.setSpacing(9)

        icon = QLabel("🤖")
        icon.setObjectName("chatIcon")
        header_layout.addWidget(icon)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)

        title = QLabel("AutoRed AI Assistant")
        title.setObjectName("chatTitle")
        title_col.addWidget(title)

        sub = QLabel("Cybersecurity guidance and scan explanation")
        sub.setObjectName("chatSub")
        title_col.addWidget(sub)

        header_layout.addLayout(title_col)
        header_layout.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("clearChatBtn")
        clear_btn.setFixedSize(54, 28)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_chat)

        header_layout.addWidget(clear_btn)
        layout.addWidget(self.header)

        self.scroll = QScrollArea()
        self.scroll.setObjectName("chatScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.chat_content = QWidget()
        self.chat_content.setObjectName("chatContent")

        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(8, 8, 8, 8)
        self.chat_layout.setSpacing(6)
        self.chat_layout.addStretch()

        self.scroll.setWidget(self.chat_content)
        layout.addWidget(self.scroll)

        self.add_bubble(self.WELCOME, is_user=False)

        self.input_frame = QFrame()
        self.input_frame.setObjectName("inputFrame")
        self.input_frame.setFixedHeight(66)

        input_layout = QHBoxLayout(self.input_frame)
        input_layout.setContentsMargins(10, 10, 10, 10)
        input_layout.setSpacing(8)

        self.input_field = QLineEdit()
        self.input_field.setObjectName("chatInput")
        self.input_field.setPlaceholderText(
            "Ask about findings, tools, vulnerabilities..."
        )
        self.input_field.returnPressed.connect(self.send_message)

        input_layout.addWidget(self.input_field)

        self.send_btn = QPushButton("↑")
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.setFixedSize(36, 36)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_btn.clicked.connect(self.send_message)

        input_layout.addWidget(self.send_btn)

        layout.addWidget(self.input_frame)

    # ─────────────────────────────────────────────
    # Chat actions
    # ─────────────────────────────────────────────

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()
        )

    def add_bubble(self, text, is_user=True):
        bubble = MessageBubble(
            text,
            is_user,
            theme=self.t,
            dark_mode=self.dark,
            font_size=max(11, self.fs - 1)
        )

        self.chat_layout.insertWidget(
            self.chat_layout.count() - 1,
            bubble
        )

        QTimer.singleShot(50, self.scroll_to_bottom)

    def send_message(self):
        text = self.input_field.text().strip()

        if not text or self.is_thinking:
            return

        self.input_field.clear()

        self.add_bubble(text, is_user=True)

        self.messages.append(
            {
                "role": "user",
                "content": text,
            }
        )

        self.is_thinking = True
        self.send_btn.setEnabled(False)
        self.input_field.setEnabled(False)

        self.thinking_bubble = MessageBubble(
            "Thinking... ⏳",
            is_user=False,
            theme=self.t,
            dark_mode=self.dark,
            font_size=max(11, self.fs - 1)
        )

        self.chat_layout.insertWidget(
            self.chat_layout.count() - 1,
            self.thinking_bubble
        )

        QTimer.singleShot(50, self.scroll_to_bottom)

        self.worker = AIWorker(list(self.messages))
        self.worker.response_signal.connect(self.on_response)
        self.worker.error_signal.connect(self.on_error)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def on_response(self, text):
        if hasattr(self, "thinking_bubble"):
            self.thinking_bubble.setParent(None)
            self.thinking_bubble.deleteLater()

        cleaned = clean_markdown(text)

        self.add_bubble(cleaned, is_user=False)

        self.messages.append(
            {
                "role": "assistant",
                "content": text,
            }
        )

    def on_error(self, error):
        if hasattr(self, "thinking_bubble"):
            self.thinking_bubble.setParent(None)
            self.thinking_bubble.deleteLater()

        self.add_bubble(
            f"Sorry, something went wrong:\n{error}",
            is_user=False
        )

    def on_finished(self):
        self.is_thinking = False

        self.send_btn.setEnabled(True)
        self.input_field.setEnabled(True)
        self.input_field.setFocus()

    def clear_chat(self):
        self.messages = []

        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()

        self.add_bubble(
            "Chat cleared! How can I help you?",
            is_user=False
        )

    def ask_about_finding(self, finding):
        severity = finding.get("severity", "")
        title = finding.get("title", "")
        description = finding.get("description", "")

        question = (
            f"I have a {severity} severity finding: {title}. "
            f"Description: {description[:200]}. "
            f"Can you explain what this means, why it is dangerous, "
            f"and how to fix it? "
            f"Please reply in plain text without any markdown formatting."
        )

        self.input_field.setText(question)
        self.send_message()

    # ─────────────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────────────

    def cleanup(self):
        worker = getattr(self, "worker", None)

        if worker is None:
            return

        for signal_name in (
            "response_signal",
            "error_signal",
            "finished_signal",
        ):
            try:
                getattr(worker, signal_name).disconnect()
            except (TypeError, RuntimeError):
                pass

        try:
            if worker.isRunning():
                _ACTIVE_WORKERS.append(worker)
                worker.finished.connect(
                    lambda:
                    _ACTIVE_WORKERS.remove(worker)
                    if worker in _ACTIVE_WORKERS else None
                )
        except RuntimeError:
            pass

        self.worker = None


class AIChatButton(QWidget):
    def __init__(self, parent=None, prefs=None):
        super().__init__(parent)

        self.chat_open = False
        self.chat_panel = None

        self.prefs = prefs or load_prefs()
        self._set_theme_colors()

        self.setFixedSize(56, 56)

        self.init_ui()

    # ─────────────────────────────────────────────
    # Theme support
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self.ACCENT = self.t["accent"]
        self.ACCENT_HOVER = self.t["accent_hover"]
        self.ACCENT_DARK = self.t["accent_dark"]

    def _fab_stylesheet(self):
        return f"""
            QPushButton {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 28px;
                font-size: 22px;
                font-weight: 900;
            }}

            QPushButton:hover {{
                background-color: {self.ACCENT_HOVER};
            }}

            QPushButton:pressed {{
                background-color: {self.ACCENT_DARK};
            }}
        """

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.fab = QPushButton("🤖")
        self.fab.setFixedSize(56, 56)
        self.fab.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fab.setStyleSheet(self._fab_stylesheet())
        self.fab.clicked.connect(self.toggle_chat)

        layout.addWidget(self.fab)

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()

        self.fab.setStyleSheet(self._fab_stylesheet())

        if self.chat_panel:
            self.chat_panel.apply_theme(prefs)

    def cleanup(self):
        if self.chat_panel and hasattr(self.chat_panel, "cleanup"):
            self.chat_panel.cleanup()

    def toggle_chat(self):
        if self.chat_open:
            self.close_chat()
        else:
            self.open_chat()

    def open_chat(self):
        if not self.chat_panel:
            parent = self.parent()

            self.chat_panel = AIChatPanel(
                parent,
                prefs=self.prefs
            )

        parent = self.parent()
        parent_height = parent.height()
        panel_height = 530

        self.chat_panel.move(
            225,
            max(10, parent_height - panel_height - 10)
        )
        self.chat_panel.show()
        self.chat_panel.raise_()

        self.chat_open = True
        self.fab.setText("✕")

    def close_chat(self):
        if self.chat_panel:
            self.chat_panel.hide()

        self.chat_open = False
        self.fab.setText("🤖")

    def reposition(self, parent_w, parent_h):
        self.move(parent_w - 70, parent_h - 70)

        if self.chat_panel and self.chat_open:
            self.open_chat()
