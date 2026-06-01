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

BG     = '#0d1117'
CARD   = '#161b22'
CARD2  = '#21262d'
BORDER = '#30363d'
TEXT   = '#e6edf3'
DIM    = '#8b949e'
RED    = '#e94560'

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
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if api_key:
        return api_key
    env_path = os.path.join(
        os.path.dirname(__file__), '..', '.env'
    )
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith('ANTHROPIC_API_KEY='):
                    return line.split('=', 1)[1].strip()
    return ''


def clean_markdown(text):
    text = re.sub(r'#{1,6}\s*', '', text)
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    text = re.sub(r'\*(.*?)\*', r'\1', text)
    text = re.sub(r'`{3}[\s\S]*?`{3}', '', text)
    text = re.sub(r'`(.*?)`', r'\1', text)
    text = re.sub(r'^\s*[-*+]\s+', '• ', text, flags=re.MULTILINE)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


class AIWorker(QThread):
    response_signal = pyqtSignal(str)
    error_signal    = pyqtSignal(str)
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

            payload = json.dumps({
                "model":      "claude-sonnet-4-5-20250929",
                "max_tokens": 1000,
                "system":     SYSTEM_PROMPT,
                "messages":   self.messages,
            }).encode('utf-8')

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type":      "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key":         api_key,
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                text = data['content'][0]['text']
                self.response_signal.emit(text)

        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8')
            try:
                err  = json.loads(body)
                msg  = err.get('error', {}).get('message', str(e))
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
    def __init__(self, text, is_user=True, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "border: none; background: transparent;"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)

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
            bubble.setStyleSheet(f"""
                QLabel {{
                    background: {RED};
                    color: white;
                    border-radius: 12px;
                    padding: 8px 12px;
                    font-size: 12px;
                    border: none;
                }}
            """)
            layout.addStretch()
            layout.addWidget(bubble)
        else:
            bubble.setStyleSheet(f"""
                QLabel {{
                    background: {CARD2};
                    color: {TEXT};
                    border-radius: 12px;
                    padding: 8px 12px;
                    font-size: 12px;
                    border: 1px solid {BORDER};
                }}
            """)
            layout.addWidget(bubble)
            layout.addStretch()


class AIChatPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.messages    = []
        self.worker      = None
        self.is_thinking = False
        self.setFixedSize(380, 520)
        self.setStyleSheet(f"""
            QWidget {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 12px;
                font-family: Arial;
            }}
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(52)
        header.setStyleSheet(f"""
            QFrame {{
                background: {RED};
                border-radius: 12px 12px 0 0;
                border: none;
            }}
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 0, 14, 0)

        icon = QLabel("🤖")
        icon.setStyleSheet(
            "font-size: 18px; background: transparent; border: none;"
        )
        hl.addWidget(icon)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)

        title = QLabel("AutoRed AI Assistant")
        title.setStyleSheet(
            "color: white; font-size: 12px; font-weight: bold; "
            "background: transparent; border: none;"
        )
        title_col.addWidget(title)

        sub = QLabel("Powered by Claude")
        sub.setStyleSheet(
            "color: rgba(255,255,255,0.7); font-size: 9px; "
            "background: transparent; border: none;"
        )
        title_col.addWidget(sub)
        hl.addLayout(title_col)
        hl.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedSize(50, 26)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255,255,255,0.2);
                color: white;
                border: 1px solid rgba(255,255,255,0.3);
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover {
                background: rgba(255,255,255,0.35);
            }
        """)
        clear_btn.clicked.connect(self.clear_chat)
        hl.addWidget(clear_btn)

        layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {BG}; }}
            QScrollBar:vertical {{
                background: {CARD2};
                width: 4px;
                border-radius: 2px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 2px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        self.chat_content = QWidget()
        self.chat_content.setStyleSheet(
            f"background: {BG}; border: none;"
        )
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(8, 8, 8, 8)
        self.chat_layout.setSpacing(6)
        self.chat_layout.addStretch()

        scroll.setWidget(self.chat_content)
        self.scroll = scroll
        layout.addWidget(scroll)

        self.add_bubble(
            "Hi! I am your AutoRed AI Assistant.\n\n"
            "I can help you:\n"
            "• Understand scan findings\n"
            "• Recommend tools for your target\n"
            "• Explain vulnerabilities in plain English\n"
            "• Provide remediation guidance\n\n"
            "What would you like to know?",
            is_user=False
        )

        input_frame = QFrame()
        input_frame.setFixedHeight(64)
        input_frame.setStyleSheet(f"""
            QFrame {{
                background: {CARD};
                border-top: 1px solid {BORDER};
                border-radius: 0 0 12px 12px;
                border-left: none;
                border-right: none;
                border-bottom: none;
            }}
        """)
        il = QHBoxLayout(input_frame)
        il.setContentsMargins(10, 10, 10, 10)
        il.setSpacing(8)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText(
            "Ask about findings, tools, vulnerabilities..."
        )
        self.input_field.setStyleSheet(f"""
            QLineEdit {{
                background: {CARD2};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 18px;
                padding: 8px 14px;
                font-size: 12px;
            }}
            QLineEdit:focus {{ border-color: {RED}; }}
        """)
        self.input_field.returnPressed.connect(self.send_message)
        il.addWidget(self.input_field)

        self.send_btn = QPushButton("↑")
        self.send_btn.setFixedSize(36, 36)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background: {RED};
                color: white;
                border: none;
                border-radius: 18px;
                font-size: 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background: #c73652; }}
            QPushButton:disabled {{
                background: {CARD2};
                color: {DIM};
            }}
        """)
        self.send_btn.clicked.connect(self.send_message)
        il.addWidget(self.send_btn)

        layout.addWidget(input_frame)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()
        )

    def add_bubble(self, text, is_user=True):
        bubble = MessageBubble(text, is_user)
        self.chat_layout.insertWidget(
            self.chat_layout.count() - 1, bubble
        )
        QTimer.singleShot(50, self.scroll_to_bottom)

    def send_message(self):
        text = self.input_field.text().strip()
        if not text or self.is_thinking:
            return

        self.input_field.clear()
        self.add_bubble(text, is_user=True)
        self.messages.append({"role": "user", "content": text})

        self.is_thinking = True
        self.send_btn.setEnabled(False)
        self.input_field.setEnabled(False)

        self.thinking_bubble = MessageBubble(
            "Thinking... ⏳", is_user=False
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
        self.thinking_bubble.setParent(None)
        self.thinking_bubble.deleteLater()
        self.add_bubble(clean_markdown(text), is_user=False)
        self.messages.append(
            {"role": "assistant", "content": text}
        )

    def on_error(self, error):
        self.thinking_bubble.setParent(None)
        self.thinking_bubble.deleteLater()
        self.add_bubble(f"Sorry, something went wrong:\n{error}", is_user=False)

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
        sev   = finding.get('severity', '')
        title = finding.get('title', '')
        desc  = finding.get('description', '')
        question = (
            f"I have a {sev} severity finding: {title}. "
            f"Description: {desc[:200]}. "
            f"Can you explain what this means, "
            f"why it is dangerous, and how to fix it? "
            f"Please reply in plain text without any markdown formatting."
        )
        self.input_field.setText(question)
        self.send_message()


class AIChatButton(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.chat_open  = False
        self.chat_panel = None
        self.setFixedSize(56, 56)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.fab = QPushButton("🤖")
        self.fab.setFixedSize(56, 56)
        self.fab.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fab.setStyleSheet(f"""
            QPushButton {{
                background: {RED};
                color: white;
                border: none;
                border-radius: 28px;
                font-size: 22px;
            }}
            QPushButton:hover {{ background: #c73652; }}
        """)
        self.fab.clicked.connect(self.toggle_chat)
        layout.addWidget(self.fab)

    def toggle_chat(self):
        if self.chat_open:
            self.close_chat()
        else:
            self.open_chat()

    def open_chat(self):
        if not self.chat_panel:
            parent = self.parent()
            self.chat_panel = AIChatPanel(parent)

        parent  = self.parent()
        ph      = parent.height()
        panel_h = 520

        self.chat_panel.move(
            225,
            max(10, ph - panel_h - 10)
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
