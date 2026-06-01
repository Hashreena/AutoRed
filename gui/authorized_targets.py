from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTextEdit, QFrame,
    QScrollArea, QMessageBox,
)
from PyQt6.QtCore import Qt


class AuthorizedTargetsManager(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(
            "AutoRed — Authorized Targets Manager"
        )
        self.setMinimumSize(700, 550)
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_existing()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(14)

        # ── Header ───────────────────────────────────────
        title = QLabel("🛡️  Authorized Targets Manager")
        title.setStyleSheet(
            "color: #e6edf3; font-size: 18px; "
            "font-weight: bold; background: transparent; "
            "border: none;"
        )
        layout.addWidget(title)

        sub = QLabel(
            "Add targets that are explicitly authorized "
            "for this engagement. "
            "These will override the scope blocklist."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none;"
        )
        layout.addWidget(sub)

        # ── Warning banner ────────────────────────────────
        warn = QLabel(
            "⚠️  Only add targets you have written "
            "authorization to test. "
            "Unauthorized scanning is illegal."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet(
            "background: #ff8c0022; color: #ff8c00; "
            "border: 1px solid #ff8c0055; "
            "border-radius: 6px; padding: 10px; "
            "font-size: 12px;"
        )
        layout.addWidget(warn)

        # ── Add new authorization ─────────────────────────
        add_frame = QFrame()
        add_frame.setStyleSheet(
            "QFrame { background: #161b22; "
            "border: 1px solid #30363d; "
            "border-radius: 6px; }"
        )
        afl = QVBoxLayout(add_frame)
        afl.setContentsMargins(16, 14, 16, 14)
        afl.setSpacing(10)

        add_title = QLabel("ADD AUTHORIZED TARGET")
        add_title.setStyleSheet(
            "color: #1d9e75; font-size: 11px; "
            "font-weight: bold; letter-spacing: 1px; "
            "background: transparent; border: none;"
        )
        afl.addWidget(add_title)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "Target domain or IP (e.g. maybank.com, "
            "192.168.1.1)"
        )
        self.target_input.setStyleSheet(
            "background: #0d1117; color: #e6edf3; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; padding: 8px; "
            "font-size: 13px;"
        )
        afl.addWidget(self.target_input)

        self.auth_by_input = QLineEdit()
        self.auth_by_input.setPlaceholderText(
            "Authorized by (e.g. John Smith — CISO, "
            "CyberShield Sdn Bhd)"
        )
        self.auth_by_input.setStyleSheet(
            "background: #0d1117; color: #e6edf3; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; padding: 8px; "
            "font-size: 13px;"
        )
        afl.addWidget(self.auth_by_input)

        self.engagement_input = QLineEdit()
        self.engagement_input.setPlaceholderText(
            "Engagement name (e.g. Q3 2025 Pentest — "
            "External Assessment)"
        )
        self.engagement_input.setStyleSheet(
            "background: #0d1117; color: #e6edf3; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; padding: 8px; "
            "font-size: 13px;"
        )
        afl.addWidget(self.engagement_input)

        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText(
            "Notes (e.g. Ref: SOW-2025-001, "
            "scope limited to web apps only)"
        )
        self.notes_input.setStyleSheet(
            "background: #0d1117; color: #e6edf3; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; padding: 8px; "
            "font-size: 13px;"
        )
        afl.addWidget(self.notes_input)

        add_btn = QPushButton("✅  Add Authorization")
        add_btn.setStyleSheet(
            "background: #1d9e75; color: white; "
            "border: none; border-radius: 6px; "
            "padding: 10px 20px; font-size: 13px; "
            "font-weight: bold;"
        )
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self.add_authorization)
        afl.addWidget(add_btn)

        layout.addWidget(add_frame)

        # ── Existing authorizations ───────────────────────
        existing_label = QLabel("EXISTING AUTHORIZATIONS")
        existing_label.setStyleSheet(
            "color: #8b949e; font-size: 11px; "
            "font-weight: bold; letter-spacing: 1px; "
            "background: transparent; border: none; "
            "margin-top: 6px;"
        )
        layout.addWidget(existing_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea { border: none; "
            "background: transparent; }"
        )

        self.list_widget = QWidget()
        self.list_widget.setStyleSheet(
            "background: transparent;"
        )
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(8)
        self.list_layout.addStretch()

        scroll.setWidget(self.list_widget)
        layout.addWidget(scroll)

    def add_authorization(self):
        target     = self.target_input.text().strip()
        auth_by    = self.auth_by_input.text().strip()
        engagement = self.engagement_input.text().strip()
        notes      = self.notes_input.text().strip()

        if not target:
            QMessageBox.warning(
                self, "Missing Target",
                "Please enter a target domain or IP."
            )
            return

        if not auth_by:
            QMessageBox.warning(
                self, "Missing Authorization",
                "Please enter who authorized this target."
            )
            return

        if not engagement:
            QMessageBox.warning(
                self, "Missing Engagement",
                "Please enter the engagement name."
            )
            return

        reply = QMessageBox.question(
            self,
            "Confirm Authorization",
            f"You are authorizing scanning of:\n\n"
            f"  Target:     {target}\n"
            f"  Auth by:    {auth_by}\n"
            f"  Engagement: {engagement}\n\n"
            f"Confirm you have written authorization "
            f"to scan this target?",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            from backend.scope import save_authorized_target
            save_authorized_target(
                target, auth_by, engagement, notes
            )
            self.target_input.clear()
            self.auth_by_input.clear()
            self.engagement_input.clear()
            self.notes_input.clear()
            self.load_existing()
            QMessageBox.information(
                self, "Authorization Added",
                f"'{target}' has been authorized\n"
                f"and will bypass scope validation."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to save authorization:\n{e}"
            )

    def load_existing(self):
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        try:
            from backend.scope import get_all_authorizations
            auths = get_all_authorizations()
        except Exception:
            auths = []

        if not auths:
            empty = QLabel(
                "No authorized targets yet. "
                "Add targets above."
            )
            empty.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.list_layout.insertWidget(0, empty)
            return

        seen = set()
        for auth in reversed(auths):
            target = auth.get('target', '')
            if target in seen:
                continue
            seen.add(target)
            self.list_layout.insertWidget(
                0, self.make_auth_card(auth)
            )

    def make_auth_card(self, auth):
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background: #161b22; "
            "border: 1px solid #1d9e7544; "
            "border-radius: 6px; }"
        )
        fl = QHBoxLayout(frame)
        fl.setContentsMargins(14, 10, 14, 10)
        fl.setSpacing(12)

        info = QVBoxLayout()
        info.setSpacing(3)

        target_lbl = QLabel(
            f"🎯  {auth.get('target', 'Unknown')}"
        )
        target_lbl.setStyleSheet(
            "color: #1d9e75; font-size: 13px; "
            "font-weight: bold; background: transparent; "
            "border: none;"
        )
        info.addWidget(target_lbl)

        auth_lbl = QLabel(
            f"Authorized by: {auth.get('authorized_by', 'N/A')} "
            f"| {auth.get('engagement', 'N/A')}"
        )
        auth_lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px; "
            "background: transparent; border: none;"
        )
        info.addWidget(auth_lbl)

        date_lbl = QLabel(
            f"Date: {auth.get('authorized_on', 'N/A')}"
        )
        date_lbl.setStyleSheet(
            "color: #555; font-size: 11px; "
            "background: transparent; border: none;"
        )
        info.addWidget(date_lbl)

        if auth.get('notes'):
            notes_lbl = QLabel(
                f"Notes: {auth.get('notes')}"
            )
            notes_lbl.setStyleSheet(
                "color: #555; font-size: 11px; "
                "background: transparent; border: none;"
            )
            info.addWidget(notes_lbl)

        fl.addLayout(info)
        fl.addStretch()

        remove_btn = QPushButton("🗑️ Remove")
        remove_btn.setStyleSheet(
            "background: transparent; color: #e94560; "
            "border: 1px solid #e9456044; "
            "border-radius: 4px; padding: 4px 10px; "
            "font-size: 11px;"
        )
        remove_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        target = auth.get('target', '')
        remove_btn.clicked.connect(
            lambda checked, t=target:
            self.remove_target(t)
        )
        fl.addWidget(remove_btn)

        return frame

    def remove_target(self, target):
        reply = QMessageBox.question(
            self,
            "Remove Authorization",
            f"Remove authorization for '{target}'?\n\n"
            f"This target will be subject to normal "
            f"scope validation again.",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            from backend.scope import remove_authorized_target
            remove_authorized_target(target)
            self.load_existing()

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
        """
