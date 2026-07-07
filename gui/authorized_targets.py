from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFrame,
    QScrollArea, QMessageBox, QInputDialog,
    QTextEdit, QCheckBox,
)
from PyQt6.QtCore import Qt
from gui.preferences import load_prefs, get_theme
# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def rgba_from_hex(hex_color, alpha):
    color = str(hex_color).strip().lstrip("#")
    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"
    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)
    return f"rgba({red}, {green}, {blue}, {alpha})"
class AuthorizedTargetsManager(QWidget):
    def __init__(self, parent=None, prefs=None):
        super().__init__(parent)
        self.prefs = prefs or load_prefs()
        self._set_theme_colors()
        self.setWindowTitle(
            "AutoRed — Authorized Targets Manager"
        )
        self.setMinimumSize(760, 620)
        self.setStyleSheet(self.get_stylesheet())
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)
        self.init_ui()
        self.load_existing()
    # ─────────────────────────────────────────────
    # Theme
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
        self.BRAND_RED = self.t.get("brand_red", self.ACCENT)
        self.BRAND_RED_HOVER = self.t.get(
            "brand_red_hover",
            self.ACCENT_HOVER
        )
        self.SUCCESS = self.t["success"]
        self.SUCCESS_HOVER = self.t.get(
            "success_hover",
            self.SUCCESS
        )
        self.WARNING = self.t["warning"]
        self.WARNING_HOVER = self.t.get(
            "warning_hover",
            self.WARNING
        )
        self.PENDING = self.t.get(
            "medium",
            "#CA8A04" if not self.dark else "#FACC15"
        )
        self.INFO = self.t["info"]
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
            "#FFFFFF" if not self.dark else "rgba(15, 23, 42, 205)"
        )
        self.CARD_HOVER = self.t.get(
            "card_hover",
            rgba_from_hex(self.ACCENT, 55 if not self.dark else 85)
        )

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()
        pending = {}
        for attr in (
            "target_input",
            "auth_by_input",
            "auth_email_input",
            "engagement_input",
            "notes_input",
        ):
            if hasattr(self, attr):
                widget = getattr(self, attr)
                if hasattr(widget, "toPlainText"):
                    pending[attr] = widget.toPlainText()
                else:
                    pending[attr] = widget.text()
        self.setStyleSheet(self.get_stylesheet())
        while self.outer.count():
            item = self.outer.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.init_ui()
        self.load_existing()
        for attr, value in pending.items():
            if hasattr(self, attr) and value:
                widget = getattr(self, attr)
                if hasattr(widget, "setPlainText"):
                    widget.setPlainText(value)
                else:
                    widget.setText(value)

    # ─────────────────────────────────────────────
    # UI helpers
    # ─────────────────────────────────────────────
    def _make_input(self, placeholder):
        inp = QLineEdit()
        inp.setObjectName("inputField")
        inp.setPlaceholderText(placeholder)
        inp.setToolTip(placeholder)
        inp.setMinimumHeight(42)
        inp.setClearButtonEnabled(True)
        return inp

    def _make_notes_input(self, placeholder):
        notes = QTextEdit()
        notes.setObjectName("notesField")
        notes.setPlaceholderText(placeholder)
        notes.setToolTip(placeholder)
        notes.setMinimumHeight(72)
        notes.setMaximumHeight(90)
        return notes

    def _field_label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("fieldLabel")
        lbl.setWordWrap(True)
        return lbl

    def _add_field(self, layout, label, widget):
        field_wrap = QFrame()
        field_wrap.setObjectName("fieldWrap")
        field_layout = QVBoxLayout(field_wrap)
        field_layout.setContentsMargins(0, 0, 0, 0)
        field_layout.setSpacing(4)
        field_layout.addWidget(self._field_label(label))
        field_layout.addWidget(widget)
        layout.addWidget(field_wrap)
        return field_wrap

    def _section_label(self, text, color=None):
        color = color or self.ACCENT
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs - 2}px;
            font-weight: 900;
            letter-spacing: 1.2px;
            background: transparent;
            border: none;
            """
        )
        return lbl

    def _small_button_style(self, color, hover_color=None):
        hover_color = hover_color or color
        return f"""
            QPushButton {{
                background-color: {self.BUTTON_SOFT};
                color: {color};
                border: 1px solid {color};
                border-radius: 7px;
                padding: 6px 12px;
                font-size: {self.fs - 2}px;
                font-weight: 800;
            }}
            QPushButton:hover {{
                background-color: {rgba_from_hex(hover_color, 28)};
                color: {color};
                border-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: {rgba_from_hex(hover_color, 65)};
                color: {color};
            }}
        """

    # ─────────────────────────────────────────────
    # UI build
    # ─────────────────────────────────────────────
    def init_ui(self):
        page_scroll = QScrollArea()
        page_scroll.setWidgetResizable(True)
        page_scroll.setFrameShape(QFrame.Shape.NoFrame)
        page_scroll.setObjectName("pageScroll")
        container = QWidget()
        container.setObjectName("contentRoot")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(14)

        # ── Header card ─────────────────────────────
        header_card = QFrame()
        header_card.setObjectName("headerCard")
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(5)
        title = QLabel("🛡️  Authorized Targets Manager")
        title.setObjectName("pageTitle")
        title.setWordWrap(True)
        header_layout.addWidget(title)
        sub = QLabel(
            "Add targets that are explicitly authorized for this engagement. "
            "An approval email will be sent to the authorizer before the target is confirmed."
        )
        sub.setObjectName("pageSub")
        sub.setWordWrap(True)
        header_layout.addWidget(sub)
        layout.addWidget(header_card)

        # ── Warning banner ──────────────────────────
        warn = QLabel(
            "⚠️  Only add targets you have written authorization to test. "
            "Unauthorized scanning is illegal under Section 3 of the "
            "Computer Crimes Act 1997 (Malaysia)."
        )
        warn.setObjectName("warningBanner")
        warn.setWordWrap(True)
        layout.addWidget(warn)

        # ── Add authorization form ──────────────────
        add_frame = QFrame()
        add_frame.setObjectName("formCard")
        form_layout = QVBoxLayout(add_frame)
        form_layout.setContentsMargins(16, 14, 16, 14)
        form_layout.setSpacing(10)

        add_title = self._section_label(
            "ADD AUTHORIZED TARGET",
            self.ACCENT
        )
        form_layout.addWidget(add_title)

        self.target_input = self._make_input(
            "Example: 192.168.112.130 or example.com"
        )
        self._add_field(
            form_layout,
            "Target domain or IP address",
            self.target_input
        )

        self.auth_by_input = self._make_input(
            "Example: John Smith, CISO"
        )
        self._add_field(
            form_layout,
            "Authorised by",
            self.auth_by_input
        )

        self.auth_email_input = self._make_input(
            "Example: authoriser@example.com"
        )
        self._add_field(
            form_layout,
            "Authoriser email address",
            self.auth_email_input
        )

        self.engagement_input = self._make_input(
            "Example: Internal Lab Assessment"
        )
        self._add_field(
            form_layout,
            "Engagement name",
            self.engagement_input
        )

        self.notes_input = self._make_notes_input(
            "Example: Ref SOW-2025-001, web apps only"
        )
        self._add_field(
            form_layout,
            "Scope notes / reference",
            self.notes_input
        )

        # ── Legal acknowledgement checkbox ──────────
        legal_frame = QFrame()
        legal_frame.setObjectName("legalFrame")
        legal_layout = QHBoxLayout(legal_frame)
        legal_layout.setContentsMargins(12, 12, 12, 12)
        legal_layout.setSpacing(12)

        self.legal_checkbox = QCheckBox()
        self.legal_checkbox.setObjectName("legalCheckbox")
        self.legal_checkbox.setFixedSize(22, 22)
        self.legal_checkbox.stateChanged.connect(
            self._on_legal_checkbox_changed
        )
        legal_layout.addWidget(
            self.legal_checkbox,
            alignment=Qt.AlignmentFlag.AlignTop
        )

        legal_text = QLabel(
            "I confirm that I am an authorized representative of the target "
            "organization or have obtained explicit written permission from the "
            "target owner to conduct this security assessment. I understand that "
            "unauthorized scanning may constitute an offence under Section 3 of "
            "the Computer Crimes Act 1997 (Malaysia) and that I am solely "
            "responsible for ensuring this assessment is conducted lawfully."
        )
        legal_text.setObjectName("legalText")
        legal_text.setWordWrap(True)
        legal_layout.addWidget(legal_text, 1)

        form_layout.addWidget(legal_frame)

        # ── Submit button (disabled until checkbox ticked) ──
        self.add_btn = QPushButton("📧  Send Authorization Request")
        self.add_btn.setObjectName("primaryBtnDisabled")
        self.add_btn.setCursor(Qt.CursorShape.ForbiddenCursor)
        self.add_btn.setEnabled(False)
        self.add_btn.clicked.connect(self.add_authorization)
        form_layout.addWidget(self.add_btn)

        layout.addWidget(add_frame)

        # ── Existing authorizations ─────────────────
        existing_label = self._section_label(
            "EXISTING AUTHORIZATIONS",
            self.DIM
        )
        layout.addWidget(existing_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("authScroll")
        scroll.setMinimumHeight(120)

        self.list_widget = QWidget()
        self.list_widget.setObjectName("listWidget")
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(8)
        self.list_layout.addStretch()

        scroll.setWidget(self.list_widget)
        layout.addWidget(scroll, 1)

        page_scroll.setWidget(container)
        self.outer.addWidget(page_scroll)

    def _on_legal_checkbox_changed(self, state):
        """Enable or disable the submit button based on checkbox state."""
        checked = state == Qt.CheckState.Checked.value
        self.add_btn.setEnabled(checked)
        if checked:
            self.add_btn.setObjectName("primaryBtn")
            self.add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            self.add_btn.setObjectName("primaryBtnDisabled")
            self.add_btn.setCursor(Qt.CursorShape.ForbiddenCursor)
        # Force stylesheet refresh
        self.add_btn.setStyleSheet("")
        self.add_btn.setStyleSheet(self.get_stylesheet())

    # ─────────────────────────────────────────────
    # Add authorization
    # ─────────────────────────────────────────────
    def add_authorization(self):
        # Extra safety check — button should already be disabled
        if not self.legal_checkbox.isChecked():
            QMessageBox.warning(
                self,
                "Legal Acknowledgement Required",
                "You must confirm the legal acknowledgement before "
                "submitting an authorization request."
            )
            return

        target = self.target_input.text().strip()
        auth_by = self.auth_by_input.text().strip()
        auth_email = self.auth_email_input.text().strip()
        engagement = self.engagement_input.text().strip()
        notes = self.notes_input.toPlainText().strip()

        if not target:
            QMessageBox.warning(
                self,
                "Missing Target",
                "Please enter a target domain or IP."
            )
            return
        if not auth_by:
            QMessageBox.warning(
                self,
                "Missing Authorization",
                "Please enter who is authorizing this target."
            )
            return
        if not auth_email:
            QMessageBox.warning(
                self,
                "Missing Authorizer Email",
                "Please enter the authorizer's email address.\n"
                "An approval code will be sent to them."
            )
            return
        if not engagement:
            QMessageBox.warning(
                self,
                "Missing Engagement",
                "Please enter the engagement name."
            )
            return

        reply = QMessageBox.question(
            self,
            "Confirm Authorization Request",
            f"An approval email will be sent to:\n"
            f"  {auth_email}\n\n"
            f"Target:     {target}\n"
            f"Auth by:    {auth_by}\n"
            f"Engagement: {engagement}\n\n"
            f"The target will remain PENDING until the authorizer provides "
            f"the approval code.\n\n"
            f"By proceeding you confirm your legal acknowledgement.\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            from backend.scope import (
                save_authorized_target,
                send_approval_email,
                generate_token,
            )
            token = generate_token()
            save_authorized_target(
                target,
                auth_by,
                engagement,
                notes,
                authorizer_email=auth_email,
                token=token,
                status="pending"
            )
            email_sent = send_approval_email(
                target,
                auth_by,
                engagement,
                auth_email,
                token
            )
            self.target_input.clear()
            self.auth_by_input.clear()
            self.auth_email_input.clear()
            self.engagement_input.clear()
            self.notes_input.clear()
            self.legal_checkbox.setChecked(False)
            self.load_existing()

            if email_sent:
                QMessageBox.information(
                    self,
                    "Request Sent",
                    f"Authorization request sent to {auth_email}.\n\n"
                    f"'{target}' is now PENDING approval.\n\n"
                    f"Once the authorizer provides the approval code, click "
                    f"'Enter Approval Code' on the target to confirm it."
                )
            else:
                QMessageBox.warning(
                    self,
                    "Email Failed",
                    f"Target saved as PENDING but the approval email could not "
                    f"be sent to {auth_email}.\n\n"
                    f"Check your SMTP config in .env and try sending manually.\n\n"
                    f"Approval code: {token}"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save authorization:\n{e}"
            )

    # ─────────────────────────────────────────────
    # Load existing authorization list
    # ─────────────────────────────────────────────
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
                "No authorized targets yet. Add a target above."
            )
            empty.setObjectName("emptyText")
            self.list_layout.insertWidget(0, empty)
            return
        seen = set()
        for auth in auths:
            target = auth.get("target", "")
            if target in seen:
                continue
            seen.add(target)
            self.list_layout.insertWidget(
                0,
                self.make_auth_card(auth)
            )

    # ─────────────────────────────────────────────
    # Authorization card
    # ─────────────────────────────────────────────
    def make_auth_card(self, auth):
        status = auth.get("status", "approved")
        pending = status == "pending"
        border_color = self.PENDING if pending else self.SUCCESS
        frame = QFrame()
        frame.setObjectName("authCard")
        frame.setStyleSheet(
            f"""
            QFrame#authCard {{
                background-color: {self.CARD};
                border: 1px solid {rgba_from_hex(self.BORDER_SOFT, 45)};
                border-left: 4px solid {border_color};
                border-radius: 10px;
            }}
            QFrame#authCard:hover {{
                border: 1px solid {self.CARD_HOVER};
                border-left: 4px solid {border_color};
                background-color: {self.CARD2};
            }}
            """
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        info_col = QVBoxLayout()
        info_col.setSpacing(4)
        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        target_lbl = QLabel(
            f"🎯  {auth.get('target', 'Unknown')}"
        )
        target_lbl.setWordWrap(True)
        target_lbl.setStyleSheet(
            f"""
            color: {border_color};
            font-size: {self.fs}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )
        header_row.addWidget(target_lbl)
        badge_text = (
            "⏳ Pending Approval"
            if pending
            else "✅ Approved"
        )
        badge_color = self.PENDING if pending else self.SUCCESS
        badge = QLabel(badge_text)
        badge.setStyleSheet(
            f"""
            color: {badge_color};
            font-size: {self.fs - 3}px;
            font-weight: 900;
            background-color: {rgba_from_hex(badge_color, 18)};
            border: 1px solid {badge_color};
            border-radius: 6px;
            padding: 3px 8px;
            """
        )
        header_row.addWidget(badge)
        header_row.addStretch()
        info_col.addLayout(header_row)
        auth_lbl = QLabel(
            f"Authorized by: {auth.get('authorized_by', 'N/A')}  •  "
            f"{auth.get('engagement', 'N/A')}"
        )
        auth_lbl.setObjectName("cardMeta")
        auth_lbl.setWordWrap(True)
        info_col.addWidget(auth_lbl)
        date_lbl = QLabel(
            f"Date: {auth.get('authorized_on', 'N/A')}"
        )
        date_lbl.setObjectName("cardMeta")
        info_col.addWidget(date_lbl)
        if auth.get("authorizer_email"):
            email_lbl = QLabel(
                f"Authorizer email: {auth.get('authorizer_email')}"
            )
            email_lbl.setObjectName("cardMeta")
            email_lbl.setWordWrap(True)
            info_col.addWidget(email_lbl)
        if auth.get("notes"):
            notes_lbl = QLabel(
                f"Notes: {auth.get('notes')}"
            )
            notes_lbl.setObjectName("cardMeta")
            notes_lbl.setWordWrap(True)
            info_col.addWidget(notes_lbl)
        layout.addLayout(info_col, 1)
        btn_col = QVBoxLayout()
        btn_col.setSpacing(6)
        if pending:
            code_btn = QPushButton("🔑 Enter Approval Code")
            code_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            code_btn.setStyleSheet(
                self._small_button_style(self.PENDING, self.WARNING)
            )
            target_val = auth.get("target", "")
            code_btn.clicked.connect(
                lambda _, tv=target_val:
                self.enter_approval_code(tv)
            )
            btn_col.addWidget(code_btn)
        remove_btn = QPushButton("🗑️ Remove")
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.setStyleSheet(
            self._small_button_style(
                self.BRAND_RED,
                self.BRAND_RED_HOVER
            )
        )
        target_val = auth.get("target", "")
        remove_btn.clicked.connect(
            lambda _, tv=target_val:
            self.remove_target(tv)
        )
        btn_col.addWidget(remove_btn)
        btn_col.addStretch()
        layout.addLayout(btn_col)
        return frame

    # ─────────────────────────────────────────────
    # Enter approval code
    # ─────────────────────────────────────────────
    def enter_approval_code(self, target):
        code, ok = QInputDialog.getText(
            self,
            "Enter Approval Code",
            f"Enter the 6-digit approval code sent to the authorizer for:\n\n"
            f"  {target}\n",
        )
        if not ok or not code.strip():
            return
        try:
            from backend.scope import confirm_authorization
            success, msg = confirm_authorization(
                target,
                code.strip()
            )
            if success:
                QMessageBox.information(
                    self,
                    "Authorization Confirmed ✅",
                    f"'{target}' has been approved and is now active "
                    f"for scanning.\n\n{msg}"
                )
                self.load_existing()
            else:
                QMessageBox.warning(
                    self,
                    "Invalid Code",
                    msg
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Could not confirm authorization:\n{e}"
            )

    # ─────────────────────────────────────────────
    # Remove target
    # ─────────────────────────────────────────────
    def remove_target(self, target):
        reply = QMessageBox.question(
            self,
            "Remove Authorization",
            f"Remove authorization for '{target}'?\n\n"
            f"This target will be subject to normal scope validation again.",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from backend.scope import remove_authorized_target
            remove_authorized_target(target)
            self.load_existing()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Remove Failed",
                f"Could not remove '{target}':\n{e}"
            )

    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────
    def get_stylesheet(self):
        fs = self.fs
        return f"""
            QWidget {{
                background-color: {self.BG};
                color: {self.TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}
            #contentRoot {{
                background-color: {self.BG};
            }}
            #headerCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}
            #headerCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}
            #pageTitle {{
                color: {self.ACCENT};
                font-size: {fs + 6}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
            #pageSub {{
                color: {self.DIM};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}
            #warningBanner {{
                background-color: {rgba_from_hex(self.WARNING, 25)};
                color: {self.WARNING};
                border: 1px solid {rgba_from_hex(self.WARNING, 100)};
                border-radius: 10px;
                padding: 11px 13px;
                font-size: {fs - 1}px;
                font-weight: 700;
            }}
            #formCard {{
                background-color: {self.CARD};
                border: 1px solid {self.BORDER};
                border-radius: 12px;
            }}
            #formCard:hover {{
                border: 1px solid {self.CARD_HOVER};
            }}
            #inputField {{
                background-color: {self.BG_DEEP};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 12px;
                min-height: 22px;
                font-size: {fs}px;
                font-weight: 600;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}
            #inputField:focus {{
                border-color: {self.ACCENT};
                background-color: {self.CARD2};
            }}
            #inputField::placeholder {{
                color: {self.DIM};
            }}
            #legalFrame {{
                background-color: {rgba_from_hex(self.WARNING, 15)};
                border: 1px solid {rgba_from_hex(self.WARNING, 80)};
                border-radius: 10px;
            }}
            #legalText {{
                color: {self.TEXT};
                font-size: {fs - 2}px;
                font-weight: 600;
                background: transparent;
                border: none;
                line-height: 1.5;
            }}
            #legalCheckbox {{
                background: transparent;
                border: none;
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border: 2px solid {self.WARNING};
                border-radius: 5px;
                background-color: {self.BG_DEEP};
            }}
            QCheckBox::indicator:checked {{
                background-color: {self.WARNING};
                border-color: {self.WARNING};
                image: none;
            }}
            QCheckBox::indicator:checked:after {{
                content: "✓";
            }}
            #primaryBtn {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: {fs}px;
                font-weight: 900;
            }}
            #primaryBtn:hover {{
                background-color: {self.ACCENT_HOVER};
            }}
            #primaryBtn:pressed {{
                background-color: {self.ACCENT_DARK};
            }}
            #primaryBtnDisabled {{
                background-color: {self.BORDER};
                color: {self.DIM};
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: {fs}px;
                font-weight: 900;
            }}
            #authScroll {{
                border: none;
                background: transparent;
            }}
            #authScroll QWidget {{
                background: transparent;
            }}
            QScrollBar:vertical {{
                background: {self.BG};
                width: 10px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: {self.BORDER_SOFT};
                border-radius: 5px;
                min-height: 28px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {self.ACCENT};
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            #listWidget {{
                background: transparent;
            }}
            #emptyText {{
                color: {self.DIM};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}
            #cardMeta {{
                color: {self.DIM};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
            }}
            #pageScroll {{
                border: none;
                background: transparent;
            }}
            #pageScroll QWidget {{
                background: transparent;
            }}
            #fieldWrap {{
                background: transparent;
                border: none;
                margin: 0px;
                padding: 0px;
            }}
            #fieldLabel {{
                color: {self.TEXT};
                font-size: {fs - 2}px;
                font-weight: 800;
                background: transparent;
                border: none;
                padding: 0px 0px 1px 2px;
                margin: 0px;
            }}
            #notesField {{
                background-color: {self.BG_DEEP};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 12px;
                font-size: {fs}px;
                font-weight: 600;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}
            #notesField:focus {{
                border-color: {self.ACCENT};
                background-color: {self.CARD2};
            }}
            #notesField::placeholder {{
                color: {self.DIM};
            }}
            QMessageBox {{
                background-color: {self.BG};
                color: {self.TEXT};
            }}
            QMessageBox QLabel {{
                color: {self.TEXT};
                background: transparent;
                border: none;
            }}
            QMessageBox QPushButton {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 7px;
                padding: 7px 18px;
                font-weight: 800;
            }}
            QMessageBox QPushButton:hover {{
                background-color: {self.ACCENT_HOVER};
            }}
            QInputDialog {{
                background-color: {self.BG};
                color: {self.TEXT};
            }}
            QInputDialog QLabel {{
                color: {self.TEXT};
                background: transparent;
                border: none;
            }}
            QInputDialog QLineEdit {{
                background-color: {self.CARD};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 8px;
                padding: 8px 10px;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}
            QInputDialog QLineEdit:focus {{
                border-color: {self.ACCENT};
                background-color: {self.CARD2};
            }}
            QInputDialog QPushButton {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 7px;
                padding: 7px 18px;
                font-weight: 800;
            }}
            QInputDialog QPushButton:hover {{
                background-color: {self.ACCENT_HOVER};
            }}
        """
