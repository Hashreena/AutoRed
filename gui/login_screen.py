"""
AutoRed -- Login screen with email OTP (MFA).

Flow:
  Step 1: username + password
  Step 2: 6-digit email code
  on_login_success(user_dict) is called once both steps pass.

The "Create first account" link is always visible, so additional
accounts can be created at any time -- not gated to only when the
database is completely empty.

"Remember Me": when checked, a remembered session token is
saved to a local file (~/.autored_session) and the user skips
straight past BOTH the password and OTP steps on next launch,
until the token expires or they log out.

"Forgot password?": opens a 3-step recovery dialog --
  1. Enter username
  2. Enter the 6-digit code emailed to the account's address
  3. Set a new password (with confirm + strength validation)
"""

import os
import math

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFrame, QMessageBox,
    QStackedWidget, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect, QDialog, QCheckBox
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve,
    QRectF, QPoint
)
from PyQt6.QtGui import (
    QColor, QPainter, QPen, QLinearGradient
)

from gui.preferences import load_prefs, get_theme


SESSION_FILE = os.path.join(
    os.path.expanduser("~"),
    ".autored_session"
)


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


def _save_session_token(token):
    try:
        with open(SESSION_FILE, "w") as f:
            f.write(token)

        os.chmod(SESSION_FILE, 0o600)

    except Exception as e:
        print(f"[!] Could not save session token: {e}")


def _load_session_token():
    if not os.path.exists(SESSION_FILE):
        return None

    try:
        with open(SESSION_FILE) as f:
            return f.read().strip() or None

    except Exception:
        return None


def _clear_session_token():
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)

    except Exception:
        pass


class AnimatedLoginBackground(QWidget):
    """
    Subtle animated AutoRed background.
    Supports dark and light mode.
    """

    def __init__(self, theme=None, dark_mode=True, parent=None):
        super().__init__(parent)

        self.phase = 0.0
        self.t = theme or get_theme(True)
        self.dark = dark_mode

        self.setObjectName("loginBg")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(30)

    def apply_theme(self, theme, dark_mode=True):
        self.t = theme
        self.dark = dark_mode
        self.update()

    def _tick(self):
        self.phase += 0.018
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()

        bg = QLinearGradient(0, 0, w, h)

        if self.dark:
            bg.setColorAt(0.0, QColor("#020617"))
            bg.setColorAt(0.4, QColor("#041127"))
            bg.setColorAt(0.75, QColor("#07111F"))
            bg.setColorAt(1.0, QColor("#01030A"))

            grid_color = QColor(148, 163, 184, 18)
            red_glow_1 = QColor(239, 68, 68, 22)
            red_glow_2 = QColor(239, 68, 68, 10)
            blue_glow = QColor(96, 165, 250, 13)
            ring_color = QColor(148, 163, 184, 20)
            cross_color = QColor(148, 163, 184, 18)
            sweep_color = QColor(239, 68, 68, 55)
            diag_color = QColor(239, 68, 68, 26)

        else:
            bg.setColorAt(0.0, QColor("#F8FAFC"))
            bg.setColorAt(0.4, QColor("#F1F5F9"))
            bg.setColorAt(0.75, QColor("#EEF2F7"))
            bg.setColorAt(1.0, QColor("#FFFFFF"))

            grid_color = QColor(100, 116, 139, 22)
            red_glow_1 = QColor(239, 68, 68, 20)
            red_glow_2 = QColor(239, 68, 68, 9)
            blue_glow = QColor(37, 99, 235, 9)
            ring_color = QColor(100, 116, 139, 24)
            cross_color = QColor(100, 116, 139, 20)
            sweep_color = QColor(239, 68, 68, 65)
            diag_color = QColor(239, 68, 68, 22)

        painter.fillRect(self.rect(), bg)

        # Moving grid
        grid_pen = QPen(grid_color)
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)

        spacing = 54
        x_shift = int(math.sin(self.phase * 0.7) * 12)
        y_shift = int(math.cos(self.phase * 0.6) * 10)

        for x in range(-spacing, w + spacing, spacing):
            painter.drawLine(x + x_shift, 0, x + x_shift, h)

        for y in range(-spacing, h + spacing, spacing):
            painter.drawLine(0, y + y_shift, w, y + y_shift)

        painter.setPen(Qt.PenStyle.NoPen)

        # Top-right red glow
        red_x = w * 0.78 + math.sin(self.phase * 1.4) * 30
        red_y = h * 0.18 + math.cos(self.phase * 1.1) * 18

        painter.setBrush(red_glow_1)
        painter.drawEllipse(
            QRectF(red_x - 170, red_y - 170, 340, 340)
        )

        painter.setBrush(red_glow_2)
        painter.drawEllipse(
            QRectF(red_x - 250, red_y - 250, 500, 500)
        )

        # Bottom-left blue glow
        blue_x = w * 0.15 + math.cos(self.phase * 0.85) * 24
        blue_y = h * 0.76 + math.sin(self.phase * 0.95) * 22

        painter.setBrush(blue_glow)
        painter.drawEllipse(
            QRectF(blue_x - 180, blue_y - 180, 360, 360)
        )

        # Radar sweep
        cx = w * 0.76
        cy = h * 0.62
        sweep_radius = min(w, h) * 0.24

        ring_pen = QPen(ring_color)
        ring_pen.setWidth(1)
        painter.setPen(ring_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        for r in (110, 170, 230):
            painter.drawEllipse(QRectF(cx - r, cy - r, r * 2, r * 2))

        cross_pen = QPen(cross_color)
        cross_pen.setWidth(1)
        painter.setPen(cross_pen)
        painter.drawLine(int(cx - 240), int(cy), int(cx + 240), int(cy))
        painter.drawLine(int(cx), int(cy - 240), int(cx), int(cy + 240))

        angle = self.phase * 1.6
        x2 = cx + math.cos(angle) * sweep_radius
        y2 = cy + math.sin(angle) * sweep_radius

        sweep_pen = QPen(sweep_color)
        sweep_pen.setWidth(2)
        painter.setPen(sweep_pen)
        painter.drawLine(int(cx), int(cy), int(x2), int(y2))

        painter.setPen(Qt.PenStyle.NoPen)

        dots = [
            (0.68, 0.52, 4, QColor(239, 68, 68, 120)),
            (0.81, 0.57, 5, QColor(37, 99, 235, 100)),
            (0.72, 0.72, 4, QColor(239, 68, 68, 95)),
            (0.84, 0.68, 3, QColor(100, 116, 139, 85)),
        ]

        pulse = (math.sin(self.phase * 2.2) + 1) / 2

        for px, py, size, col in dots:
            painter.setBrush(
                QColor(
                    col.red(),
                    col.green(),
                    col.blue(),
                    int(col.alpha() * (0.45 + pulse * 0.55))
                )
            )
            painter.drawEllipse(
                QRectF(
                    w * px - size,
                    h * py - size,
                    size * 2,
                    size * 2
                )
            )

        diag_pen = QPen(diag_color)
        diag_pen.setWidth(2)
        painter.setPen(diag_pen)
        painter.drawLine(int(w * 0.62), 0, w, int(h * 0.38))

        painter.end()


class LoginScreen(QWidget):
    def __init__(self, on_login_success=None, prefs=None):
        super().__init__()

        self.on_login_success = on_login_success

        self.prefs = prefs or load_prefs()
        self._set_theme_colors()

        self._pending_user = None
        self._resend_seconds = 0
        self._animations = []

        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

        QTimer.singleShot(80, self._try_auto_login)
        QTimer.singleShot(120, self._update_responsive_layout)

    # ─────────────────────────────────────────────
    # Theme
    # ─────────────────────────────────────────────

    def _set_theme_colors(self):
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)

        self.BG = self.t["bg"]
        self.BG_DEEP = self.t.get("bg_deep", self.BG)
        self.PAGE = self.t.get("sidebar_bg", self.BG)

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
        self.SUCCESS_HOVER = self.t.get("success_hover", self.SUCCESS)

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
            rgba_from_hex(self.ACCENT, 55 if not self.dark else 85)
        )

        if self.dark:
            # One consistent blue shade for the whole login side
            self.SHELL_BG = "rgba(10, 18, 36, 220)"
            self.BRAND_BG = "rgba(2, 6, 23, 155)"
            self.RIGHT_BG = "#0B1426"
            self.FORM_BG = "#0B1426"
            self.INPUT_BG = "#08111F"
            self.ERROR = "#FCA5A5"
            self.RED_TEXT = "#FEE2E2"

        else:
            self.SHELL_BG = "rgba(255, 255, 255, 235)"
            self.BRAND_BG = "rgba(255, 255, 255, 210)"
            self.RIGHT_BG = "#F8FAFC"
            self.FORM_BG = "#F8FAFC"
            self.INPUT_BG = "#FFFFFF"
            self.ERROR = "#B91C1C"
            self.RED_TEXT = "#7F1D1D"

    def apply_theme(self, prefs):
        self.prefs = prefs
        self._set_theme_colors()

        if hasattr(self, "background"):
            self.background.apply_theme(self.t, self.dark)

        self.setStyleSheet(self.get_stylesheet())

        for field in (
            "username_input",
            "password_input",
            "otp_input",
        ):
            if hasattr(self, field):
                getattr(self, field).setStyleSheet(self._input_style())

        if hasattr(self, "remember_checkbox"):
            self.remember_checkbox.setStyleSheet(self._checkbox_style())

        self._update_responsive_layout()

    # ─────────────────────────────────────────────
    # Remember Me / auto-login
    # ─────────────────────────────────────────────

    def _try_auto_login(self):
        token = _load_session_token()

        if not token:
            return

        try:
            from backend.auth import validate_remember_token
            user = validate_remember_token(token)

        except Exception as e:
            print(f"[!] Remember-me check failed: {e}")
            user = None

        if user and self.on_login_success:
            print(f"[+] Auto-login via remembered session: {user['username']}")
            self.on_login_success(user)

        elif token:
            _clear_session_token()

    # ─────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self.background = AnimatedLoginBackground(
            theme=self.t,
            dark_mode=self.dark
        )

        bg_layout = QVBoxLayout(self.background)
        bg_layout.setContentsMargins(32, 32, 32, 32)
        bg_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.shell = QFrame()
        self.shell.setObjectName("loginShell")
        self.shell.setFixedSize(900, 560)

        shadow = QGraphicsDropShadowEffect(self.shell)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 18)
        shadow.setColor(
            QColor(0, 0, 0, 145 if self.dark else 45)
        )
        self.shell.setGraphicsEffect(shadow)

        shell_layout = QHBoxLayout(self.shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        # ── Left brand panel ───────────────────────

        self.brand_panel = QFrame()
        self.brand_panel.setObjectName("brandPanel")
        self.brand_panel.setFixedWidth(410)

        brand_layout = QVBoxLayout(self.brand_panel)
        brand_layout.setContentsMargins(34, 34, 34, 34)
        brand_layout.setSpacing(14)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        brand_mark = QLabel("AR")
        brand_mark.setObjectName("brandMark")
        brand_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(brand_mark)

        top_text_col = QVBoxLayout()
        top_text_col.setSpacing(0)

        brand_title = QLabel("AutoRed")
        brand_title.setObjectName("brandTitle")
        top_text_col.addWidget(brand_title)

        brand_sub = QLabel("Recon Automation Platform")
        brand_sub.setObjectName("brandSubtitle")
        top_text_col.addWidget(brand_sub)

        top_row.addLayout(top_text_col)
        top_row.addStretch()

        brand_layout.addLayout(top_row)
        brand_layout.addSpacing(18)

        hero = QLabel(
            "Red-team styled reconnaissance and findings analysis workspace."
        )
        hero.setObjectName("brandHero")
        hero.setWordWrap(True)
        brand_layout.addWidget(hero)

        hero_sub = QLabel(
            "AutoRed helps analysts manage scans, organize findings, review "
            "attack exposure, and understand risk through a unified SIEM-style interface."
        )
        hero_sub.setObjectName("brandHeroSub")
        hero_sub.setWordWrap(True)
        brand_layout.addWidget(hero_sub)

        brand_layout.addSpacing(10)

        features = [
            (
                "🛡",
                "Security Dashboard",
                "View findings, severity, and analyst workflow in one place."
            ),
            (
                "📡",
                "Recon Visibility",
                "Track scan results, assets, exposed services, and attack surface."
            ),
            (
                "🤖",
                "AI Assistance",
                "Get explanations, remediation guidance, and analyst support."
            ),
            (
                "📄",
                "Reporting",
                "Review details, audit activity, and export technical results."
            ),
        ]

        for icon, title, desc in features:
            feature = self._make_feature_card(icon, title, desc)
            brand_layout.addWidget(feature)

        brand_layout.addStretch()

        footer = QLabel("Final Year Project • APU Cyber Security")
        footer.setObjectName("brandFooter")
        brand_layout.addWidget(footer)

        shell_layout.addWidget(self.brand_panel)

        # ── Right login panel ───────────────────────

        self.right_panel = QFrame()
        self.right_panel.setObjectName("rightPanel")

        self.right_layout = QVBoxLayout(self.right_panel)
        self.right_layout.setContentsMargins(42, 38, 42, 38)
        self.right_layout.setSpacing(12)
        self.right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.login_card = QFrame()
        self.login_card.setObjectName("loginCard")
        self.login_card.setFixedWidth(380)

        card_layout = QVBoxLayout(self.login_card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("loginCardHeader")

        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 24)
        header_layout.setSpacing(6)

        welcome = QLabel("Welcome back")
        welcome.setObjectName("loginLogo")
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(welcome)

        sub = QLabel("Sign in to continue to AutoRed")
        sub.setObjectName("loginSub")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(sub)

        card_layout.addWidget(header)

        self.stack = QStackedWidget()
        self.stack.setObjectName("loginStack")
        self.stack.setAttribute(
            Qt.WidgetAttribute.WA_StyledBackground,
            True
        )
        card_layout.addWidget(self.stack)

        self.password_page = self._build_password_page()
        self.otp_page = self._build_otp_page()

        self.stack.addWidget(self.password_page)
        self.stack.addWidget(self.otp_page)

        self.right_layout.addStretch()
        self.right_layout.addWidget(self.login_card)
        self.right_layout.addStretch()

        shell_layout.addWidget(self.right_panel)

        bg_layout.addWidget(self.shell)
        outer.addWidget(self.background)

        self._animate_shell()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_responsive_layout()

    def _update_responsive_layout(self):
        if not hasattr(self, "shell"):
            return

        available_width = max(360, self.width() - 64)
        compact = available_width < 850

        if compact:
            shell_width = max(380, min(430, self.width() - 32))
            self.shell.setFixedSize(shell_width, 560)

            self.brand_panel.hide()

            self.right_layout.setContentsMargins(28, 36, 28, 36)

            card_width = max(320, min(380, shell_width - 56))
            self.login_card.setFixedWidth(card_width)

        else:
            self.shell.setFixedSize(900, 560)

            self.brand_panel.show()

            self.right_layout.setContentsMargins(42, 38, 42, 38)
            self.login_card.setFixedWidth(380)

    def _make_feature_card(self, icon, title, desc):
        frame = QFrame()
        frame.setObjectName("featureCard")

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 11, 12, 11)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setObjectName("featureIcon")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setFixedSize(42, 42)
        layout.addWidget(icon_lbl)

        txt_col = QVBoxLayout()
        txt_col.setSpacing(2)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("featureTitle")
        txt_col.addWidget(title_lbl)

        desc_lbl = QLabel(desc)
        desc_lbl.setObjectName("featureDesc")
        desc_lbl.setWordWrap(True)
        txt_col.addWidget(desc_lbl)

        layout.addLayout(txt_col, 1)

        return frame

    def _animate_shell(self):
        opacity = QGraphicsOpacityEffect(self.shell)
        self.shell.setGraphicsEffect(opacity)

        fade = QPropertyAnimation(opacity, b"opacity", self)
        fade.setDuration(500)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade.start()

        self._animations.append(fade)

    def _input_style(self):
        return f"""
            QLineEdit {{
                background-color: {self.INPUT_BG};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
                border-radius: 9px;
                padding: 12px 14px;
                min-height: 20px;
                font-size: {self.fs}px;
                selection-background-color: {self.ACCENT};
                selection-color: white;
            }}

            QLineEdit:focus {{
                border-color: {self.ACCENT};
                background-color: {self.CARD2};
            }}

            QLineEdit::placeholder {{
                color: {self.SOFT};
            }}
        """

    def _checkbox_style(self):
        return f"""
            QCheckBox {{
                color: {self.DIM};
                font-size: {self.fs - 1}px;
                spacing: 8px;
                background: transparent;
                border: none;
                padding-top: 2px;
                padding-bottom: 2px;
            }}

            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 1px solid {self.BORDER};
                background: {self.INPUT_BG};
            }}

            QCheckBox::indicator:checked {{
                background: {self.ACCENT};
                border-color: {self.ACCENT};
            }}

            QCheckBox::indicator:hover {{
                border-color: {self.ACCENT};
            }}
        """

    # ─────────────────────────────────────────────
    # Step 1
    # ─────────────────────────────────────────────

    def _build_password_page(self):
        page = QWidget()
        page.setObjectName("stackPage")
        page.setAttribute(
            Qt.WidgetAttribute.WA_StyledBackground,
            True
        )

        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(9)

        user_lbl = QLabel("Username")
        user_lbl.setObjectName("fieldLabel")
        layout.addWidget(user_lbl)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setMinimumHeight(44)
        self.username_input.setStyleSheet(self._input_style())
        layout.addWidget(self.username_input)

        layout.addSpacing(2)

        pass_row = QHBoxLayout()
        pass_lbl = QLabel("Password")
        pass_lbl.setObjectName("fieldLabel")
        pass_row.addWidget(pass_lbl)
        pass_row.addStretch()

        forgot_link = QPushButton("Forgot password?")
        forgot_link.setObjectName("linkBtn")
        forgot_link.setCursor(Qt.CursorShape.PointingHandCursor)
        forgot_link.clicked.connect(self.show_forgot_password_dialog)
        pass_row.addWidget(forgot_link)
        layout.addLayout(pass_row)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(44)
        self.password_input.setStyleSheet(self._input_style())
        self.password_input.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.password_input)

        self.remember_checkbox = QCheckBox("Remember me")
        self.remember_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self.remember_checkbox.setStyleSheet(self._checkbox_style())
        layout.addWidget(self.remember_checkbox)

        self.login_error = QLabel("")
        self.login_error.setObjectName("errorLabel")
        self.login_error.setWordWrap(True)
        layout.addWidget(self.login_error)

        login_btn = QPushButton("Log In Securely")
        login_btn.setObjectName("primaryBtn")
        login_btn.setMinimumHeight(42)
        login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        login_btn.clicked.connect(self.attempt_login)
        layout.addWidget(login_btn)

        self.create_account_row = QHBoxLayout()

        no_account_lbl = QLabel("No account yet?")
        no_account_lbl.setObjectName("hintLabel")

        create_link = QPushButton("Create account")
        create_link.setObjectName("linkBtn")
        create_link.setCursor(Qt.CursorShape.PointingHandCursor)
        create_link.clicked.connect(self.show_create_account_dialog)

        self.create_account_row.addStretch()
        self.create_account_row.addWidget(no_account_lbl)
        self.create_account_row.addWidget(create_link)
        self.create_account_row.addStretch()

        layout.addLayout(self.create_account_row)

        return page

    def attempt_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            self.login_error.setText("Please enter both username and password.")
            self._shake_widget(self.stack)
            return

        from backend.auth import verify_login, generate_otp, send_otp_email

        ok, result = verify_login(username, password)

        if not ok:
            self.login_error.setText(result)
            self.password_input.clear()
            self._shake_widget(self.stack)
            return

        self.login_error.setText("")
        self._pending_user = result

        code = generate_otp(result["id"], purpose='login')
        sent = send_otp_email(result, code, purpose='login')

        self.otp_target_lbl.setText(
            f"We sent a 6-digit code to {self._mask_email(result['email'])}"
        )
        self.otp_input.clear()

        self.otp_error.setText(
            "" if sent else
            "Could not send the email — check SMTP settings in .env. "
            "Ask an admin for the code shown in the terminal."
        )

        self.stack.setCurrentWidget(self.otp_page)
        self._animate_stack_page()
        self._start_resend_cooldown()

    @staticmethod
    def _mask_email(email):
        if "@" not in email:
            return email

        name, domain = email.split("@", 1)

        if len(name) <= 2:
            masked = name[0] + "*"
        else:
            masked = name[0] + "*" * (len(name) - 2) + name[-1]

        return f"{masked}@{domain}"

    # ─────────────────────────────────────────────
    # Step 2
    # ─────────────────────────────────────────────

    def _build_otp_page(self):
        page = QWidget()
        page.setObjectName("stackPage")
        page.setAttribute(
            Qt.WidgetAttribute.WA_StyledBackground,
            True
        )

        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(11)

        otp_title = QLabel("Verify your login")
        otp_title.setObjectName("otpTitle")
        otp_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(otp_title)

        self.otp_target_lbl = QLabel("")
        self.otp_target_lbl.setObjectName("hintLabel")
        self.otp_target_lbl.setWordWrap(True)
        self.otp_target_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.otp_target_lbl)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("000000")
        self.otp_input.setMaxLength(6)
        self.otp_input.setMinimumHeight(48)
        self.otp_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.otp_input.setStyleSheet(
            self._input_style() +
            f"""
            QLineEdit {{
                font-size: {self.fs + 8}px;
                letter-spacing: 8px;
                font-weight: 900;
            }}
            """
        )
        self.otp_input.returnPressed.connect(self.attempt_otp_verify)
        layout.addWidget(self.otp_input)

        self.otp_error = QLabel("")
        self.otp_error.setObjectName("errorLabel")
        self.otp_error.setWordWrap(True)
        layout.addWidget(self.otp_error)

        verify_btn = QPushButton("Verify & Log In")
        verify_btn.setObjectName("successBtn")
        verify_btn.setMinimumHeight(42)
        verify_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        verify_btn.clicked.connect(self.attempt_otp_verify)
        layout.addWidget(verify_btn)

        bottom_row = QHBoxLayout()

        back_btn = QPushButton("← Back")
        back_btn.setObjectName("linkBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self._back_to_password)
        bottom_row.addWidget(back_btn)

        bottom_row.addStretch()

        self.resend_btn = QPushButton("Resend code")
        self.resend_btn.setObjectName("linkBtn")
        self.resend_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.resend_btn.clicked.connect(self.resend_otp)
        bottom_row.addWidget(self.resend_btn)

        layout.addLayout(bottom_row)

        return page

    def _back_to_password(self):
        self._pending_user = None
        self.password_input.clear()
        self.otp_input.clear()
        self.otp_error.setText("")
        self.stack.setCurrentWidget(self.password_page)
        self._animate_stack_page()

    def attempt_otp_verify(self):
        if not self._pending_user:
            self._back_to_password()
            return

        code = self.otp_input.text().strip()

        if len(code) != 6 or not code.isdigit():
            self.otp_error.setText("Enter the 6-digit code.")
            self._shake_widget(self.stack)
            return

        from backend.auth import verify_otp

        ok, msg = verify_otp(self._pending_user["id"], code, purpose='login')

        if not ok:
            self.otp_error.setText(msg)
            self.otp_input.clear()
            self._shake_widget(self.stack)
            return

        if (
            getattr(self, "remember_checkbox", None)
            and self.remember_checkbox.isChecked()
        ):
            try:
                from backend.auth import create_remember_token
                token = create_remember_token(self._pending_user["id"])
                _save_session_token(token)

            except Exception as e:
                print(f"[!] Could not create remember-me token: {e}")

        if self.on_login_success:
            self.on_login_success(self._pending_user)

    def resend_otp(self):
        if not self._pending_user or self._resend_seconds > 0:
            return

        from backend.auth import generate_otp, send_otp_email

        code = generate_otp(self._pending_user["id"], purpose='login')
        sent = send_otp_email(self._pending_user, code, purpose='login')

        self.otp_error.setText(
            "A new code has been sent." if sent else
            "Could not send the email — check SMTP settings."
        )
        self._start_resend_cooldown()

    def _start_resend_cooldown(self, seconds=30):
        self._resend_seconds = seconds
        self.resend_btn.setEnabled(False)
        self._tick_resend()

    def _tick_resend(self):
        if self._resend_seconds <= 0:
            self.resend_btn.setEnabled(True)
            self.resend_btn.setText("Resend code")
            return

        self.resend_btn.setText(f"Resend code ({self._resend_seconds}s)")
        self._resend_seconds -= 1
        QTimer.singleShot(1000, self._tick_resend)

    # ─────────────────────────────────────────────
    # Animations
    # ─────────────────────────────────────────────

    def _animate_stack_page(self):
        effect = QGraphicsOpacityEffect(self.stack.currentWidget())
        self.stack.currentWidget().setGraphicsEffect(effect)

        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(240)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()

        self._animations.append(anim)

    def _shake_widget(self, widget):
        start_pos = widget.pos()

        anim = QPropertyAnimation(widget, b"pos", self)
        anim.setDuration(260)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.setKeyValueAt(0.0, start_pos)
        anim.setKeyValueAt(0.18, start_pos + QPoint(-8, 0))
        anim.setKeyValueAt(0.36, start_pos + QPoint(8, 0))
        anim.setKeyValueAt(0.54, start_pos + QPoint(-6, 0))
        anim.setKeyValueAt(0.72, start_pos + QPoint(6, 0))
        anim.setKeyValueAt(1.0, start_pos)
        anim.start()

        self._animations.append(anim)

    # ─────────────────────────────────────────────
    # Create account dialog
    # ─────────────────────────────────────────────

    def show_create_account_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Account")
        dialog.setFixedWidth(410)
        dialog.setStyleSheet(self.get_stylesheet())

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(10)

        title = QLabel("Create Account")
        title.setObjectName("dialogTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        desc = QLabel(
            "Register a new AutoRed account."
        )
        desc.setObjectName("hintLabel")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)

        username_in = QLineEdit()
        username_in.setPlaceholderText("Username")
        username_in.setMinimumHeight(44)
        username_in.setStyleSheet(self._input_style())
        layout.addWidget(username_in)

        email_in = QLineEdit()
        email_in.setPlaceholderText("Email for login codes")
        email_in.setMinimumHeight(44)
        email_in.setStyleSheet(self._input_style())
        layout.addWidget(email_in)

        pw_in = QLineEdit()
        pw_in.setPlaceholderText("Password")
        pw_in.setEchoMode(QLineEdit.EchoMode.Password)
        pw_in.setMinimumHeight(44)
        pw_in.setStyleSheet(self._input_style())
        layout.addWidget(pw_in)

        strength_lbl = QLabel(
            "Must be 8+ characters with uppercase, lowercase, "
            "a number, and a special character."
        )
        strength_lbl.setObjectName("hintLabel")
        strength_lbl.setWordWrap(True)
        layout.addWidget(strength_lbl)

        confirm_lbl = QLabel("Confirm Password")
        confirm_lbl.setObjectName("fieldLabel")
        layout.addWidget(confirm_lbl)

        confirm_in = QLineEdit()
        confirm_in.setPlaceholderText("Re-enter your password")
        confirm_in.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_in.setMinimumHeight(44)
        confirm_in.setStyleSheet(self._input_style())
        layout.addWidget(confirm_in)

        match_lbl = QLabel("")
        match_lbl.setObjectName("hintLabel")
        match_lbl.setWordWrap(True)
        layout.addWidget(match_lbl)

        err_lbl = QLabel("")
        err_lbl.setObjectName("errorLabel")
        err_lbl.setWordWrap(True)
        layout.addWidget(err_lbl)

        create_btn = QPushButton("Create Account")
        create_btn.setObjectName("successBtn")
        create_btn.setMinimumHeight(42)
        create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        create_btn.setEnabled(False)
        layout.addWidget(create_btn)

        def _check_password_live():
            from backend.auth import validate_password_strength

            pw = pw_in.text()
            confirm = confirm_in.text()

            if not pw:
                strength_lbl.setText(
                    "Must be 8+ characters with uppercase, lowercase, "
                    "a number, and a special character."
                )
                strength_lbl.setStyleSheet(
                    f"""
                    color: {self.DIM};
                    font-size: {self.fs - 1}px;
                    background: transparent;
                    border: none;
                    """
                )
                pw_ok = False

            else:
                strong, reason = validate_password_strength(pw)

                if strong:
                    strength_lbl.setText("✓ Password meets all requirements")
                    strength_lbl.setStyleSheet(
                        f"""
                        color: {self.SUCCESS};
                        font-size: {self.fs - 1}px;
                        font-weight: 700;
                        background: transparent;
                        border: none;
                        """
                    )

                else:
                    strength_lbl.setText(reason)
                    strength_lbl.setStyleSheet(
                        f"""
                        color: {self.WARNING};
                        font-size: {self.fs - 1}px;
                        background: transparent;
                        border: none;
                        """
                    )

                pw_ok = strong

            if not confirm:
                match_lbl.setText("")
                match_ok = False

            elif confirm == pw:
                match_lbl.setText("✓ Passwords match")
                match_lbl.setStyleSheet(
                    f"""
                    color: {self.SUCCESS};
                    font-size: {self.fs - 1}px;
                    font-weight: 700;
                    background: transparent;
                    border: none;
                    """
                )
                match_ok = True

            else:
                match_lbl.setText("✗ Passwords do not match")
                match_lbl.setStyleSheet(
                    f"""
                    color: {self.ACCENT};
                    font-size: {self.fs - 1}px;
                    font-weight: 700;
                    background: transparent;
                    border: none;
                    """
                )
                match_ok = False

            create_btn.setEnabled(
                pw_ok
                and match_ok
                and bool(username_in.text().strip())
                and bool(email_in.text().strip())
            )

        pw_in.textChanged.connect(_check_password_live)
        confirm_in.textChanged.connect(_check_password_live)
        username_in.textChanged.connect(_check_password_live)
        email_in.textChanged.connect(_check_password_live)

        def do_create():
            from backend.auth import create_user, validate_password_strength

            pw = pw_in.text()
            confirm = confirm_in.text()

            if pw != confirm:
                err_lbl.setText("Passwords do not match.")
                return

            strong, reason = validate_password_strength(pw)

            if not strong:
                err_lbl.setText(reason)
                return

            ok, result = create_user(
                username_in.text(),
                email_in.text(),
                pw
            )

            if not ok:
                err_lbl.setText(result)
                return

            QMessageBox.information(
                dialog,
                "Account Created",
                "Account created successfully. You can now log in."
            )

            dialog.accept()
            self.username_input.setText(username_in.text().strip())
            self.password_input.setFocus()

        create_btn.clicked.connect(do_create)
        dialog.exec()

    # ─────────────────────────────────────────────
    # Forgot password dialog (3 steps)
    # ─────────────────────────────────────────────

    def show_forgot_password_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Reset Password")
        dialog.setFixedWidth(410)
        dialog.setStyleSheet(self.get_stylesheet())

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(10)

        title = QLabel("Reset Your Password")
        title.setObjectName("dialogTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        stack = QStackedWidget()
        layout.addWidget(stack)

        # State shared across the three steps
        state = {"user": None}

        # ── Step 1: username ──────────────────────
        step1 = QWidget()
        s1_layout = QVBoxLayout(step1)
        s1_layout.setContentsMargins(0, 0, 0, 0)
        s1_layout.setSpacing(10)

        s1_desc = QLabel(
            "Enter the email address linked to your account. "
            "We'll send a 6-digit reset code to that address -- "
            "no need to remember your username."
        )
        s1_desc.setObjectName("hintLabel")
        s1_desc.setWordWrap(True)
        s1_layout.addWidget(s1_desc)

        email_in = QLineEdit()
        email_in.setPlaceholderText("Email address")
        email_in.setMinimumHeight(44)
        email_in.setStyleSheet(self._input_style())
        s1_layout.addWidget(email_in)

        s1_err = QLabel("")
        s1_err.setObjectName("errorLabel")
        s1_err.setWordWrap(True)
        s1_layout.addWidget(s1_err)

        send_btn = QPushButton("Send Reset Code")
        send_btn.setObjectName("primaryBtn")
        send_btn.setMinimumHeight(42)
        send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        s1_layout.addWidget(send_btn)

        stack.addWidget(step1)

        # ── Step 2: code entry ────────────────────
        step2 = QWidget()
        s2_layout = QVBoxLayout(step2)
        s2_layout.setContentsMargins(0, 0, 0, 0)
        s2_layout.setSpacing(10)

        s2_target_lbl = QLabel("")
        s2_target_lbl.setObjectName("hintLabel")
        s2_target_lbl.setWordWrap(True)
        s2_layout.addWidget(s2_target_lbl)

        code_in = QLineEdit()
        code_in.setPlaceholderText("000000")
        code_in.setMaxLength(6)
        code_in.setMinimumHeight(48)
        code_in.setAlignment(Qt.AlignmentFlag.AlignCenter)
        code_in.setStyleSheet(
            self._input_style() +
            f"""
            QLineEdit {{
                font-size: {self.fs + 8}px;
                letter-spacing: 8px;
                font-weight: 900;
            }}
            """
        )
        s2_layout.addWidget(code_in)

        s2_err = QLabel("")
        s2_err.setObjectName("errorLabel")
        s2_err.setWordWrap(True)
        s2_layout.addWidget(s2_err)

        verify_code_btn = QPushButton("Verify Code")
        verify_code_btn.setObjectName("primaryBtn")
        verify_code_btn.setMinimumHeight(42)
        verify_code_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        s2_layout.addWidget(verify_code_btn)

        s2_bottom_row = QHBoxLayout()
        s2_back_btn = QPushButton("← Back")
        s2_back_btn.setObjectName("linkBtn")
        s2_back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        s2_bottom_row.addWidget(s2_back_btn)
        s2_bottom_row.addStretch()

        s2_resend_btn = QPushButton("Resend code")
        s2_resend_btn.setObjectName("linkBtn")
        s2_resend_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        s2_bottom_row.addWidget(s2_resend_btn)
        s2_layout.addLayout(s2_bottom_row)

        stack.addWidget(step2)

        # ── Step 3: new password ──────────────────
        step3 = QWidget()
        s3_layout = QVBoxLayout(step3)
        s3_layout.setContentsMargins(0, 0, 0, 0)
        s3_layout.setSpacing(10)

        new_pw_lbl = QLabel("New Password")
        new_pw_lbl.setObjectName("fieldLabel")
        s3_layout.addWidget(new_pw_lbl)

        new_pw_in = QLineEdit()
        new_pw_in.setPlaceholderText("Enter a new password")
        new_pw_in.setEchoMode(QLineEdit.EchoMode.Password)
        new_pw_in.setMinimumHeight(44)
        new_pw_in.setStyleSheet(self._input_style())
        s3_layout.addWidget(new_pw_in)

        new_strength_lbl = QLabel(
            "Must be 8+ characters with uppercase, lowercase, "
            "a number, and a special character."
        )
        new_strength_lbl.setObjectName("hintLabel")
        new_strength_lbl.setWordWrap(True)
        s3_layout.addWidget(new_strength_lbl)

        confirm_pw_lbl = QLabel("Confirm New Password")
        confirm_pw_lbl.setObjectName("fieldLabel")
        s3_layout.addWidget(confirm_pw_lbl)

        confirm_pw_in = QLineEdit()
        confirm_pw_in.setPlaceholderText("Re-enter the new password")
        confirm_pw_in.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_pw_in.setMinimumHeight(44)
        confirm_pw_in.setStyleSheet(self._input_style())
        s3_layout.addWidget(confirm_pw_in)

        new_match_lbl = QLabel("")
        new_match_lbl.setObjectName("hintLabel")
        new_match_lbl.setWordWrap(True)
        s3_layout.addWidget(new_match_lbl)

        s3_err = QLabel("")
        s3_err.setObjectName("errorLabel")
        s3_err.setWordWrap(True)
        s3_layout.addWidget(s3_err)

        reset_btn = QPushButton("Set New Password")
        reset_btn.setObjectName("successBtn")
        reset_btn.setMinimumHeight(42)
        reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reset_btn.setEnabled(False)
        s3_layout.addWidget(reset_btn)

        stack.addWidget(step3)

        # ── Step logic ─────────────────────────────
        def do_send_code():
            from backend.auth import request_password_reset

            email = email_in.text().strip()
            if not email:
                s1_err.setText("Please enter your email address.")
                return

            ok, result = request_password_reset(email)
            if not ok:
                s1_err.setText(result)
                return

            s1_err.setText("")
            state["user"] = result
            s2_target_lbl.setText(
                f"We sent a 6-digit reset code to "
                f"{self._mask_email(result['email'])}"
            )
            code_in.clear()
            s2_err.setText("")
            stack.setCurrentWidget(step2)

        def do_verify_code():
            # We don't actually consume the OTP here -- final
            # consumption happens in reset_password() at step 3,
            # so the code stays valid if the user navigates back
            # and forth between step 2 and step 3 once.
            code = code_in.text().strip()
            if len(code) != 6 or not code.isdigit():
                s2_err.setText("Enter the 6-digit code.")
                return

            state["code"] = code
            s3_err.setText("")
            new_pw_in.clear()
            confirm_pw_in.clear()
            reset_btn.setEnabled(False)
            stack.setCurrentWidget(step3)

        def do_resend():
            if not state.get("user"):
                return
            from backend.auth import generate_otp, send_otp_email
            user = state["user"]
            code = generate_otp(user["id"], purpose='reset')
            sent = send_otp_email(user, code, purpose='reset')
            s2_err.setText(
                "A new code has been sent." if sent else
                "Could not send the email — check SMTP settings."
            )

        def back_to_step1():
            stack.setCurrentWidget(step1)

        def _check_new_password_live():
            from backend.auth import validate_password_strength
            pw = new_pw_in.text()
            confirm = confirm_pw_in.text()

            if not pw:
                new_strength_lbl.setText(
                    "Must be 8+ characters with uppercase, lowercase, "
                    "a number, and a special character."
                )
                new_strength_lbl.setStyleSheet(
                    f"color: {self.DIM}; font-size: {self.fs - 1}px; "
                    f"background: transparent; border: none;"
                )
                pw_ok = False
            else:
                strong, reason = validate_password_strength(pw)
                if strong:
                    new_strength_lbl.setText("✓ Password meets all requirements")
                    new_strength_lbl.setStyleSheet(
                        f"color: {self.SUCCESS}; font-size: {self.fs - 1}px; "
                        f"font-weight: 700; "
                        f"background: transparent; border: none;"
                    )
                else:
                    new_strength_lbl.setText(reason)
                    new_strength_lbl.setStyleSheet(
                        f"color: {self.WARNING}; font-size: {self.fs - 1}px; "
                        f"background: transparent; border: none;"
                    )
                pw_ok = strong

            if not confirm:
                new_match_lbl.setText("")
                match_ok = False
            elif confirm == pw:
                new_match_lbl.setText("✓ Passwords match")
                new_match_lbl.setStyleSheet(
                    f"color: {self.SUCCESS}; font-size: {self.fs - 1}px; "
                    f"font-weight: 700; "
                    f"background: transparent; border: none;"
                )
                match_ok = True
            else:
                new_match_lbl.setText("✗ Passwords do not match")
                new_match_lbl.setStyleSheet(
                    f"color: {self.ACCENT}; font-size: {self.fs - 1}px; "
                    f"font-weight: 700; "
                    f"background: transparent; border: none;"
                )
                match_ok = False

            reset_btn.setEnabled(pw_ok and match_ok)

        def do_reset():
            from backend.auth import reset_password

            user = state.get("user")
            code = state.get("code")
            if not user or not code:
                back_to_step1()
                return

            pw = new_pw_in.text()
            confirm = confirm_pw_in.text()
            if pw != confirm:
                s3_err.setText("Passwords do not match.")
                return

            ok, msg = reset_password(user["id"], code, pw)
            if not ok:
                s3_err.setText(msg)
                # If the code itself was wrong/expired, send the
                # user back to re-enter or request a fresh one.
                if "code" in msg.lower() or "expired" in msg.lower():
                    stack.setCurrentWidget(step2)
                return

            QMessageBox.information(
                dialog,
                "Password Reset",
                "Your password has been reset successfully. "
                "Please log in with your new password."
            )
            dialog.accept()
            self.username_input.setText(user["username"])
            self.password_input.clear()
            self.password_input.setFocus()

        send_btn.clicked.connect(do_send_code)
        verify_code_btn.clicked.connect(do_verify_code)
        s2_back_btn.clicked.connect(back_to_step1)
        s2_resend_btn.clicked.connect(do_resend)
        new_pw_in.textChanged.connect(_check_new_password_live)
        confirm_pw_in.textChanged.connect(_check_new_password_live)
        reset_btn.clicked.connect(do_reset)

        dialog.exec()

    # ─────────────────────────────────────────────
    # Stylesheet
    # ─────────────────────────────────────────────

    def get_stylesheet(self):
        return f"""
            QWidget {{
                background-color: {self.BG};
                color: {self.TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {self.fs}px;
            }}

            #loginBg {{
                background-color: {self.BG};
            }}

            #loginShell {{
                background-color: {self.SHELL_BG};
                border: 1px solid {rgba_from_hex(self.BORDER_SOFT, 42)};
                border-radius: 20px;
            }}

            #brandPanel {{
                background-color: {self.BRAND_BG};
                border-right: 1px solid {rgba_from_hex(self.BORDER_SOFT, 34)};
                border-radius: 20px 0 0 20px;
            }}

            #rightPanel {{
                background-color: {self.RIGHT_BG};
                border-radius: 0 20px 20px 0;
            }}

            #brandMark {{
                background-color: {rgba_from_hex(self.ACCENT, 28)};
                color: {self.RED_TEXT};
                border: 1px solid {rgba_from_hex(self.ACCENT, 105)};
                border-radius: 14px;
                font-size: {self.fs + 5}px;
                font-weight: 900;
                min-width: 48px;
                min-height: 48px;
            }}

            #brandTitle {{
                color: {self.ACCENT};
                font-size: {self.fs + 9}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #brandSubtitle {{
                color: {self.DIM};
                font-size: {self.fs - 3}px;
                background: transparent;
                border: none;
            }}

            #brandHero {{
                color: {self.TEXT};
                font-size: {self.fs + 11}px;
                font-weight: 900;
                background: transparent;
                border: none;
                line-height: 1.25;
            }}

            #brandHeroSub {{
                color: {self.DIM};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
                line-height: 1.42;
            }}

            #brandFooter {{
                color: {self.SOFT};
                font-size: {self.fs - 3}px;
                background: transparent;
                border: none;
            }}

            #featureCard {{
                background-color: {rgba_from_hex(self.CARD2, 140 if self.dark else 210)};
                border: 1px solid {rgba_from_hex(self.BORDER_SOFT, 34)};
                border-radius: 12px;
            }}

            #featureCard:hover {{
                background-color: {rgba_from_hex(self.ACCENT, 15 if self.dark else 18)};
                border: 1px solid {rgba_from_hex(self.ACCENT, 70)};
            }}

            #featureIcon {{
                background-color: {rgba_from_hex(self.ACCENT, 22)};
                color: {self.RED_TEXT};
                border: 1px solid {rgba_from_hex(self.ACCENT, 78)};
                border-radius: 10px;
                font-size: {self.fs + 4}px;
                font-weight: 900;
            }}

            #featureTitle {{
                color: {self.TEXT};
                font-size: {self.fs - 1}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}

            #featureDesc {{
                color: {self.DIM};
                font-size: {self.fs - 3}px;
                background: transparent;
                border: none;
            }}

            #loginCard {{
                background-color: transparent;
                border: none;
            }}

            #loginCardHeader {{
                background-color: transparent;
                border: none;
            }}

            #loginLogo {{
                color: {self.TEXT};
                font-size: {self.fs + 16}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #loginSub {{
                color: {self.DIM};
                font-size: {self.fs - 1}px;
                background: transparent;
                border: none;
            }}

            #loginStack {{
                background-color: {self.FORM_BG};
                border: none;
            }}

            QStackedWidget#loginStack {{
                background-color: {self.FORM_BG};
                border: none;
            }}

            QStackedWidget#loginStack > QWidget {{
                background-color: {self.FORM_BG};
                border: none;
            }}

            #stackPage {{
                background-color: {self.FORM_BG};
                border: none;
            }}

            #fieldLabel {{
                color: {self.DIM};
                font-size: {self.fs - 2}px;
                font-weight: 800;
                background-color: {self.FORM_BG};
                border: none;
                padding-left: 2px;
                margin-bottom: 2px;
                min-height: 18px;
            }}

            #otpTitle {{
                color: {self.ACCENT};
                font-size: {self.fs + 6}px;
                font-weight: 900;
                background-color: {self.FORM_BG};
                border: none;
            }}

            #dialogTitle {{
                color: {self.ACCENT};
                font-size: {self.fs + 6}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}

            #hintLabel {{
                color: {self.DIM};
                font-size: {self.fs - 1}px;
                background-color: {self.FORM_BG};
                border: none;
            }}

            #errorLabel {{
                color: {self.ERROR};
                font-size: {self.fs - 1}px;
                background-color: {self.FORM_BG};
                border: none;
                min-height: 18px;
            }}

            #primaryBtn {{
                background-color: {self.ACCENT};
                color: white;
                border: none;
                border-radius: 9px;
                padding: 12px;
                font-size: {self.fs}px;
                font-weight: 900;
            }}

            #primaryBtn:hover {{
                background-color: {self.ACCENT_HOVER};
            }}

            #primaryBtn:pressed {{
                background-color: {self.ACCENT_DARK};
            }}

            #successBtn {{
                background-color: {self.SUCCESS};
                color: white;
                border: none;
                border-radius: 9px;
                padding: 12px;
                font-size: {self.fs}px;
                font-weight: 900;
            }}

            #successBtn:hover {{
                background-color: {self.SUCCESS_HOVER};
            }}

            #successBtn:disabled {{
                background-color: {self.BORDER_SOFT};
                color: {self.SOFT};
            }}

            #linkBtn {{
                background: transparent;
                color: {self.ACCENT};
                border: none;
                font-size: {self.fs - 1}px;
                font-weight: 900;
                padding: 4px;
            }}

            #linkBtn:hover {{
                color: {self.ACCENT_HOVER};
                text-decoration: underline;
            }}

            #linkBtn:disabled {{
                color: {self.SOFT};
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

            QDialog {{
                background-color: {self.CARD};
                color: {self.TEXT};
                border: 1px solid {self.BORDER};
            }}
        """
