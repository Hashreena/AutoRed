import json
import os

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QSlider, QFrame, QButtonGroup
)
from PyQt6.QtCore import Qt, pyqtSignal


PREFS_FILE = os.path.expanduser(
    "~/.autored_prefs.json"
)


# ─────────────────────────────────────────────
# AutoRed Theme System
# Dark: Blackish Blue + AutoRed Red
# Light: Clean White + AutoRed Red
# ─────────────────────────────────────────────

DARK_THEME = {
    "bg": "#020617",
    "bg_deep": "#01030A",
    "sidebar_bg": "#07111F",

    "card_bg": "#0F172A",
    "card_bg_2": "#111827",

    "border": "#22304A",
    "border_soft": "#334155",

    "text": "#E5EDF7",
    "text_muted": "#94A3B8",
    "text_soft": "#64748B",

    "accent": "#EF4444",
    "accent_hover": "#DC2626",
    "accent_dark": "#991B1B",

    "brand_red": "#EF4444",
    "brand_red_hover": "#DC2626",

    "success": "#22C55E",
    "success_hover": "#16A34A",

    "warning": "#F97316",
    "warning_hover": "#EA580C",

    "medium": "#FACC15",
    "info": "#60A5FA",

    "purple": "#8B5CF6",
    "purple_hover": "#7C3AED",

    "hover": "rgba(239, 68, 68, 25)",
    "selection_bg": "rgba(239, 68, 68, 35)",
    "selection_text": "#FEE2E2",

    "button_soft": "rgba(15, 23, 42, 185)",
    "card_hover": "rgba(239, 68, 68, 85)",
}

LIGHT_THEME = {
    "bg": "#F8FAFC",
    "bg_deep": "#EEF2F7",
    "sidebar_bg": "#FFFFFF",

    "card_bg": "#FFFFFF",
    "card_bg_2": "#F1F5F9",

    "border": "#CBD5E1",
    "border_soft": "#94A3B8",

    "text": "#0F172A",
    "text_muted": "#475569",
    "text_soft": "#64748B",

    "accent": "#EF4444",
    "accent_hover": "#DC2626",
    "accent_dark": "#991B1B",

    "brand_red": "#EF4444",
    "brand_red_hover": "#DC2626",

    "success": "#16A34A",
    "success_hover": "#15803D",

    "warning": "#EA580C",
    "warning_hover": "#C2410C",

    "medium": "#CA8A04",
    "info": "#2563EB",

    "purple": "#7C3AED",
    "purple_hover": "#6D28D9",

    "hover": "rgba(239, 68, 68, 18)",
    "selection_bg": "rgba(239, 68, 68, 28)",
    "selection_text": "#7F1D1D",

    "button_soft": "#FFFFFF",
    "card_hover": "rgba(239, 68, 68, 55)",
}


DEFAULT_PREFS = {
    "dark_mode": True,
    "font_size": 13,
}


def rgba_from_hex(hex_color, alpha):
    color = str(hex_color).strip().lstrip("#")

    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"

    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)

    return f"rgba({red}, {green}, {blue}, {alpha})"


def load_prefs():
    prefs = DEFAULT_PREFS.copy()

    try:
        if os.path.exists(PREFS_FILE):
            with open(PREFS_FILE, "r") as file:
                saved = json.load(file)

            prefs["dark_mode"] = bool(
                saved.get("dark_mode", prefs["dark_mode"])
            )

            try:
                prefs["font_size"] = int(
                    saved.get("font_size", prefs["font_size"])
                )
            except Exception:
                prefs["font_size"] = DEFAULT_PREFS["font_size"]

            prefs["font_size"] = max(
                10,
                min(16, prefs["font_size"])
            )

    except Exception:
        pass

    return prefs


def save_prefs(prefs):
    safe_prefs = {
        "dark_mode": bool(
            prefs.get("dark_mode", DEFAULT_PREFS["dark_mode"])
        ),
        "font_size": max(
            10,
            min(
                16,
                int(prefs.get("font_size", DEFAULT_PREFS["font_size"]))
            )
        ),
    }

    try:
        with open(PREFS_FILE, "w") as file:
            json.dump(safe_prefs, file, indent=2)

    except Exception as e:
        print(f"[!] Could not save prefs: {e}")


def get_theme(dark_mode=True):
    base = DARK_THEME if dark_mode else LIGHT_THEME

    theme = base.copy()

    fallback = DARK_THEME if dark_mode else LIGHT_THEME

    for key, value in fallback.items():
        theme.setdefault(key, value)

    theme.setdefault("medium", "#FACC15" if dark_mode else "#CA8A04")
    theme.setdefault("warning_hover", "#EA580C" if dark_mode else "#C2410C")
    theme.setdefault("purple_hover", "#7C3AED" if dark_mode else "#6D28D9")
    theme.setdefault("brand_red", theme["accent"])
    theme.setdefault("brand_red_hover", theme["accent_hover"])
    theme.setdefault("success_hover", theme["success"])
    theme.setdefault("button_soft", theme["card_bg"])
    theme.setdefault(
        "card_hover",
        rgba_from_hex(theme["accent"], 85 if dark_mode else 55)
    )

    return theme


def build_stylesheet(dark_mode=True, font_size=13):
    t = get_theme(dark_mode)
    fs = font_size

    success_hover_bg = rgba_from_hex(
        t["success"],
        35 if dark_mode else 22
    )

    info_hover_bg = rgba_from_hex(
        t["info"],
        30 if dark_mode else 22
    )

    purple_bg = rgba_from_hex(
        t["purple"],
        90 if dark_mode else 24
    )

    purple_hover_bg = rgba_from_hex(
        t["purple_hover"],
        140 if dark_mode else 38
    )

    red_bg = rgba_from_hex(
        t["accent"],
        95 if dark_mode else 24
    )

    red_hover_bg = rgba_from_hex(
        t["accent_hover"],
        145 if dark_mode else 38
    )

    red_border = rgba_from_hex(
        t["accent"],
        150 if dark_mode else 110
    )

    red_text = "#FEE2E2" if dark_mode else "#7F1D1D"

    return f"""
        QMainWindow {{
            background-color: {t["bg"]};
        }}

        QWidget {{
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: {fs}px;
            color: {t["text"]};
        }}

        #contentArea {{
            background-color: {t["bg"]};
        }}

        QScrollBar:vertical {{
            background: {t["bg"]};
            width: 10px;
            margin: 0;
        }}

        QScrollBar::handle:vertical {{
            background: {t["border_soft"]};
            border-radius: 5px;
            min-height: 28px;
        }}

        QScrollBar::handle:vertical:hover {{
            background: {t["accent"]};
        }}

        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {{
            height: 0px;
        }}

        QScrollBar:horizontal {{
            background: {t["bg"]};
            height: 10px;
            margin: 0;
        }}

        QScrollBar::handle:horizontal {{
            background: {t["border_soft"]};
            border-radius: 5px;
            min-width: 28px;
        }}

        QScrollBar::handle:horizontal:hover {{
            background: {t["accent"]};
        }}

        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}

        /* ───────────────── Sidebar ───────────────── */

        #sidebar {{
            background-color: {t["sidebar_bg"]};
            border-right: none;
        }}

        #sidebarTitle {{
            color: {t["accent"]};
            font-size: {fs + 9}px;
            font-weight: 900;
            padding: 10px;
            background: {t["sidebar_bg"]};
            border: none;
        }}

        #sidebarSubtitle {{
            color: {t["text_muted"]};
            font-size: {fs - 2}px;
            padding-bottom: 10px;
            background: {t["sidebar_bg"]};
            border: none;
        }}

        #divider {{
            background-color: transparent;
            border: none;
            min-height: 12px;
            max-height: 12px;
        }}

        #sidebarBtn {{
            background-color: transparent;
            color: {t["text"]};
            border: none;
            border-left: 3px solid transparent;
            padding: 12px 20px;
            text-align: left;
            font-size: {fs}px;
            font-weight: 700;
        }}

        #sidebarBtn:hover {{
            background-color: {t["hover"]};
            color: {t["accent"]};
            border-left: 3px solid {t["accent"]};
        }}

        #authSideBtn {{
            background-color: {rgba_from_hex(t["success"], 16 if dark_mode else 18)};
            color: {t["success"]};
            border: none;
            border-left: 3px solid {t["success"]};
            padding: 12px 20px;
            text-align: left;
            font-size: {fs}px;
            font-weight: 900;
        }}

        #authSideBtn:hover {{
            background-color: {success_hover_bg};
            color: {t["success"]};
        }}

        #prefsSideBtn {{
            background-color: transparent;
            color: {t["text_muted"]};
            border: none;
            border-left: 3px solid transparent;
            padding: 12px 20px;
            text-align: left;
            font-size: {fs}px;
            font-weight: 700;
        }}

        #prefsSideBtn:hover {{
            background-color: {t["hover"]};
            color: {t["text"]};
            border-left: 3px solid {t["accent"]};
        }}

        #chatSideBtn {{
            background-color: {red_bg};
            color: {red_text};
            border: none;
            border-top: 1px solid {red_border};
            padding: 14px 20px;
            text-align: left;
            font-size: {fs}px;
            font-weight: 900;
        }}

        #chatSideBtn:hover {{
            background-color: {red_hover_bg};
            color: {red_text};
        }}

        /* ───────────────── Shared cards / titles ───────────────── */

        #dashTitle,
        #pageTitle,
        #wizardTitle,
        #auditTitle,
        #scanTitle {{
            color: {t["accent"]};
            font-size: {fs + 7}px;
            font-weight: 900;
            background: transparent;
            border: none;
        }}

        #dashSub,
        #pageSub,
        #wizardSub,
        #auditSub,
        #scanSub {{
            color: {t["text_muted"]};
            font-size: {fs - 1}px;
            background: transparent;
            border: none;
        }}

        #summaryCard,
        #statsCard,
        #statCard {{
            background-color: {t["card_bg"]};
            border: 1px solid {t["border"]};
            border-radius: 10px;
            min-width: 85px;
            max-width: 140px;
        }}

        #summaryCard:hover,
        #statsCard:hover,
        #statCard:hover {{
            background-color: {t["card_bg_2"]};
            border: 1px solid {t["card_hover"]};
        }}

        #filterLbl {{
            color: {t["text_muted"]};
            font-size: {fs - 1}px;
            background: transparent;
            border: none;
        }}

        #hintLbl {{
            color: {t["text_muted"]};
            font-size: {fs - 2}px;
            margin-top: 4px;
            background: transparent;
            border: none;
        }}

        /* ───────────────── Tables ───────────────── */

        QTableWidget {{
            background-color: {t["card_bg"]};
            alternate-background-color: {t["card_bg_2"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            gridline-color: {t["border"]};
            border-radius: 10px;
            selection-background-color: {t["selection_bg"]};
            selection-color: {t["selection_text"]};
        }}

        #findingsTable,
        #scansTable {{
            background-color: {t["card_bg"]};
            alternate-background-color: {t["card_bg_2"]};
            border: 1px solid {t["border"]};
            gridline-color: {t["border"]};
            border-radius: 10px;
            color: {t["text"]};
            selection-background-color: {t["selection_bg"]};
            selection-color: {t["selection_text"]};
        }}

        QHeaderView::section {{
            background-color: {t["bg_deep"]};
            color: {t["text_muted"]};
            padding: 9px;
            border: none;
            border-bottom: 1px solid {t["border"]};
            font-weight: 900;
            font-size: {fs - 2}px;
        }}

        QTableWidget::item {{
            padding: 6px 8px;
            background-color: transparent;
            color: {t["text"]};
            border: none;
        }}

        QTableWidget::item:selected {{
            background-color: {t["selection_bg"]};
            color: {t["selection_text"]};
        }}

        /* ───────────────── Inputs ───────────────── */

        QLineEdit,
        QTextEdit,
        QComboBox {{
            background-color: {t["card_bg"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            padding: 9px 12px;
            selection-background-color: {t["accent"]};
            selection-color: white;
        }}

        QLineEdit:focus,
        QTextEdit:focus,
        QComboBox:focus {{
            border-color: {t["accent"]};
            background-color: {t["card_bg_2"]};
        }}

        QComboBox::drop-down {{
            border: none;
            width: 28px;
        }}

        QComboBox::down-arrow {{
            image: none;
            border: none;
        }}

        QComboBox QAbstractItemView {{
            background-color: {t["card_bg"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            selection-background-color: {t["selection_bg"]};
            selection-color: {t["selection_text"]};
            outline: none;
        }}

        /* ───────────────── Shared buttons ───────────────── */

        #backBtn {{
            background-color: {t["button_soft"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            padding: 8px 16px;
            font-size: {fs - 1}px;
            font-weight: 800;
        }}

        #backBtn:hover {{
            color: {t["accent"]};
            border-color: {t["accent"]};
            background-color: {t["hover"]};
        }}

        #primaryBtn {{
            background-color: {t["accent"]};
            color: white;
            border: none;
            border-radius: 8px;
            padding: 9px 18px;
            font-size: {fs - 1}px;
            font-weight: 900;
        }}

        #primaryBtn:hover {{
            background-color: {t["accent_hover"]};
        }}

        #primaryBtn:pressed {{
            background-color: {t["accent_dark"]};
        }}

        #filterBtn,
        #auditBtn,
        #actionBtn {{
            background-color: {t["button_soft"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            padding: 7px 14px;
            font-size: {fs - 1}px;
            font-weight: 800;
        }}

        #filterBtn:hover,
        #auditBtn:hover,
        #actionBtn:hover {{
            border-color: {t["accent"]};
            color: {t["accent"]};
            background-color: {t["hover"]};
        }}

        #visualizeBtn {{
            background-color: {purple_bg};
            color: {t["purple"]};
            border: 1px solid {t["purple"]};
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 900;
        }}

        #visualizeBtn:hover {{
            background-color: {purple_hover_bg};
        }}

        #visualizeBtn::menu-indicator {{
            image: none;
        }}

        #exportDropBtn {{
            background-color: {red_bg};
            color: {red_text};
            border: 1px solid {red_border};
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 900;
        }}

        #exportDropBtn:hover {{
            background-color: {red_hover_bg};
        }}

        #exportDropBtn::menu-indicator {{
            image: none;
        }}

        #aiSummaryBtn {{
            background-color: {red_bg};
            color: {red_text};
            border: 1px solid {red_border};
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 900;
        }}

        #aiSummaryBtn:hover {{
            background-color: {red_hover_bg};
        }}

        #nvdBtn {{
            background-color: {t["button_soft"]};
            color: {t["info"]};
            border: 1px solid {rgba_from_hex(t["info"], 90)};
            border-radius: 8px;
            padding: 6px 14px;
            font-size: {fs - 2}px;
            margin-top: 4px;
            font-weight: 800;
        }}

        #nvdBtn:hover {{
            background-color: {info_hover_bg};
            border-color: {t["info"]};
            color: {t["info"]};
        }}

        /* ───────────────── Text panels ───────────────── */

        #sectionText {{
            background-color: {t["card_bg"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            padding: 9px;
            font-size: {fs - 1}px;
        }}

        /* ───────────────── Menus / dialogs ───────────────── */

        QMenu {{
            background-color: {t["card_bg"]};
            color: {t["text"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            padding: 6px;
        }}

        QMenu::item {{
            padding: 8px 24px;
            border-radius: 6px;
        }}

        QMenu::item:selected {{
            background-color: {t["selection_bg"]};
            color: {t["selection_text"]};
        }}

        QMessageBox {{
            background-color: {t["bg"]};
            color: {t["text"]};
        }}

        QMessageBox QLabel {{
            color: {t["text"]};
            background: transparent;
            border: none;
        }}

        QMessageBox QPushButton {{
            background-color: {t["accent"]};
            color: white;
            border: none;
            border-radius: 7px;
            padding: 7px 18px;
            font-weight: 800;
        }}

        QMessageBox QPushButton:hover {{
            background-color: {t["accent_hover"]};
        }}
    """


class PreferencesDialog(QDialog):
    prefs_changed = pyqtSignal(dict)

    def __init__(
        self,
        parent=None,
        current_prefs=None,
    ):
        super().__init__(parent)

        self.prefs = (
            current_prefs.copy()
            if current_prefs
            else load_prefs()
        )

        self.setWindowTitle("Preferences")
        self.setMinimumSize(520, 430)
        self.setModal(True)

        self._apply_dialog_style()
        self.init_ui()

    def _theme(self):
        return get_theme(
            self.prefs.get("dark_mode", True)
        )

    def _apply_dialog_style(self):
        t = self._theme()
        fs = self.prefs.get("font_size", 13)

        self.setStyleSheet(
            f"""
            QDialog {{
                background-color: {t["bg"]};
                color: {t["text"]};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}

            QLabel {{
                background: transparent;
                border: none;
                color: {t["text"]};
            }}

            QFrame {{
                background: transparent;
                border: none;
            }}

            #prefTitle {{
                color: {t["accent"]};
                font-size: {fs + 5}px;
                font-weight: 900;
            }}

            #prefSub {{
                color: {t["text_muted"]};
                font-size: {fs - 1}px;
            }}

            #prefCard {{
                background-color: {t["card_bg"]};
                border: 1px solid {t["border"]};
                border-radius: 12px;
            }}

            #prefCard:hover {{
                border: 1px solid {t["card_hover"]};
            }}

            #settingLabel {{
                color: {t["text"]};
                font-size: {fs}px;
                font-weight: 900;
            }}

            #settingSub {{
                color: {t["text_muted"]};
                font-size: {fs - 2}px;
            }}

            QPushButton {{
                border-radius: 8px;
                padding: 8px 18px;
                font-size: {fs - 1}px;
                font-weight: 900;
            }}

            #cancelBtn {{
                background-color: {t["button_soft"]};
                color: {t["text_muted"]};
                border: 1px solid {t["border"]};
            }}

            #cancelBtn:hover {{
                color: {t["accent"]};
                border-color: {t["accent"]};
                background-color: {t["hover"]};
            }}

            #applyBtn {{
                background-color: {t["accent"]};
                color: white;
                border: none;
            }}

            #applyBtn:hover {{
                background-color: {t["accent_hover"]};
            }}

            #applyBtn:pressed {{
                background-color: {t["accent_dark"]};
            }}

            QSlider::groove:horizontal {{
                height: 5px;
                background: {t["border"]};
                border-radius: 3px;
            }}

            QSlider::handle:horizontal {{
                background: {t["accent"]};
                width: 18px;
                height: 18px;
                margin: -7px 0;
                border-radius: 9px;
            }}

            QSlider::handle:horizontal:hover {{
                background: {t["accent_hover"]};
            }}

            QSlider::sub-page:horizontal {{
                background: {t["accent"]};
                border-radius: 3px;
            }}
            """
        )

    def init_ui(self):
        fs = self.prefs.get("font_size", 13)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title = QLabel("⚙️  Preferences")
        title.setObjectName("prefTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Adjust the AutoRed interface theme and font size."
        )
        subtitle.setObjectName("prefSub")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(
            f"""
            background: {self._theme()["border"]};
            max-height: 1px;
            border: none;
            """
        )
        layout.addWidget(divider)

        theme_card = QFrame()
        theme_card.setObjectName("prefCard")

        theme_layout = QVBoxLayout(theme_card)
        theme_layout.setContentsMargins(16, 14, 16, 14)
        theme_layout.setSpacing(10)

        theme_title = QLabel("Theme")
        theme_title.setObjectName("settingLabel")
        theme_layout.addWidget(theme_title)

        self.theme_desc = QLabel(
            "Choose between the professional dark SIEM theme or a cleaner light theme."
        )
        self.theme_desc.setObjectName("settingSub")
        self.theme_desc.setWordWrap(True)
        theme_layout.addWidget(self.theme_desc)

        theme_btn_row = QHBoxLayout()
        theme_btn_row.setSpacing(10)

        self.dark_theme_btn = QPushButton(
            "🌙  Dark Theme\nBlackish Blue + AutoRed Red"
        )
        self.dark_theme_btn.setCheckable(True)
        self.dark_theme_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.dark_theme_btn.clicked.connect(
            lambda: self._select_theme(True)
        )

        self.light_theme_btn = QPushButton(
            "☀️  Light Theme\nClean White + AutoRed Red"
        )
        self.light_theme_btn.setCheckable(True)
        self.light_theme_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.light_theme_btn.clicked.connect(
            lambda: self._select_theme(False)
        )

        self.theme_group = QButtonGroup(self)
        self.theme_group.setExclusive(True)
        self.theme_group.addButton(self.dark_theme_btn)
        self.theme_group.addButton(self.light_theme_btn)

        theme_btn_row.addWidget(self.dark_theme_btn)
        theme_btn_row.addWidget(self.light_theme_btn)

        theme_layout.addLayout(theme_btn_row)
        layout.addWidget(theme_card)

        font_card = QFrame()
        font_card.setObjectName("prefCard")

        font_layout = QVBoxLayout(font_card)
        font_layout.setContentsMargins(16, 14, 16, 14)
        font_layout.setSpacing(10)

        font_lbl = QLabel("Font Size")
        font_lbl.setObjectName("settingLabel")
        font_layout.addWidget(font_lbl)

        slider_row = QHBoxLayout()

        self.small_lbl = QLabel("Small")
        self.small_lbl.setStyleSheet(
            self._small_large_label_style()
        )
        slider_row.addWidget(self.small_lbl)

        self.font_slider = QSlider(Qt.Orientation.Horizontal)
        self.font_slider.setMinimum(10)
        self.font_slider.setMaximum(16)
        self.font_slider.setValue(fs)
        self.font_slider.setTickInterval(1)
        self.font_slider.setFixedHeight(30)
        slider_row.addWidget(self.font_slider)

        self.large_lbl = QLabel("Large")
        self.large_lbl.setStyleSheet(
            self._small_large_label_style()
        )
        slider_row.addWidget(self.large_lbl)

        font_layout.addLayout(slider_row)

        self.font_size_lbl = QLabel(
            f"Current size: {fs}px"
        )
        self.font_size_lbl.setObjectName("settingSub")
        font_layout.addWidget(self.font_size_lbl)

        self.font_slider.valueChanged.connect(
            self._on_font_changed
        )

        layout.addWidget(font_card)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("cancelBtn")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        btn_row.addSpacing(8)

        apply_btn = QPushButton("Apply")
        apply_btn.setObjectName("applyBtn")
        apply_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        apply_btn.clicked.connect(self._apply)
        btn_row.addWidget(apply_btn)

        layout.addLayout(btn_row)

        self._refresh_theme_buttons()

    def _small_large_label_style(self):
        t = self._theme()
        fs = self.prefs.get("font_size", 13)

        return f"""
            color: {t["text_muted"]};
            font-size: {fs - 2}px;
            background: transparent;
            border: none;
        """

    def _theme_button_style(self, active=False):
        t = self._theme()

        if active:
            return f"""
                QPushButton {{
                    background-color: {t["hover"]};
                    color: {t["accent"]};
                    border: 2px solid {t["accent"]};
                    border-radius: 10px;
                    padding: 12px;
                    text-align: left;
                    font-weight: 900;
                }}
            """

        return f"""
            QPushButton {{
                background-color: {t["card_bg_2"]};
                color: {t["text_muted"]};
                border: 1px solid {t["border"]};
                border-radius: 10px;
                padding: 12px;
                text-align: left;
                font-weight: 800;
            }}

            QPushButton:hover {{
                color: {t["accent"]};
                border-color: {t["accent"]};
                background-color: {t["hover"]};
            }}
        """

    def _refresh_theme_buttons(self):
        dark_mode = self.prefs.get("dark_mode", True)

        self.dark_theme_btn.setChecked(dark_mode)
        self.light_theme_btn.setChecked(not dark_mode)

        self.dark_theme_btn.setStyleSheet(
            self._theme_button_style(active=dark_mode)
        )
        self.light_theme_btn.setStyleSheet(
            self._theme_button_style(active=not dark_mode)
        )

        if hasattr(self, "small_lbl"):
            self.small_lbl.setStyleSheet(
                self._small_large_label_style()
            )

        if hasattr(self, "large_lbl"):
            self.large_lbl.setStyleSheet(
                self._small_large_label_style()
            )

    def _select_theme(self, dark_mode):
        self.prefs["dark_mode"] = dark_mode
        self._apply_dialog_style()
        self._refresh_theme_buttons()

    def _on_font_changed(self, value):
        self.prefs["font_size"] = value
        self.font_size_lbl.setText(
            f"Current size: {value}px"
        )

        self._apply_dialog_style()
        self._refresh_theme_buttons()

    def _apply(self):
        self.prefs["dark_mode"] = bool(
            self.prefs.get("dark_mode", True)
        )
        self.prefs["font_size"] = self.font_slider.value()

        save_prefs(self.prefs)

        self.prefs_changed.emit(self.prefs.copy())
        self.accept()
