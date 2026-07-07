from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView,
    QDialog, QLineEdit, QMessageBox, QStackedWidget,
    QGridLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette
from backend.db import (
    get_connection,
    get_folders,
    insert_folder,
    delete_folder,
)
from gui.preferences import load_prefs, get_theme
def rgba_from_hex(hex_color, alpha):
    color = hex_color.strip().lstrip("#")
    if len(color) != 6:
        return f"rgba(239, 68, 68, {alpha})"
    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)
    return f"rgba({red}, {green}, {blue}, {alpha})"
class CreateFolderDialog(QDialog):
    def __init__(self, parent=None, theme=None, font_size=13):
        super().__init__(parent)
        self.t = theme or get_theme(True)
        self.fs = font_size
        self.folder_name = ""
        self.folder_desc = ""
        self.setWindowTitle("Create New Folder")
        self.setFixedSize(400, 250)
        self.setWindowModality(
            Qt.WindowModality.ApplicationModal
        )
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowCloseButtonHint
        )
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()

    def apply_clear_placeholder(self, line_edit):
        """Make placeholder readable and vertically centred inside the input box."""
        palette = line_edit.palette()
        palette.setColor(
            QPalette.ColorRole.PlaceholderText,
            QColor(self.t["text"])
        )
        line_edit.setPalette(palette)
        # Prevent placeholder text from being clipped by the input padding.
        # This does not change the font size, field width, or theme colours.
        line_edit.setTextMargins(0, 0, 0, 0)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(10)
        title = QLabel("Create New Folder")
        title.setObjectName("dialogTitle")
        layout.addWidget(title)
        sub = QLabel(
            "Organise your scans by client, project, or engagement."
        )
        sub.setObjectName("dialogSub")
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(6)
        name_lbl = QLabel("Folder Name")
        name_lbl.setObjectName("fieldLabel")
        layout.addWidget(name_lbl)
        self.name_input = QLineEdit()
        self.name_input.setObjectName("dialogInput")
        self.name_input.setPlaceholderText(
            "e.g. Client A — VAPT"
        )
        self.apply_clear_placeholder(self.name_input)
        layout.addWidget(self.name_input)
        desc_lbl = QLabel("Description (optional)")
        desc_lbl.setObjectName("fieldSub")
        layout.addWidget(desc_lbl)
        self.desc_input = QLineEdit()
        self.desc_input.setObjectName("dialogInput")
        self.desc_input.setPlaceholderText(
            "e.g. External VAPT for Client A"
        )
        self.apply_clear_placeholder(self.desc_input)
        layout.addWidget(self.desc_input)
        layout.addStretch()
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondaryBtn")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        create_btn = QPushButton("Create Folder")
        create_btn.setObjectName("primaryBtn")
        create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        create_btn.clicked.connect(self.do_create)
        btn_row.addWidget(create_btn)
        layout.addLayout(btn_row)
    def do_create(self):
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(
                self,
                "Missing Name",
                "Please enter a folder name."
            )
            return
        self.folder_name = name
        self.folder_desc = self.desc_input.text().strip()
        self.accept()
    def get_stylesheet(self):
        fs = self.fs
        t = self.t
        return f"""
            QDialog {{
                background-color: {t["bg"]};
                color: {t["text"]};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}
            QLabel {{
                background: transparent;
                border: none;
            }}
            #dialogTitle {{
                color: {t["accent"]};
                font-size: {fs + 4}px;
                font-weight: 900;
            }}
            #dialogSub {{
                color: {t["text_muted"]};
                font-size: {fs - 2}px;
            }}
            #fieldLabel {{
                color: {t["text"]};
                font-size: {fs - 1}px;
                font-weight: 800;
            }}
            #fieldSub {{
                color: {t["text_muted"]};
                font-size: {fs - 2}px;
            }}
            #dialogInput {{
                background-color: {t["card_bg"]};
                color: {t["text"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 4px 12px;
                font-size: {fs - 1}px;
                selection-background-color: {t["accent"]};
                selection-color: white;
                placeholder-text-color: {t["text"]};
            }}
            #dialogInput:focus {{
                border-color: {t["accent"]};
                background-color: {t["card_bg_2"]};
            }}
            #dialogInput::placeholder {{
                color: {t["text"]};
            }}
            #secondaryBtn {{
                background-color: {t.get("button_soft", t["card_bg"])};
                color: {t["text_muted"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 8px 18px;
                font-size: {fs - 1}px;
                font-weight: 700;
            }}
            #secondaryBtn:hover {{
                border-color: {t["accent"]};
                color: {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 22))};
            }}
            #primaryBtn {{
                background-color: {t["accent"]};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 18px;
                font-size: {fs - 1}px;
                font-weight: 900;
            }}
            #primaryBtn:hover {{
                background-color: {t["accent_hover"]};
            }}
            #primaryBtn:pressed {{
                background-color: {t["accent_dark"]};
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
                padding: 7px 16px;
                font-weight: 800;
            }}
            QMessageBox QPushButton:hover {{
                background-color: {t["accent_hover"]};
            }}
        """
class CompareScanDialog(QDialog):
    """Dialog to pick two scans to compare, with live search."""
    def __init__(
        self,
        scans,
        parent=None,
        theme=None,
        font_size=13,
    ):
        super().__init__(parent)
        self.scans = scans
        self.visible_scans = list(scans)
        self.scan_a_id = None
        self.scan_b_id = None
        self.selected_a = None
        self.selected_b = None
        self.t = theme or get_theme(True)
        self.fs = font_size
        self.setWindowTitle("Compare Two Scans")
        self.setMinimumSize(680, 560)
        self.setWindowModality(
            Qt.WindowModality.ApplicationModal
        )
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
    def _slot_idle_style(self):
        return f"""
            QLabel {{
                background-color: {self.t["card_bg"]};
                color: {self.t["text_muted"]};
                border: 1px solid {self.t["border"]};
                border-radius: 8px;
                padding: 9px 12px;
                font-size: {self.fs - 1}px;
            }}
        """
    def _slot_a_style(self):
        return f"""
            QLabel {{
                background-color: {rgba_from_hex(self.t["accent"], 22)};
                color: {self.t["accent"]};
                border: 1px solid {self.t["accent"]};
                border-radius: 8px;
                padding: 9px 12px;
                font-size: {self.fs - 1}px;
                font-weight: 900;
            }}
        """
    def _slot_b_style(self):
        return f"""
            QLabel {{
                background-color: {rgba_from_hex(self.t["success"], 20)};
                color: {self.t["success"]};
                border: 1px solid {self.t["success"]};
                border-radius: 8px;
                padding: 9px 12px;
                font-size: {self.fs - 1}px;
                font-weight: 900;
            }}
        """
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)
        title = QLabel("Compare Two Scans")
        title.setObjectName("dialogTitle")
        layout.addWidget(title)
        sub = QLabel(
            "Select Scan A as the baseline and Scan B as the newer scan to generate a diff report."
        )
        sub.setObjectName("dialogSub")
        sub.setWordWrap(True)
        layout.addWidget(sub)
        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        search_icon = QLabel("🔍")
        search_icon.setObjectName("searchIcon")
        search_row.addWidget(search_icon)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText(
            "Search by scan name, target, or date"
        )
        self.search_input.textChanged.connect(
            self.on_search_changed
        )
        search_row.addWidget(self.search_input, 1)
        clear_btn = QPushButton("✕")
        clear_btn.setObjectName("clearBtn")
        clear_btn.setFixedWidth(36)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(
            lambda: self.search_input.clear()
        )
        search_row.addWidget(clear_btn)
        layout.addLayout(search_row)
        sel_row = QHBoxLayout()
        sel_row.setSpacing(14)
        self.scan_a_lbl = QLabel("Scan A: Not selected")
        self.scan_a_lbl.setStyleSheet(self._slot_idle_style())
        sel_row.addWidget(self.scan_a_lbl, 1)
        arrow = QLabel("→")
        arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow.setStyleSheet(
            f"""
            color: {self.t["accent"]};
            font-size: {self.fs + 6}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )
        sel_row.addWidget(arrow)
        self.scan_b_lbl = QLabel("Scan B: Not selected")
        self.scan_b_lbl.setStyleSheet(self._slot_idle_style())
        sel_row.addWidget(self.scan_b_lbl, 1)
        layout.addLayout(sel_row)
        hint_row = QHBoxLayout()
        hint = QLabel(
            "Click a row to set Scan A, then click another row to set Scan B."
        )
        hint.setObjectName("hintLbl")
        hint_row.addWidget(hint)
        hint_row.addStretch()
        self.result_count_lbl = QLabel("")
        self.result_count_lbl.setObjectName("hintLbl")
        hint_row.addWidget(self.result_count_lbl)
        layout.addLayout(hint_row)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["#", "Name", "Target", "Findings", "Date"]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setColumnWidth(0, 46)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 105)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setObjectName("compareTable")
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self.on_cell_click)
        layout.addWidget(self.table, 1)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondaryBtn")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        self.compare_btn = QPushButton("Compare Scans →")
        self.compare_btn.setObjectName("primaryBtn")
        self.compare_btn.setEnabled(False)
        self.compare_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.compare_btn.clicked.connect(self.accept)
        btn_row.addWidget(self.compare_btn)
        layout.addLayout(btn_row)
        self.populate_table(self.scans)
    def on_search_changed(self, query):
        query = query.strip().lower()
        if not query:
            filtered = list(self.scans)
        else:
            filtered = [
                scan for scan in self.scans
                if query in str(scan[1]).lower()
                or query in str(scan[2]).lower()
                or query in str(scan[5] or "").lower()
            ]
        self.populate_table(filtered)
    def populate_table(self, scans):
        self.visible_scans = list(scans)
        self.table.setRowCount(0)
        muted = QColor(self.t["text_muted"])
        text = QColor(self.t["text"])
        for i, scan in enumerate(scans, 1):
            row = self.table.rowCount()
            self.table.insertRow(row)
            scan_id = scan[0]
            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(muted)
            name_item = QTableWidgetItem(str(scan[1]))
            name_item.setForeground(text)
            target_item = QTableWidgetItem(str(scan[2]))
            target_item.setForeground(QColor(self.t["info"]))
            count_item = QTableWidgetItem(str(scan[6]))
            count_item.setForeground(text)
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            date_item = QTableWidgetItem(
                str(scan[5])[:10] if scan[5] else ""
            )
            date_item.setForeground(muted)
            if scan_id == self.selected_a:
                for item in (
                    num_item, name_item, target_item,
                    count_item, date_item,
                ):
                    item.setForeground(QColor(self.t["accent"]))
            elif scan_id == self.selected_b:
                for item in (
                    num_item, name_item, target_item,
                    count_item, date_item,
                ):
                    item.setForeground(QColor(self.t["success"]))
            self.table.setItem(row, 0, num_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, target_item)
            self.table.setItem(row, 3, count_item)
            self.table.setItem(row, 4, date_item)
            self.table.setRowHeight(row, 34)
        total = len(self.scans)
        shown = len(scans)
        if shown == total:
            self.result_count_lbl.setText(
                f"{total} scan{'s' if total != 1 else ''}"
            )
        else:
            self.result_count_lbl.setText(
                f"{shown} of {total} match{'es' if shown != 1 else ''}"
            )
    def on_cell_click(self, row, col):
        if row >= len(self.visible_scans):
            return
        scan = self.visible_scans[row]
        scan_id = scan[0]
        label = f"#{scan_id} — {scan[1]} ({scan[2]})"
        if self.selected_a is None:
            self.selected_a = scan_id
            self.scan_a_id = scan_id
            self.scan_a_lbl.setText(f"Scan A: {label}")
            self.scan_a_lbl.setStyleSheet(self._slot_a_style())
        elif self.selected_b is None and scan_id != self.selected_a:
            self.selected_b = scan_id
            self.scan_b_id = scan_id
            self.scan_b_lbl.setText(f"Scan B: {label}")
            self.scan_b_lbl.setStyleSheet(self._slot_b_style())
            self.compare_btn.setEnabled(True)
        else:
            self.selected_a = scan_id
            self.selected_b = None
            self.scan_a_id = scan_id
            self.scan_b_id = None
            self.scan_a_lbl.setText(f"Scan A: {label}")
            self.scan_a_lbl.setStyleSheet(self._slot_a_style())
            self.scan_b_lbl.setText("Scan B: Not selected")
            self.scan_b_lbl.setStyleSheet(self._slot_idle_style())
            self.compare_btn.setEnabled(False)
        self.populate_table(self.visible_scans)
    def get_stylesheet(self):
        fs = self.fs
        t = self.t
        return f"""
            QDialog {{
                background-color: {t["bg"]};
                color: {t["text"]};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}
            QLabel {{
                background: transparent;
                border: none;
            }}
            #dialogTitle {{
                color: {t["accent"]};
                font-size: {fs + 5}px;
                font-weight: 900;
            }}
            #dialogSub {{
                color: {t["text_muted"]};
                font-size: {fs - 1}px;
            }}
            #searchIcon {{
                color: {t["accent"]};
                font-size: {fs}px;
                background: transparent;
                border: none;
            }}
            #searchInput {{
                background-color: {t["card_bg"]};
                color: {t["text"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 9px 12px;
                font-size: {fs - 1}px;
                selection-background-color: {t["accent"]};
                selection-color: white;
            }}
            #searchInput:focus {{
                border-color: {t["accent"]};
                background-color: {t["card_bg_2"]};
            }}
            #searchInput::placeholder {{
                color: {t["text_soft"]};
            }}
            #clearBtn {{
                background-color: {t.get("button_soft", t["card_bg"])};
                color: {t["text_muted"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 7px;
                font-weight: 800;
            }}
            #clearBtn:hover {{
                border-color: {t["accent"]};
                color: {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 22))};
            }}
            #hintLbl {{
                color: {t["text_muted"]};
                font-size: {fs - 2}px;
                background: transparent;
                border: none;
            }}
            #compareTable {{
                background-color: {t["card_bg"]};
                alternate-background-color: {t["card_bg_2"]};
                border: 1px solid {t["border"]};
                gridline-color: {t["border"]};
                border-radius: 10px;
                color: {t["text"]};
                selection-background-color: {t.get("selection_bg", rgba_from_hex(t["accent"], 35))};
                selection-color: {t.get("selection_text", "#FEE2E2")};
            }}
            QHeaderView::section {{
                background-color: {t.get("bg_deep", t["bg"])};
                color: {t["text_muted"]};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {t["border"]};
                font-weight: 900;
                font-size: {fs - 2}px;
            }}
            QTableWidget::item {{
                padding: 5px 8px;
                background-color: transparent;
                color: {t["text"]};
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {t.get("selection_bg", rgba_from_hex(t["accent"], 35))};
                color: {t.get("selection_text", "#FEE2E2")};
            }}
            #secondaryBtn {{
                background-color: {t.get("button_soft", t["card_bg"])};
                color: {t["text_muted"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 9px 22px;
                font-size: {fs - 1}px;
                font-weight: 700;
            }}
            #secondaryBtn:hover {{
                border-color: {t["accent"]};
                color: {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 22))};
            }}
            #primaryBtn {{
                background-color: {t["accent"]};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 9px 22px;
                font-size: {fs - 1}px;
                font-weight: 900;
            }}
            #primaryBtn:hover {{
                background-color: {t["accent_hover"]};
            }}
            #primaryBtn:pressed {{
                background-color: {t["accent_dark"]};
            }}
            #primaryBtn:disabled {{
                background-color: {t["card_bg_2"]};
                color: {t["text_soft"]};
                border: 1px solid {t["border"]};
            }}
        """
class OpenScanScreen(QWidget):
    def __init__(
        self,
        on_scan_select=None,
        on_diff=None,
        prefs=None,
    ):
        super().__init__()
        self.on_scan_select = on_scan_select
        self.on_diff = on_diff
        self.current_tab = "folders"
        self.scans = []
        self.current_folder_id = None
        self.current_folder_name = None
        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_data()
    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.t = get_theme(self.dark)
        self.setStyleSheet(self.get_stylesheet())
        self._refresh_tab_styles()
        self.load_folders()
        self.load_scans(self.current_folder_id)
        self.load_stats()
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 22, 30, 22)
        layout.setSpacing(12)
        header_card = QFrame()
        header_card.setObjectName("headerCard")
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(4)
        title = QLabel("Scan Library")
        title.setObjectName("pageTitle")
        header_layout.addWidget(title)
        sub = QLabel(
            "Organise your scans into folders by client, project, or engagement."
        )
        sub.setObjectName("pageSub")
        sub.setWordWrap(True)
        header_layout.addWidget(sub)
        layout.addWidget(header_card)
        tab_card = QFrame()
        tab_card.setObjectName("tabCard")
        tab_row = QHBoxLayout(tab_card)
        tab_row.setContentsMargins(12, 8, 12, 8)
        tab_row.setSpacing(8)
        self.tab_folders = QPushButton("All Folders")
        self.tab_folders.setCursor(Qt.CursorShape.PointingHandCursor)
        self.tab_folders.clicked.connect(self.show_folders_tab)
        tab_row.addWidget(self.tab_folders)
        self.tab_scans = QPushButton("All Scans")
        self.tab_scans.setCursor(Qt.CursorShape.PointingHandCursor)
        self.tab_scans.clicked.connect(
            lambda: self.show_scans_tab()
        )
        tab_row.addWidget(self.tab_scans)
        tab_row.addStretch()
        layout.addWidget(tab_card)
        self._refresh_tab_styles()
        self.stack = QStackedWidget()
        self.stack.setObjectName("libraryStack")
        layout.addWidget(self.stack)
        self.folders_page = self.build_folders_page()
        self.scans_page = self.build_scans_page()
        self.stack.addWidget(self.folders_page)
        self.stack.addWidget(self.scans_page)
    def build_folders_page(self):
        page = QWidget()
        page.setObjectName("pageBody")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        top_row = QHBoxLayout()
        top_row.addStretch()
        self.compare_btn = QPushButton("Compare Scans")
        self.compare_btn.setObjectName("compareBtn")
        self.compare_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.compare_btn.clicked.connect(self.open_compare)
        top_row.addWidget(self.compare_btn)
        new_folder_btn = QPushButton("+ New Folder")
        new_folder_btn.setObjectName("primaryBtn")
        new_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        new_folder_btn.clicked.connect(self.create_folder)
        top_row.addWidget(new_folder_btn)
        layout.addLayout(top_row)
        self.folder_grid_widget = QWidget()
        self.folder_grid_widget.setObjectName("folderGridWidget")
        self.folder_grid = QGridLayout(self.folder_grid_widget)
        self.folder_grid.setSpacing(10)
        self.folder_grid.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.folder_grid_widget)
        layout.addStretch()
        return page
    def build_scans_page(self):
        page = QWidget()
        page.setObjectName("pageBody")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(10)
        layout.addLayout(self.stats_row)
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(8)
        self.scans_table.setHorizontalHeaderLabels(
            [
                "#", "Scan Name", "Target", "Folder",
                "Findings", "Status", "Date", "Action",
            ]
        )
        self.scans_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.scans_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.scans_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.scans_table.verticalHeader().setVisible(False)
        self.scans_table.setObjectName("scansTable")
        self.scans_table.setAlternatingRowColors(True)
        self.scans_table.cellDoubleClicked.connect(self.open_scan)
        self.scans_table.setColumnWidth(0, 46)
        self.scans_table.setColumnWidth(2, 160)
        self.scans_table.setColumnWidth(3, 150)
        self.scans_table.setColumnWidth(4, 90)
        self.scans_table.setColumnWidth(5, 105)
        self.scans_table.setColumnWidth(6, 105)
        self.scans_table.setColumnWidth(7, 60)
        layout.addWidget(self.scans_table)
        hint = QLabel(
            "Double-click any row to open scan  •  "
            "Click 🗑️ to permanently delete a scan and all its findings"
        )
        hint.setObjectName("hintLbl")
        layout.addWidget(hint)
        return page
    def load_data(self):
        self.load_folders()
        self.load_scans()
        self.load_stats()
    def load_folders(self):
        while self.folder_grid.count():
            child = self.folder_grid.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        folders = get_folders()
        col = 0
        row = 0
        max_cols = 3
        for folder in folders:
            card = self.make_folder_card(folder)
            self.folder_grid.addWidget(card, row, col)
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
        new_card = self.make_new_folder_card()
        self.folder_grid.addWidget(new_card, row, col)
    def make_folder_card(self, folder):
        """
        Folder card with a 🗑️ delete button in the top-right corner.
        Clicking the card body opens the folder.
        Clicking the delete button prompts for confirmation then
        cascade-deletes the folder, all its scans, and all their
        findings/tool_runs/audit_logs.
        """
        card = QFrame()
        card.setObjectName("folderCard")
        card.setFixedSize(190, 118)
        # Outer layout — holds the delete button row + content
        outer = QVBoxLayout(card)
        outer.setContentsMargins(0, 6, 8, 0)
        outer.setSpacing(0)
        # ── Delete button row (top-right) ────────────────────
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.addStretch()
        delete_btn = QPushButton("🗑️")
        delete_btn.setToolTip(
            "Delete this folder and all its scans permanently"
        )
        delete_btn.setFixedSize(26, 22)
        delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        delete_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border: none;
                font-size: {self.fs - 2}px;
                color: {self.t["text_muted"]};
                padding: 0px;
            }}
            QPushButton:hover {{
                color: {self.t["accent"]};
            }}
        """)
        folder_id   = folder["id"]
        folder_name = folder["name"]
        scan_count  = folder.get("scan_count", 0)
        delete_btn.clicked.connect(
            lambda _, fid=folder_id, fname=folder_name,
            count=scan_count:
            self.on_delete_folder(fid, fname, count)
        )
        btn_row.addWidget(delete_btn)
        outer.addLayout(btn_row)
        # ── Card content (clickable to open folder) ──────────
        content = QWidget()
        content.setCursor(Qt.CursorShape.PointingHandCursor)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(14, 2, 14, 12)
        content_layout.setSpacing(5)
        icon = QLabel("📁")
        icon.setStyleSheet(
            f"""
            font-size: {self.fs + 9}px;
            background: transparent;
            border: none;
            """
        )
        content_layout.addWidget(icon)
        name_lbl = QLabel(folder_name)
        name_lbl.setObjectName("folderName")
        name_lbl.setWordWrap(True)
        content_layout.addWidget(name_lbl)
        count = folder.get("scan_count", 0)
        meta = QLabel(
            f"{count} scan{'s' if count != 1 else ''}"
        )
        meta.setObjectName("folderMeta")
        content_layout.addWidget(meta)
        content.mousePressEvent = (
            lambda event, f=folder: self.open_folder(f)
        )
        outer.addWidget(content, 1)
        return card
    def on_delete_folder(self, folder_id, folder_name, scan_count):
        """
        Confirm then cascade-delete a folder, all its scans,
        and all findings/tool_runs/audit_logs for those scans.
        """
        short_name = (
            folder_name[:55] + "…"
            if len(folder_name) > 55 else folder_name
        )
        scan_word = f"{scan_count} scan{'s' if scan_count != 1 else ''}"
        reply = QMessageBox.question(
            self,
            "Delete Folder",
            f"Delete this folder permanently?\n\n"
            f"\"{short_name}\"\n\n"
            f"This will also permanently delete all {scan_word} "
            f"inside it, along with every finding, tool run, "
            f"and audit log associated with those scans.\n\n"
            f"This cannot be undone.",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            delete_folder(folder_id)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Delete Failed",
                f"Could not delete folder:\n{e}"
            )
            return
        # Refresh everything
        self.load_folders()
        self.load_stats()
        # If the user was viewing scans inside this folder,
        # drop back to showing all scans
        if self.current_folder_id == folder_id:
            self.current_folder_id = None
            self.current_folder_name = None
            self.load_scans()
    def make_new_folder_card(self):
        card = QFrame()
        card.setObjectName("newFolderCard")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        card.setFixedSize(190, 118)
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        plus = QLabel("+")
        plus.setAlignment(Qt.AlignmentFlag.AlignCenter)
        plus.setStyleSheet(
            f"""
            font-size: {self.fs + 13}px;
            color: {self.t["accent"]};
            background: transparent;
            border: none;
            font-weight: 900;
            """
        )
        layout.addWidget(plus)
        lbl = QLabel("Create New Folder")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            f"""
            color: {self.t["text_muted"]};
            font-size: {self.fs - 2}px;
            background: transparent;
            border: none;
            font-weight: 700;
            """
        )
        layout.addWidget(lbl)
        card.mousePressEvent = (
            lambda event: self.create_folder()
        )
        return card
    def open_folder(self, folder):
        self.current_folder_id = folder["id"]
        self.current_folder_name = folder["name"]
        self.show_scans_tab(
            folder_id=folder["id"],
            folder_name=folder["name"]
        )
    def load_stats(self):
        while self.stats_row.count():
            child = self.stats_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]
        cursor.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='Critical'"
        )
        critical = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM folders")
        total_folders = cursor.fetchone()[0]
        conn.close()
        stats = [
            ("Total Scans", str(total_scans), self.t["info"]),
            ("Total Findings", str(total_findings), self.t["accent"]),
            ("Critical", str(critical), self.t["brand_red"]),
            ("Folders", str(total_folders), self.t["success"]),
        ]
        for label, value, color in stats:
            card = self.make_stat_card(label, value, color)
            self.stats_row.addWidget(card)
        self.stats_row.addStretch()
    def make_stat_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(
            f"""
            QFrame#statCard {{
                background-color: {self.t["card_bg"]};
                border: 1px solid {color};
                border-radius: 10px;
                min-width: 100px;
                max-width: 140px;
            }}
            QFrame#statCard:hover {{
                background-color: {self.t["card_bg_2"]};
            }}
            """
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(2)
        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"""
            color: {color};
            font-size: {self.fs + 8}px;
            font-weight: 900;
            background: transparent;
            border: none;
            """
        )
        label_lbl = QLabel(label)
        label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label_lbl.setStyleSheet(
            f"""
            color: {self.t["text_muted"]};
            font-size: {self.fs - 3}px;
            font-weight: 700;
            background: transparent;
            border: none;
            """
        )
        layout.addWidget(val_lbl)
        layout.addWidget(label_lbl)
        return card
    def load_scans(self, folder_id=None):
        conn = get_connection()
        cursor = conn.cursor()
        if folder_id:
            cursor.execute(
                """
                SELECT s.id, s.name, s.target, s.profile,
                       s.status, s.created_at,
                       COUNT(f.id) as finding_count,
                       fo.name as folder_name
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                LEFT JOIN folders fo ON s.folder_id = fo.id
                WHERE s.folder_id = ?
                GROUP BY s.id
                ORDER BY s.id DESC
                """,
                (folder_id,)
            )
        else:
            cursor.execute(
                """
                SELECT s.id, s.name, s.target, s.profile,
                       s.status, s.created_at,
                       COUNT(f.id) as finding_count,
                       fo.name as folder_name
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                LEFT JOIN folders fo ON s.folder_id = fo.id
                GROUP BY s.id
                ORDER BY s.id DESC
                """
            )
        self.scans = cursor.fetchall()
        conn.close()
        self.populate_scans_table(self.scans)
    def populate_scans_table(self, scans):
        muted = QColor(self.t["text_muted"])
        text = QColor(self.t["text"])
        self.scans_table.setRowCount(0)
        for i, scan in enumerate(scans, 1):
            row = self.scans_table.rowCount()
            self.scans_table.insertRow(row)
            scan_id = scan[0]
            name = scan[1]
            target = scan[2]
            status = scan[4]
            created = scan[5][:10] if scan[5] else ""
            finding_count = scan[6]
            folder_name = scan[7] or "—"
            num = QTableWidgetItem(str(i))
            num.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num.setForeground(muted)
            name_item = QTableWidgetItem(name)
            name_item.setForeground(text)
            target_item = QTableWidgetItem(target)
            target_item.setForeground(QColor(self.t["info"]))
            folder_item = QTableWidgetItem(
                f"📁 {folder_name}" if folder_name != "—" else "—"
            )
            folder_item.setForeground(muted)
            count_item = QTableWidgetItem(str(finding_count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if finding_count > 100:
                count_item.setForeground(QColor(self.t["brand_red"]))
            elif finding_count > 50:
                count_item.setForeground(QColor(self.t["warning"]))
            else:
                count_item.setForeground(QColor(self.t["success"]))
            status_item = QTableWidgetItem(status.title())
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if status == "completed":
                status_item.setForeground(QColor(self.t["success"]))
            else:
                status_item.setForeground(QColor(self.t["warning"]))
            date_item = QTableWidgetItem(created)
            date_item.setForeground(muted)
            for col, item in enumerate(
                [num, name_item, target_item, folder_item,
                 count_item, status_item, date_item]
            ):
                self.scans_table.setItem(row, col, item)
            delete_btn = QPushButton("🗑️")
            delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            delete_btn.setToolTip("Delete this scan")
            delete_btn.setFixedSize(30, 26)
            delete_btn.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: transparent;
                    border: 1px solid {self.t["border"]};
                    border-radius: 6px;
                    font-size: {self.fs - 1}px;
                }}
                QPushButton:hover {{
                    background-color: {self.t.get("selection_bg", rgba_from_hex(self.t["accent"], 35))};
                    border-color: {self.t["accent"]};
                }}
                """
            )
            scan_name = name
            scan_finding_count = finding_count
            delete_btn.clicked.connect(
                lambda _, sid=scan_id, sname=scan_name,
                count=scan_finding_count:
                self.delete_scan(sid, sname, count)
            )
            btn_wrap = QWidget()
            btn_wrap_layout = QHBoxLayout(btn_wrap)
            btn_wrap_layout.setContentsMargins(0, 0, 0, 0)
            btn_wrap_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_wrap_layout.addWidget(delete_btn)
            self.scans_table.setCellWidget(row, 7, btn_wrap)
            self.scans_table.setRowHeight(row, 38)
    def delete_scan(self, scan_id, scan_name, finding_count):
        short_name = (
            scan_name[:60] + "…"
            if len(scan_name) > 60 else scan_name
        )
        reply = QMessageBox.question(
            self,
            "Delete Scan",
            f"Delete this scan permanently?\n\n"
            f"\"{short_name}\"\n\n"
            f"This will also permanently delete all "
            f"{finding_count} finding{'s' if finding_count != 1 else ''} "
            f"associated with this scan, along with its tool run "
            f"history and audit log.\n\n"
            f"This cannot be undone.",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            conn = get_connection()
            cursor = conn.cursor()
            for table in ("findings", "tool_runs", "audit_logs"):
                try:
                    cursor.execute(
                        f"DELETE FROM {table} WHERE scan_id=?",
                        (scan_id,)
                    )
                except Exception:
                    pass
            cursor.execute(
                "DELETE FROM scans WHERE id=?", (scan_id,)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(
                self, "Delete Failed",
                f"Could not delete scan:\n{e}"
            )
            return
        self.load_scans(self.current_folder_id)
        self.load_folders()
        self.load_stats()
    def show_folders_tab(self):
        self.current_tab = "folders"
        self.current_folder_id = None
        self.current_folder_name = None
        self._refresh_tab_styles()
        self.stack.setCurrentIndex(0)
        self.load_folders()
    def show_scans_tab(self, folder_id=None, folder_name=None):
        self.current_tab = "scans"
        if folder_id is not None:
            self.current_folder_id = folder_id
            self.current_folder_name = folder_name
        self._refresh_tab_styles()
        self.stack.setCurrentIndex(1)
        self.load_scans(self.current_folder_id)
        self.load_stats()
    def open_scan(self, row, col):
        if col == 7:
            return
        if row < len(self.scans):
            scan_id = self.scans[row][0]
            if self.on_scan_select:
                self.on_scan_select(scan_id)
    def create_folder(self):
        dialog = CreateFolderDialog(
            self, theme=self.t, font_size=self.fs
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            insert_folder(
                dialog.folder_name,
                dialog.folder_desc
            )
            self.load_folders()
            self.load_stats()
    def open_compare(self):
        if len(self.scans) < 2:
            QMessageBox.information(
                self,
                "Not Enough Scans",
                "You need at least 2 scans to compare.\n\nRun another scan first!"
            )
            return
        dialog = CompareScanDialog(
            self.scans, self, theme=self.t, font_size=self.fs
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.scan_a_id and dialog.scan_b_id:
                if self.on_diff:
                    self.on_diff(
                        dialog.scan_a_id,
                        dialog.scan_b_id
                    )
    def _refresh_tab_styles(self):
        if self.current_tab == "folders":
            self.tab_folders.setStyleSheet(
                self.get_tab_active_style()
            )
            self.tab_scans.setStyleSheet(
                self.get_tab_inactive_style()
            )
        else:
            self.tab_folders.setStyleSheet(
                self.get_tab_inactive_style()
            )
            self.tab_scans.setStyleSheet(
                self.get_tab_active_style()
            )
    def get_tab_active_style(self):
        return f"""
            QPushButton {{
                background-color: {rgba_from_hex(self.t["accent"], 35)};
                color: {self.t["accent"]};
                border: 1px solid {rgba_from_hex(self.t["accent"], 145)};
                border-radius: 8px;
                padding: 8px 18px;
                font-size: {self.fs - 1}px;
                font-weight: 900;
            }}
        """
    def get_tab_inactive_style(self):
        return f"""
            QPushButton {{
                background-color: {self.t.get("button_soft", self.t["card_bg"])};
                color: {self.t["text_muted"]};
                border: 1px solid {self.t["border"]};
                border-radius: 8px;
                padding: 8px 18px;
                font-size: {self.fs - 1}px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                color: {self.t["accent"]};
                border-color: {self.t["accent"]};
                background-color: {self.t.get("hover", rgba_from_hex(self.t["accent"], 22))};
            }}
        """
    def get_stylesheet(self):
        fs = self.fs
        t = self.t
        return f"""
            QWidget {{
                background-color: {t["bg"]};
                color: {t["text"]};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: {fs}px;
            }}
            #headerCard {{
                background-color: {t["card_bg"]};
                border: 1px solid {t["border"]};
                border-radius: 12px;
            }}
            #headerCard:hover {{
                border: 1px solid {t.get("card_hover", rgba_from_hex(t["accent"], 75))};
            }}
            #tabCard {{
                background-color: {t["card_bg"]};
                border: 1px solid {t["border"]};
                border-radius: 10px;
            }}
            #tabCard:hover {{
                border: 1px solid {t.get("card_hover", rgba_from_hex(t["accent"], 65))};
            }}
            #libraryStack {{
                background-color: transparent;
                border: none;
            }}
            #pageBody {{
                background-color: transparent;
                border: none;
            }}
            #folderGridWidget {{
                background-color: transparent;
                border: none;
            }}
            #pageTitle {{
                color: {t["accent"]};
                font-size: {fs + 7}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
            #pageSub {{
                color: {t["text_muted"]};
                font-size: {fs - 1}px;
                background: transparent;
                border: none;
            }}
            #folderCard {{
                background-color: {t["card_bg"]};
                border: 1px solid {t["border"]};
                border-radius: 10px;
            }}
            #folderCard:hover {{
                border: 1px solid {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 18))};
            }}
            #newFolderCard {{
                background-color: {rgba_from_hex(t["card_bg"], 115)};
                border: 1px dashed {t["border_soft"]};
                border-radius: 10px;
            }}
            #newFolderCard:hover {{
                border: 1px dashed {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 18))};
            }}
            #folderName {{
                color: {t["text"]};
                font-size: {fs - 1}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}
            #folderMeta {{
                color: {t["text_muted"]};
                font-size: {fs - 3}px;
                background: transparent;
                border: none;
            }}
            #statCard {{
                background-color: {t["card_bg"]};
                border-radius: 10px;
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
            #compareBtn {{
                background-color: {t.get("button_soft", t["card_bg"])};
                color: {t["text"]};
                border: 1px solid {t["border"]};
                border-radius: 8px;
                padding: 9px 18px;
                font-size: {fs - 1}px;
                font-weight: 800;
            }}
            #compareBtn:hover {{
                color: {t["accent"]};
                border-color: {t["accent"]};
                background-color: {t.get("hover", rgba_from_hex(t["accent"], 22))};
            }}
            #scansTable {{
                background-color: {t["card_bg"]};
                alternate-background-color: {t["card_bg_2"]};
                border: 1px solid {t["border"]};
                gridline-color: {t["border"]};
                border-radius: 10px;
                color: {t["text"]};
                selection-background-color: {t.get("selection_bg", rgba_from_hex(t["accent"], 35))};
                selection-color: {t.get("selection_text", "#FEE2E2")};
            }}
            QHeaderView::section {{
                background-color: {t.get("bg_deep", t["bg"])};
                color: {t["text_muted"]};
                padding: 9px;
                border: none;
                border-bottom: 1px solid {t["border"]};
                font-size: {fs - 2}px;
                font-weight: 900;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
                background-color: transparent;
                color: {t["text"]};
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {t.get("selection_bg", rgba_from_hex(t["accent"], 35))};
                color: {t.get("selection_text", "#FEE2E2")};
            }}
            #hintLbl {{
                color: {t["text_muted"]};
                font-size: {fs - 2}px;
                margin-top: 4px;
                background: transparent;
                border: none;
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
            QScrollBar:vertical {{
                background: {t["bg"]};
                width: 10px;
                margin: 0px;
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
        """
