from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView,
    QDialog, QLineEdit, QMessageBox, QStackedWidget,
    QGridLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from backend.db import (
    get_connection, get_folders,
    insert_folder, delete_folder
)


class CreateFolderDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Folder")
        self.setFixedSize(380, 230)
        self.setWindowModality(
            Qt.WindowModality.ApplicationModal
        )
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowCloseButtonHint
        )
        self.setStyleSheet("""
            QDialog {
                background-color: #161b22;
                color: #e6edf3;
                font-family: Arial;
            }
            QLabel {
                color: #e6edf3;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 10px;
                color: #e6edf3;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #e94560; }
        """)
        self.folder_name = ''
        self.folder_desc = ''
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("Create New Folder")
        title.setStyleSheet(
            "color: #e94560; font-size: 15px; "
            "font-weight: bold;"
        )
        layout.addWidget(title)

        sub = QLabel(
            "Organise your scans by client, "
            "project or engagement."
        )
        sub.setStyleSheet(
            "color: #8b949e; font-size: 11px;"
        )
        layout.addWidget(sub)
        layout.addSpacing(4)

        name_lbl = QLabel("Folder Name")
        name_lbl.setStyleSheet(
            "color: #e6edf3; font-size: 11px; "
            "font-weight: bold;"
        )
        layout.addWidget(name_lbl)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText(
            "e.g. Client A — VAPT"
        )
        layout.addWidget(self.name_input)

        desc_lbl = QLabel("Description (optional)")
        desc_lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px;"
        )
        layout.addWidget(desc_lbl)

        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText(
            "e.g. External VAPT for Client A"
        )
        layout.addWidget(self.desc_input)
        layout.addSpacing(4)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 7px 16px;
                color: #8b949e;
                font-size: 12px;
            }
            QPushButton:hover {
                border-color: #e94560;
                color: #e94560;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        create_btn = QPushButton("Create Folder")
        create_btn.setStyleSheet("""
            QPushButton {
                background: #e94560;
                border: none;
                border-radius: 6px;
                padding: 7px 16px;
                color: white;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background: #c73652; }
        """)
        create_btn.clicked.connect(self.do_create)
        btn_row.addWidget(create_btn)
        layout.addLayout(btn_row)

    def do_create(self):
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(
                self, "Missing Name",
                "Please enter a folder name."
            )
            return
        self.folder_name = name
        self.folder_desc = self.desc_input.text().strip()
        self.accept()


class CompareScanDialog(QDialog):
    """Dialog to pick two scans to compare."""

    def __init__(self, scans, parent=None):
        super().__init__(parent)
        self.scans       = scans
        self.scan_a_id   = None
        self.scan_b_id   = None
        self.setWindowTitle("Compare Two Scans")
        self.setMinimumSize(600, 480)
        self.setWindowModality(
            Qt.WindowModality.ApplicationModal
        )
        self.setStyleSheet("""
            QDialog {
                background: #0d1117;
                color: #e6edf3;
                font-family: Arial;
            }
            QLabel {
                background: transparent;
                border: none;
                color: #e6edf3;
            }
        """)
        self.selected_a = None
        self.selected_b = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Compare Two Scans")
        title.setStyleSheet(
            "color: #e94560; font-size: 16px; "
            "font-weight: bold;"
        )
        layout.addWidget(title)

        sub = QLabel(
            "Select Scan A (baseline) and Scan B (new) "
            "to generate a diff report."
        )
        sub.setStyleSheet(
            "color: #8b949e; font-size: 12px;"
        )
        layout.addWidget(sub)

        # ── Selection row ─────────────────────────────────
        sel_row = QHBoxLayout()
        sel_row.setSpacing(16)

        self.scan_a_lbl = QLabel("Scan A: Not selected")
        self.scan_a_lbl.setStyleSheet(
            "background: #161b22; color: #8b949e; "
            "border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; "
            "font-size: 12px;"
        )
        sel_row.addWidget(self.scan_a_lbl, 1)

        arrow = QLabel("→")
        arrow.setStyleSheet(
            "color: #e94560; font-size: 18px; "
            "font-weight: bold;"
        )
        arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sel_row.addWidget(arrow)

        self.scan_b_lbl = QLabel("Scan B: Not selected")
        self.scan_b_lbl.setStyleSheet(
            "background: #161b22; color: #8b949e; "
            "border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; "
            "font-size: 12px;"
        )
        sel_row.addWidget(self.scan_b_lbl, 1)
        layout.addLayout(sel_row)

        hint = QLabel(
            "Click a row to set as Scan A, "
            "then click another row to set as Scan B."
        )
        hint.setStyleSheet(
            "color: #555; font-size: 11px;"
        )
        layout.addWidget(hint)

        # ── Scans table ───────────────────────────────────
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            '#', 'Name', 'Target', 'Findings', 'Date'
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 70)
        self.table.setColumnWidth(4, 90)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setStyleSheet("""
            QTableWidget {
                background: #161b22;
                border: 1px solid #30363d;
                gridline-color: #21262d;
                border-radius: 4px;
                color: #e6edf3;
            }
            QHeaderView::section {
                background: #21262d;
                color: #8b949e;
                padding: 6px 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 4px 8px;
                background: #0d1117;
            }
            QTableWidget::item:selected {
                background: #21262d;
                color: #e94560;
            }
        """)
        self.table.cellClicked.connect(self.on_cell_click)

        for i, scan in enumerate(self.scans, 1):
            row = self.table.rowCount()
            self.table.insertRow(row)

            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            num_item.setForeground(QColor('#555'))

            name_item = QTableWidgetItem(scan[1])
            tgt_item  = QTableWidgetItem(scan[2])
            tgt_item.setForeground(QColor('#4a9eff'))
            cnt_item  = QTableWidgetItem(str(scan[6]))
            cnt_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            date_item = QTableWidgetItem(
                str(scan[5])[:10] if scan[5] else ''
            )
            date_item.setForeground(QColor('#8b949e'))

            self.table.setItem(row, 0, num_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, tgt_item)
            self.table.setItem(row, 3, cnt_item)
            self.table.setItem(row, 4, date_item)
            self.table.setRowHeight(row, 32)

        layout.addWidget(self.table)

        # ── Buttons ───────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 12px;
            }
            QPushButton:hover {
                border-color: #e94560;
                color: #e94560;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        self.compare_btn = QPushButton(
            "Compare Scans →"
        )
        self.compare_btn.setEnabled(False)
        self.compare_btn.setStyleSheet("""
            QPushButton {
                background: #e94560;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background: #c73652; }
            QPushButton:disabled {
                background: #21262d;
                color: #555;
            }
        """)
        self.compare_btn.clicked.connect(self.accept)
        btn_row.addWidget(self.compare_btn)
        layout.addLayout(btn_row)

    def on_cell_click(self, row, col):
        scan    = self.scans[row]
        scan_id = scan[0]
        label   = f"#{scan_id} — {scan[1]} ({scan[2]})"

        if self.selected_a is None:
            self.selected_a = scan_id
            self.scan_a_id  = scan_id
            self.scan_a_lbl.setText(f"Scan A: {label}")
            self.scan_a_lbl.setStyleSheet(
                "background: #161b22; color: #4a9eff; "
                "border: 1px solid #4a9eff; "
                "border-radius: 6px; padding: 8px 12px; "
                "font-size: 12px; font-weight: bold;"
            )
        elif self.selected_b is None and scan_id != self.selected_a:
            self.selected_b = scan_id
            self.scan_b_id  = scan_id
            self.scan_b_lbl.setText(f"Scan B: {label}")
            self.scan_b_lbl.setStyleSheet(
                "background: #161b22; color: #1d9e75; "
                "border: 1px solid #1d9e75; "
                "border-radius: 6px; padding: 8px 12px; "
                "font-size: 12px; font-weight: bold;"
            )
            self.compare_btn.setEnabled(True)
        else:
            # Reset and start over
            self.selected_a = scan_id
            self.selected_b = None
            self.scan_a_id  = scan_id
            self.scan_b_id  = None
            self.scan_a_lbl.setText(f"Scan A: {label}")
            self.scan_a_lbl.setStyleSheet(
                "background: #161b22; color: #4a9eff; "
                "border: 1px solid #4a9eff; "
                "border-radius: 6px; padding: 8px 12px; "
                "font-size: 12px; font-weight: bold;"
            )
            self.scan_b_lbl.setText("Scan B: Not selected")
            self.scan_b_lbl.setStyleSheet(
                "background: #161b22; color: #8b949e; "
                "border: 1px solid #30363d; "
                "border-radius: 6px; padding: 8px 12px; "
                "font-size: 12px;"
            )
            self.compare_btn.setEnabled(False)


class OpenScanScreen(QWidget):
    def __init__(self, on_scan_select=None,
                 on_diff=None):
        super().__init__()
        self.on_scan_select = on_scan_select
        self.on_diff        = on_diff
        self.current_tab    = 'folders'
        self.scans          = []
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_data()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 20, 30, 20)

        title = QLabel("Scan Library")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        sub = QLabel(
            "Organise your scans into folders by client, "
            "project or engagement."
        )
        sub.setObjectName("pageSub")
        layout.addWidget(sub)
        layout.addSpacing(12)

        tab_row = QHBoxLayout()

        self.tab_folders = QPushButton("All Folders")
        self.tab_folders.setStyleSheet(
            self.get_tab_active_style()
        )
        self.tab_folders.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.tab_folders.clicked.connect(
            self.show_folders_tab
        )
        tab_row.addWidget(self.tab_folders)

        self.tab_scans = QPushButton("All Scans")
        self.tab_scans.setStyleSheet(
            self.get_tab_inactive_style()
        )
        self.tab_scans.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.tab_scans.clicked.connect(
            lambda: self.show_scans_tab()
        )
        tab_row.addWidget(self.tab_scans)

        tab_row.addStretch()

        # ── Compare Scans button ──────────────────────────
        compare_btn = QPushButton("🔀 Compare Scans")
        compare_btn.setObjectName("compareBtn")
        compare_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        compare_btn.clicked.connect(self.open_compare)
        tab_row.addWidget(compare_btn)

        layout.addLayout(tab_row)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #30363d;")
        layout.addWidget(divider)
        layout.addSpacing(12)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.folders_page = self.build_folders_page()
        self.scans_page   = self.build_scans_page()
        self.stack.addWidget(self.folders_page)
        self.stack.addWidget(self.scans_page)

    def build_folders_page(self):
        page   = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)

        top_row = QHBoxLayout()
        top_row.addStretch()

        new_folder_btn = QPushButton("+ New Folder")
        new_folder_btn.setObjectName("primaryBtn")
        new_folder_btn.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        new_folder_btn.clicked.connect(self.create_folder)
        top_row.addWidget(new_folder_btn)
        layout.addLayout(top_row)
        layout.addSpacing(10)

        self.folder_grid_widget = QWidget()
        self.folder_grid = QGridLayout(
            self.folder_grid_widget
        )
        self.folder_grid.setSpacing(10)
        layout.addWidget(self.folder_grid_widget)
        layout.addStretch()
        return page

    def build_scans_page(self):
        page   = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)

        self.stats_row = QHBoxLayout()
        layout.addLayout(self.stats_row)
        layout.addSpacing(12)

        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(7)
        self.scans_table.setHorizontalHeaderLabels([
            '#', 'Scan Name', 'Target', 'Folder',
            'Findings', 'Status', 'Date'
        ])
        self.scans_table.horizontalHeader(
        ).setSectionResizeMode(
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
        self.scans_table.cellDoubleClicked.connect(
            self.open_scan
        )
        self.scans_table.setColumnWidth(0, 40)
        self.scans_table.setColumnWidth(2, 140)
        self.scans_table.setColumnWidth(3, 140)
        self.scans_table.setColumnWidth(4, 80)
        self.scans_table.setColumnWidth(5, 90)
        self.scans_table.setColumnWidth(6, 90)
        layout.addWidget(self.scans_table)

        hint = QLabel(
            "Double-click any row to open scan"
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

        folders  = get_folders()
        col      = 0
        row      = 0
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
        card = QFrame()
        card.setObjectName("folderCard")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        card.setFixedSize(180, 110)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)

        icon = QLabel("📁")
        icon.setStyleSheet(
            "font-size: 22px; background: transparent;"
        )
        layout.addWidget(icon)

        name = QLabel(folder['name'])
        name.setObjectName("folderName")
        name.setWordWrap(True)
        layout.addWidget(name)

        count = folder.get('scan_count', 0)
        meta  = QLabel(
            f"{count} scan{'s' if count != 1 else ''}"
        )
        meta.setObjectName("folderMeta")
        layout.addWidget(meta)

        card.mousePressEvent = (
            lambda e, f=folder: self.open_folder(f)
        )
        return card

    def make_new_folder_card(self):
        card = QFrame()
        card.setObjectName("newFolderCard")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        card.setFixedSize(180, 110)
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        plus = QLabel("+")
        plus.setAlignment(Qt.AlignmentFlag.AlignCenter)
        plus.setStyleSheet(
            "font-size: 24px; color: #8b949e; "
            "background: transparent;"
        )
        layout.addWidget(plus)

        lbl = QLabel("Create New Folder")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px; "
            "background: transparent;"
        )
        layout.addWidget(lbl)

        card.mousePressEvent = (
            lambda e: self.create_folder()
        )
        return card

    def open_folder(self, folder):
        self.show_scans_tab(
            folder_id   = folder['id'],
            folder_name = folder['name']
        )

    def load_stats(self):
        while self.stats_row.count():
            child = self.stats_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM findings')
        total_findings = cursor.fetchone()[0]
        cursor.execute(
            "SELECT COUNT(*) FROM findings "
            "WHERE severity='Critical'"
        )
        critical = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM folders')
        total_folders = cursor.fetchone()[0]
        conn.close()

        stats = [
            ("Total Scans",    str(total_scans),    "#58a6ff"),
            ("Total Findings", str(total_findings), "#e94560"),
            ("Critical",       str(critical),       "#e94560"),
            ("Folders",        str(total_folders),  "#1d9e75"),
        ]

        for label, value, color in stats:
            card = QFrame()
            card.setObjectName("statCard")
            cl   = QVBoxLayout(card)
            cl.setContentsMargins(12, 8, 12, 8)

            val_lbl = QLabel(value)
            val_lbl.setAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            val_lbl.setStyleSheet(
                f"font-size: 20px; font-weight: bold; "
                f"color: {color}; border: none;"
            )
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                "font-size: 10px; color: #8b949e; "
                "border: none;"
            )
            cl.addWidget(val_lbl)
            cl.addWidget(lbl)
            self.stats_row.addWidget(card)

        self.stats_row.addStretch()

    def load_scans(self, folder_id=None):
        conn   = get_connection()
        cursor = conn.cursor()

        if folder_id:
            cursor.execute('''
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
            ''', (folder_id,))
        else:
            cursor.execute('''
                SELECT s.id, s.name, s.target, s.profile,
                       s.status, s.created_at,
                       COUNT(f.id) as finding_count,
                       fo.name as folder_name
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                LEFT JOIN folders fo ON s.folder_id = fo.id
                GROUP BY s.id
                ORDER BY s.id DESC
            ''')

        self.scans = cursor.fetchall()
        conn.close()
        self.populate_scans_table(self.scans)

    def populate_scans_table(self, scans):
        self.scans_table.setRowCount(0)
        for i, scan in enumerate(scans, 1):
            row = self.scans_table.rowCount()
            self.scans_table.insertRow(row)

            scan_id       = scan[0]
            name          = scan[1]
            target        = scan[2]
            status        = scan[4]
            created       = scan[5][:10] if scan[5] else ''
            finding_count = scan[6]
            folder_name   = scan[7] or '—'

            num = QTableWidgetItem(str(i))
            num.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            num.setForeground(QColor('#555'))

            name_item   = QTableWidgetItem(name)
            target_item = QTableWidgetItem(target)
            target_item.setForeground(QColor('#58a6ff'))

            folder_item = QTableWidgetItem(
                f"📁 {folder_name}"
                if folder_name != '—' else '—'
            )
            folder_item.setForeground(QColor('#8b949e'))

            count_item = QTableWidgetItem(
                str(finding_count)
            )
            count_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            if finding_count > 100:
                count_item.setForeground(QColor('#e94560'))
            elif finding_count > 50:
                count_item.setForeground(QColor('#ff8c00'))
            else:
                count_item.setForeground(QColor('#1d9e75'))

            status_item = QTableWidgetItem(
                status.title()
            )
            status_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            if status == 'completed':
                status_item.setForeground(QColor('#1d9e75'))
            else:
                status_item.setForeground(QColor('#ff8c00'))

            date_item = QTableWidgetItem(created)
            date_item.setForeground(QColor('#8b949e'))

            for col, item in enumerate([
                num, name_item, target_item,
                folder_item, count_item,
                status_item, date_item
            ]):
                self.scans_table.setItem(row, col, item)
            self.scans_table.setRowHeight(row, 36)

    def show_folders_tab(self):
        self.current_tab = 'folders'
        self.tab_folders.setStyleSheet(
            self.get_tab_active_style()
        )
        self.tab_scans.setStyleSheet(
            self.get_tab_inactive_style()
        )
        self.stack.setCurrentIndex(0)
        self.load_folders()

    def show_scans_tab(self, folder_id=None,
                       folder_name=None):
        self.current_tab = 'scans'
        self.tab_folders.setStyleSheet(
            self.get_tab_inactive_style()
        )
        self.tab_scans.setStyleSheet(
            self.get_tab_active_style()
        )
        self.stack.setCurrentIndex(1)
        self.load_scans(folder_id)
        self.load_stats()

    def open_scan(self, row, col):
        if row < len(self.scans):
            scan_id = self.scans[row][0]
            if self.on_scan_select:
                self.on_scan_select(scan_id)

    def create_folder(self):
        dialog = CreateFolderDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            insert_folder(
                dialog.folder_name, dialog.folder_desc
            )
            self.load_folders()

    def open_compare(self):
        if len(self.scans) < 2:
            QMessageBox.information(
                self,
                "Not Enough Scans",
                "You need at least 2 scans to compare.\n\n"
                "Run another scan first!"
            )
            return

        dialog = CompareScanDialog(self.scans, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.scan_a_id and dialog.scan_b_id:
                if self.on_diff:
                    self.on_diff(
                        dialog.scan_a_id,
                        dialog.scan_b_id
                    )

    def get_tab_active_style(self):
        return """
            QPushButton {
                background: transparent;
                color: #e94560;
                border: none;
                border-bottom: 2px solid #e94560;
                border-radius: 0;
                padding: 8px 20px;
                font-size: 12px;
                font-weight: bold;
            }
        """

    def get_tab_inactive_style(self):
        return """
            QPushButton {
                background: transparent;
                color: #8b949e;
                border: none;
                border-bottom: 2px solid transparent;
                border-radius: 0;
                padding: 8px 20px;
                font-size: 12px;
            }
            QPushButton:hover { color: #e6edf3; }
        """

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            #pageTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #pageSub {
                color: #8b949e;
                font-size: 12px;
            }
            #folderCard {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            #folderCard:hover {
                border: 1px solid #e94560;
            }
            #newFolderCard {
                background: transparent;
                border: 1px dashed #30363d;
                border-radius: 8px;
            }
            #newFolderCard:hover {
                border: 1px dashed #e94560;
            }
            #folderName {
                color: #e6edf3;
                font-size: 12px;
                font-weight: bold;
                background: transparent;
            }
            #folderMeta {
                color: #8b949e;
                font-size: 10px;
                background: transparent;
            }
            #statCard {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                min-width: 90px;
                max-width: 130px;
            }
            #primaryBtn {
                background: #e94560;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            #primaryBtn:hover { background: #c73652; }
            #compareBtn {
                background: #1d9e75;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            #compareBtn:hover { background: #178a64; }
            #scansTable {
                background: #161b22;
                border: 1px solid #30363d;
                gridline-color: #21262d;
                border-radius: 4px;
            }
            QHeaderView::section {
                background: #21262d;
                color: #8b949e;
                padding: 8px;
                border: none;
                font-size: 11px;
                font-weight: bold;
            }
            QTableWidget::item { padding: 4px 8px; }
            QTableWidget::item:selected {
                background: #21262d;
                color: #e94560;
            }
            #hintLbl {
                color: #444;
                font-size: 11px;
                margin-top: 4px;
            }
        """
