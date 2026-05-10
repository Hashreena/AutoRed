from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from backend.db import get_connection
import os
import shutil

ACTION_STYLE = """
    QWidget { background-color: transparent; }
    QPushButton#openBtn {
        background-color: #1d9e75;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: bold;
    }
    QPushButton#openBtn:hover { background-color: #158a63; }
    QPushButton#deleteBtn {
        background-color: transparent;
        color: #e94560;
        border: 1px solid #e94560;
        border-radius: 4px;
        padding: 4px 10px;
        font-size: 12px;
    }
    QPushButton#deleteBtn:hover {
        background-color: #e94560;
        color: white;
    }
"""

class OpenScanScreen(QWidget):
    def __init__(self, on_scan_select=None):
        super().__init__()
        self.on_scan_select = on_scan_select
        self.scans = []
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        self.load_scans()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 20, 30, 20)

        top_row = QHBoxLayout()
        title = QLabel("Open Existing Scan")
        title.setObjectName("screenTitle")
        top_row.addWidget(title)
        top_row.addStretch()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("refreshBtn")
        refresh_btn.clicked.connect(self.load_scans)
        top_row.addWidget(refresh_btn)
        layout.addLayout(top_row)

        subtitle = QLabel("Select a past scan to view its findings dashboard.")
        subtitle.setObjectName("subTitle")
        layout.addWidget(subtitle)
        layout.addSpacing(15)

        self.stats_row = QHBoxLayout()
        layout.addLayout(self.stats_row)
        layout.addSpacing(15)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            '#', 'Scan Name', 'Target', 'Profile',
            'Date', 'Findings', 'Actions'
        ])
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setObjectName("scanTable")
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 140)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 160)
        layout.addWidget(self.table)

        hint = QLabel(
            "Click 'Open' to view findings  |  "
            "Click 'Delete' to remove a scan permanently."
        )
        hint.setObjectName("hintLbl")
        layout.addWidget(hint)

    def load_scans(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.id, s.name, s.target, s.profile,
                   s.created_at, COUNT(f.id) as finding_count
            FROM scans s
            LEFT JOIN findings f ON s.id = f.scan_id
            GROUP BY s.id
            ORDER BY s.id DESC
        ''')
        self.scans = cursor.fetchall()
        conn.close()
        self.update_stats()
        self.populate_table()

    def update_stats(self):
        while self.stats_row.count():
            child = self.stats_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        total_scans = len(self.scans)
        total_findings = sum(s[5] for s in self.scans)
        scans_with_findings = sum(1 for s in self.scans if s[5] > 0)

        cards = [
            ("Total Scans",         str(total_scans),         "#4a9eff"),
            ("Scans with Findings", str(scans_with_findings), "#1d9e75"),
            ("Total Findings",      str(total_findings),      "#e94560"),
        ]
        for label, value, color in cards:
            card = self.make_card(label, value, color)
            self.stats_row.addWidget(card)
        self.stats_row.addStretch()

    def make_card(self, label, value, color):
        card = QFrame()
        card.setObjectName("statsCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 10, 20, 10)
        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"font-size: 26px; font-weight: bold; "
            f"color: {color}; border: none;"
        )
        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 11px; color: #888; border: none;")
        card_layout.addWidget(val_lbl)
        card_layout.addWidget(lbl)
        return card

    def populate_table(self):
        self.table.setRowCount(0)
        for i, scan in enumerate(self.scans, 1):
            scan_id, name, target, profile, created_at, finding_count = scan
            row = self.table.rowCount()
            self.table.insertRow(row)

            num_item = QTableWidgetItem(str(i))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(QColor('#888'))

            name_item = QTableWidgetItem(str(name))
            target_item = QTableWidgetItem(str(target))

            profile_item = QTableWidgetItem(str(profile))
            profile_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            date_str = str(created_at)[:16] if created_at else 'N/A'
            date_item = QTableWidgetItem(date_str)
            date_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            count_item = QTableWidgetItem(str(finding_count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if finding_count > 0:
                count_item.setForeground(QColor('#e94560'))
            else:
                count_item.setForeground(QColor('#888'))

            self.table.setItem(row, 0, num_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, target_item)
            self.table.setItem(row, 3, profile_item)
            self.table.setItem(row, 4, date_item)
            self.table.setItem(row, 5, count_item)

            action_widget = QWidget()
            action_widget.setStyleSheet(ACTION_STYLE)
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(8, 4, 8, 4)
            action_layout.setSpacing(8)

            open_btn = QPushButton("Open")
            open_btn.setObjectName("openBtn")
            open_btn.setFixedHeight(28)
            open_btn.setMinimumWidth(60)
            open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            open_btn.clicked.connect(
                lambda checked, sid=scan_id: self.open_scan(sid)
            )

            delete_btn = QPushButton("Delete")
            delete_btn.setObjectName("deleteBtn")
            delete_btn.setFixedHeight(28)
            delete_btn.setMinimumWidth(60)
            delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            delete_btn.clicked.connect(
                lambda checked, sid=scan_id,
                sname=name: self.delete_scan(sid, sname)
            )

            action_layout.addWidget(open_btn)
            action_layout.addWidget(delete_btn)
            action_layout.addStretch()
            self.table.setCellWidget(row, 6, action_widget)
            self.table.setRowHeight(row, 44)

    def open_scan(self, scan_id):
        if self.on_scan_select:
            self.on_scan_select(scan_id)

    def delete_scan(self, scan_id, scan_name):
        msg = QMessageBox()
        msg.setWindowTitle("Confirm Delete")
        msg.setText(
            f"Are you sure you want to delete:\n'{scan_name}'?\n\n"
            f"This will permanently remove all findings\n"
            f"and stored output files for this scan."
        )
        msg.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        msg.setDefaultButton(QMessageBox.StandardButton.No)
        reply = msg.exec()

        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM findings WHERE scan_id=?', (scan_id,)
            )
            cursor.execute(
                'DELETE FROM tool_runs WHERE scan_id=?', (scan_id,)
            )
            cursor.execute(
                'DELETE FROM audit_logs WHERE scan_id=?', (scan_id,)
            )
            cursor.execute(
                'DELETE FROM scans WHERE id=?', (scan_id,)
            )
            conn.commit()
            conn.close()

            storage_path = os.path.join('storage', str(scan_id))
            if os.path.exists(storage_path):
                shutil.rmtree(storage_path)

            print(f"[+] Scan {scan_id} deleted")
            self.load_scans()

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 13px;
            }
            #screenTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
            }
            #subTitle {
                color: #888;
                font-size: 12px;
            }
            #statsCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                min-width: 130px;
                max-width: 200px;
            }
            #scanTable {
                background-color: #16213e;
                border: 1px solid #0f3460;
                gridline-color: #0f3460;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #e0e0e0;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 4px 8px;
            }
            QTableWidget::item:selected {
                background-color: #0f3460;
                color: #e94560;
            }
            #refreshBtn {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
                border-radius: 4px;
                padding: 6px 16px;
            }
            #refreshBtn:hover {
                border: 1px solid #e94560;
                color: #e94560;
            }
            #hintLbl {
                color: #444;
                font-size: 11px;
                margin-top: 4px;
            }
        """
