import math

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QFrame
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QColor, QPen,
    QLinearGradient, QRadialGradient, QBrush
)

from gui.preferences import load_prefs, get_theme


def rgba_from_hex(hex_color, alpha):
    color = QColor(hex_color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


class FindingEnrichWorker(QThread):
    done = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, finding):
        super().__init__()
        self.finding = finding

    def run(self):
        try:
            from backend.cve_enricher import (
                enrich_finding,
                get_attack_path_ai
            )

            result = enrich_finding(self.finding)
            nvd_best = result.get("nvd_best")

            attack_path, verify_steps = get_attack_path_ai(
                self.finding,
                nvd_best
            )

            result["attack_path"] = attack_path
            result["verify_steps"] = verify_steps

            self.done.emit(result)

        except Exception as e:
            self.error.emit(str(e))


class FindingLoadingScreen(QWidget):
    def __init__(
        self,
        finding,
        cached_data=None,
        on_loaded=None,
        on_back=None,
        prefs=None,
    ):
        super().__init__()

        self.finding = finding
        self.cached_data = cached_data
        self.on_loaded = on_loaded
        self.on_back = on_back

        self.worker = None
        self.progress_value = 0
        self.status_index = 0
        self.bg_phase = 0

        self.prefs = prefs or load_prefs()
        self.dark = self.prefs.get("dark_mode", True)
        self.fs = self.prefs.get("font_size", 13)
        self.theme = get_theme(self.dark)

        self.status_messages = [
            "Preparing finding context...",
            "Extracting CVE identifiers...",
            "Querying NVD, CIRCL and MITRE...",
            "Retrieving CWE and CVSS intelligence...",
            "Mapping MITRE ATT&CK techniques...",
            "Generating AI attack path recommendation...",
            "Generating verification steps...",
            "Preparing finding detail view..."
        ]

        self.init_ui()
        self.start_loading()

    def init_ui(self):
        t = self.theme

        self.setStyleSheet(f"""
            QWidget {{
                background-color: transparent;
                color: {t.get("text", "#E5EDF7")};
                font-family: Arial;
                font-size: {self.fs}px;
            }}
        """)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.card = QFrame()
        self.card.setObjectName("loadingCard")
        self.card.setFixedWidth(720)

        self.card.setStyleSheet("""
            QFrame#loadingCard {
                background-color: rgba(15, 23, 42, 230);
                border: 1px solid rgba(148, 163, 184, 80);
                border-radius: 18px;
            }
        """)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(42, 34, 42, 34)
        card_layout.setSpacing(18)

        # Shield icon
        self.icon_outer = QLabel("🛡")
        self.icon_outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_outer.setFixedSize(86, 86)
        self.icon_outer.setStyleSheet(f"""
            QLabel {{
                color: {t.get("accent", "#EF4444")};
                font-size: 42px;
                font-weight: 900;
                background-color: rgba(239, 68, 68, 18);
                border: 2px solid rgba(239, 68, 68, 110);
                border-radius: 43px;
            }}
        """)

        icon_row = QHBoxLayout()
        icon_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_row.addWidget(self.icon_outer)
        card_layout.addLayout(icon_row)

        # Title
        title = QLabel(
            'Loading <span style="color:#EF4444;">Finding Intelligence</span>'
        )
        title.setTextFormat(Qt.TextFormat.RichText)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"""
            QLabel {{
                color: {t.get("text", "#E5EDF7")};
                font-size: {self.fs + 15}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
        """)
        card_layout.addWidget(title)

        # Subtitle
        subtitle = QLabel(
            "AutoRed is collecting CVE, CWE, CVSS, MITRE and attack path data\n"
            "to build comprehensive finding intelligence."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"""
            QLabel {{
                color: {t.get("text_muted", "#94A3B8")};
                font-size: {self.fs + 1}px;
                background: transparent;
                border: none;
            }}
        """)
        card_layout.addWidget(subtitle)

        # Progress bar row
        progress_row = QHBoxLayout()
        progress_row.setSpacing(14)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(14)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(2, 6, 23, 210);
                border: 1px solid rgba(148, 163, 184, 75);
                border-radius: 7px;
            }
            QProgressBar::chunk {
                background-color: #EF4444;
                border-radius: 7px;
            }
        """)

        self.percent_label = QLabel("0%")
        self.percent_label.setFixedWidth(54)
        self.percent_label.setAlignment(
            Qt.AlignmentFlag.AlignRight |
            Qt.AlignmentFlag.AlignVCenter
        )
        self.percent_label.setStyleSheet(f"""
            QLabel {{
                color: {t.get("accent", "#EF4444")};
                font-size: {self.fs + 4}px;
                font-weight: 900;
                background: transparent;
                border: none;
            }}
        """)

        progress_row.addWidget(self.progress, 1)
        progress_row.addWidget(self.percent_label)
        card_layout.addLayout(progress_row)

        # Status row
        status_row = QHBoxLayout()
        status_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_row.setSpacing(12)

        self.dot = QLabel("●")
        self.dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dot.setFixedSize(28, 28)
        self.dot.setStyleSheet("""
            QLabel {
                color: #EF4444;
                font-size: 18px;
                background-color: rgba(239, 68, 68, 28);
                border: 1px solid rgba(239, 68, 68, 95);
                border-radius: 14px;
            }
        """)

        self.status_label = QLabel("Starting enrichment...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {t.get("text", "#E5EDF7")};
                font-size: {self.fs + 2}px;
                font-weight: 800;
                background: transparent;
                border: none;
            }}
        """)

        status_row.addWidget(self.dot)
        status_row.addWidget(self.status_label)
        card_layout.addLayout(status_row)

        # Divider
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet("""
            QFrame {
                background-color: rgba(148, 163, 184, 45);
                border: none;
            }
        """)
        card_layout.addWidget(divider)

        # Info message
        info = QLabel(
            "ⓘ  Please wait. The full finding detail screen will open automatically."
        )
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet(f"""
            QLabel {{
                color: {t.get("text_muted", "#94A3B8")};
                font-size: {self.fs}px;
                background: transparent;
                border: none;
            }}
        """)
        card_layout.addWidget(info)

        # TRUE CENTERING: vertical + horizontal spacers
        outer.addStretch(1)

        middle_row = QHBoxLayout()
        middle_row.setContentsMargins(0, 0, 0, 0)
        middle_row.setSpacing(0)

        middle_row.addStretch(1)
        middle_row.addWidget(
            self.card,
            0,
            Qt.AlignmentFlag.AlignCenter
        )
        middle_row.addStretch(1)

        outer.addLayout(middle_row)
        outer.addStretch(1)

        # Background animation
        self.bg_timer = QTimer(self)
        self.bg_timer.timeout.connect(self.animate_background)
        self.bg_timer.start(35)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()

        bg = QLinearGradient(0, 0, w, h)
        bg.setColorAt(0.0, QColor("#020617"))
        bg.setColorAt(0.45, QColor("#07111F"))
        bg.setColorAt(1.0, QColor("#01030A"))
        painter.fillRect(self.rect(), bg)

        red_glow = QRadialGradient(
            int(w * 0.50),
            int(h * 0.34),
            int(max(w, h) * 0.55)
        )
        red_glow.setColorAt(0.0, QColor(239, 68, 68, 34))
        red_glow.setColorAt(0.35, QColor(239, 68, 68, 12))
        red_glow.setColorAt(1.0, QColor(239, 68, 68, 0))
        painter.fillRect(self.rect(), QBrush(red_glow))

        blue_glow = QRadialGradient(
            int(w * 0.22),
            int(h * 0.18),
            int(max(w, h) * 0.48)
        )
        blue_glow.setColorAt(0.0, QColor(37, 99, 235, 20))
        blue_glow.setColorAt(0.40, QColor(37, 99, 235, 8))
        blue_glow.setColorAt(1.0, QColor(37, 99, 235, 0))
        painter.fillRect(self.rect(), QBrush(blue_glow))

        # Grid
        grid_pen = QPen(QColor(148, 163, 184, 24))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)

        shift = int(self.bg_phase % 48)

        for x in range(-48, w + 48, 48):
            painter.drawLine(x + shift, 0, x + shift, h)

        for y in range(-48, h + 48, 48):
            painter.drawLine(0, y + shift, w, y + shift)

        # Red wave points
        wave_pen = QPen(QColor(239, 68, 68, 38))
        wave_pen.setWidth(2)
        painter.setPen(wave_pen)

        base_y = int(h * 0.72)

        for x in range(0, w, 10):
            y = base_y + int(
                24 * math.sin((x + self.bg_phase * 3) / 60)
            )
            painter.drawPoint(x, y)

        fade = QLinearGradient(0, int(h * 0.55), 0, h)
        fade.setColorAt(0.0, QColor(2, 6, 23, 0))
        fade.setColorAt(1.0, QColor(2, 6, 23, 190))
        painter.fillRect(self.rect(), QBrush(fade))

    def animate_background(self):
        self.bg_phase = (self.bg_phase + 1) % 1000
        self.update()

    def start_loading(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate_progress)
        self.timer.start(280)

        if self.cached_data:
            QTimer.singleShot(900, self.finish_with_cached_data)
            return

        self.worker = FindingEnrichWorker(self.finding)
        self.worker.done.connect(self.finish_with_result)
        self.worker.error.connect(self.finish_with_error)
        self.worker.start()

    def animate_progress(self):
        if self.progress_value < 94:
            self.progress_value += 3
            self.progress.setValue(self.progress_value)
            self.percent_label.setText(f"{self.progress_value}%")

        self.status_index = (
            self.status_index + 1
        ) % len(self.status_messages)

        self.status_label.setText(
            self.status_messages[self.status_index]
        )

        if self.status_index % 2 == 0:
            self.dot.setStyleSheet("""
                QLabel {
                    color: #FCA5A5;
                    font-size: 18px;
                    background-color: rgba(239, 68, 68, 45);
                    border: 1px solid rgba(239, 68, 68, 130);
                    border-radius: 14px;
                }
            """)
        else:
            self.dot.setStyleSheet("""
                QLabel {
                    color: #EF4444;
                    font-size: 18px;
                    background-color: rgba(239, 68, 68, 22);
                    border: 1px solid rgba(239, 68, 68, 90);
                    border-radius: 14px;
                }
            """)

    def finish_with_cached_data(self):
        self.progress_value = 100
        self.progress.setValue(100)
        self.percent_label.setText("100%")
        self.status_label.setText(
            "Cached intelligence found. Opening finding detail..."
        )

        QTimer.singleShot(
            450,
            lambda: self.on_loaded(self.finding, self.cached_data)
            if self.on_loaded else None
        )

    def finish_with_result(self, result):
        self.progress_value = 100
        self.progress.setValue(100)
        self.percent_label.setText("100%")
        self.status_label.setText(
            "Intelligence ready. Opening finding detail..."
        )

        QTimer.singleShot(
            450,
            lambda: self.on_loaded(self.finding, result)
            if self.on_loaded else None
        )

    def finish_with_error(self, error):
        self.progress_value = 100
        self.progress.setValue(100)
        self.percent_label.setText("100%")
        self.status_label.setText(
            "Some enrichment failed. Opening detail with available data..."
        )

        fallback = {
            "error": error,
            "attack_path": "No attack path generated.",
            "verify_steps": "No verification steps generated.",
        }

        QTimer.singleShot(
            700,
            lambda: self.on_loaded(self.finding, fallback)
            if self.on_loaded else None
        )

    def apply_theme(self, prefs):
        self.prefs = prefs
        self.dark = prefs.get("dark_mode", True)
        self.fs = prefs.get("font_size", 13)
        self.theme = get_theme(self.dark)
        self.update()

    def cleanup(self):
        if hasattr(self, "timer"):
            self.timer.stop()

        if hasattr(self, "bg_timer"):
            self.bg_timer.stop()

        if self.worker and self.worker.isRunning():
            try:
                self.worker.done.disconnect()
                self.worker.error.disconnect()
            except Exception:
                pass
