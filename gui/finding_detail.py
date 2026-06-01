from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QDesktopServices
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}


class EnrichWorker(QThread):
    done  = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, finding):
        super().__init__()
        self.finding = finding

    def run(self):
        try:
            from backend.cve_enricher import (
                enrich_finding, get_attack_path_ai
            )
            result      = enrich_finding(self.finding)
            nvd_best    = result.get('nvd_best')
            attack, verify = get_attack_path_ai(
                self.finding, nvd_best
            )
            result['attack_path']  = attack
            result['verify_steps'] = verify
            self.done.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class FindingDetail(QWidget):
    def __init__(self, finding, on_close=None,
                 on_status_change=None, cached_data=None):
        super().__init__()
        self.finding          = finding
        self.on_close         = on_close
        self.on_status_change = on_status_change
        self.enrich_worker    = None
        self.cached_data      = cached_data
        self.setStyleSheet(self.get_stylesheet())
        self.init_ui()
        if cached_data:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(
                50, lambda: self.on_enriched(cached_data)
            )
        else:
            self.start_enrichment()

    def sel(self, widget):
        widget.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        return widget

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: #0d1117; }"
        )

        content = QWidget()
        content.setStyleSheet("background: #0d1117;")
        layout  = QVBoxLayout(content)
        layout.setContentsMargins(30, 20, 30, 30)
        layout.setSpacing(14)

        # ── Back button ──────────────────────────────────────
        top_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        # ── Severity badge + title ───────────────────────────
        severity = self.finding.get('severity', 'Info')
        color    = SEVERITY_COLORS.get(severity, '#888')

        sev_badge = QLabel(f"  {severity}  ")
        sev_badge.setStyleSheet(
            f"background-color: {color}; color: white; "
            f"font-weight: bold; font-size: 12px; "
            f"border-radius: 4px; padding: 4px 8px; "
            f"border: none;"
        )
        sev_badge.setFixedHeight(28)

        title_lbl = self.sel(QLabel(
            self.finding.get('title', 'Untitled')
        ))
        title_lbl.setObjectName("detailTitle")
        title_lbl.setWordWrap(True)

        layout.addWidget(sev_badge)
        layout.addWidget(title_lbl)

        # ── Basic Info ───────────────────────────────────────
        info_frame = self.make_card()
        ifl        = QVBoxLayout(info_frame)
        ifl.setContentsMargins(16, 12, 16, 12)
        ifl.setSpacing(6)

        for label, key in [
            ("Tool",     'tool'),
            ("Asset",    'asset'),
            ("Category", 'category'),
        ]:
            row = QHBoxLayout()
            k   = QLabel(f"{label}:")
            k.setFixedWidth(100)
            k.setStyleSheet(
                "color: #8b949e; font-size: 12px; "
                "background: transparent; border: none;"
            )
            v = self.sel(QLabel(
                str(self.finding.get(key, 'N/A'))
            ))
            v.setStyleSheet(
                "color: #e6edf3; font-size: 12px; "
                "background: transparent; border: none;"
            )
            v.setWordWrap(True)
            row.addWidget(k)
            row.addWidget(v)
            row.addStretch()
            ifl.addLayout(row)

        layout.addWidget(info_frame)

        # ── Threat Intelligence & Exposure Analysis ──────────
        layout.addWidget(self.make_section_header(
            "🔍  THREAT INTELLIGENCE & EXPOSURE ANALYSIS",
            "CVE · CVSS · CWE · Exploitability · Attack Surface"
        ))

        self.intel_frame  = self.make_card(border='#4a9eff44')
        self.intel_layout = QVBoxLayout(self.intel_frame)
        self.intel_layout.setContentsMargins(16, 14, 16, 14)
        self.intel_layout.setSpacing(8)

        self.intel_loading = self.sel(QLabel(
            "🔍  Analysing threat intelligence..."
        ))
        self.intel_loading.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none;"
        )
        self.intel_layout.addWidget(self.intel_loading)
        layout.addWidget(self.intel_frame)

        # ── MITRE ATT&CK ─────────────────────────────────────
        layout.addWidget(self.make_section_header(
            "💥  MITRE ATT&CK CLASSIFICATION",
            "Live data from MITRE ATT&CK GitHub dataset (697 techniques)"
        ))

        self.mitre_frame  = self.make_card(border='#e9456044')
        self.mitre_layout = QVBoxLayout(self.mitre_frame)
        self.mitre_layout.setContentsMargins(16, 12, 16, 12)

        self.mitre_loading = self.sel(QLabel(
            "Mapping to MITRE ATT&CK..."
        ))
        self.mitre_loading.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none;"
        )
        self.mitre_layout.addWidget(self.mitre_loading)
        layout.addWidget(self.mitre_frame)

        # ── Finding Details ──────────────────────────────────
        layout.addWidget(
            self.make_section_header("📋  FINDING DETAILS")
        )

        for section_title, key, default in [
            ("Description",
             'description', 'No description.'),
            ("Evidence",
             'evidence', 'No evidence.'),
            ("Recommendation",
             'recommendation', 'No recommendation.'),
        ]:
            lbl = QLabel(section_title)
            lbl.setStyleSheet(
                "color: #8b949e; font-size: 11px; "
                "font-weight: bold; letter-spacing: 1px; "
                "background: transparent; border: none;"
            )
            layout.addWidget(lbl)

            txt = QTextEdit()
            txt.setPlainText(
                self.finding.get(key, default) or default
            )
            txt.setReadOnly(True)
            txt.setObjectName("sectionText")
            txt.setMaximumHeight(90)
            layout.addWidget(txt)

        # ── Attack Path ──────────────────────────────────────
        layout.addWidget(self.make_section_header(
            "🤖  ATTACK PATH RECOMMENDATION",
            "AI-generated exploitation planning (Claude API)"
        ))

        self.ap_frame = self.make_card(border='#e9456033')
        ap_fl = QVBoxLayout(self.ap_frame)
        ap_fl.setContentsMargins(16, 12, 16, 12)

        self.ap_lbl = self.sel(QLabel(
            "⏳  Generating AI attack path recommendations..."
        ))
        self.ap_lbl.setWordWrap(True)
        self.ap_lbl.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none; "
            "line-height: 1.8;"
        )
        ap_fl.addWidget(self.ap_lbl)
        layout.addWidget(self.ap_frame)

        # ── Verification Steps ───────────────────────────────
        layout.addWidget(self.make_section_header(
            "✅  HOW TO VERIFY THIS FINDING",
            "AI-generated manual verification guide for students"
        ))

        self.verify_frame = self.make_card(border='#1d9e7544')
        vf_fl = QVBoxLayout(self.verify_frame)
        vf_fl.setContentsMargins(16, 12, 16, 12)

        self.verify_lbl = self.sel(QLabel(
            "⏳  Generating verification steps..."
        ))
        self.verify_lbl.setWordWrap(True)
        self.verify_lbl.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none; "
            "line-height: 1.8;"
        )
        vf_fl.addWidget(self.verify_lbl)
        layout.addWidget(self.verify_frame)

        # ── Technical Notes ──────────────────────────────────
        layout.addWidget(self.make_section_header(
            "📝  YOUR TECHNICAL NOTES",
            "Add your manual verification results and findings"
        ))

        self.notes_input = QTextEdit()
        self.notes_input.setObjectName("sectionText")
        self.notes_input.setPlaceholderText(
            "e.g. Manually verified — connected to port 6200 "
            "and got root shell. CVE confirmed..."
        )
        self.notes_input.setMaximumHeight(100)
        saved = self.finding.get('analyst_notes', '')
        if saved:
            self.notes_input.setPlainText(saved)
        layout.addWidget(self.notes_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        save_btn = QPushButton("💾  Save Notes")
        save_btn.setObjectName("saveBtn")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self.save_notes)
        btn_row.addWidget(save_btn)

        copy_btn = QPushButton("📋  Copy Finding")
        copy_btn.setObjectName("copyBtn")
        copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_btn.clicked.connect(self.copy_finding)
        btn_row.addWidget(copy_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def make_card(self, border='#30363d'):
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background: #161b22; "
            f"border: 1px solid {border}; "
            f"border-radius: 6px; }}"
        )
        return frame

    def make_section_header(self, title, subtitle=None):
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background: transparent; border: none; }"
        )
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(0, 6, 0, 0)
        fl.setSpacing(2)

        row = QHBoxLayout()
        lbl = QLabel(title)
        lbl.setStyleSheet(
            "color: #e94560; font-size: 12px; "
            "font-weight: bold; letter-spacing: 1px; "
            "background: transparent; border: none;"
        )
        row.addWidget(lbl)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(
            "background: #30363d; border: none; "
            "max-height: 1px;"
        )
        row.addWidget(line)
        fl.addLayout(row)

        if subtitle:
            sub = self.sel(QLabel(subtitle))
            sub.setStyleSheet(
                "color: #555; font-size: 10px; "
                "background: transparent; border: none;"
            )
            fl.addWidget(sub)

        return frame

    def divider(self):
        d = QFrame()
        d.setFrameShape(QFrame.Shape.HLine)
        d.setStyleSheet(
            "background: #21262d; border: none; "
            "max-height: 1px; margin: 4px 0;"
        )
        return d

    def kv_row(self, key, value, val_color='#e6edf3'):
        row = QHBoxLayout()
        k   = QLabel(f"{key}:")
        k.setFixedWidth(150)
        k.setStyleSheet(
            "color: #8b949e; font-size: 12px; "
            "background: transparent; border: none;"
        )
        k.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        v = self.sel(QLabel(str(value)))
        v.setStyleSheet(
            f"color: {val_color}; font-size: 12px; "
            f"font-weight: bold; "
            f"background: transparent; border: none;"
        )
        v.setWordWrap(True)
        row.addWidget(k)
        row.addWidget(v)
        row.addStretch()
        return row

    def badge(self, text, bg, fg='white'):
        lbl = self.sel(QLabel(f"  {text}  "))
        lbl.setStyleSheet(
            f"background: {bg}33; color: {fg}; "
            f"border: 1px solid {bg}; "
            f"border-radius: 4px; "
            f"padding: 4px 10px; font-size: 11px; "
            f"font-weight: bold;"
        )
        return lbl

    def start_enrichment(self):
        self.enrich_worker = EnrichWorker(self.finding)
        self.enrich_worker.done.connect(self.on_enriched)
        self.enrich_worker.error.connect(self.on_enrich_error)
        self.enrich_worker.start()

    def on_enriched(self, result):
        self.render_intel(result)
        self.render_mitre(result)
        self.render_attack_path(result)
        self.render_verify_steps(result)

    def render_intel(self, result):
        # Clear loading
        while self.intel_layout.count():
            item = self.intel_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        nvd      = result.get('nvd_best') or {}
        cwe_data = result.get('cwe_data')
        tags     = result.get('attack_surface', [])
        level    = result.get('exploit_level', '')
        reason   = result.get('exploit_reason', '')
        is_fb    = nvd.get('is_fallback', False)
        cve_id   = nvd.get('cve_id', '')
        has_cve  = bool(cve_id and 'No CVE' not in cve_id)

        # ── Section: CVE ─────────────────────────────────────
        cve_header = QLabel("CVE IDENTIFIER")
        cve_header.setStyleSheet(
            "color: #4a9eff; font-size: 10px; "
            "font-weight: bold; letter-spacing: 2px; "
            "background: transparent; border: none; "
            "margin-top: 4px;"
        )
        self.intel_layout.addWidget(cve_header)

        if has_cve:
            score    = nvd.get('cvss_score', 'N/A')
            version  = nvd.get('cvss_version', '')
            severity = nvd.get('cvss_severity', '')
            pub      = nvd.get('published', '')
            mod      = nvd.get('last_modified', 'N/A')
            vector   = nvd.get('cvss_vector', '')
            desc     = nvd.get('description', '')[:250]
            nvd_url  = nvd.get('nvd_url', '')
            av       = nvd.get('attack_vector', '')
            ac       = nvd.get('attack_complexity', '')
            pr       = nvd.get('privileges_req', '')
            ui       = nvd.get('user_interaction', '')
            weak     = ', '.join(nvd.get('weaknesses', []))

            sev_color = {
                'CRITICAL': '#8b0000',
                'HIGH':     '#e94560',
                'MEDIUM':   '#ff8c00',
                'LOW':      '#ffd700',
            }.get(str(severity).upper(), '#4a9eff')

            source = (
                'NVD API (Live)'
                if not is_fb and not nvd.get('found_by')
                else 'NVD API — Keyword Match'
                if nvd.get('found_by')
                else 'Known Vulnerability DB + NVD'
            )

            for label, value, col in [
                ("CVE ID",       cve_id,                         '#4a9eff'),
                ("CVSS Score",
                 f"{score} / 10.0 (v{version})",                sev_color),
                ("Severity",     severity or 'See score',        sev_color),
                ("Published",    pub,                            '#e6edf3'),
                ("Last Updated", mod,                            '#e6edf3'),
                ("CVSS Vector",  vector,                         '#8b949e'),
                ("Attack Vector",av,                             '#e6edf3'),
                ("Complexity",   ac,                             '#e6edf3'),
                ("Privileges",   pr,                             '#e6edf3'),
                ("User Interaction", ui,                         '#e6edf3'),
                ("Weakness",     weak or 'N/A',                  '#e6edf3'),
                ("Data Source",  source,                         '#555'),
            ]:
                if value:
                    self.intel_layout.addLayout(
                        self.kv_row(label, value, col)
                    )

            if desc:
                d = self.sel(QLabel(f"NVD Description: {desc}..."))
                d.setWordWrap(True)
                d.setStyleSheet(
                    "color: #8b949e; font-size: 11px; "
                    "background: transparent; border: none; "
                    "margin-top: 4px;"
                )
                self.intel_layout.addWidget(d)

            if nvd_url:
                btn = QPushButton(f"🔗  View on NVD — {cve_id}")
                btn.setObjectName("nvdBtn")
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.clicked.connect(
                    lambda u=nvd_url:
                    QDesktopServices.openUrl(QUrl(u))
                )
                self.intel_layout.addWidget(btn)

        else:
            no_cve = self.sel(QLabel(
                "No direct CVE assigned — "
                "this is a configuration or protocol exposure."
            ))
            no_cve.setWordWrap(True)
            no_cve.setStyleSheet(
                "color: #8b949e; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.intel_layout.addWidget(no_cve)

            if cve_id and 'No CVE' in cve_id:
                score   = nvd.get('cvss_score', '')
                version = nvd.get('cvss_version', '')
                vector  = nvd.get('cvss_vector', '')
                if score:
                    self.intel_layout.addLayout(
                        self.kv_row(
                            "Exposure CVSS",
                            f"{score} / 10.0 (v{version})",
                            '#ff8c00'
                        )
                    )
                if vector:
                    self.intel_layout.addLayout(
                        self.kv_row(
                            "CVSS Vector",
                            vector,
                            '#8b949e'
                        )
                    )

        # ── Section: CWE ─────────────────────────────────────
        self.intel_layout.addWidget(self.divider())

        cwe_header = QLabel("CWE WEAKNESS CLASSIFICATION")
        cwe_header.setStyleSheet(
            "color: #ff8c00; font-size: 10px; "
            "font-weight: bold; letter-spacing: 2px; "
            "background: transparent; border: none; "
            "margin-top: 4px;"
        )
        self.intel_layout.addWidget(cwe_header)

        if cwe_data:
            self.intel_layout.addLayout(
                self.kv_row(
                    "CWE ID",
                    f"{cwe_data['cwe_id']}",
                    '#ff8c00'
                )
            )
            self.intel_layout.addLayout(
                self.kv_row(
                    "Weakness Name",
                    cwe_data['name'],
                    '#e6edf3'
                )
            )
            self.intel_layout.addLayout(
                self.kv_row(
                    "Risk Basis",
                    cwe_data.get('risk', ''),
                    '#8b949e'
                )
            )
            cwe_url = cwe_data.get('url', '')
            if cwe_url:
                cwe_btn = QPushButton(
                    f"🔗  View on MITRE CWE — {cwe_data['cwe_id']}"
                )
                cwe_btn.setObjectName("nvdBtn")
                cwe_btn.setCursor(
                    Qt.CursorShape.PointingHandCursor
                )
                cwe_btn.clicked.connect(
                    lambda u=cwe_url:
                    QDesktopServices.openUrl(QUrl(u))
                )
                self.intel_layout.addWidget(cwe_btn)
        else:
            no_cwe = self.sel(QLabel(
                "No CWE classification available for this finding."
            ))
            no_cwe.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.intel_layout.addWidget(no_cwe)

        # ── Section: Exploitability ───────────────────────────
        self.intel_layout.addWidget(self.divider())

        exp_header = QLabel("EXPLOITABILITY ASSESSMENT")
        exp_header.setStyleSheet(
            "color: #1d9e75; font-size: 10px; "
            "font-weight: bold; letter-spacing: 2px; "
            "background: transparent; border: none; "
            "margin-top: 4px;"
        )
        self.intel_layout.addWidget(exp_header)

        color_map = {
            'Easy':      '#e94560',
            'Moderate':  '#ff8c00',
            'Difficult': '#ffd700',
            'Unknown':   '#555',
        }
        exp_color = color_map.get(level or 'Unknown', '#555')

        exp_row = QHBoxLayout()
        if level:
            exp_badge = self.badge(
                f"⚡ {level}", exp_color
            )
            exp_row.addWidget(exp_badge)

        exp_score = nvd.get('exploitability', '')
        if exp_score:
            score_lbl = self.sel(QLabel(
                f"  NVD Score: {exp_score} / 3.9"
            ))
            score_lbl.setStyleSheet(
                "color: #8b949e; font-size: 12px; "
                "background: transparent; border: none;"
            )
            exp_row.addWidget(score_lbl)

        exp_row.addStretch()
        self.intel_layout.addLayout(exp_row)

        if reason:
            r = self.sel(QLabel(f"Basis: {reason}"))
            r.setWordWrap(True)
            r.setStyleSheet(
                "color: #8b949e; font-size: 11px; "
                "background: transparent; border: none; "
                "margin-top: 2px;"
            )
            self.intel_layout.addWidget(r)

        if not level and not exp_score:
            no_exp = self.sel(QLabel(
                "Exploitability not determined — "
                "manual assessment required."
            ))
            no_exp.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.intel_layout.addWidget(no_exp)

        # ── Section: Attack Surface ───────────────────────────
        self.intel_layout.addWidget(self.divider())

        surf_header = QLabel("ATTACK SURFACE TAGS")
        surf_header.setStyleSheet(
            "color: #9b59b6; font-size: 10px; "
            "font-weight: bold; letter-spacing: 2px; "
            "background: transparent; border: none; "
            "margin-top: 4px;"
        )
        self.intel_layout.addWidget(surf_header)

        if tags:
            tag_row = QHBoxLayout()
            tag_row.setSpacing(8)
            for tag in tags:
                lbl = self.sel(QLabel(f"  {tag}  "))
                lbl.setStyleSheet(
                    "background: #9b59b633; color: #9b59b6; "
                    "border: 1px solid #9b59b6; "
                    "border-radius: 4px; "
                    "padding: 4px 8px; font-size: 11px; "
                    "font-weight: bold;"
                )
                tag_row.addWidget(lbl)
            tag_row.addStretch()
            self.intel_layout.addLayout(tag_row)
        else:
            no_tags = self.sel(QLabel("No attack surface tags detected."))
            no_tags.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.intel_layout.addWidget(no_tags)

    def render_mitre(self, result):
        while self.mitre_layout.count():
            item = self.mitre_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        mitre = result.get('mitre')
        if not mitre:
            lbl = self.sel(QLabel(
                "No MITRE ATT&CK mapping found for this finding."
            ))
            lbl.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.mitre_layout.addWidget(lbl)
            return

        tactic    = mitre.get('tactic', '')
        tactic_id = mitre.get('tactic_id', '')
        tech      = mitre.get('technique', '')
        tech_id   = mitre.get('tech_id', '')
        sub       = mitre.get('subtechnique') or 'N/A'
        source    = mitre.get('source', 'MITRE ATT&CK GitHub')

        for label, value, col in [
            ("Tactic",
             f"{tactic} ({tactic_id})", '#ff8c00'),
            ("Technique",
             f"{tech} ({tech_id})",     '#e6edf3'),
            ("Sub-technique", sub,      '#8b949e'),
            ("Source",        source,   '#555'),
        ]:
            self.mitre_layout.addLayout(
                self.kv_row(label, value, col)
            )

        url = mitre.get('url', '')
        if url:
            btn = QPushButton(
                f"🔗  Open MITRE ATT&CK — {tech_id}"
            )
            btn.setObjectName("nvdBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda u=url:
                QDesktopServices.openUrl(QUrl(u))
            )
            self.mitre_layout.addWidget(btn)

    def render_attack_path(self, result):
        attack = result.get('attack_path')
        if attack:
            self.ap_lbl.setStyleSheet(
                "color: #e6edf3; font-size: 12px; "
                "background: transparent; border: none; "
                "line-height: 1.8;"
            )
            self.ap_lbl.setText(attack)
        else:
            self.ap_lbl.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.ap_lbl.setText(
                "Attack path not available. "
                "Check AI API key in .env file."
            )

    def render_verify_steps(self, result):
        verify = result.get('verify_steps')
        if verify:
            self.verify_lbl.setStyleSheet(
                "color: #b5e5b5; font-size: 12px; "
                "background: transparent; border: none; "
                "line-height: 1.8;"
            )
            self.verify_lbl.setText(verify)
        else:
            self.verify_lbl.setStyleSheet(
                "color: #555; font-size: 12px; "
                "background: transparent; border: none;"
            )
            self.verify_lbl.setText(
                "Verification steps not available."
            )

    def on_enrich_error(self, error):
        self.intel_loading.setText(
            f"Intelligence unavailable: {error}"
        )
        self.ap_lbl.setText("Attack path unavailable.")
        self.verify_lbl.setText(
            "Verification steps unavailable."
        )

    def save_notes(self):
        notes      = self.notes_input.toPlainText().strip()
        finding_id = self.finding.get('id')
        if finding_id:
            try:
                conn   = get_connection()
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        'ALTER TABLE findings '
                        'ADD COLUMN analyst_notes TEXT'
                    )
                    conn.commit()
                except Exception:
                    pass
                cursor.execute(
                    'UPDATE findings SET analyst_notes=? '
                    'WHERE id=?',
                    (notes, finding_id)
                )
                conn.commit()
                conn.close()
                self.finding['analyst_notes'] = notes
                print(
                    f"[+] Notes saved for "
                    f"finding {finding_id}"
                )
            except Exception as e:
                print(f"[!] Save notes error: {e}")

    def copy_finding(self):
        from PyQt6.QtWidgets import QApplication
        severity = self.finding.get('severity', '')
        title    = self.finding.get('title', '')
        tool     = self.finding.get('tool', '')
        asset    = self.finding.get('asset', '')
        desc     = self.finding.get('description', '')
        rec      = self.finding.get('recommendation', '')

        text = (
            f"[{severity}] {title}\n"
            f"Tool: {tool} | Asset: {asset}\n\n"
            f"Description:\n{desc}\n\n"
            f"Recommendation:\n{rec}"
        )
        QApplication.clipboard().setText(text)
        print("[+] Finding copied to clipboard")

    def go_back(self):
        if self.on_close:
            self.on_close()

    def get_stylesheet(self):
        return """
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: Arial;
                font-size: 13px;
            }
            QScrollArea {
                border: none;
                background: #0d1117;
            }
            #backBtn {
                background-color: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 12px;
            }
            #backBtn:hover {
                color: #e6edf3;
                border-color: #e6edf3;
            }
            #detailTitle {
                color: #e6edf3;
                font-size: 18px;
                font-weight: bold;
                background: transparent;
                border: none;
            }
            #sectionText {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                font-size: 12px;
            }
            #saveBtn {
                background-color: #1d9e75;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            #saveBtn:hover { background-color: #178a64; }
            #copyBtn {
                background-color: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 12px;
            }
            #copyBtn:hover {
                color: #e6edf3;
                border-color: #e6edf3;
            }
            #nvdBtn {
                background-color: transparent;
                color: #4a9eff;
                border: 1px solid #4a9eff44;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 11px;
                margin-top: 4px;
            }
            #nvdBtn:hover {
                background: #4a9eff22;
                border-color: #4a9eff;
            }
        """
