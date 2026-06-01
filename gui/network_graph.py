import json
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from backend.db import get_connection

SEVERITY_COLORS = {
    'Critical': '#8b0000',
    'High':     '#e94560',
    'Medium':   '#ff8c00',
    'Low':      '#ffd700',
    'Info':     '#4a9eff',
}

SEVERITY_REASONS = {
    'Critical': 'Immediately exploitable. Poses direct risk of system compromise, data breach or remote code execution.',
    'High':     'Significant vulnerability. Could be exploited with moderate effort to compromise system integrity.',
    'Medium':   'Moderate risk. Requires specific conditions to exploit but should be remediated promptly.',
    'Low':      'Minor risk. Limited impact but contributes to attack surface. Should be addressed in future patches.',
    'Info':     'Informational finding. No direct risk but provides useful reconnaissance data.',
}

CATEGORY_COLORS = {
    'host':      '#1f6feb',
    'port':      '#e94560',
    'endpoint':  '#ff8c00',
    'tech':      '#1d9e75',
    'subdomain': '#9b59b6',
    'osint':     '#ffd700',
    'vuln':      '#ff4444',
}


class NetworkGraphView(QWidget):
    def __init__(self, scan_id, on_close=None):
        super().__init__()
        self.scan_id = scan_id
        self.on_close = on_close
        self.findings = []
        self.setStyleSheet(self.get_stylesheet())
        self.load_findings()
        self.init_ui()

    def load_findings(self):
        conn = get_connection()
        conn.row_factory = None
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, tool, asset, category, severity,
                   title, description, recommendation
            FROM findings WHERE scan_id=?
        ''', (self.scan_id,))
        rows = cursor.fetchall()
        conn.close()
        self.findings = [
            {
                'id':             r[0],
                'tool':           r[1],
                'asset':          r[2],
                'category':       r[3],
                'severity':       r[4],
                'title':          r[5],
                'description':    r[6] or '',
                'recommendation': r[7] or '',
            }
            for r in rows
        ]

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(8)

        top_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.setObjectName("backBtn")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        top_row.addWidget(back_btn)
        top_row.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("refreshBtn")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_graph)
        top_row.addWidget(refresh_btn)
        layout.addLayout(top_row)

        title = QLabel(f"Network Graph — Scan #{self.scan_id}")
        title.setObjectName("graphTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Hierarchical attack surface map. "
            "Hover nodes for details. Click to highlight connections."
        )
        subtitle.setObjectName("graphSub")
        layout.addWidget(subtitle)

        legend_row = QHBoxLayout()
        legend_lbl = QLabel("Legend:")
        legend_lbl.setStyleSheet(
            "color: #8b949e; font-size: 11px; "
            "background: transparent; border: none;"
        )
        legend_row.addWidget(legend_lbl)
        items = [
            ("Host",      CATEGORY_COLORS['host']),
            ("Port",      CATEGORY_COLORS['port']),
            ("Endpoint",  CATEGORY_COLORS['endpoint']),
            ("Tech",      CATEGORY_COLORS['tech']),
            ("Vuln",      CATEGORY_COLORS['vuln']),
            ("Subdomain", CATEGORY_COLORS['subdomain']),
            ("OSINT",     CATEGORY_COLORS['osint']),
        ]
        for label, color in items:
            dot = QLabel(f"● {label}")
            dot.setStyleSheet(
                f"color: {color}; font-size: 11px; "
                f"font-weight: bold; border: none; "
                f"background: transparent; padding: 0 6px;"
            )
            legend_row.addWidget(dot)
        legend_row.addStretch()
        layout.addLayout(legend_row)

        self.web = QWebEngineView()
        self.web.settings().setAttribute(
            QWebEngineSettings.WebAttribute.JavascriptEnabled, True
        )
        self.web.settings().setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls,
            True
        )
        layout.addWidget(self.web)
        self.load_graph()

    def build_graph_data(self):
        nodes = []
        edges = []
        seen_nodes = set()
        service_nodes = {}

        target_host = None
        for f in self.findings:
            if f['category'] == 'open_port':
                target_host = f['asset'].split('(')[0].strip()
                break
            elif f['category'] in ['live_host', 'tech_fingerprint',
                                    'endpoint']:
                url = f['asset']
                target_host = url.replace(
                    'http://', ''
                ).replace('https://', '').split('/')[0]
                break
        if not target_host:
            target_host = f"Target #{self.scan_id}"

        host_id = 'host_0'
        nodes.append({
            'data': {
                'id':       host_id,
                'label':    target_host,
                'type':     'host',
                'severity': 'Info',
                'tool':     'system',
                'title':    f'Target Host: {target_host}',
                'desc':     f'Primary scan target. All findings branch from this host.',
                'reason':   'This is the root scan target. All discovered assets belong to this host.',
                'fix':      'Ensure this host is within the authorised scope of your engagement.',
                'color':    CATEGORY_COLORS['host'],
                'size':     55,
                'shape':    'ellipse',
            }
        })
        seen_nodes.add(host_id)

        for f in self.findings:
            cat   = f['category']
            sev   = f['severity']
            title = f['title']
            asset = f['asset']
            tool  = f['tool']
            desc  = f['description']
            rec   = f['recommendation']
            sev_reason = SEVERITY_REASONS.get(sev, '')

            if cat == 'open_port':
                port_match = title.split('port ')
                if len(port_match) < 2:
                    continue
                port_str = port_match[1].split('/')[0]
                service  = title.split('— ')[-1].strip() \
                    if '— ' in title else 'unknown'

                port_id = f"port_{port_str}"
                if port_id not in seen_nodes:
                    nodes.append({
                        'data': {
                            'id':       port_id,
                            'label':    f":{port_str}\n{service[:10]}",
                            'type':     'port',
                            'severity': sev,
                            'tool':     tool,
                            'title':    f"Port {port_str} — {service}",
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Review and restrict access.',
                            'color':    SEVERITY_COLORS.get(sev, CATEGORY_COLORS['port']),
                            'size':     32,
                            'shape':    'ellipse',
                        }
                    })
                    seen_nodes.add(port_id)
                    edges.append({
                        'data': {
                            'id':     f"e_{host_id}_{port_id}",
                            'source': host_id,
                            'target': port_id,
                            'label':  'exposes',
                            'color':  SEVERITY_COLORS.get(sev, '#888'),
                        }
                    })
                    service_nodes[service.lower()[:8]] = port_id

            elif cat == 'endpoint':
                path = '/' + '/'.join(asset.split('/')[3:]) \
                    if len(asset.split('/')) > 3 else asset
                path_short = path[:18] + '..' \
                    if len(path) > 18 else path

                ep_id = f"ep_{abs(hash(asset)) % 999999}"
                if ep_id not in seen_nodes:
                    http_port = None
                    for s, pid in service_nodes.items():
                        if 'http' in s or 'web' in s or 'www' in s:
                            http_port = pid
                            break
                    parent = http_port or host_id

                    nodes.append({
                        'data': {
                            'id':       ep_id,
                            'label':    path_short,
                            'type':     'endpoint',
                            'severity': sev,
                            'tool':     tool,
                            'title':    f"Endpoint: {path_short}",
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Review endpoint accessibility.',
                            'color':    SEVERITY_COLORS.get(sev, CATEGORY_COLORS['endpoint']),
                            'size':     24,
                            'shape':    'round-rectangle',
                        }
                    })
                    seen_nodes.add(ep_id)
                    edges.append({
                        'data': {
                            'id':     f"e_{parent}_{ep_id}",
                            'source': parent,
                            'target': ep_id,
                            'label':  'hosts',
                            'color':  SEVERITY_COLORS.get(sev, '#888'),
                        }
                    })

            elif cat == 'tech_fingerprint':
                tech = title.replace(
                    'Technology detected: ', ''
                )[:22]
                tech_id = f"tech_{abs(hash(tech)) % 999999}"
                if tech_id not in seen_nodes:
                    http_port = None
                    for s, pid in service_nodes.items():
                        if 'http' in s or 'web' in s:
                            http_port = pid
                            break
                    parent = http_port or host_id

                    nodes.append({
                        'data': {
                            'id':       tech_id,
                            'label':    tech,
                            'type':     'tech',
                            'severity': sev,
                            'tool':     tool,
                            'title':    f"Technology: {tech}",
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Keep software updated.',
                            'color':    CATEGORY_COLORS['tech'],
                            'size':     24,
                            'shape':    'round-rectangle',
                        }
                    })
                    seen_nodes.add(tech_id)
                    edges.append({
                        'data': {
                            'id':     f"e_{parent}_{tech_id}",
                            'source': parent,
                            'target': tech_id,
                            'label':  'runs',
                            'color':  CATEGORY_COLORS['tech'],
                        }
                    })

            elif cat in ['web_vulnerability', 'network_vulnerability',
                         'service_vulnerability', 'cms_vulnerability',
                         'directory']:
                short   = title[:22] + '..' if len(title) > 22 else title
                vuln_id = f"vuln_{abs(hash(title+asset)) % 999999}"
                if vuln_id not in seen_nodes:
                    is_cve = 'CVE' in title.upper()
                    nodes.append({
                        'data': {
                            'id':       vuln_id,
                            'label':    short,
                            'type':     'vuln',
                            'severity': sev,
                            'tool':     tool,
                            'title':    title[:60],
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Apply vendor patch immediately.',
                            'color':    SEVERITY_COLORS.get(sev, CATEGORY_COLORS['vuln']),
                            'size':     28 if sev in ['Critical', 'High'] else 22,
                            'shape':    'diamond' if is_cve else 'ellipse',
                        }
                    })
                    seen_nodes.add(vuln_id)
                    port_parent = None
                    for s, pid in service_nodes.items():
                        if any(k in asset.lower() for k in [s[:4], s[:3]]):
                            port_parent = pid
                            break
                    parent = port_parent or host_id
                    edges.append({
                        'data': {
                            'id':     f"e_{parent}_{vuln_id}",
                            'source': parent,
                            'target': vuln_id,
                            'label':  'vulnerable_to',
                            'color':  SEVERITY_COLORS.get(sev, '#888'),
                        }
                    })

            elif cat == 'subdomain':
                sub_id = f"sub_{abs(hash(asset)) % 999999}"
                if sub_id not in seen_nodes:
                    nodes.append({
                        'data': {
                            'id':       sub_id,
                            'label':    asset[:20],
                            'type':     'subdomain',
                            'severity': sev,
                            'tool':     tool,
                            'title':    f"Subdomain: {asset}",
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Remove unused subdomains.',
                            'color':    CATEGORY_COLORS['subdomain'],
                            'size':     22,
                            'shape':    'ellipse',
                        }
                    })
                    seen_nodes.add(sub_id)
                    edges.append({
                        'data': {
                            'id':     f"e_{host_id}_{sub_id}",
                            'source': host_id,
                            'target': sub_id,
                            'label':  'subdomain',
                            'color':  CATEGORY_COLORS['subdomain'],
                        }
                    })

            elif cat in ['osint_host', 'osint_email',
                         'osint_ip', 'dns_record']:
                osint_id = f"osint_{abs(hash(asset+cat)) % 999999}"
                if osint_id not in seen_nodes:
                    nodes.append({
                        'data': {
                            'id':       osint_id,
                            'label':    asset[:18],
                            'type':     'osint',
                            'severity': sev,
                            'tool':     tool,
                            'title':    f"OSINT: {asset}",
                            'desc':     desc[:120] if desc else '',
                            'reason':   f"Rated {sev} because: {sev_reason}",
                            'fix':      rec[:120] if rec else 'Review OSINT exposure.',
                            'color':    CATEGORY_COLORS['osint'],
                            'size':     18,
                            'shape':    'round-rectangle',
                        }
                    })
                    seen_nodes.add(osint_id)
                    edges.append({
                        'data': {
                            'id':     f"e_{host_id}_{osint_id}",
                            'source': host_id,
                            'target': osint_id,
                            'label':  'discovered',
                            'color':  CATEGORY_COLORS['osint'],
                        }
                    })

        return nodes, edges

    def load_graph(self):
        nodes, edges = self.build_graph_data()
        graph_data   = json.dumps({'nodes': nodes, 'edges': edges})

        sev_colors_js = json.dumps(SEVERITY_COLORS)

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;font-family:Arial,sans-serif;overflow:hidden}}
#cy{{width:100vw;height:100vh;background:#0d1117}}
#tooltip{{
    position:absolute;background:#161b22;
    border:1px solid #30363d;border-radius:10px;
    padding:14px 16px;color:#e6edf3;font-size:12px;
    pointer-events:none;display:none;max-width:320px;
    z-index:999;box-shadow:0 8px 32px rgba(0,0,0,0.6);
}}
.tt-header{{display:flex;align-items:center;gap:8px;margin-bottom:10px;
    padding-bottom:8px;border-bottom:1px solid #30363d}}
.tt-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0}}
.tt-title{{color:#e6edf3;font-weight:bold;font-size:13px;line-height:1.3}}
.tt-sev{{display:inline-block;font-size:10px;font-weight:bold;
    padding:2px 8px;border-radius:10px;margin-bottom:8px}}
.tt-section{{margin-bottom:8px}}
.tt-label{{color:#8b949e;font-size:10px;font-weight:bold;
    text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}}
.tt-value{{color:#e6edf3;font-size:11px;line-height:1.5}}
.tt-reason{{color:#ff8c00;font-size:11px;line-height:1.5;
    background:#1a1208;border-radius:4px;padding:6px 8px;
    border-left:3px solid #ff8c00}}
.tt-fix{{color:#3fb950;font-size:11px;line-height:1.5;
    background:#0a1a0a;border-radius:4px;padding:6px 8px;
    border-left:3px solid #3fb950}}
#controls{{position:absolute;top:10px;right:10px;
    display:flex;flex-direction:column;gap:5px;z-index:100}}
.ctrl-btn{{background:#161b22;border:1px solid #30363d;
    border-radius:6px;color:#e6edf3;padding:6px 12px;
    cursor:pointer;font-size:11px;text-align:center;
    transition:all .15s}}
.ctrl-btn:hover{{border-color:#e94560;color:#e94560}}
.ctrl-btn.active{{background:#e94560;border-color:#e94560;color:white}}
#stats{{position:absolute;bottom:10px;left:10px;
    background:#161b22;border:1px solid #30363d;
    border-radius:8px;padding:8px 14px;color:#8b949e;
    font-size:10px;z-index:100;display:flex;gap:14px}}
#stats span{{color:#e6edf3;font-weight:bold}}
#stats .crit{{color:#e94560}}
</style>
</head>
<body>
<div id="cy"></div>
<div id="tooltip">
    <div class="tt-header">
        <div class="tt-dot" id="tt-dot"></div>
        <div class="tt-title" id="tt-title"></div>
    </div>
    <div id="tt-sev-badge" class="tt-sev"></div>
    <div class="tt-section">
        <div class="tt-label">Tool</div>
        <div class="tt-value" id="tt-tool"></div>
    </div>
    <div class="tt-section">
        <div class="tt-label">Description</div>
        <div class="tt-value" id="tt-desc"></div>
    </div>
    <div class="tt-section">
        <div class="tt-label">⚠ Why this severity?</div>
        <div class="tt-reason" id="tt-reason"></div>
    </div>
    <div class="tt-section">
        <div class="tt-label">✓ Recommendation</div>
        <div class="tt-fix" id="tt-fix"></div>
    </div>
</div>
<div id="controls">
    <div class="ctrl-btn" onclick="cy.fit()">⊞ Fit All</div>
    <div class="ctrl-btn" onclick="cy.zoom(cy.zoom()*1.3)">+ Zoom In</div>
    <div class="ctrl-btn" onclick="cy.zoom(cy.zoom()*0.75)">− Zoom Out</div>
    <div class="ctrl-btn" onclick="treeLayout()">🌳 Tree</div>
    <div class="ctrl-btn" onclick="forceLayout()">⊛ Force</div>
    <div class="ctrl-btn" onclick="toggleLabels(this)">⊟ Labels</div>
    <div class="ctrl-btn" onclick="filterCritical(this)">🔴 Critical</div>
    <div class="ctrl-btn" onclick="showAll()">✦ Show All</div>
</div>
<div id="stats">
    <div>Nodes: <span id="s-nodes">0</span></div>
    <div>Edges: <span id="s-edges">0</span></div>
    <div>Critical: <span id="s-crit" class="crit">0</span></div>
    <div>High: <span id="s-high" style="color:#ff8c00">0</span></div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<script>
const graphData = {graph_data};
const SEV_COLORS = {sev_colors_js};
let showLabels = true;
let criticalFilter = false;

const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: [...graphData.nodes, ...graphData.edges],
    style: [
        {{
            selector: 'node',
            style: {{
                'background-color':      'data(color)',
                'label':                 'data(label)',
                'color':                 '#ffffff',
                'text-valign':           'center',
                'text-halign':           'center',
                'font-size':             '8px',
                'font-weight':           'bold',
                'font-family':           'Arial',
                'width':                 'data(size)',
                'height':                'data(size)',
                'shape':                 'data(shape)',
                'text-wrap':             'wrap',
                'text-max-width':        '70px',
                'border-width':          1.5,
                'border-color':          'rgba(255,255,255,0.2)',
                'text-outline-width':    1.5,
                'text-outline-color':    'rgba(0,0,0,0.9)',
            }}
        }},
        {{
            selector: 'node[type="host"]',
            style: {{
                'font-size':      '10px',
                'border-width':   3,
                'border-color':   '#58a6ff',
                'text-outline-width': 2,
            }}
        }},
        {{
            selector: 'node[severity="Critical"]',
            style: {{
                'border-width':   3,
                'border-color':   '#ff0000',
                'border-opacity': 0.9,
            }}
        }},
        {{
            selector: 'node[severity="High"]',
            style: {{
                'border-width':   2.5,
                'border-color':   '#e94560',
            }}
        }},
        {{
            selector: 'node:selected',
            style: {{
                'border-width':   4,
                'border-color':   '#ffffff',
            }}
        }},
        {{
            selector: 'edge',
            style: {{
                'line-color':           'data(color)',
                'target-arrow-color':   'data(color)',
                'target-arrow-shape':   'triangle',
                'curve-style':          'bezier',
                'width':                1.2,
                'opacity':              0.45,
                'label':                'data(label)',
                'font-size':            '7px',
                'color':                '#8b949e',
                'text-outline-width':   1,
                'text-outline-color':   '#0d1117',
                'font-family':          'Arial',
                'text-rotation':        'autorotate',
            }}
        }},
        {{
            selector: '.faded',
            style: {{
                'opacity': 0.08,
            }}
        }},
        {{
            selector: '.highlighted',
            style: {{
                'opacity':        1,
                'border-width':   3,
                'border-color':   '#ffffff',
            }}
        }},
    ],
    layout: {{
        name:                        'breadthfirst',
        animate:                     true,
        animationDuration:           1000,
        directed:                    true,
        spacingFactor:               1.6,
        fit:                         true,
        padding:                     50,
        roots:                       '#host_0',
        avoidOverlap:                true,
        nodeDimensionsIncludeLabels: true,
        circle:                      false,
    }},
    minZoom: 0.05,
    maxZoom: 5,
    wheelSensitivity: 0.15,
}});

document.getElementById('s-nodes').textContent = cy.nodes().length;
document.getElementById('s-edges').textContent = cy.edges().length;
document.getElementById('s-crit').textContent  =
    cy.nodes().filter('[severity="Critical"]').length;
document.getElementById('s-high').textContent  =
    cy.nodes().filter('[severity="High"]').length;

const tooltip = document.getElementById('tooltip');

cy.on('mouseover', 'node', function(evt) {{
    const d = evt.target.data();
    if (d.type === 'host') {{
        tooltip.style.display = 'none';
        return;
    }}

    document.getElementById('tt-dot').style.background   = d.color;
    document.getElementById('tt-title').textContent       =
        d.title || d.label.replace(/\\n/g,' ');

    const sevBadge = document.getElementById('tt-sev-badge');
    const sevColor = SEV_COLORS[d.severity] || '#888';
    sevBadge.textContent        = d.severity || 'Info';
    sevBadge.style.background   = sevColor + '33';
    sevBadge.style.color        = sevColor;
    sevBadge.style.border       = '1px solid ' + sevColor;

    document.getElementById('tt-tool').textContent   =
        d.tool || 'N/A';
    document.getElementById('tt-desc').textContent   =
        d.desc || 'No description available.';
    document.getElementById('tt-reason').textContent =
        d.reason || 'See severity definition.';
    document.getElementById('tt-fix').textContent    =
        d.fix || 'Review and remediate.';

    tooltip.style.display = 'block';
}});

cy.on('mousemove', function(evt) {{
    const e   = evt.originalEvent;
    const rect = document.getElementById('cy').getBoundingClientRect();
    let x = e.clientX - rect.left + 18;
    let y = e.clientY - rect.top  + 12;
    if (x + 330 > rect.width)  x -= 340;
    if (y + 400 > rect.height) y -= 420;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
}});

cy.on('mouseout', 'node', function() {{
    tooltip.style.display = 'none';
}});

cy.on('tap', 'node', function(evt) {{
    cy.elements().removeClass('faded highlighted');
    const node      = evt.target;
    const connected = node.closedNeighborhood();
    cy.elements().not(connected).addClass('faded');
    connected.addClass('highlighted');
    setTimeout(() => {{
        cy.elements().removeClass('faded highlighted');
    }}, 3000);
}});

cy.on('tap', function(evt) {{
    if (evt.target === cy) {{
        cy.elements().removeClass('faded highlighted');
        tooltip.style.display = 'none';
    }}
}});

function treeLayout() {{
    cy.layout({{
        name:                        'breadthfirst',
        animate:                     true,
        animationDuration:           700,
        directed:                    true,
        spacingFactor:               1.6,
        fit:                         true,
        padding:                     50,
        roots:                       '#host_0',
        avoidOverlap:                true,
        nodeDimensionsIncludeLabels: true,
        circle:                      false,
    }}).run();
}}

function forceLayout() {{
    cy.layout({{
        name:             'cose',
        animate:          true,
        animationDuration:700,
        nodeRepulsion:    9000,
        idealEdgeLength:  130,
        fit:              true,
        padding:          50,
        randomize:        false,
    }}).run();
}}

function toggleLabels(btn) {{
    showLabels = !showLabels;
    cy.nodes().style({{
        'label': showLabels ? 'data(label)' : ''
    }});
    cy.edges().style({{
        'label': showLabels ? 'data(label)' : ''
    }});
    btn.classList.toggle('active', !showLabels);
}}

function filterCritical(btn) {{
    criticalFilter = !criticalFilter;
    btn.classList.toggle('active', criticalFilter);
    if (criticalFilter) {{
        cy.elements().addClass('faded');
        cy.nodes().filter(function(n) {{
            return n.data('severity') === 'Critical' ||
                   n.data('severity') === 'High'     ||
                   n.data('type')     === 'host';
        }}).removeClass('faded').addClass('highlighted');
    }} else {{
        cy.elements().removeClass('faded highlighted');
    }}
}}

function showAll() {{
    criticalFilter = false;
    showLabels     = true;
    cy.elements().removeClass('faded highlighted');
    cy.nodes().style({{'label': 'data(label)'}});
    cy.edges().style({{'label': 'data(label)'}});
    document.querySelectorAll('.ctrl-btn').forEach(
        b => b.classList.remove('active')
    );
    cy.fit(50);
}}
</script>
</body>
</html>"""

        self.web.setHtml(html, QUrl("http://localhost"))

    def refresh_graph(self):
        self.load_findings()
        self.load_graph()

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
            #graphTitle {
                color: #e94560;
                font-size: 20px;
                font-weight: bold;
                background: transparent;
                border: none;
            }
            #graphSub {
                color: #8b949e;
                font-size: 12px;
                background: transparent;
                border: none;
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
            #refreshBtn {
                background-color: transparent;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 12px;
            }
            #refreshBtn:hover {
                border-color: #e94560;
                color: #e94560;
            }
        """
