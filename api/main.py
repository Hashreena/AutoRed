from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.db import init_db, insert_scan, get_scans, get_findings, get_connection
from backend.scope import validate_target

app = FastAPI(
    title="AutoRed API",
    description="REST API for AutoRed Recon Automation Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

class ScanRequest(BaseModel):
    name: str
    target: str
    profile: str = "Standard"
    tools: List[str] = ["nmap", "subfinder", "httpx", "whatweb", "ffuf"]
    approval_ref: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: int
    name: str
    target: str
    profile: str
    status: str
    message: str

def run_scan_background(scan_id, target, profile, tools):
    from backend.job_queue import run_scan
    presets = {t: 'quick' for t in tools}
    run_scan(
        scan_id=scan_id,
        target=target,
        profile=profile,
        selected_tools=tools,
        presets=presets
    )
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='completed' WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()

@app.get("/")
def root():
    return {
        "name": "AutoRed API",
        "version": "1.0.0",
        "description": "Recon Automation Platform API",
        "endpoints": [
            "GET  /scans          — list all scans",
            "POST /scans          — start a new scan",
            "GET  /scans/{id}     — get scan details",
            "GET  /scans/{id}/findings — get findings",
            "GET  /scans/{id}/status   — get scan status",
            "GET  /tools          — list available tools",
            "POST /validate       — validate a target",
        ]
    }

@app.get("/tools")
def list_tools():
    return {
        "tools": [
            {
                "name": "nmap",
                "description": "Port scanning and service detection",
                "category": "port_scanner"
            },
            {
                "name": "subfinder",
                "description": "Subdomain enumeration via OSINT",
                "category": "asset_discovery"
            },
            {
                "name": "httpx",
                "description": "Live host identification",
                "category": "host_discovery"
            },
            {
                "name": "whatweb",
                "description": "Web technology fingerprinting",
                "category": "fingerprinting"
            },
            {
                "name": "ffuf",
                "description": "Directory and endpoint fuzzing",
                "category": "enumeration"
            },
        ]
    }

@app.post("/validate")
def validate(target: dict):
    t = target.get("target", "")
    result = validate_target(t)
    return {
        "target": t,
        "allowed": result["allowed"],
        "reason": result["reason"]
    }

@app.get("/scans")
def list_scans():
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.id, s.name, s.target, s.profile, s.status,
               s.created_at, COUNT(f.id) as finding_count
        FROM scans s
        LEFT JOIN findings f ON s.id = f.scan_id
        GROUP BY s.id
        ORDER BY s.id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": len(rows),
        "scans": [
            {
                "id": r[0],
                "name": r[1],
                "target": r[2],
                "profile": r[3],
                "status": r[4],
                "created_at": r[5],
                "finding_count": r[6]
            }
            for r in rows
        ]
    }

@app.post("/scans")
def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    validation = validate_target(request.target)
    if not validation["allowed"]:
        raise HTTPException(
            status_code=400,
            detail=f"Target blocked: {validation['reason']}"
        )

    valid_tools = ["nmap", "subfinder", "httpx", "whatweb", "ffuf"]
    tools = [t for t in request.tools if t in valid_tools]
    if not tools:
        raise HTTPException(
            status_code=400,
            detail="No valid tools selected"
        )

    valid_profiles = ["Production", "Standard", "Deep"]
    if request.profile not in valid_profiles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid profile. Choose from: {valid_profiles}"
        )

    scan_id = insert_scan(
        name=request.name,
        target=request.target,
        profile=request.profile,
        approval_ref=request.approval_ref
    )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='running' WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()

    background_tasks.add_task(
        run_scan_background,
        scan_id,
        request.target,
        request.profile,
        tools
    )

    return {
        "scan_id": scan_id,
        "name": request.name,
        "target": request.target,
        "profile": request.profile,
        "tools": tools,
        "status": "running",
        "message": f"Scan started. Use GET /scans/{scan_id}/status to check progress."
    }

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": row[0],
        "name": row[1],
        "target": row[2],
        "profile": row[3],
        "status": row[4],
        "approval_ref": row[5],
        "created_at": row[6],
        "completed_at": row[7]
    }

@app.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: int):
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM scans WHERE id=?', (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    cursor.execute('''
        SELECT tool, status FROM tool_runs
        WHERE scan_id=?
    ''', (scan_id,))
    tool_runs = cursor.fetchall()

    cursor.execute(
        'SELECT COUNT(*) FROM findings WHERE scan_id=?',
        (scan_id,)
    )
    finding_count = cursor.fetchone()[0]
    conn.close()

    return {
        "scan_id": scan_id,
        "status": row[0],
        "finding_count": finding_count,
        "tool_runs": [
            {"tool": r[0], "status": r[1]}
            for r in tool_runs
        ]
    }

@app.get("/scans/{scan_id}/findings")
def get_scan_findings(
    scan_id: int,
    severity: Optional[str] = None,
    tool: Optional[str] = None
):
    conn = get_connection()
    conn.row_factory = None
    cursor = conn.cursor()

    query = '''
        SELECT id, tool, asset, category, severity,
               title, description, evidence, recommendation, status
        FROM findings WHERE scan_id=?
    '''
    params = [scan_id]

    if severity:
        query += ' AND severity=?'
        params.append(severity)
    if tool:
        query += ' AND tool=?'
        params.append(tool)

    query += '''
        ORDER BY CASE severity
            WHEN "Critical" THEN 0
            WHEN "High" THEN 1
            WHEN "Medium" THEN 2
            WHEN "Low" THEN 3
            WHEN "Info" THEN 4
            ELSE 5 END
    '''

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    findings = [
        {
            "id": r[0],
            "tool": r[1],
            "asset": r[2],
            "category": r[3],
            "severity": r[4],
            "title": r[5],
            "description": r[6],
            "evidence": r[7],
            "recommendation": r[8],
            "status": r[9]
        }
        for r in rows
    ]

    counts = {}
    for f in findings:
        sev = f['severity']
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "scan_id": scan_id,
        "total": len(findings),
        "summary": counts,
        "findings": findings
    }

@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM scans WHERE id=?', (scan_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    cursor.execute('DELETE FROM findings WHERE scan_id=?', (scan_id,))
    cursor.execute('DELETE FROM tool_runs WHERE scan_id=?', (scan_id,))
    cursor.execute('DELETE FROM audit_logs WHERE scan_id=?', (scan_id,))
    cursor.execute('DELETE FROM scans WHERE id=?', (scan_id,))
    conn.commit()
    conn.close()

    import shutil
    storage_path = os.path.join('storage', str(scan_id))
    if os.path.exists(storage_path):
        shutil.rmtree(storage_path)

    return {"message": f"Scan {scan_id} deleted successfully"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
