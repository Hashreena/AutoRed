import sqlite3
import os
from datetime import datetime
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'autored.db')
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            profile TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            approval_ref TEXT,
            folder_id INTEGER,
            created_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (folder_id) REFERENCES folders(id)
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            value TEXT,
            discovered_by TEXT,
            created_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            tool TEXT,
            asset TEXT,
            category TEXT,
            severity TEXT DEFAULT 'Info',
            title TEXT,
            description TEXT,
            evidence TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'Potential',
            created_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS tool_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            tool TEXT,
            command TEXT,
            status TEXT DEFAULT 'queued',
            started_at TEXT,
            completed_at TEXT,
            exit_code INTEGER,
            output_path TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            action TEXT,
            detail TEXT,
            timestamp TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    ''')
    try:
        cursor.execute(
            'ALTER TABLE scans ADD COLUMN folder_id INTEGER'
        )
        conn.commit()
        print("Added folder_id column to scans table.")
    except Exception:
        pass
    conn.commit()
    conn.close()
    print("Database initialized successfully.")
def insert_scan(name, target, profile, approval_ref=None, folder_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans
        (name, target, profile, approval_ref, folder_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        name, target, profile, approval_ref,
        folder_id, datetime.now().isoformat()
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id
def insert_folder(name, description=''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO folders (name, description) VALUES (?, ?)',
        (name, description)
    )
    folder_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return folder_id
def get_folders():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT f.id, f.name, f.description, f.created_at,
               COUNT(s.id) as scan_count
        FROM folders f
        LEFT JOIN scans s ON f.id = s.folder_id
        GROUP BY f.id
        ORDER BY f.created_at DESC
    ''')
    folders = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return folders
def delete_folder(folder_id):
    """
    Permanently delete a folder and cascade delete ALL scans
    inside it, along with every finding, tool_run, and audit_log
    tied to those scans.
    Order matters: child tables must be deleted before parent rows
    to avoid orphaned records.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Step 1: get all scan IDs inside this folder
        cursor.execute(
            'SELECT id FROM scans WHERE folder_id=?',
            (folder_id,)
        )
        scan_ids = [row[0] for row in cursor.fetchall()]

        # Step 2: cascade delete child rows for each scan
        for scan_id in scan_ids:
            for table in ('findings', 'tool_runs', 'audit_logs'):
                try:
                    cursor.execute(
                        f'DELETE FROM {table} WHERE scan_id=?',
                        (scan_id,)
                    )
                except Exception:
                    pass

        # Step 3: delete the scans themselves
        if scan_ids:
            placeholders = ','.join('?' * len(scan_ids))
            cursor.execute(
                f'DELETE FROM scans WHERE id IN ({placeholders})',
                scan_ids
            )

        # Step 4: delete the folder
        cursor.execute(
            'DELETE FROM folders WHERE id=?',
            (folder_id,)
        )
        conn.commit()
        print(
            f"[+] Folder {folder_id} deleted with "
            f"{len(scan_ids)} scan(s) and all associated data"
        )
    except Exception as e:
        print(f"[!] delete_folder failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()
def insert_finding(
    scan_id, tool, asset, category, severity,
    title, description, evidence, recommendation
):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO findings
        (scan_id, tool, asset, category, severity, title,
         description, evidence, recommendation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id, tool, asset, category, severity, title,
        description, evidence, recommendation,
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
def insert_tool_run(scan_id, tool, command):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO tool_runs
        (scan_id, tool, command, status, started_at)
        VALUES (?, ?, ?, 'running', ?)
    ''', (scan_id, tool, command, datetime.now().isoformat()))
    conn.commit()
    run_id = cursor.lastrowid
    conn.close()
    return run_id
def update_tool_run(run_id, status, exit_code, output_path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE tool_runs
        SET status=?, exit_code=?, output_path=?, completed_at=?
        WHERE id=?
    ''', (
        status, exit_code, output_path,
        datetime.now().isoformat(), run_id
    ))
    conn.commit()
    conn.close()
def insert_audit_log(scan_id, action, detail):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (scan_id, action, detail, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (scan_id, action, detail, datetime.now().isoformat()))
    conn.commit()
    conn.close()
def get_findings(scan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM findings WHERE scan_id=? ORDER BY severity',
        (scan_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows
def get_scans():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows
if __name__ == '__main__':
    init_db()
