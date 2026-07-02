"""
AutoRed — Path Enricher
========================
Maps discovered paths (from ffuf / gobuster / dirsearch) to:
  - CWE ID      (weakness classification)
  - CVSS score  (risk score for this type of exposure)
  - Severity    (may upgrade from parser's initial assessment)
  - Better description and recommendation

After insert_finding(), call post_enrich_finding() to
write cwe_id and cvss_score into the findings table.
"""

from backend.db import get_connection

# ── Path knowledge base ───────────────────────────────────────
# Each entry: (pattern, cwe_id, severity, cvss, short_desc, recommendation)
# Pattern matching is case-insensitive substring match on the path.
# Order matters — first match wins.

PATH_KB = [
    # ── Credential / secret files ─────────────────────────
    (
        '.git',
        'CWE-538', 'Critical', 9.1,
        'Git repository exposed — source code, credentials, '
        'and history are publicly accessible.',
        'Immediately remove the .git directory from the web '
        'root or block access via server configuration. '
        'Rotate any credentials found in git history.'
    ),
    (
        '.env',
        'CWE-538', 'Critical', 9.1,
        'Environment file exposed — likely contains API keys, '
        'database credentials, and application secrets.',
        'Remove .env from the web root immediately. '
        'Rotate all credentials referenced in the file.'
    ),
    (
        '.htpasswd',
        'CWE-522', 'Critical', 9.1,
        'Password file (.htpasswd) is accessible — '
        'contains hashed credentials that can be brute-forced.',
        'Restrict .htpasswd access via server configuration. '
        'Move it outside the web root if possible.'
    ),
    (
        'passwd',
        'CWE-522', 'Critical', 9.1,
        'Password or credentials file is publicly accessible.',
        'Remove or restrict access to credential files immediately.'
    ),
    (
        'credentials',
        'CWE-522', 'Critical', 9.1,
        'Credentials file or directory is publicly accessible.',
        'Restrict access immediately and rotate any exposed secrets.'
    ),
    (
        'secret',
        'CWE-538', 'High', 8.0,
        'Path containing sensitive or secret data is accessible.',
        'Restrict access to this path and review its contents.'
    ),
    (
        'private',
        'CWE-538', 'High', 7.5,
        'Private directory is accessible — '
        'may contain sensitive files.',
        'Restrict access via authentication or server configuration.'
    ),

    # ── Shell / command execution ─────────────────────────
    (
        'shell',
        'CWE-78', 'Critical', 9.8,
        'Web shell or shell access path discovered — '
        'potential remote code execution.',
        'Investigate immediately. Remove any web shells and '
        'audit server for compromise indicators.'
    ),
    (
        '/cmd',
        'CWE-78', 'Critical', 9.8,
        'Command execution endpoint discovered.',
        'Investigate immediately for signs of compromise.'
    ),

    # ── Admin panels ──────────────────────────────────────
    (
        'phpmyadmin',
        'CWE-284', 'High', 8.8,
        'phpMyAdmin database administration panel is exposed. '
        'Unauthenticated or weakly authenticated access could '
        'allow full database compromise.',
        'Restrict phpMyAdmin to trusted IPs only, enforce strong '
        'authentication, and consider moving it off the default path.'
    ),
    (
        'wp-admin',
        'CWE-284', 'High', 7.5,
        'WordPress admin panel is exposed.',
        'Restrict wp-admin access by IP, enable two-factor '
        'authentication, and keep WordPress updated.'
    ),
    (
        'administrator',
        'CWE-284', 'High', 7.5,
        'Administrator panel is accessible.',
        'Enforce strong authentication and restrict access by IP.'
    ),
    (
        '/admin',
        'CWE-284', 'High', 7.5,
        'Admin panel is accessible — could expose management '
        'functions to unauthorised users.',
        'Enforce authentication and consider IP-based access control.'
    ),
    (
        'dashboard',
        'CWE-284', 'High', 7.5,
        'Dashboard or management interface is accessible.',
        'Enforce strong authentication and restrict access by IP.'
    ),
    (
        'manage',
        'CWE-284', 'High', 7.5,
        'Management interface discovered.',
        'Enforce authentication and restrict access.'
    ),
    (
        'console',
        'CWE-284', 'High', 8.0,
        'Server console or management endpoint accessible.',
        'Restrict console access to internal/trusted IPs only.'
    ),

    # ── Configuration / source files ──────────────────────
    (
        'config',
        'CWE-312', 'High', 7.5,
        'Configuration file or directory is accessible — '
        'may contain sensitive settings, credentials, or '
        'database connection strings.',
        'Move configuration files outside the web root or '
        'restrict access via server configuration.'
    ),
    (
        'phpinfo',
        'CWE-200', 'High', 7.5,
        'PHP info page is accessible — exposes server '
        'configuration, PHP version, loaded modules, and '
        'environment variables to attackers.',
        'Remove phpinfo() pages from production environments.'
    ),
    (
        'web.config',
        'CWE-312', 'High', 7.5,
        'ASP.NET web.config file accessible — may expose '
        'connection strings and application secrets.',
        'Restrict access to web.config via server rules.'
    ),

    # ── Backup files ──────────────────────────────────────
    (
        'backup',
        'CWE-530', 'High', 7.5,
        'Backup directory or file is publicly accessible — '
        'may contain database dumps, source code, or '
        'full application backups.',
        'Remove backup files from the web root or restrict '
        'access. Store backups in a non-web-accessible location.'
    ),

    # ── Intentionally vulnerable apps ─────────────────────
    (
        'dvwa',
        'CWE-489', 'Critical', 9.8,
        'DVWA (Damn Vulnerable Web Application) is accessible '
        'on this server — this is an intentionally insecure '
        'application that should never be on a production system.',
        'Remove DVWA from any production or internet-facing '
        'server immediately.'
    ),
    (
        'mutillidae',
        'CWE-489', 'Critical', 9.8,
        'Mutillidae (intentionally vulnerable app) is accessible '
        '— should never be deployed on a production server.',
        'Remove Mutillidae from any production server immediately.'
    ),

    # ── Setup / install pages ─────────────────────────────
    (
        'setup',
        'CWE-489', 'High', 7.5,
        'Setup or installation page is accessible — '
        'could allow an attacker to reconfigure or '
        'reinstall the application.',
        'Remove or restrict setup pages after installation.'
    ),
    (
        'install',
        'CWE-489', 'High', 7.5,
        'Installation page is accessible.',
        'Remove install pages from production environments.'
    ),

    # ── File upload ───────────────────────────────────────
    (
        'uploads',
        'CWE-434', 'Medium', 6.5,
        'Uploads directory is accessible — '
        'may allow browsing of user-uploaded files.',
        'Disable directory listing and restrict direct access '
        'to the uploads directory.'
    ),

    # ── Server info disclosure ────────────────────────────
    (
        'server-status',
        'CWE-200', 'Medium', 5.3,
        'Apache server-status page is accessible — '
        'discloses active requests, connected clients, '
        'and server configuration details.',
        'Restrict mod_status to localhost or trusted IPs only.'
    ),
    (
        'server-info',
        'CWE-200', 'Medium', 5.3,
        'Apache server-info page is accessible — '
        'discloses loaded modules and server configuration.',
        'Restrict mod_info to localhost or trusted IPs only.'
    ),

    # ── WebDAV ────────────────────────────────────────────
    (
        'webdav',
        'CWE-284', 'Medium', 6.5,
        'WebDAV endpoint is accessible — '
        'may allow file upload or modification.',
        'Disable WebDAV if not required or restrict by IP and auth.'
    ),
    (
        '/dav',
        'CWE-284', 'Medium', 6.5,
        'WebDAV endpoint is accessible.',
        'Disable WebDAV or restrict access by IP and authentication.'
    ),

    # ── CMS / wiki ────────────────────────────────────────
    (
        'twiki',
        'CWE-284', 'Medium', 5.3,
        'TWiki installation accessible — '
        'potential for unauthorised wiki access or CVE exposure.',
        'Update TWiki to latest version and enforce authentication.'
    ),
    (
        'tikiwiki',
        'CWE-284', 'Medium', 5.3,
        'TikiWiki installation accessible.',
        'Update TikiWiki and enforce authentication.'
    ),

    # ── Login pages ───────────────────────────────────────
    (
        'login',
        'CWE-287', 'Medium', 5.3,
        'Login page discovered — '
        'potential target for brute-force or credential stuffing.',
        'Implement rate limiting, account lockout, and '
        'multi-factor authentication on the login page.'
    ),

    # ── Documentation / info ──────────────────────────────
    (
        '/doc',
        'CWE-200', 'Low', 3.1,
        'Documentation directory is accessible — '
        'may disclose application structure or API details.',
        'Review whether documentation should be publicly accessible.'
    ),
    (
        'database',
        'CWE-284', 'High', 7.5,
        'Database-related path is accessible.',
        'Restrict access to database management paths immediately.'
    ),
]


def enrich_path(path, status_code=200):
    """
    Match a discovered path against the knowledge base.

    Returns a dict with enrichment data, or None if no match.
    Dict keys: cwe_id, severity, cvss_score, description, recommendation
    """
    path_lower = path.lower()

    for (
        pattern, cwe_id, severity,
        cvss_score, desc, rec
    ) in PATH_KB:
        if pattern.lower() in path_lower:
            return {
                'cwe_id':         cwe_id,
                'severity':       severity,
                'cvss_score':     cvss_score,
                'description':    desc,
                'recommendation': rec,
            }

    return None


def severity_rank(s):
    return {
        'Critical': 4, 'High': 3,
        'Medium': 2, 'Low': 1, 'Info': 0
    }.get(s, 0)


def best_severity(s1, s2):
    """Return the higher of two severity strings."""
    return s1 if severity_rank(s1) >= severity_rank(s2) else s2


def post_enrich_cve(scan_id, tool, asset,
                    cve_id=None, cwe_id=None, cvss_score=None):
    """
    Update a finding's CVE ID, CWE ID and/or CVSS score after insert.
    Only fills columns that are currently NULL — won't overwrite
    existing enrichment data.
    Silently skips if columns don't exist in older DB schemas.
    """
    if not any([cve_id, cwe_id, cvss_score is not None]):
        return
    try:
        conn    = get_connection()
        cursor  = conn.cursor()
        sets, params = [], []
        if cve_id:
            sets.append("cve_id = COALESCE(cve_id, ?)")
            params.append(cve_id)
        if cwe_id:
            sets.append("cwe_id = COALESCE(cwe_id, ?)")
            params.append(cwe_id)
        if cvss_score is not None:
            sets.append("cvss_score = COALESCE(cvss_score, ?)")
            params.append(cvss_score)
        params.extend([scan_id, tool, asset])
        cursor.execute(
            f"UPDATE findings SET {', '.join(sets)} "
            f"WHERE scan_id=? AND tool=? AND asset=?",
            params
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    """
    After insert_finding(), update the DB row with
    cwe_id and cvss_score for path-based findings.
    Silently skips if columns don't exist.
    """
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE findings
            SET cwe_id = ?, cvss_score = ?
            WHERE scan_id = ? AND tool = ? AND asset = ?
              AND (cwe_id IS NULL OR cwe_id = '')
        ''', (cwe_id, cvss_score, scan_id, tool, asset))
        conn.commit()
        conn.close()
    except Exception:
        pass   # Silently skip — columns may not exist in older schema
