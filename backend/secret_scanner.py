import re
from backend.db import get_connection

SECRET_PATTERNS = [
    (
        'Exposed AWS Access Key',
        r'AKIA[0-9A-Z]{16}',
        'Critical',
        'AWS Access Key ID detected in scan data. '
        'This allows full AWS account access if valid.',
    ),
    (
        'Exposed AWS Secret Key',
        r'(?i)aws.{0,20}secret.{0,20}["\']?([A-Za-z0-9/+=]{40})',
        'Critical',
        'AWS Secret Access Key detected. '
        'Combined with Access Key ID gives full AWS access.',
    ),
    (
        'Exposed JWT Token',
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'High',
        'JSON Web Token (JWT) detected in scan data. '
        'May allow session hijacking or privilege escalation.',
    ),
    (
        'Exposed Google API Key',
        r'AIza[0-9A-Za-z_-]{35}',
        'High',
        'Google API Key detected. '
        'May allow unauthorized API calls and billing abuse.',
    ),
    (
        'Exposed Telegram Bot Token',
        r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
        'High',
        'Telegram Bot Token detected. '
        'Allows full control of the Telegram bot.',
    ),
    (
        'Exposed Private Key',
        r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'Critical',
        'Private cryptographic key detected. '
        'Allows decryption of communications or server access.',
    ),
    (
        'Exposed Database Connection String',
        r'(?i)(mysql|postgresql|mongodb|redis|mssql)://[^\s"\'<>]+',
        'Critical',
        'Database connection string with credentials detected. '
        'Allows direct database access.',
    ),
    (
        'Exposed Basic Auth Credentials',
        r'https?://[^:@\s]+:[^@\s]+@[^\s"\'<>]+',
        'High',
        'Basic authentication credentials embedded in URL. '
        'Username and password exposed in plaintext.',
    ),
    (
        'Exposed SendGrid API Key',
        r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        'High',
        'SendGrid API key detected. '
        'Allows sending emails on behalf of the account.',
    ),
    (
        'Exposed Stripe API Key',
        r'sk_(live|test)_[0-9a-zA-Z]{24,}',
        'Critical',
        'Stripe secret API key detected. '
        'Allows full access to payment processing.',
    ),
    (
        'Exposed GitHub Token',
        r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
        'High',
        'GitHub personal access token detected. '
        'Allows access to repositories and account actions.',
    ),
    (
        'Exposed Generic API Key',
        r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\s:=]+["\']?([A-Za-z0-9_\-]{20,})',
        'High',
        'Generic API key or secret detected in scan data. '
        'May allow unauthorized API access.',
    ),
    (
        'Exposed Password in Config',
        r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\'<>{}\[\]]{8,})',
        'High',
        'Password found in configuration or response data. '
        'Credential exposure risk.',
    ),
    (
        'Exposed Twilio Credentials',
        r'(?i)twilio.{0,20}(AC[a-z0-9]{32}|SK[a-z0-9]{32})',
        'High',
        'Twilio API credentials detected. '
        'Allows making calls and sending SMS.',
    ),
    (
        'Exposed Slack Token',
        r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        'High',
        'Slack API token detected. '
        'May allow reading messages and impersonating users.',
    ),
]


def run_secret_scan(scan_id):
    """
    Scan all findings evidence/description for secrets.
    Returns list of new secret findings found.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, tool, asset, title,
               description, evidence
        FROM findings WHERE scan_id=?
    ''', (scan_id,))
    findings = cursor.fetchall()

    # Get existing secret findings to avoid duplicates
    cursor.execute('''
        SELECT title FROM findings
        WHERE scan_id=? AND tool='secret_scanner'
    ''', (scan_id,))
    existing = {r[0] for r in cursor.fetchall()}

    new_secrets = []

    for finding in findings:
        fid         = finding[0]
        tool        = finding[1]
        asset       = finding[2] or ''
        title       = finding[3] or ''
        description = finding[4] or ''
        evidence    = finding[5] or ''

        # Skip existing secret scanner findings
        if tool == 'secret_scanner':
            continue

        # Text to search
        search_text = (
            f"{title} {description} {evidence}"
        )

        for (
            secret_name, pattern,
            severity, recommendation
        ) in SECRET_PATTERNS:
            try:
                matches = re.findall(
                    pattern, search_text
                )
                if not matches:
                    continue

                # Build unique title
                finding_title = (
                    f"{secret_name} — "
                    f"found in {tool} output"
                )

                # Skip if already exists
                if finding_title in existing:
                    continue

                # Mask the match for evidence
                match_str = (
                    str(matches[0])[:40]
                    if matches else ''
                )
                masked = (
                    match_str[:6] + '...' +
                    match_str[-4:]
                    if len(match_str) > 12
                    else match_str[:4] + '...'
                )

                evidence_text = (
                    f"Pattern matched in {tool} output "
                    f"for asset: {asset}\n"
                    f"Match preview: {masked}\n"
                    f"Source finding: {title}"
                )

                # Insert into findings
                cursor.execute('''
                    INSERT INTO findings (
                        scan_id, tool, asset, category,
                        severity, title, description,
                        evidence, recommendation, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    'secret_scanner',
                    asset,
                    'Secret Exposure',
                    severity,
                    finding_title,
                    (
                        f"{secret_name} detected in "
                        f"reconnaissance data. "
                        f"{recommendation}"
                    ),
                    evidence_text,
                    recommendation,
                    'New',
                ))

                existing.add(finding_title)
                new_secrets.append({
                    'title':    finding_title,
                    'severity': severity,
                    'asset':    asset,
                })
                print(
                    f"[!] SECRET FOUND: {secret_name} "
                    f"in {tool} output for {asset}"
                )

            except Exception as e:
                print(
                    f"[!] Secret scan pattern error: {e}"
                )

    conn.commit()
    conn.close()
    return new_secrets
