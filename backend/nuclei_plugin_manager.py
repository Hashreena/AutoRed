"""
AutoRed — Nuclei Plugin Manager
================================
Profile-based Nuclei template selection.
Custom templates: drop any .yaml file into AutoRed/custom_templates/
and it will run automatically on every scan.

Profile → templates selected:
  Production  →  critical severity only  (safe for live environments)
  Standard    →  critical + high         (recommended)
  Deep        →  critical + high + medium (thorough, test envs only)
"""

import os
import glob

# Path to nuclei's template library (installed by nuclei -update-templates)
TEMPLATES_DIR = os.path.expanduser('~/.local/nuclei-templates')

# Drop your own .yaml files here — they run on every scan
CUSTOM_TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'custom_templates')
)

# Profile-driven template selection
PROFILE_CONFIG = {
    'Production': {
        'severity': 'critical',
        'tags':     'cve,rce',
        'desc':     'Critical CVEs + RCE only — safe for live systems',
    },
    'Standard': {
        'severity': 'critical,high',
        'tags':     'cve,misconfig,rce,sqli',
        'desc':     'Critical + High — recommended for most engagements',
    },
    'Deep': {
        'severity': 'critical,high,medium',
        'tags':     'cve,misconfig,exposure,rce,sqli,xss',
        'desc':     'Critical to Medium — thorough, use on test environments',
    },
}


def _ensure_custom_dir():
    """Create custom_templates/ folder if it doesn't exist."""
    os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)


def get_custom_templates():
    """Return list of .yaml files in custom_templates/."""
    _ensure_custom_dir()
    return sorted(
        glob.glob(os.path.join(CUSTOM_TEMPLATES_DIR, '*.yaml'))
    )


def get_custom_template_count():
    return len(get_custom_templates())


def list_custom_templates():
    return [
        os.path.basename(t) for t in get_custom_templates()
    ]


def get_nuclei_flags(profile='Standard'):
    """
    Return nuclei CLI flags based on scan profile.
    Appends -t flags for any custom templates found.

    Example output:
      '-severity critical,high -tags cve,misconfig,rce,sqli'
      '-severity critical,high -tags cve,misconfig -t /path/custom.yaml'
    """
    cfg      = PROFILE_CONFIG.get(profile, PROFILE_CONFIG['Standard'])
    severity = cfg['severity']
    tags     = cfg['tags']

    flags = f"-severity {severity} -tags {tags}"

    # Append custom templates
    custom = get_custom_templates()
    if custom:
        print(
            f"[*] Nuclei plugin manager: "
            f"{len(custom)} custom template(s) loaded"
        )
        for t in custom:
            flags += f" -t {t}"

    return flags


def get_profile_summary():
    """Return human-readable summary of all profiles."""
    lines = ["Nuclei template profiles:"]
    for profile, cfg in PROFILE_CONFIG.items():
        count = f"custom: {get_custom_template_count()}"
        lines.append(
            f"  {profile:12} severity={cfg['severity']}"
            f"  tags={cfg['tags']}  ({count})"
        )
    return '\n'.join(lines)


if __name__ == '__main__':
    print(get_profile_summary())
    print(f"\nCustom templates folder: {CUSTOM_TEMPLATES_DIR}")
    custom = list_custom_templates()
    if custom:
        print(f"Custom templates ({len(custom)}):")
        for t in custom:
            print(f"  - {t}")
    else:
        print(
            "No custom templates yet — "
            "drop .yaml files into custom_templates/"
        )
    print()
    for p in ['Production', 'Standard', 'Deep']:
        print(f"[{p}] nuclei {get_nuclei_flags(p)} -u <target>")
