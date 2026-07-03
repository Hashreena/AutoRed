import json
import os
import urllib.request
import urllib.error


def load_openai_key():
    key = os.environ.get('OPENAI_API_KEY', '')
    if not key:
        env_path = os.path.join(
            os.path.dirname(__file__), '..', '.env'
        )
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('OPENAI_API_KEY='):
                        key = line.split('=', 1)[1]
                        break
    return key


def load_claude_key():
    try:
        from gui.ai_chat import load_api_key
        return load_api_key()
    except Exception:
        pass

    key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not key:
        env_path = os.path.join(
            os.path.dirname(__file__), '..', '.env'
        )
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('ANTHROPIC_API_KEY='):
                        key = line.split('=', 1)[1]
                        break
    return key


def call_claude(prompt, max_tokens=600):
    claude_key = load_claude_key()
    if not claude_key:
        raise Exception("No Claude API key")

    payload = json.dumps({
        "model":      "claude-sonnet-4-5-20250929",
        "max_tokens": max_tokens,
        "messages":   [{
            "role":    "user",
            "content": prompt
        }],
    }).encode('utf-8')

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key":         claude_key,
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data    = json.loads(resp.read().decode('utf-8'))
        content = data['content'][0]['text'].strip()
        return content


def call_gpt(prompt, max_tokens=600):
    api_key = load_openai_key()
    if not api_key:
        raise Exception("No OpenAI API key")

    payload = json.dumps({
        "model":       "gpt-4o-mini",
        "max_tokens":  max_tokens,
        "temperature": 0.1,
        "messages": [
            {
                "role":    "system",
                "content": (
                    "You are a cybersecurity expert. "
                    "Return only valid JSON when asked. "
                    "Never invent CVE numbers."
                )
            },
            {
                "role":    "user",
                "content": prompt
            }
        ],
    }).encode('utf-8')

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        return data['choices'][0]['message']['content']


def parse_json_response(content):
    content = content.strip()
    if content.startswith('```'):
        lines   = content.split('\n')
        content = '\n'.join(lines[1:-1])
    content = content.strip()
    return json.loads(content)


def gpt_classify_finding(finding, existing_data=None):
    title       = finding.get('title', '')
    description = finding.get('description', '')
    severity    = finding.get('severity', '')
    asset       = finding.get('asset', '')
    tool        = finding.get('tool', '')
    category    = finding.get('category', '')

    context = ""
    if existing_data:
        cve  = existing_data.get('cve_id', '')
        cvss = existing_data.get('cvss_score', '')
        if cve and 'No CVE' not in str(cve):
            context = (
                f"CVE already confirmed: {cve} "
                f"CVSS: {cvss}\n"
            )

    prompt = f"""You are a cybersecurity expert analyzing a penetration testing finding.

Finding Title: {title}
Tool: {tool}
Category: {category}
Severity: {severity}
Asset: {asset}
Description: {description[:400]}
{context}
This finding does NOT have a confirmed CVE from NVD.

Analyze this finding and respond ONLY in this exact JSON format with no extra text:
{{
  "cwe_id": "CWE-XXX",
  "cwe_name": "exact CWE name from MITRE",
  "cwe_url": "https://cwe.mitre.org/data/definitions/XXX.html",
  "exposure_type": "Protocol Weakness|Configuration Weakness|Vulnerability|Information Disclosure|Authentication Weakness|Discovery Finding|Technology Detection",
  "attack_surface": ["tag1", "tag2"],
  "mitre_technique": "T1XXX",
  "mitre_tactic": "tactic name",
  "mitre_url": "https://attack.mitre.org/techniques/TXXX",
  "exploitability": "Easy|Moderate|Difficult",
  "ai_explanation": "2-3 sentence explanation of the risk in plain English",
  "confidence": "High|Medium|Low",
  "no_cve_reason": "1-2 sentence explanation of why this specific finding has no CVE number — be specific to the finding type, tool, and category"
}}

Rules:
- Only assign CWE if confident it is correct
- Only assign MITRE if confident
- Do NOT invent CVE numbers
- For no_cve_reason: explain clearly why this TYPE of finding has no CVE (e.g. it is a protocol design choice, a server configuration setting, a discovery result, a technology fingerprint, a missing header — be specific to THIS finding)
- Return valid JSON only, no markdown, no extra text"""

    # ── Try Claude first ──────────────────────────────────────
    try:
        print("[*] Phase 2 classify — using Claude API...")
        content = call_claude(prompt, max_tokens=700)
        result  = parse_json_response(content)
        print(
            f"[+] Claude classified: "
            f"{result.get('cwe_id', 'N/A')} — "
            f"{result.get('exposure_type', 'N/A')} "
            f"(confidence: {result.get('confidence', 'N/A')})"
        )
        return result
    except Exception as e:
        print(f"[!] Claude classify error: {e}")

    # ── Fallback to GPT ───────────────────────────────────────
    try:
        print("[*] Phase 2 classify — trying GPT fallback...")
        content = call_gpt(prompt, max_tokens=700)
        result  = parse_json_response(content)
        print(
            f"[+] GPT classified: "
            f"{result.get('cwe_id', 'N/A')} — "
            f"{result.get('exposure_type', 'N/A')} "
            f"(confidence: {result.get('confidence', 'N/A')})"
        )
        return result
    except Exception as e:
        print(f"[!] GPT classify error: {e}")
        return None


def gpt_attack_path(finding, intel_data=None):
    title       = finding.get('title', '')
    severity    = finding.get('severity', '')
    asset       = finding.get('asset', '')
    description = finding.get('description', '')

    context = ""
    if intel_data:
        cve  = intel_data.get('cve_id', '')
        cvss = intel_data.get('cvss_score', '')
        cwe  = intel_data.get('cwe_id', '')
        if cve and 'No CVE' not in str(cve):
            context += f"CVE: {cve} | CVSS: {cvss}\n"
        if cwe:
            context += f"CWE: {cwe}\n"

    prompt_attack = f"""You are an expert penetration tester.

Finding: {title}
Severity: {severity}
Asset: {asset}
Description: {description[:300]}
{context}
Give exactly 5 specific next steps for exploitation planning.
Use bullet points starting with •
Include specific tool commands where applicable.
No markdown, no bold, no headers.
Be specific and technical."""

    prompt_verify = f"""You are an expert penetration tester helping a student verify a finding.

Finding: {title}
Severity: {severity}
Asset: {asset}
Description: {description[:300]}
{context}
Give exactly 5 specific steps to VERIFY and CONFIRM this finding is real and not a false positive.
Use bullet points starting with •
Include specific commands the student can run.
No markdown, no bold, no headers."""

    # ── Try Claude first ──────────────────────────────────────
    try:
        print("[*] Attack path — using Claude API...")
        attack = call_claude(prompt_attack, max_tokens=500)
        verify = call_claude(prompt_verify, max_tokens=500)
        print("[+] Claude attack path generated")
        return attack, verify
    except Exception as e:
        print(f"[!] Claude attack path error: {e}")

    # ── Fallback to GPT ───────────────────────────────────────
    try:
        print("[*] Attack path — trying GPT fallback...")
        attack = call_gpt(prompt_attack, max_tokens=500)
        verify = call_gpt(prompt_verify, max_tokens=500)
        print("[+] GPT attack path generated")
        return attack, verify
    except Exception as e:
        print(f"[!] GPT attack path error: {e}")
        return None, None


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — GPT/Claude Enricher Test")
    print("=" * 60)

    tests = [
        {
            'title':       'Telnet Service on Port 23',
            'severity':    'High',
            'asset':       '192.168.112.130:23',
            'description': 'Telnet cleartext protocol detected',
            'tool':        'nmap',
            'category':    'open_port',
            'evidence':    '',
        },
        {
            'title':       'Directory found: /.htpasswd [403]',
            'severity':    'High',
            'asset':       'http://192.168.112.130/.htpasswd',
            'description': 'Sensitive file found at predictable path',
            'tool':        'gobuster',
            'category':    'directory',
            'evidence':    '',
        },
        {
            'title':       'Nikto: Apache/2.2.8 appears to be outdated',
            'severity':    'High',
            'asset':       'http://192.168.112.130/',
            'description': 'Apache version is outdated',
            'tool':        'nikto',
            'category':    'web_vulnerability',
            'evidence':    '',
        },
    ]

    for t in tests:
        print(f"\n{'─' * 50}")
        print(f"Finding: {t['title']}")
        result = gpt_classify_finding(t)
        if result:
            print(f"  CWE:          {result.get('cwe_id')}")
            print(f"  Exposure:     {result.get('exposure_type')}")
            print(f"  Confidence:   {result.get('confidence')}")
            print(f"  No CVE Reason: {result.get('no_cve_reason', 'N/A')[:100]}")
        else:
            print("  Classification failed")

    print(f"\n{'=' * 60}")
    print("[+] Test complete!")
