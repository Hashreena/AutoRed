"""
AutoRed — Multi-Source CVE Enrichment
======================================

Queries three independent CVE data sources for a given CVE ID, then
cross-checks the scores for confidence.  Falls back to Claude API when
all three sources return nothing.

Sources:
  1. NVD  (services.nvd.nist.gov)  — authoritative CVSS v3.1 + description
  2. CIRCL (cve.circl.lu)          — independent score, free, no key needed
  3. MITRE (cveawg.mitre.org)      — authoritative CVE identity, description,
                                      CWE; no CVSS (MITRE doesn't score)

Cross-check:
  NVD score vs CIRCL score → confidence: High / Medium / Low / AI-Estimated

Claude fallback:
  If all three APIs fail (very new CVE, NVD outage, etc.) Claude generates
  a best-effort assessment.  Clearly tagged is_ai_estimated=True.

Integration:
  Used by cve_enricher.enrich_finding Step 2 instead of the old single-
  source lookup_nvd call.
"""

import json
import os
import re
import subprocess
import time


# ── Rate-limit state (one timestamp per host) ─────────────────
_LAST = {'nvd': 0.0, 'circl': 0.0, 'mitre': 0.0}


# ── NVD API key ───────────────────────────────────────────────
def _load_nvd_key():
    key = os.environ.get('NVD_API_KEY', '')
    if key:
        return key.strip()
    env = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env):
        try:
            with open(env) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('NVD_API_KEY='):
                        return line.split('=', 1)[1].strip()
        except Exception:
            pass
    return ''


_NVD_KEY = _load_nvd_key()


# ── Generic curl helper ───────────────────────────────────────
def _fetch(url, service='generic', extra_headers=None,
           retries=3, min_gap=0.6):
    """Curl with rate-spacing, retry, and backoff."""
    cmd = [
        'curl', '-s', '--max-time', '40',
        '-H', 'User-Agent: AutoRed/1.0',
        '-H', 'Accept: application/json',
    ]
    for h in (extra_headers or []):
        cmd += ['-H', h]
    cmd.append(url)

    elapsed = time.time() - _LAST.get(service, 0.0)
    if elapsed < min_gap:
        time.sleep(min_gap - elapsed)

    for attempt in range(retries):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=50
            )
            _LAST[service] = time.time()
            out = (r.stdout or '').strip()

            if r.returncode != 0 or not out:
                print(f"[!] {service} empty/failed "
                      f"(attempt {attempt + 1}/{retries})")
            elif out.startswith('<'):
                print(f"[!] {service} returned HTML — "
                      f"likely JS-rendered or error page "
                      f"(attempt {attempt + 1}/{retries})")
            else:
                return json.loads(out)
        except subprocess.TimeoutExpired:
            print(f"[!] {service} curl timed out "
                  f"(attempt {attempt + 1}/{retries})")
        except json.JSONDecodeError:
            print(f"[!] {service} JSON parse failed "
                  f"(attempt {attempt + 1}/{retries})")
        except Exception as e:
            print(f"[!] {service} error: {e} "
                  f"(attempt {attempt + 1}/{retries})")

        time.sleep(3)
        _LAST[service] = time.time()

    print(f"[!] {service} gave up after {retries} attempts.")
    return None


# ── NVD parsing helpers ───────────────────────────────────────
def _exploit_level(score):
    if score is None:
        return 'Unknown'
    if score >= 3.5:
        return 'Easy'
    if score >= 2.0:
        return 'Moderate'
    return 'Difficult'


def _parse_nvd_response(data):
    """Convert raw NVD API JSON to the standard nvd_best dict shape."""
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        return None

    cve_data = vulns[0].get('cve', {})
    cve_id   = cve_data.get('id', '')

    desc = ''
    for d in cve_data.get('descriptions', []):
        if d.get('lang') == 'en':
            desc = d.get('value', '')
            break

    metrics  = cve_data.get('metrics', {})
    cvss_v3  = metrics.get('cvssMetricV31', [])
    cvss_v2  = metrics.get('cvssMetricV2', [])

    score = severity = version = vector = None
    exploit_sub = impact_sub = None
    av = ac = pr = ui = None

    if cvss_v3:
        d        = cvss_v3[0].get('cvssData', {})
        score    = d.get('baseScore')
        severity = d.get('baseSeverity')
        version  = '3.1'
        vector   = d.get('vectorString')
        exploit_sub = cvss_v3[0].get('exploitabilityScore')
        impact_sub  = cvss_v3[0].get('impactScore')
        av = d.get('attackVector')
        ac = d.get('attackComplexity')
        pr = d.get('privilegesRequired')
        ui = d.get('userInteraction')
    elif cvss_v2:
        d        = cvss_v2[0].get('cvssData', {})
        score    = d.get('baseScore')
        severity = cvss_v2[0].get('baseSeverity')
        version  = '2.0'
        vector   = d.get('vectorString')
        exploit_sub = cvss_v2[0].get('exploitabilityScore')
        impact_sub  = cvss_v2[0].get('impactScore')
        av = d.get('accessVector')
        ac = d.get('accessComplexity')
        pr = d.get('authentication')
        ui = 'NONE'

    weaknesses = []
    for w in cve_data.get('weaknesses', []):
        for wd in w.get('description', []):
            if wd.get('lang') == 'en':
                weaknesses.append(wd.get('value', ''))

    references = []
    for ref in cve_data.get('references', [])[:5]:
        u = ref.get('url', '')
        if u:
            references.append({'url': u, 'tags': ref.get('tags', [])})

    return {
        'cve_id':            cve_id,
        'description':       desc,
        'cvss_score':        score,
        'cvss_version':      version,
        'cvss_severity':     severity,
        'cvss_vector':       vector,
        'published':         cve_data.get('published', '')[:10],
        'last_modified':     cve_data.get('lastModified', '')[:10],
        'attack_vector':     av,
        'attack_complexity': ac,
        'privileges_req':    pr,
        'user_interaction':  ui,
        'exploitability':    exploit_sub,
        'exploit_level':     _exploit_level(exploit_sub),
        'exploit_reason':    'From NVD exploitability sub-score',
        'weaknesses':        weaknesses,
        'references':        references,
        'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        'is_fallback':       False,
        '_source':           'NVD',
    }


# ── Source 1: NVD ─────────────────────────────────────────────
def fetch_nvd(cve_id):
    """Query NVD API 2.0 for a specific CVE."""
    url     = (f"https://services.nvd.nist.gov/rest/json/"
               f"cves/2.0?cveId={cve_id}")
    headers = []
    if _NVD_KEY:
        headers.append(f'apiKey: {_NVD_KEY}')
    min_gap = 0.8 if _NVD_KEY else 6.5

    print(f"[*] NVD  → {cve_id}")
    data = _fetch(url, 'nvd', headers, min_gap=min_gap)
    if not data:
        return None
    result = _parse_nvd_response(data)
    if result:
        print(f"[+] NVD  ✓ {cve_id} — CVSS {result.get('cvss_score')} "
              f"{result.get('cvss_severity')}")
    return result


# ── Source 2: CIRCL CVE API ───────────────────────────────────
def _parse_circl_cvss3(val):
    """Robustly extract a float from CIRCL's cvss3 field."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val)
        except ValueError:
            pass
    if isinstance(val, dict):
        for k in ('baseScore', 'score', 'base_score'):
            if k in val:
                try:
                    return float(val[k])
                except (TypeError, ValueError):
                    pass
    return None


def _circl_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def fetch_circl(cve_id):
    """Query CIRCL CVE API (free, no key needed)."""
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    print(f"[*] CIRCL → {cve_id}")
    data = _fetch(url, 'circl', min_gap=0.5)
    if not data or not data.get('id'):
        return None

    # CIRCL may have CVSS3 or only CVSS2
    score3  = _parse_circl_cvss3(data.get('cvss3'))
    score2  = float(data['cvss']) if data.get('cvss') else None
    score   = score3 if score3 is not None else score2
    version = '3.1' if score3 is not None else ('2.0' if score2 else None)
    vector  = (data.get('cvss3-vector') or
               data.get('cvss-vector'))

    cwe_raw = data.get('cwe', '')
    cwe = (cwe_raw if str(cwe_raw).startswith('CWE-') else None)

    refs = []
    for r in (data.get('references') or [])[:5]:
        if isinstance(r, str) and r.startswith('http'):
            refs.append({'url': r, 'tags': []})

    if score:
        print(f"[+] CIRCL ✓ {cve_id} — CVSS {score} "
              f"{_circl_severity(score)}")

    return {
        'cve_id':        data.get('id', cve_id),
        'description':   data.get('summary', ''),
        'cvss_score':    score,
        'cvss_version':  version,
        'cvss_severity': _circl_severity(score),
        'cvss_vector':   vector,
        'published':     str(data.get('Published', ''))[:10],
        'last_modified': str(data.get('Modified', ''))[:10],
        'weaknesses':    [cwe] if cwe else [],
        'references':    refs,
        'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        'is_fallback':   False,
        '_source':       'CIRCL',
    }


# ── Source 3: MITRE CVE.org API ───────────────────────────────
def fetch_mitre(cve_id):
    """Query MITRE CVE Services API (free, no key, no CVSS)."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    print(f"[*] MITRE → {cve_id}")
    data = _fetch(url, 'mitre', min_gap=0.5)
    if not data:
        return None

    try:
        cna = data.get('containers', {}).get('cna', {})

        # Description
        desc = ''
        for d in cna.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break

        # CWE
        cwe = None
        for pt in cna.get('problemTypes', []):
            for d in pt.get('descriptions', []):
                val = d.get('cweId') or d.get('description', '')
                if str(val).startswith('CWE-'):
                    cwe = val
                    break
            if cwe:
                break

        # CVSS (sometimes CNAs include it, but usually empty)
        score = None
        for m in cna.get('metrics', []):
            for key in ('cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                if key in m:
                    score = m[key].get('baseScore')
                    break
            if score:
                break

        # Published
        meta      = data.get('cveMetadata', {})
        published = str(meta.get('datePublished', ''))[:10]

        refs = []
        for r in cna.get('references', [])[:5]:
            u = r.get('url', '')
            if u:
                refs.append({'url': u, 'tags': r.get('tags', [])})

        print(f"[+] MITRE ✓ {cve_id} — CWE: {cwe or 'N/A'}")

        return {
            'cve_id':        cve_id,
            'description':   desc,
            'cvss_score':    score,
            'published':     published,
            'weaknesses':    [cwe] if cwe else [],
            'references':    refs,
            '_source':       'MITRE',
        }
    except Exception as e:
        print(f"[!] MITRE parse error for {cve_id}: {e}")
        return None


# ── Cross-check & Merge ───────────────────────────────────────
def _cross_check(nvd, circl, mitre, cve_id):
    """
    Merge results from all three sources.
    NVD is preferred as the authoritative CVSS source.
    CIRCL provides an independent score for confidence checking.
    MITRE provides authoritative CWE and description validation.
    """
    sources_found = [s for s in [nvd, circl, mitre] if s]
    if not sources_found:
        return None

    # ── Pick primary (NVD > CIRCL > MITRE) ──────────────────
    primary = nvd or circl

    if primary is None:
        # MITRE-only: description + CWE but no CVSS
        return {**mitre,
                'sources_checked':  ['MITRE'],
                'data_confidence':  'Low',
                'cross_check_note': 'Only MITRE responded — no CVSS available.',
                'is_fallback':       False}

    # ── Cross-check NVD vs CIRCL ─────────────────────────────
    nvd_score   = (nvd   or {}).get('cvss_score')
    circl_score = (circl or {}).get('cvss_score')

    sources_checked = []
    if nvd:
        sources_checked.append('NVD')
    if circl:
        sources_checked.append('CIRCL')
    if mitre:
        sources_checked.append('MITRE')

    if nvd_score and circl_score:
        diff = abs(nvd_score - circl_score)
        if diff <= 0.5:
            confidence = 'High'
            note = (f"NVD and CIRCL agree: "
                    f"NVD={nvd_score}, CIRCL={circl_score} "
                    f"(Δ{diff:.1f})")
        elif diff <= 1.5:
            confidence = 'Medium'
            note = (f"Minor score difference: "
                    f"NVD={nvd_score}, CIRCL={circl_score} "
                    f"(Δ{diff:.1f}) — using NVD")
        else:
            confidence = 'Low'
            note = (f"⚠ Score discrepancy: "
                    f"NVD={nvd_score}, CIRCL={circl_score} "
                    f"(Δ{diff:.1f}) — verify manually")
    elif nvd_score:
        confidence = 'Medium'
        note       = f"Only NVD score available ({nvd_score}). CIRCL not found."
    elif circl_score:
        confidence = 'Medium'
        note       = f"Only CIRCL score available ({circl_score}). NVD not found."
    else:
        confidence = 'Low'
        note       = "No CVSS score from any source."

    # ── Build merged result (start from primary) ─────────────
    merged = dict(primary)

    # Fill gaps from secondary sources
    if not merged.get('description') and circl:
        merged['description'] = circl.get('description', '')
    if not merged.get('description') and mitre:
        merged['description'] = mitre.get('description', '')
    if not merged.get('weaknesses') and circl:
        merged['weaknesses'] = circl.get('weaknesses', [])
    if not merged.get('weaknesses') and mitre:
        merged['weaknesses'] = mitre.get('weaknesses', [])
    if not merged.get('published') and circl:
        merged['published'] = circl.get('published', 'N/A')

    # Add multi-source metadata
    merged['sources_checked']  = sources_checked
    merged['data_confidence']  = confidence
    merged['cross_check_note'] = note
    merged['alt_score']        = circl_score if nvd else None
    merged['alt_source']       = 'CIRCL'    if nvd else None
    merged['mitre_cwe']        = ((mitre or {}).get('weaknesses') or [''])[0] or None

    # Remove internal key
    merged.pop('_source', None)

    print(f"[+] Cross-check: {confidence} — {note}")
    return merged


# ── Claude fallback ───────────────────────────────────────────
def _claude_fallback(cve_id, finding=None):
    """
    When all three APIs return nothing, ask Claude for a best-effort
    CVE assessment.  Always tagged is_ai_estimated=True — never mixed
    with real database results or presented as ground truth.
    """
    title = ''
    if finding:
        title = finding.get('title', '')

    prompt = f"""You are a cybersecurity expert. A finding in a penetration test references {cve_id}.

Finding title: {title}

All CVE database lookups (NVD, CIRCL, MITRE) failed to return data for this CVE ID. Provide a best-effort assessment based on your training knowledge.

Respond ONLY in this exact JSON format, no markdown:
{{
  "description": "Brief description of the vulnerability",
  "cvss_score": 0.0,
  "cvss_severity": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "cvss_vector": "CVSS:3.1/AV:.../...",
  "cwe": "CWE-XXX",
  "confidence": "HIGH|MEDIUM|LOW",
  "notes": "Any caveats about this AI-generated assessment"
}}

Rules:
- Only provide information you are highly confident about
- Set confidence LOW if you are unsure
- If completely unknown, set cvss_score to 5.0 and confidence to LOW
- Return valid JSON only"""

    try:
        from backend.gpt_enricher import call_claude
        print(f"[*] Claude fallback → {cve_id}")
        content = call_claude(prompt, max_tokens=400)
        content = content.strip()
        if content.startswith('```'):
            content = '\n'.join(content.split('\n')[1:-1])
        ai = json.loads(content.strip())

        score    = float(ai.get('cvss_score', 5.0))
        severity = ai.get('cvss_severity', 'MEDIUM')

        print(f"[+] Claude ✓ {cve_id} — AI-estimated CVSS {score} {severity} "
              f"(confidence: {ai.get('confidence', 'LOW')})")

        return {
            'cve_id':            cve_id,
            'description':       ai.get('description', ''),
            'cvss_score':        score,
            'cvss_version':      '3.1',
            'cvss_severity':     severity,
            'cvss_vector':       ai.get('cvss_vector', ''),
            'published':         'N/A',
            'last_modified':     'N/A',
            'attack_vector':     None,
            'attack_complexity': None,
            'privileges_req':    None,
            'user_interaction':  None,
            'exploitability':    None,
            'exploit_level':     'Unknown',
            'exploit_reason':    'AI-estimated — no database match found',
            'weaknesses':        ([ai['cwe']] if ai.get('cwe') else []),
            'references':        [],
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'is_fallback':       False,
            'is_ai_estimated':   True,
            'ai_confidence':     ai.get('confidence', 'LOW'),
            'ai_notes':          ai.get('notes', ''),
            'sources_checked':   ['Claude AI'],
            'data_confidence':   'AI-Estimated',
            'cross_check_note':  (
                f"NVD, CIRCL and MITRE all returned no data. "
                f"This score was estimated by Claude AI "
                f"(confidence: {ai.get('confidence', 'LOW')}). "
                f"Treat as indicative only."
            ),
        }
    except Exception as e:
        print(f"[!] Claude fallback failed for {cve_id}: {e}")
        return None


# ── Main entry point ──────────────────────────────────────────
def lookup_cve_multi(cve_id, finding=None):
    """
    Query NVD + CIRCL + MITRE for a CVE ID, cross-check scores,
    and fall back to Claude if all sources return nothing.

    Returns a dict shaped like nvd_best (the existing UI standard)
    with additional multi-source fields:
      sources_checked   — list of sources that responded
      data_confidence   — High / Medium / Low / AI-Estimated
      cross_check_note  — human-readable comparison result
      alt_score         — CIRCL score for comparison
      mitre_cwe         — CWE from MITRE record
    """
    print(f"\n[*] Multi-source CVE lookup: {cve_id}")
    print(f"{'─' * 45}")

    nvd   = fetch_nvd(cve_id)
    circl = fetch_circl(cve_id)
    mitre = fetch_mitre(cve_id)

    merged = _cross_check(nvd, circl, mitre, cve_id)
    if merged:
        return merged

    # All three sources empty → Claude fallback
    print(f"[*] All sources empty for {cve_id} — "
          f"trying Claude API fallback...")
    fallback = _claude_fallback(cve_id, finding)
    if fallback:
        return fallback

    print(f"[!] No data found for {cve_id} from any source.")
    return None


if __name__ == '__main__':
    print("=" * 55)
    print("AutoRed — Multi-Source CVE Lookup Test")
    print("=" * 55)

    test_cves = [
        ('CVE-2011-2523', None),   # vsftpd backdoor
        ('CVE-2004-2687', None),   # DistCC RCE
        ('CVE-2012-1823', None),   # PHP CGI
    ]

    for cve_id, finding in test_cves:
        print(f"\n{'═' * 55}")
        result = lookup_cve_multi(cve_id, finding)
        if result:
            print(f"\n  CVE      : {result['cve_id']}")
            print(f"  CVSS     : {result.get('cvss_score')} "
                  f"{result.get('cvss_severity')}")
            print(f"  Sources  : {result.get('sources_checked')}")
            print(f"  Confidence: {result.get('data_confidence')}")
            print(f"  Note     : {result.get('cross_check_note')}")
            desc = (result.get('description') or '')[:80]
            print(f"  Desc     : {desc}...")
        else:
            print(f"  No data found.")

    print(f"\n{'=' * 55}")
    print("[+] Test complete.")
