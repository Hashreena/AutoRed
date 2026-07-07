"""
AutoRed — Multi-Source CVE Enrichment
======================================
Queries four independent CVE data sources for a given CVE ID, then
cross-checks the scores for confidence. Falls back to Claude AI when
all sources return nothing, then verifies the AI suggestion against
two authoritative sources before accepting it.

Lookup order:
  1. CVE.org REST API  (cve.circl.lu/api/cve or www.cve.org/api)
                        — MITRE-authoritative CVE identity + description
  2. NVD               (services.nvd.nist.gov)
                        — authoritative CVSS v3.1 + description
  3. CIRCL             (cve.circl.lu)
                        — independent score, free, no key needed
  4. MITRE CVE AWG     (cveawg.mitre.org)
                        — authoritative CWE mapping

Cross-check:
  NVD score vs CIRCL score → confidence: High / Medium / Low / AI-Estimated

Claude fallback + verification:
  If all four APIs fail, Claude suggests a CVE ID. The suggestion is
  then verified against BOTH CVE.org AND NVD before being accepted.
  If neither confirms the CVE exists → discarded as hallucinated.
  Accepted AI suggestions are clearly tagged is_ai_estimated=True.

Integration:
  Used by cve_enricher.enrich_finding Step 2.
"""
import json
import os
import re
import subprocess
import time

# ── Rate-limit state (one timestamp per host) ─────────────────
_LAST = {'nvd': 0.0, 'circl': 0.0, 'mitre': 0.0, 'cveorg': 0.0}

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


# ── Source 1: CVE.org REST API (MITRE authoritative) ─────────
def fetch_cve_org(cve_id):
    """
    Query the official CVE.org REST API.
    CVE.org is maintained by MITRE and is the most authoritative
    source for CVE identity, description and CWE mapping.
    It receives new CVEs faster than NVD which has a scoring backlog.
    Endpoint: https://cveawg.mitre.org/api/cve/{CVE-ID}
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    print(f"[*] CVE.org → {cve_id}")
    data = _fetch(url, 'cveorg', min_gap=0.5)
    if not data:
        return None
    try:
        cna = data.get('containers', {}).get('cna', {})

        # Description
        desc = ''
        for d in cna.get('descriptions', []):
            if d.get('lang') in ('en', 'en-US', 'en_US'):
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

        # CVSS (some CNAs include scores)
        score = None
        severity = None
        vector = None
        for m in cna.get('metrics', []):
            for key in ('cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                if key in m:
                    score    = m[key].get('baseScore')
                    severity = m[key].get('baseSeverity')
                    vector   = m[key].get('vectorString')
                    break
            if score:
                break

        # Published date
        meta      = data.get('cveMetadata', {})
        published = str(meta.get('datePublished', ''))[:10]
        state     = meta.get('state', '')

        # References
        refs = []
        for r in cna.get('references', [])[:5]:
            u = r.get('url', '')
            if u:
                refs.append({'url': u, 'tags': r.get('tags', [])})

        if not desc and state != 'PUBLISHED':
            print(f"[!] CVE.org: {cve_id} state={state} — "
                  f"may be reserved or rejected")
            return None

        print(f"[+] CVE.org ✓ {cve_id} — CWE: {cwe or 'N/A'} "
              f"| CVSS: {score or 'N/A'}")
        return {
            'cve_id':        cve_id,
            'description':   desc,
            'cvss_score':    score,
            'cvss_severity': severity,
            'cvss_vector':   vector,
            'published':     published,
            'weaknesses':    [cwe] if cwe else [],
            'references':    refs,
            'nvd_url':       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'cve_org_url':   f"https://www.cve.org/CVERecord?id={cve_id}",
            '_source':       'CVE.org',
        }
    except Exception as e:
        print(f"[!] CVE.org parse error for {cve_id}: {e}")
        return None


# ── Source 2: NVD ─────────────────────────────────────────────
def fetch_nvd(cve_id):
    """Query NVD API 2.0 for a specific CVE."""
    url     = (f"https://services.nvd.nist.gov/rest/json/"
               f"cves/2.0?cveId={cve_id}")
    headers = []
    if _NVD_KEY:
        headers.append(f'apiKey: {_NVD_KEY}')
    min_gap = 0.8 if _NVD_KEY else 6.5
    print(f"[*] NVD    → {cve_id}")
    data = _fetch(url, 'nvd', headers, min_gap=min_gap)
    if not data:
        return None
    result = _parse_nvd_response(data)
    if result:
        print(f"[+] NVD    ✓ {cve_id} — CVSS {result.get('cvss_score')} "
              f"{result.get('cvss_severity')}")
    return result


# ── Source 3: CIRCL CVE API ───────────────────────────────────
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
    print(f"[*] CIRCL  → {cve_id}")
    data = _fetch(url, 'circl', min_gap=0.5)
    if not data or not data.get('id'):
        return None
    score3  = _parse_circl_cvss3(data.get('cvss3'))
    score2  = float(data['cvss']) if data.get('cvss') else None
    score   = score3 if score3 is not None else score2
    version = '3.1' if score3 is not None else ('2.0' if score2 else None)
    vector  = (data.get('cvss3-vector') or data.get('cvss-vector'))
    cwe_raw = data.get('cwe', '')
    cwe = (cwe_raw if str(cwe_raw).startswith('CWE-') else None)
    refs = []
    for r in (data.get('references') or [])[:5]:
        if isinstance(r, str) and r.startswith('http'):
            refs.append({'url': r, 'tags': []})
    if score:
        print(f"[+] CIRCL  ✓ {cve_id} — CVSS {score} "
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


# ── Source 4: MITRE CVE AWG ───────────────────────────────────
def fetch_mitre(cve_id):
    """
    Query MITRE CVE AWG API (free, no key, no CVSS).
    Used as a supplementary source for CWE mapping.
    Note: CVE.org (fetch_cve_org) is preferred over this as
    it uses the same underlying data with a better API format.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    print(f"[*] MITRE  → {cve_id}")
    data = _fetch(url, 'mitre', min_gap=0.5)
    if not data:
        return None
    try:
        cna = data.get('containers', {}).get('cna', {})
        desc = ''
        for d in cna.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        cwe = None
        for pt in cna.get('problemTypes', []):
            for d in pt.get('descriptions', []):
                val = d.get('cweId') or d.get('description', '')
                if str(val).startswith('CWE-'):
                    cwe = val
                    break
            if cwe:
                break
        score = None
        for m in cna.get('metrics', []):
            for key in ('cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                if key in m:
                    score = m[key].get('baseScore')
                    break
            if score:
                break
        meta      = data.get('cveMetadata', {})
        published = str(meta.get('datePublished', ''))[:10]
        refs = []
        for r in cna.get('references', [])[:5]:
            u = r.get('url', '')
            if u:
                refs.append({'url': u, 'tags': r.get('tags', [])})
        print(f"[+] MITRE  ✓ {cve_id} — CWE: {cwe or 'N/A'}")
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
def _cross_check(cveorg, nvd, circl, mitre, cve_id):
    """
    Merge results from all four sources.
    Priority: CVE.org description/CWE → NVD CVSS → CIRCL cross-check
    → MITRE supplementary CWE.

    CVE.org is authoritative for identity and description.
    NVD is authoritative for CVSS scoring.
    CIRCL provides independent score for confidence cross-check.
    MITRE provides supplementary CWE when others are missing.
    """
    sources_found = [s for s in [cveorg, nvd, circl, mitre] if s]
    if not sources_found:
        return None

    sources_checked = []
    if cveorg:
        sources_checked.append('CVE.org')
    if nvd:
        sources_checked.append('NVD')
    if circl:
        sources_checked.append('CIRCL')
    if mitre:
        sources_checked.append('MITRE')

    # ── Pick primary for CVSS (NVD preferred) ────────────────
    # CVE.org sometimes has CVSS from the CNA but NVD is more reliable
    cvss_primary = nvd or circl

    if cvss_primary is None and cveorg:
        # CVE.org only — use it with Low confidence since no CVSS
        result = dict(cveorg)
        result['sources_checked']  = sources_checked
        result['data_confidence']  = 'Low'
        result['cross_check_note'] = (
            'CVE.org confirmed the CVE identity and description '
            'but NVD and CIRCL returned no CVSS score. '
            'This may be a recently published CVE pending NVD scoring.'
        )
        result['is_fallback'] = False
        result.pop('_source', None)
        return result

    if cvss_primary is None:
        # MITRE-only fallback
        if mitre:
            return {
                **mitre,
                'sources_checked':  sources_checked,
                'data_confidence':  'Low',
                'cross_check_note': 'Only MITRE responded — no CVSS available.',
                'is_fallback':       False,
            }
        return None

    # ── Cross-check NVD vs CIRCL scores ──────────────────────
    nvd_score   = (nvd   or {}).get('cvss_score')
    circl_score = (circl or {}).get('cvss_score')

    if nvd_score and circl_score:
        diff = abs(nvd_score - circl_score)
        if diff <= 0.5:
            confidence = 'High'
            note = (
                f"NVD and CIRCL agree: "
                f"NVD={nvd_score}, CIRCL={circl_score} (Δ{diff:.1f})"
            )
        elif diff <= 1.5:
            confidence = 'Medium'
            note = (
                f"Minor score difference: "
                f"NVD={nvd_score}, CIRCL={circl_score} "
                f"(Δ{diff:.1f}) — using NVD"
            )
        else:
            confidence = 'Low'
            note = (
                f"⚠ Score discrepancy: "
                f"NVD={nvd_score}, CIRCL={circl_score} "
                f"(Δ{diff:.1f}) — verify manually"
            )
    elif nvd_score:
        confidence = 'Medium'
        note = f"Only NVD score available ({nvd_score}). CIRCL not found."
    elif circl_score:
        confidence = 'Medium'
        note = f"Only CIRCL score available ({circl_score}). NVD not found."
    else:
        confidence = 'Low'
        note = "No CVSS score from any source."

    # Add CVE.org confirmation note
    if cveorg:
        note += " CVE.org confirmed CVE identity."

    # ── Build merged result ───────────────────────────────────
    # Start from NVD (best CVSS data) or CIRCL
    merged = dict(cvss_primary)

    # Fill description gaps: prefer CVE.org → NVD → CIRCL → MITRE
    if cveorg and cveorg.get('description'):
        merged['description'] = cveorg['description']
    elif not merged.get('description') and circl:
        merged['description'] = circl.get('description', '')
    if not merged.get('description') and mitre:
        merged['description'] = mitre.get('description', '')

    # Fill CWE gaps: prefer CVE.org → MITRE → CIRCL
    if cveorg and cveorg.get('weaknesses'):
        merged['weaknesses'] = cveorg['weaknesses']
    elif not merged.get('weaknesses') and mitre:
        merged['weaknesses'] = mitre.get('weaknesses', [])
    elif not merged.get('weaknesses') and circl:
        merged['weaknesses'] = circl.get('weaknesses', [])

    # Fill published date
    if not merged.get('published') and cveorg:
        merged['published'] = cveorg.get('published', 'N/A')
    elif not merged.get('published') and circl:
        merged['published'] = circl.get('published', 'N/A')

    # Add CVE.org URL
    merged['cve_org_url'] = f"https://www.cve.org/CVERecord?id={cve_id}"

    # Add multi-source metadata
    merged['sources_checked']  = sources_checked
    merged['data_confidence']  = confidence
    merged['cross_check_note'] = note
    merged['alt_score']        = circl_score if nvd else None
    merged['alt_source']       = 'CIRCL' if nvd else None
    merged['mitre_cwe']        = (
        ((cveorg or {}).get('weaknesses') or
         (mitre  or {}).get('weaknesses') or [''])[0] or None
    )
    merged.pop('_source', None)

    print(f"[+] Cross-check: {confidence} — {note}")
    return merged


# ── Claude CVE Suggester ──────────────────────────────────────
def claude_suggest_cve(finding):
    """
    Ask Claude to suggest the single most relevant CVE ID for a finding
    when all keyword/version searches have returned nothing.
    Returns a CVE ID string (e.g. 'CVE-2009-1891') or None.

    IMPORTANT: The caller MUST verify the suggestion against
    CVE.org AND NVD before trusting it — Claude can hallucinate
    CVE numbers that look real but don't exist.
    """
    title       = finding.get('title', '')
    description = finding.get('description', '')
    evidence    = finding.get('evidence', '')
    asset       = finding.get('asset', '')
    prompt = f"""You are a cybersecurity expert assisting a penetration tester.
A scan found this finding and no CVE has been identified yet:
Title      : {title}
Description: {description[:300]}
Evidence   : {evidence[:200]}
Asset      : {asset}
Task: Identify the single most relevant, specific CVE ID for this finding.
Rules:
- Only suggest a CVE you are HIGHLY CONFIDENT exists and directly applies.
- For outdated software (e.g. Apache 2.2.8), suggest the most critical CVE for that exact version.
- For configuration weaknesses (telnet open, FTP open, missing headers), respond: NONE
- Do NOT invent or guess CVE numbers — if unsure, respond: NONE
- Response must be ONLY a CVE ID in format CVE-YYYY-NNNNN, or the word NONE. Nothing else."""
    try:
        from backend.gpt_enricher import call_claude
        print("[*] Claude → suggesting CVE for this finding...")
        result = call_claude(prompt, max_tokens=30).strip().upper()
        print(f"[*] Claude raw suggestion: {result}")
        match = re.search(r'CVE-\d{4}-\d{4,7}', result)
        if match:
            cve = match.group(0)
            print(f"[+] Claude suggested: {cve}")
            return cve
        print("[*] Claude: no specific CVE for this finding (NONE)")
    except Exception as e:
        print(f"[!] Claude CVE suggestion error: {e}")
    return None


# ── Claude AI suggestion verifier ────────────────────────────
def _verify_ai_suggestion(cve_id):
    """
    Verify a Claude-suggested CVE against CVE.org AND NVD.
    Both sources are checked independently.

    Returns:
      (verified_result, verified_sources) if confirmed by at least one
      (None, []) if neither source confirms the CVE exists

    This prevents hallucinated CVE IDs from entering the system.
    A CVE ID that Claude invented will not exist in either database.
    """
    print(f"[*] Verifying AI suggestion {cve_id} against CVE.org + NVD...")
    verified_sources = []
    cveorg_result = None
    nvd_result    = None

    # Check CVE.org first (faster for new CVEs)
    cveorg_result = fetch_cve_org(cve_id)
    if cveorg_result:
        verified_sources.append('CVE.org')
        print(f"[+] CVE.org confirmed: {cve_id}")
    else:
        print(f"[!] CVE.org did not confirm: {cve_id}")

    # Check NVD independently
    nvd_result = fetch_nvd(cve_id)
    if nvd_result:
        verified_sources.append('NVD')
        print(f"[+] NVD confirmed: {cve_id}")
    else:
        print(f"[!] NVD did not confirm: {cve_id}")

    if not verified_sources:
        print(
            f"[!] AI suggestion {cve_id} NOT confirmed by CVE.org or NVD "
            f"— discarded as likely hallucinated"
        )
        return None, []

    # Build verified result from available sources
    circl_result  = fetch_circl(cve_id)
    mitre_result  = fetch_mitre(cve_id)
    merged = _cross_check(
        cveorg_result, nvd_result,
        circl_result, mitre_result, cve_id
    )
    if merged:
        merged['is_ai_estimated']   = True
        merged['ai_verified']       = True
        merged['ai_verified_by']    = verified_sources
        merged['data_confidence']   = (
            'Medium'
            if len(verified_sources) >= 2
            else 'Low'
        )
        merged['cross_check_note']  = (
            f"AI-suggested CVE verified by: "
            f"{', '.join(verified_sources)}. "
            + merged.get('cross_check_note', '')
        )
    return merged, verified_sources


# ── Claude AI fallback (when CVE ID is known but no data) ─────
def _claude_fallback(cve_id, finding=None):
    """
    When all four APIs return nothing for a KNOWN CVE ID,
    ask Claude for a best-effort assessment.
    Always tagged is_ai_estimated=True.
    """
    title = ''
    if finding:
        title = finding.get('title', '')
    prompt = f"""You are a cybersecurity expert. A finding in a penetration test references {cve_id}.
Finding title: {title}
All CVE database lookups (CVE.org, NVD, CIRCL, MITRE) failed to return data for this CVE ID.
Provide a best-effort assessment based on your training knowledge.
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
            'nvd_url':  f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'cve_org_url': f"https://www.cve.org/CVERecord?id={cve_id}",
            'is_fallback':       False,
            'is_ai_estimated':   True,
            'ai_confidence':     ai.get('confidence', 'LOW'),
            'ai_notes':          ai.get('notes', ''),
            'sources_checked':   ['Claude AI'],
            'data_confidence':   'AI-Estimated',
            'cross_check_note':  (
                f"CVE.org, NVD, CIRCL and MITRE all returned no data. "
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
    Full multi-source CVE lookup with AI fallback and verification.

    Lookup order:
      1. CVE.org  — authoritative identity + description + CWE
      2. NVD      — authoritative CVSS scoring
      3. CIRCL    — independent score for cross-check
      4. MITRE    — supplementary CWE mapping

    If all four return nothing:
      5. Claude suggests a CVE ID
      6. Suggestion verified against CVE.org AND NVD
         → Confirmed by at least one: accepted (is_ai_estimated=True)
         → Confirmed by neither: discarded (hallucination prevention)
      7. If suggestion fails: Claude estimates data for the known CVE ID

    Returns a dict shaped like nvd_best with additional fields:
      sources_checked   — list of sources that responded
      data_confidence   — High / Medium / Low / AI-Estimated
      cross_check_note  — human-readable comparison result
      alt_score         — CIRCL score for comparison
      mitre_cwe         — CWE from MITRE/CVE.org record
      cve_org_url       — link to CVE.org record
      is_ai_estimated   — True if Claude was involved
      ai_verified       — True if AI suggestion was database-verified
    """
    print(f"\n[*] Multi-source CVE lookup: {cve_id}")
    print(f"{'─' * 50}")

    # ── Step 1-4: Query all four sources ─────────────────────
    cveorg = fetch_cve_org(cve_id)
    nvd    = fetch_nvd(cve_id)
    circl  = fetch_circl(cve_id)
    mitre  = fetch_mitre(cve_id)

    merged = _cross_check(cveorg, nvd, circl, mitre, cve_id)
    if merged:
        return merged

    # ── Step 5-6: Claude suggest + verify ────────────────────
    print(f"[*] All sources empty for {cve_id} — "
          f"trying Claude suggestion + verification...")

    suggested = claude_suggest_cve(finding) if finding else None
    if suggested and suggested != cve_id:
        print(f"[*] Claude suggested alternative: {suggested} "
              f"— verifying against CVE.org + NVD...")
        verified, verified_by = _verify_ai_suggestion(suggested)
        if verified:
            print(f"[+] AI suggestion {suggested} verified by "
                  f"{verified_by} — accepted")
            return verified
        else:
            print(f"[!] AI suggestion {suggested} not confirmed "
                  f"by any database — discarded")

    # ── Step 7: Claude fallback for known CVE ID ─────────────
    print(f"[*] Trying Claude fallback for known ID {cve_id}...")
    fallback = _claude_fallback(cve_id, finding)
    if fallback:
        return fallback

    print(f"[!] No data found for {cve_id} from any source.")
    return None


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRed — Multi-Source CVE Lookup Test")
    print("=" * 60)
    test_cves = [
        ('CVE-2011-2523', None),   # vsftpd backdoor
        ('CVE-2004-2687', None),   # DistCC RCE
        ('CVE-2012-1823', None),   # PHP CGI
        ('CVE-2014-0160', None),   # Heartbleed
        ('CVE-2017-0144', None),   # EternalBlue
    ]
    for cve_id, finding in test_cves:
        print(f"\n{'═' * 60}")
        result = lookup_cve_multi(cve_id, finding)
        if result:
            print(f"\n  CVE       : {result['cve_id']}")
            print(f"  CVSS      : {result.get('cvss_score')} "
                  f"{result.get('cvss_severity')}")
            print(f"  Sources   : {result.get('sources_checked')}")
            print(f"  Confidence: {result.get('data_confidence')}")
            print(f"  AI Est.   : {result.get('is_ai_estimated', False)}")
            print(f"  AI Verified: {result.get('ai_verified', False)}")
            print(f"  CVE.org   : {result.get('cve_org_url', 'N/A')}")
            print(f"  Note      : {result.get('cross_check_note')}")
            desc = (result.get('description') or '')[:80]
            print(f"  Desc      : {desc}...")
        else:
            print(f"  No data found.")
    print(f"\n{'=' * 60}")
    print("[+] Test complete.")
