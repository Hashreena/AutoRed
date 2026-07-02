"""
AutoRed — CVSS Model Trainer
============================

Learns to predict a CVSS v3.1 *vector* from a finding's text + CWE, using
real NVD data as the training set. The score itself is then computed by the
official formula in cvss_predictor.cvss31_base — so the model only does the
qualitative part (the vector), and the maths stays authoritative.

Pipeline per CVSS metric (AV, AC, PR, UI, S, C, I, A):
    [ TF-IDF(description)  +  OneHot(CWE) ]  ->  LogisticRegression
(metrics that are constant in the data fall back to a DummyClassifier).

Run this ON YOUR MACHINE (needs internet to reach the NVD API):

    python3 backend/train_cvss_model.py --max 30000

A free NVD API key (https://nvd.nist.gov/developers/request-an-api-key)
makes it much faster — put NVD_API_KEY=... in your .env.

Output: backend/cvss_model.joblib  (+ a printed evaluation report).
Once it exists, cvss_predictor uses it automatically; until then the app
falls back to the CWE baseline table.
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.parse
import urllib.error

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import joblib

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
)
from backend.cvss_predictor import (
    parse_vector, cvss31_base, derive_cvss_from_cwe, CWE_CVSS_VECTORS
)

METRICS  = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HERE     = os.path.dirname(__file__)
CACHE    = os.path.join(HERE, 'nvd_cache')
MODEL    = os.path.join(HERE, 'cvss_model.joblib')


def load_nvd_key():
    key = os.environ.get('NVD_API_KEY', '')
    if key:
        return key
    env = os.path.join(HERE, '..', '.env')
    if os.path.exists(env):
        with open(env) as f:
            for line in f:
                line = line.strip()
                if line.startswith('NVD_API_KEY='):
                    return line.split('=', 1)[1].strip()
    return ''


def fetch_page(start, per_page, api_key):
    params = {'resultsPerPage': per_page, 'startIndex': start}
    url    = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
    cache_f = os.path.join(CACHE, f"page_{start}.json")
    if os.path.exists(cache_f):
        with open(cache_f) as f:
            return json.load(f)

    headers = {'User-Agent': 'AutoRed-Trainer/1.0'}
    if api_key:
        headers['apiKey'] = api_key

    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            os.makedirs(CACHE, exist_ok=True)
            with open(cache_f, 'w') as f:
                json.dump(data, f)
            return data
        except urllib.error.HTTPError as e:
            wait = 10 if e.code == 403 else 6
            print(f"   HTTP {e.code} — backing off {wait}s "
                  f"(attempt {attempt + 1})")
            time.sleep(wait)
        except Exception as e:
            print(f"   fetch error: {e} — retrying")
            time.sleep(6)
    return None


def first_cwe(cve):
    for w in cve.get('weaknesses', []):
        for d in w.get('description', []):
            val = d.get('value', '')
            if val.startswith('CWE-') and val.split('-')[1].isdigit():
                return val
    return 'CWE-0'   # unknown / NVD-CWE-noinfo


def english_desc(cve):
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            return d.get('value', '')
    return ''


def v31_vector(cve):
    metrics = cve.get('metrics', {})
    arr     = metrics.get('cvssMetricV31', [])
    if not arr:
        return None
    return arr[0].get('cvssData', {}).get('vectorString')


def build_dataset(max_cves, per_page, api_key):
    rows  = []
    start = 0
    total = None
    delay = 0.7 if api_key else 6.5   # respect rate limits

    while True:
        print(f"[*] Fetching CVEs {start}..{start + per_page}")
        data = fetch_page(start, per_page, api_key)
        if not data:
            print("[!] Stopping — fetch failed.")
            break
        if total is None:
            total = data.get('totalResults', 0)
            print(f"[*] NVD reports {total} total CVEs")

        for item in data.get('vulnerabilities', []):
            cve  = item.get('cve', {})
            vec  = v31_vector(cve)
            desc = english_desc(cve)
            if not vec or not desc:
                continue
            m = parse_vector(vec)
            if not all(k in m for k in METRICS):
                continue
            rows.append({
                'text': desc,
                'cwe':  first_cwe(cve),
                **{k: m[k] for k in METRICS},
            })

        start += per_page
        if start >= min(total or 0, max_cves):
            break
        time.sleep(delay)

    print(f"[+] Usable training rows: {len(rows)}")
    return rows


def train(rows):
    X = np.array([[r['text'], r['cwe']] for r in rows], dtype=object)
    X_tr, X_te, idx_tr, idx_te = train_test_split(
        X, np.arange(len(rows)), test_size=0.2, random_state=42
    )

    models = {}
    for metric in METRICS:
        y    = np.array([rows[i][metric] for i in idx_tr])
        pre  = ColumnTransformer([
            ('txt', TfidfVectorizer(ngram_range=(1, 2),
                                    min_df=3, max_features=20000), 0),
            ('cwe', OneHotEncoder(handle_unknown='ignore'), [1]),
        ])
        est = (DummyClassifier(strategy='most_frequent')
               if len(set(y)) < 2 else
               LogisticRegression(max_iter=1000, C=4.0))
        pipe = Pipeline([('pre', pre), ('clf', est)])
        pipe.fit(X_tr, y)
        models[metric] = pipe
        print(f"   trained {metric}: classes={sorted(set(y))}")

    return models, X_te, idx_te


def evaluate(models, rows, X_te, idx_te):
    print("\n" + "=" * 56)
    print("EVALUATION (held-out 20%)")
    print("=" * 56)

    # per-metric accuracy
    per_metric = {}
    preds = {m: models[m].predict(X_te) for m in METRICS}
    for m in METRICS:
        truth = np.array([rows[i][m] for i in idx_te])
        acc   = (preds[m] == truth).mean()
        per_metric[m] = acc
        print(f"  {m}: accuracy {acc:.3f}")

    # exact-vector match + score MAE (ML vs CWE baseline)
    exact = 0
    ml_abs, base_abs = [], []
    order = METRICS
    for n, i in enumerate(idx_te):
        true_vec = "CVSS:3.1/" + "/".join(
            f"{k}:{rows[i][k]}" for k in order
        )
        pred_vec = "CVSS:3.1/" + "/".join(
            f"{k}:{preds[k][n]}" for k in order
        )
        if pred_vec == true_vec:
            exact += 1
        t_score = cvss31_base(true_vec)['base_score']
        p_score = cvss31_base(pred_vec)['base_score']
        ml_abs.append(abs(p_score - t_score))
        # CWE-table baseline for comparison
        base = derive_cvss_from_cwe(rows[i]['cwe'])
        base_abs.append(abs(base['cvss_score'] - t_score))

    n_te = len(idx_te)
    print(f"\n  Exact vector match: {exact}/{n_te} "
          f"({100 * exact / n_te:.1f}%)")
    print(f"  Score MAE — ML model     : {np.mean(ml_abs):.2f}")
    print(f"  Score MAE — CWE baseline : {np.mean(base_abs):.2f}")
    print("  (lower MAE = closer to the real NVD score)")
    return per_metric


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max', type=int, default=30000,
                    help='max CVEs to pull (default 30000)')
    ap.add_argument('--per-page', type=int, default=2000)
    args = ap.parse_args()

    key = load_nvd_key()
    print(f"[*] NVD API key: {'yes' if key else 'no (slower)'}")

    rows = build_dataset(args.max, args.per_page, key)
    if len(rows) < 500:
        print("[!] Too few rows to train a useful model. Aborting.")
        return

    models, X_te, idx_te = train(rows)
    evaluate(models, rows, X_te, idx_te)

    bundle = {
        'metrics':         METRICS,
        'models':          models,
        'trained_rows':    len(rows),
        'sklearn_version': __import__('sklearn').__version__,
    }
    joblib.dump(bundle, MODEL)
    print(f"\n[+] Saved model -> {MODEL}")
    print("[+] cvss_predictor will now use it automatically.")


if __name__ == '__main__':
    main()
