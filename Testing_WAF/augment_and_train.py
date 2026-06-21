import pickle
import sys
import time
import urllib.parse
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from features import STAT_FEATURE_NAMES, build_matrix
from waf_train import load as load_srbh

SECLISTS = HERE.parent / "SecLists"
MODEL_OUT = HERE / "waf.pkl"
SPLIT_OUT = HERE / "test_split.pkl"

CORE_SRBH = {"Normal", "SQLi", "OS_Command_Injection", "Path_Traversal", "Code_Injection"}
SRBH_CAPS = {"Normal": 50000, "SQLi": 30000}
FINAL_CAP = 32000

GET_TEMPLATES = [
    ("GET", "/index.php", "page"), ("GET", "/search", "q"), ("GET", "/product", "id"),
    ("GET", "/view", "file"), ("GET", "/api/items", "filter"), ("GET", "/comment", "text"),
    ("GET", "/profile", "name"), ("GET", "/load", "url"), ("GET", "/proxy", "target"),
    ("GET", "/page", "include"), ("GET", "/article", "lang"), ("GET", "/redirect", "next"),
    ("GET", "/fetch", "uri"), ("GET", "/render", "tpl"), ("GET", "/q", "query"),
]
POST_TEMPLATES = [
    ("POST", "/submit", "data"), ("POST", "/comment", "message"),
    ("POST", "/login", "username"), ("POST", "/api/render", "template"),
    ("POST", "/upload", "filename"),
]


def read_lines(rel, limit=None):
    p = SECLISTS / rel
    if not p.exists():
        print(f"  [warn] missing {rel}")
        return []
    out = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
        if limit and len(out) >= limit:
            break
    return out


def make_requests(payloads, label, per_payload, rng):
    rows = []
    templates = GET_TEMPLATES + POST_TEMPLATES
    for raw in payloads:
        dec = urllib.parse.unquote(raw)
        forms = {raw, dec, urllib.parse.quote(dec, safe="")}
        chosen = rng.choice(len(templates), size=min(per_payload, len(templates)), replace=False)
        for ti in chosen:
            method, path, param = templates[ti]
            val = rng.choice(list(forms))
            if method == "GET":
                rows.append((f"GET {path}?{param}={val} ", label))
            else:
                rows.append((f"POST {path} {param}={val}", label))
    return rows


def synth_ssrf(rng, n):
    hosts = ["169.254.169.254", "127.0.0.1", "localhost", "0.0.0.0", "[::1]",
             "metadata.google.internal", "internal.local", "10.0.0.1", "192.168.1.1"]
    schemes = ["http://", "https://", "file://", "gopher://", "dict://", "ftp://"]
    paths = ["/latest/meta-data/", "/admin", "/", "/server-status", ":6379/_INFO",
             ":8080/actuator/env", "/etc/passwd", ":22", "/.env"]
    out = set()
    while len(out) < n:
        out.add(rng.choice(schemes) + rng.choice(hosts) + rng.choice(paths))
    return list(out)


def synth_rfi(rng, n):
    hosts = ["evil.com", "attacker.example", "malicious.host", "pastebin.com/raw",
             "raw.githubusercontent.com/x/y", "169.254.13.37", "10.10.10.10"]
    files = ["/shell.txt", "/c99.php", "/backdoor.txt", "/r57.txt", "/cmd.php?", "/x.txt%00"]
    schemes = ["http://", "https://", "ftp://", "//"]
    out = set()
    while len(out) < n:
        out.add(rng.choice(schemes) + rng.choice(hosts) + rng.choice(files))
    return list(out)


def synth_benign(rng, n):
    paths = ["/", "/index.php", "/home", "/about", "/contact", "/products", "/product",
             "/search", "/blog", "/blog/post", "/login", "/account", "/cart", "/checkout",
             "/api/users", "/api/products", "/static/css/main.css", "/images/logo.png",
             "/js/app.js", "/category", "/faq", "/pricing", "/dashboard", "/settings",
             "/wp-login.php", "/news", "/help", "/support", "/view", "/page", "/profile",
             "/article", "/download", "/render", "/load"]
    params = ["q", "id", "page", "file", "name", "url", "lang", "ref", "sort", "category",
              "slug", "include", "target", "tpl", "query", "filter", "text", "next", "uri",
              "view", "p", "tab", "section", "format"]
    vals = ["home", "about", "index.html", "main.css", "logo.png", "report.pdf", "contact",
            "products", "books", "laptop", "hello-world", "summer-sale", "john", "en", "us",
            "dashboard", "profile", "settings", "blue", "medium", "guide", "help", "faq",
            "news", "welcome", "app.js", "data.json", "page-2", "best-sellers", "default"]
    rows = []
    for _ in range(n):
        path = rng.choice(paths)
        r = rng.random()
        if r < 0.25:
            rows.append((f"GET {path} ", "Normal"))
        elif r < 0.7:
            k = rng.choice(params)
            v = rng.choice(vals) if rng.random() < 0.6 else str(rng.integers(1, 9999))
            if rng.random() < 0.3:
                rows.append((f"GET {path}?{k}={v}&{rng.choice(params)}={rng.integers(1,500)} ", "Normal"))
            else:
                rows.append((f"GET {path}?{k}={v} ", "Normal"))
        else:
            forms = [
                f"username={rng.choice(vals)}&password={rng.integers(1000,99999)}",
                f"email={rng.choice(vals)}@example.com&remember=1",
                f"name={rng.choice(vals)}&message={rng.choice(vals)}",
                f"q={rng.choice(vals)}&sort=price&page={rng.integers(1,20)}",
            ]
            rows.append((f"POST {path} {rng.choice(forms)}", "Normal"))
    return rows


def cap(text, lab, n, rng):
    keep = []
    for cls in np.unique(lab):
        idx = np.where(lab == cls)[0]
        if len(idx) > n:
            idx = rng.choice(idx, n, replace=False)
        keep.append(idx)
    keep = np.concatenate(keep)
    rng.shuffle(keep)
    return text[keep], lab[keep]


def main():
    t0 = time.time()
    rng = np.random.default_rng(42)

    print("[srbh] loading + filtering to core classes ...", flush=True)
    s_text, s_lab = load_srbh()
    rows_text, rows_lab = [], []
    for cls in CORE_SRBH:
        idx = np.where(s_lab == cls)[0]
        c = SRBH_CAPS.get(cls)
        if c and len(idx) > c:
            idx = rng.choice(idx, c, replace=False)
        rows_text.append(s_text[idx]); rows_lab.append(np.full(len(idx), cls, dtype=object))
    aug = list(zip(np.concatenate(rows_text), np.concatenate(rows_lab)))
    print(f"[srbh] kept {len(aug):,} rows", flush=True)

    print("[augment] adding SecLists + synthetic attack payloads ...", flush=True)
    aug += make_requests(read_lines("Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt"), "XSS", 60, rng)
    aug += make_requests(read_lines("Fuzzing/Databases/SQLi/Generic-SQLi.txt"), "SQLi", 12, rng)
    aug += make_requests(read_lines("Fuzzing/LFI/LFI-Jhaddix.txt", 600), "Path_Traversal", 6, rng)
    aug += make_requests(read_lines("Fuzzing/command-injection-commix.txt", 3000), "OS_Command_Injection", 2, rng)
    ssti = read_lines("Fuzzing/template-engines-expression.txt") + read_lines("Fuzzing/template-engines-special-vars.txt") + [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "{{''.__class__}}",
        "${{7*7}}", "{{request.application}}", "@(7*7)", "{php}echo 1;{/php}", "{{7*'7'}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}", "${T(java.lang.Runtime)}",
    ]
    aug += make_requests(ssti, "SSTI", 60, rng)
    aug += make_requests(synth_ssrf(rng, 120), "SSRF", 20, rng)
    aug += make_requests(synth_rfi(rng, 120), "RFI", 20, rng)
    aug += synth_benign(rng, 38000)

    text = np.array([r[0] for r in aug], dtype=object)
    lab = np.array([r[1] for r in aug], dtype=object)
    text, lab = cap(text, lab, FINAL_CAP, rng)

    vals, counts = np.unique(lab, return_counts=True)
    print("[labels] final class distribution:")
    for v, c in sorted(zip(vals, counts), key=lambda kv: -kv[1]):
        print(f"   {v:<22} {c:>8,}")

    Xtr_t, Xte_t, ytr_l, yte_l = train_test_split(text, lab, test_size=0.20, random_state=42, stratify=lab)
    print(f"[split] train={len(Xtr_t):,} test={len(Xte_t):,}", flush=True)

    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(1, 2), max_features=2000, lowercase=True, min_df=3)
    tfidf.fit(Xtr_t)
    print("[features] building matrices ...", flush=True)
    Xtr = build_matrix(Xtr_t, tfidf)
    Xte = build_matrix(Xte_t, tfidf)

    le = LabelEncoder().fit(ytr_l)
    ytr, yte = le.transform(ytr_l), le.transform(yte_l)
    sw = compute_sample_weight("balanced", ytr)

    print(f"[xgb] training {len(le.classes_)}-class model ...", flush=True)
    clf = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2, subsample=0.9,
                        colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
                        objective="multi:softprob", eval_metric="mlogloss", random_state=42)
    clf.fit(Xtr, ytr, sample_weight=sw)

    pickle.dump({"model": clf, "vectorizer": tfidf, "label_encoder": le,
                 "stat_feature_names": STAT_FEATURE_NAMES}, open(MODEL_OUT, "wb"))
    pickle.dump({"text": Xte_t, "y": yte_l}, open(SPLIT_OUT, "wb"))
    print(f"[save] {MODEL_OUT} + {SPLIT_OUT}", flush=True)

    pred = clf.predict(Xte)
    print(f"\n[result] accuracy={accuracy_score(yte, pred)*100:.2f}%  macro-F1={f1_score(yte, pred, average='macro')*100:.2f}%")
    print(classification_report(yte, pred, target_names=list(le.classes_), digits=3, zero_division=0))
    print(f"[done] {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
