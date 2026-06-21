import pickle
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import STAT_FEATURE_NAMES, build_matrix

HERE = Path(__file__).parent
CSV = HERE.parent / "dataset" / "data_capec_multilabel.csv"
MODEL_OUT = HERE / "waf.pkl"
SPLIT_OUT = HERE / "test_split.pkl"

TEXT_COLS = ["request_http_method", "request_http_request", "request_body"]

LABELS = {
    "66 - SQL Injection": "SQLi",
    "88 - OS Command Injection": "OS_Command_Injection",
    "248 - Command Injection": "Command_Injection",
    "242 - Code Injection": "Code_Injection",
    "126 - Path Traversal": "Path_Traversal",
    "34 - HTTP Response Splitting": "Response_Splitting",
    "33 - HTTP Request Smuggling": "Request_Smuggling",
    "274 - HTTP Verb Tampering": "Verb_Tampering",
    "272 - Protocol Manipulation": "Protocol_Manipulation",
    "153 - Input Data Manipulation": "Input_Manipulation",
    "194 - Fake the Source of Data": "Fake_Source",
    "16 - Dictionary-based Password Attack": "Dictionary_Attack",
    "310 - Scanning for Vulnerable Software": "Scanning",
}
PRIORITY = list(LABELS.keys())
RARE_THRESHOLD = 40


def load():
    import os
    print(f"[load] reading {CSV} ...", flush=True)
    cols = TEXT_COLS + ["000 - Normal"] + PRIORITY
    nrows = int(os.getenv("WAF_MAX_ROWS", "0")) or None
    df = pd.read_csv(CSV, usecols=cols, dtype=str, keep_default_na=False,
                     encoding="utf-8", encoding_errors="replace", low_memory=False, nrows=nrows)
    print(f"[load] {len(df):,} rows", flush=True)

    text = (df["request_http_method"] + " " + df["request_http_request"]
            + " " + df["request_body"]).str.slice(0, 4000)

    label_arr = np.full(len(df), "Normal", dtype=object)
    for col in reversed(PRIORITY):
        mask = df[col].astype(str).str.strip().isin(["1", "1.0", "True"])
        label_arr[mask.values] = LABELS[col]
    return text.values, label_arr


def collapse_rare(y):
    vals, counts = np.unique(y, return_counts=True)
    rare = {v for v, c in zip(vals, counts) if c < RARE_THRESHOLD and v != "Normal"}
    if rare:
        y = np.array(["Other_Attack" if v in rare else v for v in y], dtype=object)
        print(f"[labels] collapsed rare classes {sorted(rare)} -> Other_Attack", flush=True)
    return y


def subsample(text, y, cap):
    rng = np.random.default_rng(42)
    keep = []
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        if len(idx) > cap:
            idx = rng.choice(idx, cap, replace=False)
        keep.append(idx)
    keep = np.concatenate(keep)
    rng.shuffle(keep)
    return text[keep], y[keep]


def main():
    import os
    t0 = time.time()
    text, y = load()

    cap = int(os.getenv("WAF_CLASS_CAP", "60000"))
    text, y = subsample(text, y, cap)
    print(f"[subsample] capped each class at {cap:,} -> {len(y):,} rows", flush=True)

    vals, counts = np.unique(y, return_counts=True)
    drop = {v for v, c in zip(vals, counts) if c < 50 and v != "Normal"}
    if drop:
        mask = ~np.isin(y, list(drop))
        text, y = text[mask], y[mask]
        print(f"[labels] dropped ultra-rare classes (<50): {sorted(drop)}", flush=True)

    vals, counts = np.unique(y, return_counts=True)
    print("[labels] class distribution:")
    for v, c in sorted(zip(vals, counts), key=lambda kv: -kv[1]):
        print(f"   {v:<24} {c:>8,}")

    X_train_txt, X_test_txt, y_train, y_test = train_test_split(
        text, y, test_size=0.20, random_state=42, stratify=y)
    print(f"[split] train={len(X_train_txt):,}  test={len(X_test_txt):,}", flush=True)

    print("[tfidf] fitting char n-gram (1,2) max_features=2000 ...", flush=True)
    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(1, 2), max_features=2000,
                            lowercase=True, min_df=3)
    tfidf.fit(X_train_txt)

    print("[features] building train matrix ...", flush=True)
    Xtr = build_matrix(X_train_txt, tfidf)
    print("[features] building test matrix ...", flush=True)
    Xte = build_matrix(X_test_txt, tfidf)

    le = LabelEncoder().fit(y_train)
    ytr = le.transform(y_train)
    yte = le.transform(y_test)

    sw = compute_sample_weight("balanced", ytr)

    print(f"[xgb] training {len(le.classes_)}-class XGBoost ...", flush=True)
    clf = XGBClassifier(
        n_estimators=400, max_depth=9, learning_rate=0.2, subsample=0.9,
        colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
        objective="multi:softprob", eval_metric="mlogloss", random_state=42,
    )
    clf.fit(Xtr, ytr, sample_weight=sw)

    with open(MODEL_OUT, "wb") as f:
        pickle.dump({"model": clf, "vectorizer": tfidf, "label_encoder": le,
                     "stat_feature_names": STAT_FEATURE_NAMES}, f)
    print(f"[save] wrote {MODEL_OUT} ({MODEL_OUT.stat().st_size/1e6:.1f} MB)", flush=True)

    with open(SPLIT_OUT, "wb") as f:
        pickle.dump({"text": X_test_txt, "y": y_test}, f)
    print(f"[save] wrote {SPLIT_OUT}", flush=True)

    from sklearn.metrics import accuracy_score, classification_report, f1_score
    pred = clf.predict(Xte)
    acc = accuracy_score(yte, pred)
    macro = f1_score(yte, pred, average="macro")
    print(f"\n[result] accuracy={acc*100:.2f}%  macro-F1={macro*100:.2f}%")
    print(classification_report(yte, pred, target_names=list(le.classes_), digits=3, zero_division=0))
    print(f"[done] {time.time()-t0:.0f}s total")


if __name__ == "__main__":
    main()
