import re
from collections import Counter

import numpy as np
import pandas as pd
from scipy import sparse
from scipy.stats import entropy as scipy_entropy

SPECIAL = set("<>\"';(){}|&$`!@#^~[]")
SPECIAL_CLASS = "[" + re.escape("".join(sorted(SPECIAL))) + "]"

REGEX_CATEGORIES = {
    "sqli": [
        r"(?i)\bunion\b.{0,20}\bselect\b", r"(?i)\bselect\b.{0,40}\bfrom\b",
        r"(?i)\binsert\b.{0,20}\binto\b", r"(?i)\bdrop\b.{0,10}\btable\b",
        r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+", r"(?i)'\s*(or|and)\s*'?\d",
        r"(?i)(sleep|benchmark|waitfor|pg_sleep)\s*\(", r"(?i)information_schema",
        r"(?i)\b(exec|execute)\b.{0,10}(sp_|xp_)",
        r"(?i)\bload_file\s*\(", r"(?i)\binto\s+(outfile|dumpfile)\b", r"(?i)0x[0-9a-f]{4,}",
    ],
    "xss": [
        r"(?i)<script\b", r"(?i)</script>", r"(?i)javascript:",
        r"(?i)on(error|load|mouseover|click|focus|submit)\s*=", r"(?i)alert\s*\(",
        r"(?i)<img\b[^>]*\bsrc\b", r"(?i)<svg\b", r"(?i)<iframe\b",
        r"(?i)document\.(cookie|write|location)", r"(?i)eval\s*\(",
        r"(?i)String\.fromCharCode", r"(?i)%3cscript", r"(?i)expression\s*\(",
    ],
    "traversal": [
        r"(\.\./){2,}", r"(\.\.\\){2,}", r"(?i)(%2e%2e[/\\])", r"(?i)/etc/(passwd|shadow|hosts)",
        r"(?i)/proc/self", r"(?i)c:\\\\?windows", r"(?i)\bboot\.ini\b",
        r"(?i)\.\.[/\\]\.\.[/\\]", r"(?i)%252e%252e",
    ],
    "rce": [
        r"(?i);\s*(ls|id|whoami|cat|nc|curl|wget|ping|uname|dir|type)\b",
        r"(?i)\|\s*(ls|id|whoami|cat|nc|curl|wget|ping|bash|sh)\b",
        r"(?i)&&\s*(ls|id|whoami|cat|nc|curl|wget|ping)\b", r"\$\([^)]+\)",
        r"`[^`]+`", r"(?i)(system|exec|passthru|shell_exec|popen|proc_open)\s*\(",
        r"(?i)/bin/(bash|sh)\b", r"(?i)%0a|%0d", r"(?i)\$\{IFS\}",
    ],
    "rfi_ssrf": [
        r"(?i)(https?|ftp|gopher|dict|file)://", r"(?i)\\\\[\w.]+\\",
        r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)",
        r"(?i)(php|data|expect|zip|phar)://", r"(?i)=https?%3a%2f%2f",
    ],
    "ssti": [
        r"\{\{.{0,40}\}\}", r"\$\{.{0,40}\}", r"(?i)<%.{0,40}%>",
        r"(?i)\{%.{0,40}%\}", r"(?i)(__class__|__mro__|__subclasses__|__globals__)",
        r"(?i)\b(config|self)\.__", r"#\{.{0,40}\}",
    ],
}

STAT_FEATURE_NAMES = [
    "length", "special_count", "special_ratio", "digit_count", "digit_ratio",
    "pct_count", "entropy", "depth", "unique_chars", "upper_ratio", "space_count",
    "alpha_ratio", "param_count", "kw_density",
] + [f"rx_{cat}" for cat in REGEX_CATEGORIES] + [f"rxhit_{cat}" for cat in REGEX_CATEGORIES]


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = np.array(list(Counter(s).values()), dtype=float)
    probs /= probs.sum()
    return float(scipy_entropy(probs, base=2))


def compute_stats(s):
    s = str(s)
    length = len(s)
    spec = len(re.findall(SPECIAL_CLASS, s))
    digit = len(re.findall(r"[0-9]", s))
    alpha = len(re.findall(r"[A-Za-z]", s))
    upper = len(re.findall(r"[A-Z]", s))
    space = len(re.findall(r"\s", s))
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", s))
    depth = s.count("/")
    params = s.count("&") + s.count("=")
    sql_kw = len(re.findall(r"(?i)union|select|insert|drop|exec|sleep", s))
    base = [
        length, spec, spec / max(length, 1), digit, digit / max(length, 1),
        pct, shannon_entropy(s), depth, len(set(s)), upper / max(length, 1), space,
        alpha / max(length, 1), params, sql_kw / max(length, 1),
    ]
    counts, hits = [], []
    for cat in REGEX_CATEGORIES:
        n = sum(1 for p in REGEX_CATEGORIES[cat] if re.search(p, s))
        counts.append(n)
        hits.append(1 if n else 0)
    return base + counts + hits


def any_attack_signal(s):
    s = str(s)
    for cat in REGEX_CATEGORIES:
        for p in REGEX_CATEGORIES[cat]:
            if re.search(p, s):
                return True
    return False


def stats_frame(texts):
    s = pd.Series(texts, dtype="object").fillna("").astype(str)
    length = s.str.len().to_numpy(dtype=np.float32)
    safe = np.maximum(length, 1)
    spec = s.str.count(SPECIAL_CLASS).to_numpy(dtype=np.float32)
    digit = s.str.count(r"[0-9]").to_numpy(dtype=np.float32)
    alpha = s.str.count(r"[A-Za-z]").to_numpy(dtype=np.float32)
    upper = s.str.count(r"[A-Z]").to_numpy(dtype=np.float32)
    space = s.str.count(r"\s").to_numpy(dtype=np.float32)
    pct = s.str.count(r"%[0-9a-fA-F]{2}").to_numpy(dtype=np.float32)
    depth = s.str.count("/").to_numpy(dtype=np.float32)
    params = s.str.count(r"[&=]").to_numpy(dtype=np.float32)
    sql_kw = s.str.count(r"(?i)union|select|insert|drop|exec|sleep").to_numpy(dtype=np.float32)
    uniq = s.map(lambda x: len(set(x))).to_numpy(dtype=np.float32)
    ent = s.map(shannon_entropy).to_numpy(dtype=np.float32)
    base = np.column_stack([
        length, spec, spec / safe, digit, digit / safe,
        pct, ent, depth, uniq, upper / safe, space,
        alpha / safe, params, sql_kw / safe,
    ])
    counts, hits = [], []
    for cat in REGEX_CATEGORIES:
        acc = np.zeros(len(s), dtype=np.float32)
        for p in REGEX_CATEGORIES[cat]:
            acc += s.str.contains(p, regex=True, na=False).to_numpy(dtype=np.float32)
        counts.append(acc)
        hits.append((acc > 0).astype(np.float32))
    cat = np.column_stack(counts + hits)
    return np.hstack([base, cat]).astype(np.float32)


def extract_features(payload, tfidf):
    X_tfidf = tfidf.transform([payload])
    X_stat = sparse.csr_matrix(np.array([compute_stats(payload)], dtype=np.float32))
    return sparse.hstack([X_tfidf, X_stat], format="csr")
