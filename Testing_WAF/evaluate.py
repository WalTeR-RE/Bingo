import importlib.util
import pickle
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from features import build_matrix

CHARTS = HERE / "charts"
CHARTS.mkdir(exist_ok=True)
CURRENT_PKL = HERE.parent / "Ai-Agent" / "Defensive-Agent" / "waf_model.pkl"
CMP_SAMPLE = 15000


def load_current_engine():
    path = HERE.parent / "Ai-Agent" / "Defensive-Agent" / "waf_engine.py"
    spec = importlib.util.spec_from_file_location("cur_waf_engine", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.WAFEngine(str(CURRENT_PKL))


def binary_metrics(true_attack, pred_attack):
    return {
        "accuracy": accuracy_score(true_attack, pred_attack),
        "detection_rate": recall_score(true_attack, pred_attack, zero_division=0),
        "precision": precision_score(true_attack, pred_attack, zero_division=0),
        "f1": f1_score(true_attack, pred_attack, zero_division=0),
        "fpr": float(np.mean(pred_attack[~true_attack])) if (~true_attack).any() else 0.0,
    }


def main():
    bundle = pickle.load(open(HERE / "waf.pkl", "rb"))
    model, tfidf, le = bundle["model"], bundle["vectorizer"], bundle["label_encoder"]
    split = pickle.load(open(HERE / "test_split.pkl", "rb"))
    texts, y = np.array(split["text"], dtype=object), np.array(split["y"], dtype=object)
    print(f"[eval] test set: {len(texts):,} samples")

    print("[eval] featurizing test set for the new model ...")
    X = build_matrix(texts, tfidf)
    pred_idx = model.predict(X)
    pred = le.inverse_transform(pred_idx)

    acc = accuracy_score(y, pred)
    macro = f1_score(y, pred, average="macro")
    print(f"\n=== NEW MODEL (WAMM-style, SR-BH 2020) multiclass ===")
    print(f"  accuracy = {acc*100:.2f}%   macro-F1 = {macro*100:.2f}%")
    print(classification_report(y, pred, digits=3, zero_division=0))

    classes = list(le.classes_)
    cm = confusion_matrix(y, pred, labels=classes)
    fig, ax = plt.subplots(figsize=(9, 7.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(classes)), classes, fontsize=8)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title(f"New WAF (SR-BH 2020) — accuracy {acc*100:.2f}%, macro-F1 {macro*100:.2f}%")
    thr = cm.max() / 2
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=7,
                    color="white" if cm[i, j] > thr else "#0f172a")
    fig.tight_layout(); fig.savefig(CHARTS / "new_model_confusion.png", dpi=150); plt.close(fig)
    print(f"[chart] {CHARTS / 'new_model_confusion.png'}")

    true_attack = (y != "Normal")
    new_attack = (pred != "Normal")
    new_bin = binary_metrics(true_attack, new_attack)

    rng = np.random.default_rng(7)
    sample = rng.choice(len(texts), min(CMP_SAMPLE, len(texts)), replace=False)
    print(f"\n[eval] running CURRENT model on {len(sample):,}-sample attack-vs-benign comparison ...")
    engine = load_current_engine()
    cur_attack = np.array([engine.analyze(str(texts[i]))["is_threat"] for i in sample])
    ta = true_attack[sample]
    cur_bin = binary_metrics(ta, cur_attack)
    new_bin_s = binary_metrics(ta, new_attack[sample])

    print("\n=== ATTACK-vs-BENIGN on SR-BH 2020 test set (same samples) ===")
    hdr = f"{'metric':<16}{'CURRENT model':>16}{'NEW model':>14}"
    print(hdr); print("-" * len(hdr))
    for k in ["accuracy", "detection_rate", "precision", "f1", "fpr"]:
        print(f"{k:<16}{cur_bin[k]*100:>15.2f}%{new_bin_s[k]*100:>13.2f}%")

    metrics = ["accuracy", "detection_rate", "precision", "f1", "fpr"]
    labels = ["Accuracy", "Detection", "Precision", "F1", "False-Pos"]
    cur_v = [cur_bin[m] * 100 for m in metrics]
    new_v = [new_bin_s[m] * 100 for m in metrics]
    x = np.arange(len(metrics))
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.bar(x - 0.2, cur_v, 0.4, label="Current model", color="#64748b")
    ax.bar(x + 0.2, new_v, 0.4, label="New (SR-BH 2020)", color="#2563eb")
    ax.set_xticks(x, labels); ax.set_ylabel("%")
    ax.set_title("WAF comparison — attack vs benign (SR-BH 2020 test set)")
    for i, (c, n) in enumerate(zip(cur_v, new_v)):
        ax.text(i - 0.2, c + 1, f"{c:.1f}", ha="center", fontsize=8)
        ax.text(i + 0.2, n + 1, f"{n:.1f}", ha="center", fontsize=8)
    ax.legend(); ax.set_ylim(0, 105)
    fig.tight_layout(); fig.savefig(CHARTS / "model_comparison.png", dpi=150); plt.close(fig)
    print(f"[chart] {CHARTS / 'model_comparison.png'}")

    print("\n=== VERDICT ===")
    better = (new_bin_s["f1"] >= cur_bin["f1"] and new_bin_s["fpr"] <= cur_bin["fpr"] + 0.02)
    print(f"  New model F1={new_bin_s['f1']*100:.2f}% vs current F1={cur_bin['f1']*100:.2f}%; "
          f"FPR {new_bin_s['fpr']*100:.2f}% vs {cur_bin['fpr']*100:.2f}%")
    print("  -> NEW model is better" if better else "  -> current model holds up better/comparable")


if __name__ == "__main__":
    main()
