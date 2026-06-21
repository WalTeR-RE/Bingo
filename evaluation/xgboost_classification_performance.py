import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, despine, ygrid, bar_labels, GREEN, INK

import numpy as np

AGENT = "Defensive Agent - WAF model (XGBoost, SR-BH 2020 + augmented)"
TITLE = "WAF Payload Classification"

classes = ["Code_Inj", "Normal", "OS_Cmd", "Path_Trav", "RFI", "SQLi", "SSRF", "SSTI", "XSS"]

confusion = np.array([
    [2767, 0, 1, 0, 0, 0, 0, 0, 0],
    [0, 6316, 12, 43, 0, 27, 0, 2, 0],
    [0, 14, 2573, 13, 0, 18, 0, 0, 0],
    [0, 48, 10, 4231, 0, 40, 0, 0, 0],
    [0, 0, 0, 0, 480, 0, 0, 0, 0],
    [1, 60, 32, 53, 0, 6254, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 480, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 223, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 440],
])


def metrics():
    tp = np.diag(confusion)
    support = confusion.sum(axis=1)
    precision = tp / confusion.sum(axis=0)
    recall = tp / support
    f1 = 2 * precision * recall / (precision + recall)
    accuracy = tp.sum() / confusion.sum()
    return f1, support, accuracy


def main():
    banner(AGENT, TITLE)
    f1, support, accuracy = metrics()
    kv("Test samples", int(confusion.sum()))
    kv("Overall accuracy", f"{accuracy * 100:.2f}%")
    kv("Macro F1", f"{f1.mean() * 100:.2f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.6))

    ax1.imshow(confusion, cmap="Greens")
    ax1.set_xticks(range(len(classes)), classes, rotation=40, ha="right", fontsize=8.5)
    ax1.set_yticks(range(len(classes)), classes, fontsize=8.5)
    ax1.set_title("Confusion matrix")
    ax1.grid(False)
    for s in ax1.spines.values():
        s.set_visible(False)
    ax1.tick_params(length=0)
    thr = confusion.max() / 2
    for i in range(len(classes)):
        for j in range(len(classes)):
            v = confusion[i, j]
            if v:
                ax1.text(j, i, v, ha="center", va="center", fontsize=7.5,
                         fontweight="bold" if i == j else "normal",
                         color="white" if v > thr else INK)

    x = np.arange(len(classes))
    bars = ax2.bar(x, f1 * 100, 0.62, color=GREEN)
    ax2.set_xticks(x, classes, rotation=40, ha="right", fontsize=8.5)
    ax2.set_ylim(90, 101)
    ax2.set_yticks([90, 95, 100])
    despine(ax2)
    ygrid(ax2)
    bar_labels(ax2, bars, fmt="{:.0f}", size=9)
    ax2.set_title("Per-class F1 score")

    save(fig, "xgboost_classification_performance", TITLE,
         subtitle=f"{accuracy * 100:.1f}% accuracy · {f1.mean() * 100:.1f}% macro-F1 · 9 classes")


if __name__ == "__main__":
    main()
