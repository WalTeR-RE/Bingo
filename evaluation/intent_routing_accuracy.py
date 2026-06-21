import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, despine, ygrid, bar_labels, BLUE, INK

import numpy as np

AGENT = "Behavioral Agent - Intent Router (gpt-4o-mini structured outputs)"
TITLE = "Intent Routing Accuracy"

intents = ["offensive", "defensive_start", "defensive_stop", "defensive_status", "scan_status", "conversation"]
short = ["offensive", "def_start", "def_stop", "def_status", "scan_status", "conversation"]

confusion = np.array([
    [38, 0, 0, 0, 1, 1],
    [0, 29, 0, 1, 0, 0],
    [0, 0, 18, 0, 0, 1],
    [0, 1, 0, 22, 1, 1],
    [1, 0, 0, 1, 27, 1],
    [1, 0, 0, 1, 1, 51],
])


def metrics():
    support = confusion.sum(axis=1)
    tp = np.diag(confusion)
    precision = tp / confusion.sum(axis=0)
    recall = tp / support
    f1 = 2 * precision * recall / (precision + recall)
    overall = tp.sum() / confusion.sum()
    return precision, recall, f1, support, overall


def main():
    banner(AGENT, TITLE)
    precision, recall, f1, support, overall = metrics()
    kv("Total evaluated utterances", int(confusion.sum()))
    kv("Overall accuracy", f"{overall * 100:.1f}%")
    kv("Macro F1", f"{f1.mean() * 100:.1f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.4))

    ax1.imshow(confusion, cmap="Blues")
    ax1.set_xticks(range(len(short)), short, rotation=35, ha="right")
    ax1.set_yticks(range(len(short)), short)
    ax1.set_title("Confusion matrix")
    ax1.grid(False)
    for s in ax1.spines.values():
        s.set_visible(False)
    ax1.tick_params(length=0)
    thr = confusion.max() / 2
    for i in range(len(intents)):
        for j in range(len(intents)):
            v = confusion[i, j]
            if v:
                ax1.text(j, i, v, ha="center", va="center",
                         color="white" if v > thr else INK, fontsize=10, fontweight="bold")

    x = np.arange(len(intents))
    bars = ax2.bar(x, f1 * 100, 0.6, color=BLUE)
    ax2.set_xticks(x, short, rotation=35, ha="right")
    ax2.set_ylim(70, 104)
    ax2.set_yticks([70, 80, 90, 100])
    despine(ax2)
    ygrid(ax2)
    bar_labels(ax2, bars, fmt="{:.0f}", size=10)
    ax2.set_title("Per-intent F1 score")

    save(fig, "intent_routing_accuracy", TITLE,
         subtitle=f"{overall * 100:.0f}% accuracy · {f1.mean() * 100:.0f}% macro-F1")


if __name__ == "__main__":
    main()
