import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, bar_labels, MUTED, BLUE, GREEN, AMBER

AGENT = "Offensive Agent - validator + dedup confirmation stage"
TITLE = "False Positive Analysis"

stages = ["Raw STATUS\nblocks", "Unique\n(type, endpoint)", "Confirmed\nfindings"]
counts = [34, 9, 9]

outcomes = {"Confirmed (TP)": 9, "Duplicate / re-confirmed": 25}
false_positives = 0
precision_after = counts[2] / counts[1] * 100


def main():
    banner(AGENT, TITLE)
    kv("Raw STATUS blocks (incl. critic rounds)", counts[0])
    kv("Unique (type, endpoint)", counts[1])
    kv("Confirmed findings", counts[2])
    kv("False positives in confirmed set", false_positives)
    kv("Precision of confirmed findings", f"{precision_after:.0f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1.15, 1]})

    bars = ax1.bar(stages, counts, color=[MUTED, BLUE, GREEN], width=0.6)
    ax1.set_ylim(0, max(counts) * 1.18)
    ax1.set_yticks([])
    despine(ax1, left=False)
    bar_labels(ax1, bars, fmt="{:.0f}", size=13)
    ax1.set_title("Claim → confirmation funnel")

    donut(ax2, outcomes, colors=[GREEN, AMBER],
          center="0", center_sub="false positives", pct=False)
    ax2.set_title("Outcome of raw blocks")

    save(fig, "false_positive_analysis", TITLE,
         subtitle=f"{precision_after:.0f}% precision · {false_positives} false positives")


if __name__ == "__main__":
    main()
