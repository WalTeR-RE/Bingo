import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, despine, ygrid, BLUE, GREEN, RED, MUTED

import numpy as np

AGENT = "Defensive Agent - WAF decision threshold (SR-BH 2020 + augmented)"
TITLE = "Threat Threshold Evaluation"

thresholds = np.array([0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95])
detection_rate = np.array([0.9989, 0.9988, 0.9980, 0.9958, 0.9926, 0.9901, 0.9884, 0.9864, 0.9856, 0.9837])
false_positive = np.array([0.0223, 0.0222, 0.0205, 0.0166, 0.0116, 0.0069, 0.0045, 0.0022, 0.0013, 0.0011])
f1 = np.array([0.9954, 0.9954, 0.9953, 0.9949, 0.9942, 0.9938, 0.9933, 0.9928, 0.9925, 0.9916])

CHOSEN = 0.70


def main():
    banner(AGENT, TITLE)
    idx = int(np.where(thresholds == CHOSEN)[0][0])
    kv("Deployed threshold", f"{CHOSEN:.2f}")
    kv("Detection rate (TPR)", f"{detection_rate[idx]*100:.2f}%")
    kv("False positive rate", f"{false_positive[idx]*100:.2f}%")
    kv("F1", f"{f1[idx]*100:.2f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2))

    ax1.plot(thresholds, detection_rate * 100, "-o", color=GREEN, label="Detection", lw=2.4, ms=5)
    ax1.plot(thresholds, f1 * 100, "-o", color=BLUE, label="F1", lw=2.4, ms=5)
    ax1.plot(thresholds, false_positive * 100, "-o", color=RED, label="False positive", lw=2.4, ms=5)
    ax1.axvline(CHOSEN, color=MUTED, linestyle="--", lw=1.4)
    ax1.set_xlabel("Confidence threshold")
    despine(ax1)
    ygrid(ax1)
    ax1.set_title("Detection vs false positives")
    ax1.legend(loc="center right")

    ax2.plot(false_positive * 100, detection_rate * 100, "-", color=BLUE, lw=2.4, alpha=0.5)
    ax2.scatter(false_positive * 100, detection_rate * 100, color=BLUE, s=28, zorder=3)
    ax2.scatter([false_positive[idx] * 100], [detection_rate[idx] * 100],
                color=RED, s=130, zorder=5, edgecolor="white", linewidth=1.5)
    ax2.annotate(f"deployed {CHOSEN:.2f}\n{detection_rate[idx]*100:.1f}% / {false_positive[idx]*100:.1f}%",
                 (false_positive[idx] * 100, detection_rate[idx] * 100),
                 xytext=(14, -6), textcoords="offset points", fontsize=9, color=MUTED)
    ax2.set_xlabel("False positive rate (%)")
    ax2.set_ylabel("Detection rate (%)")
    despine(ax2)
    ygrid(ax2)
    ax2.set_title("ROC operating curve")

    save(fig, "threat_threshold_evaluation", TITLE,
         subtitle=f"deployed at {CHOSEN:.2f} → {detection_rate[idx]*100:.1f}% detection · {false_positive[idx]*100:.1f}% FPR")


if __name__ == "__main__":
    main()
