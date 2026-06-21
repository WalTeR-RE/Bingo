import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, SEVERITY, GREEN, RED

import numpy as np

AGENT = "Offensive Agent - end-to-end exploitation (DVWA, security=low)"
TITLE = "Vulnerability Detection Results"

vuln_types = ["SQLi", "SQLi (blind)", "XSS reflected", "XSS stored", "XSS DOM",
              "Command Inj", "LFI", "File upload", "CSRF", "Brute force"]
confirmed = [1, 1, 1, 1, 1, 1, 1, 1, 1, 0]

severity_breakdown = {"Critical": 3, "High": 5, "Medium": 1}

detection_rate = sum(confirmed) / len(confirmed) * 100


def main():
    banner(AGENT, TITLE)
    kv("Vulnerabilities present (ground truth)", len(confirmed))
    kv("Confirmed by agent", sum(confirmed))
    kv("Detection rate", f"{detection_rate:.0f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [1.25, 1]})

    y = np.arange(len(vuln_types))[::-1]
    colors = [GREEN if c else RED for c in confirmed]
    ax1.barh(y, [1] * len(vuln_types), color=colors, height=0.66)
    for yi, c in zip(y, confirmed):
        ax1.text(0.97, yi, "✓" if c else "✗", ha="right", va="center",
                 color="white", fontsize=14, fontweight="bold")
    ax1.set_yticks(y, vuln_types, fontsize=11)
    ax1.set_xlim(0, 1)
    ax1.set_xticks([])
    despine(ax1, left=False, bottom=False)
    ax1.set_title(f"{sum(confirmed)} / {len(confirmed)} confirmed")

    donut(ax2, severity_breakdown,
          colors=[SEVERITY["critical"], SEVERITY["high"], SEVERITY["medium"]],
          center=str(sum(severity_breakdown.values())), center_sub="findings", pct=False)
    ax2.set_title("By severity")

    save(fig, "vuln_detection_results", TITLE, subtitle=f"DVWA · {detection_rate:.0f}% detection")


if __name__ == "__main__":
    main()
