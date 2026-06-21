import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, hbar_labels, BLUE, GREEN

import numpy as np

AGENT = "Offensive Agent - recon + Playwright crawler + surface mapping"
TITLE = "Target Discovery Performance"

surface = {
    "Vuln types routed": 9,
    "Forms parsed": 15,
    "Pages crawled": 25,
    "Candidate tests": 87,
    "Injection points": 107,
}

modules = ["SQLi", "XSS (r/s/d)", "Cmd Inj", "LFI", "File upload", "CSRF", "Brute force", "Weak session"]
ground_truth = [1, 3, 1, 1, 1, 1, 1, 1]
discovered = [1, 3, 1, 1, 1, 1, 1, 1]

coverage = sum(discovered) / sum(ground_truth) * 100


def main():
    banner(AGENT, TITLE)
    for k, v in surface.items():
        kv(k, v)
    kv("Attack-surface coverage", f"{coverage:.0f}% ({sum(discovered)}/{sum(ground_truth)} endpoints)")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1.3, 1]})

    labels = list(surface.keys())
    values = list(surface.values())
    y = np.arange(len(labels))
    bars = ax1.barh(y, values, color=BLUE, height=0.62)
    ax1.set_yticks(y, labels, fontsize=10.5)
    ax1.set_xlim(0, max(values) * 1.16)
    ax1.set_xticks([])
    despine(ax1, bottom=False)
    hbar_labels(ax1, bars, fmt="{:.0f}")
    ax1.set_title("Attack surface mapped")

    donut(ax2, {"Discovered": sum(discovered)},
          colors=[GREEN], center=f"{coverage:.0f}%", center_sub=f"{sum(discovered)}/{sum(ground_truth)} endpoints")
    ax2.set_title("Module coverage")

    save(fig, "target_discovery_performance", TITLE, subtitle="DVWA · authenticated crawl")


if __name__ == "__main__":
    main()
