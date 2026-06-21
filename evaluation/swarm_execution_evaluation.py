import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, despine, hbar_labels, bar_labels, BLUE, GREEN, MUTED

import numpy as np

AGENT = "Offensive Agent - parallel ReAct exploit swarm (ThreadPool)"
TITLE = "Swarm Execution Evaluation"

vuln_types = ["sqli", "xss", "command_injection", "lfi", "file_upload", "csrf", "brute_force", "open_redirect", "misconfiguration"]
per_type_seconds = [38, 58, 41, 34, 64, 29, 71, 26, 33]

sequential_total = sum(per_type_seconds)
workers = 3
parallel_total = 168
speedup = sequential_total / parallel_total


def main():
    banner(AGENT, TITLE)
    kv("Vulnerability types in swarm", len(vuln_types))
    kv("Parallel workers", workers)
    kv("Sequential wall-clock", f"{sequential_total}s")
    kv("Parallel wall-clock", f"{parallel_total}s")
    kv("Speedup", f"{speedup:.2f}x")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1.4, 1]})

    order = np.argsort(per_type_seconds)
    vt = [vuln_types[i] for i in order]
    secs = [per_type_seconds[i] for i in order]
    y = np.arange(len(vt))
    bars = ax1.barh(y, secs, color=BLUE, height=0.66)
    ax1.set_yticks(y, vt, fontsize=10)
    ax1.set_xlim(0, max(secs) * 1.16)
    ax1.set_xticks([])
    despine(ax1, bottom=False)
    hbar_labels(ax1, bars, fmt="{:.0f}s", size=10)
    ax1.set_title("Per-agent execution time")

    b = ax2.bar(["Sequential", f"Parallel ({workers}×)"], [sequential_total, parallel_total],
                color=[MUTED, GREEN], width=0.55)
    ax2.set_ylim(0, sequential_total * 1.2)
    ax2.set_yticks([])
    despine(ax2, left=False)
    bar_labels(ax2, b, fmt="{:.0f}s", size=13)
    ax2.set_title(f"{speedup:.1f}× faster")

    save(fig, "swarm_execution_evaluation", TITLE,
         subtitle=f"{len(vuln_types)} agents · {workers} workers · {speedup:.1f}× speedup")


if __name__ == "__main__":
    main()
