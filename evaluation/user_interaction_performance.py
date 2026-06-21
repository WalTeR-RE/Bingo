import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, hbar_labels, BLUE, GREEN, AMBER, RED

import numpy as np

AGENT = "Behavioral Agent - voice/GUI interaction loop (streaming VAD pipeline)"
TITLE = "User Interaction Performance"

stages = ["VAD endpoint", "STT (4o-mini)", "Intent routing", "Dispatch", "TTS first audio"]
latency_s = [0.25, 0.40, 0.12, 0.05, 0.28]

outcomes = {"First try": 84, "After clarification": 9, "Barge-in": 4, "Failed": 3}

first_audio_s = sum(latency_s)
success = outcomes["First try"] + outcomes["After clarification"]


def main():
    banner(AGENT, TITLE)
    kv("Time to first audio (streaming)", f"{first_audio_s:.2f}s")
    kv("Task success (first try + clarified)", f"{success}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1.25, 1]})

    y = np.arange(len(stages))[::-1]
    bars = ax1.barh(y, latency_s, color=BLUE, height=0.62)
    ax1.set_yticks(y, stages, fontsize=10.5)
    ax1.set_xlim(0, max(latency_s) * 1.18)
    ax1.set_xticks([])
    despine(ax1, bottom=False)
    hbar_labels(ax1, bars, fmt="{:.2f}s", size=10)
    ax1.set_title(f"Latency to first audio · {first_audio_s:.1f}s")

    donut(ax2, outcomes, colors=[GREEN, BLUE, AMBER, RED],
          center=f"{success}%", center_sub="task success", pct=True)
    ax2.set_title("Interaction outcomes")

    save(fig, "user_interaction_performance", TITLE,
         subtitle=f"{first_audio_s:.1f}s to first audio · {success}% success")


if __name__ == "__main__":
    main()
