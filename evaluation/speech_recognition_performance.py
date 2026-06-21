import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, ygrid, bar_labels, BLUE, GREEN, AMBER, RED

AGENT = "Behavioral Agent - OpenAI Whisper (whisper-1)"
TITLE = "Speech Recognition Performance"

categories = ["Scan", "Defensive", "Status", "Targets", "Chat"]
command_accuracy = [95.0, 90.6, 96.4, 87.5, 88.5]
word_error_rate = [5.8, 7.1, 4.9, 11.3, 9.4]

overall_wer = 7.6
overall_accuracy = 91.8
outcomes = {"Exact": 78, "Minor errors": 16, "Misrecognized": 6}


def main():
    banner(AGENT, TITLE)
    kv("Overall command accuracy", f"{overall_accuracy:.1f}%")
    kv("Overall word error rate (WER)", f"{overall_wer:.1f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1.2, 1]})

    bars = ax1.bar(categories, command_accuracy, color=BLUE, width=0.62)
    ax1.axhline(overall_accuracy, color=GREEN, linestyle="--", lw=1.6)
    ax1.set_ylim(70, 102)
    ax1.set_yticks([70, 80, 90, 100])
    despine(ax1)
    ygrid(ax1)
    bar_labels(ax1, bars, fmt="{:.0f}", size=10)
    ax1.set_title("Accuracy by command category")

    donut(ax2, outcomes, colors=[GREEN, AMBER, RED],
          center=f"{overall_accuracy:.0f}%", center_sub="accuracy", pct=True)
    ax2.set_title("Transcription outcomes")

    save(fig, "speech_recognition_performance", TITLE,
         subtitle=f"{overall_accuracy:.0f}% accuracy · {overall_wer:.1f}% WER")


if __name__ == "__main__":
    main()
