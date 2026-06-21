import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, despine, bar_labels, BLUE, GREEN, AMBER, MUTED, TEAL

modes = ["Direct", "WAF proxy", "WAF sniffer"]
median_latency_ms = [4.1, 9.8, 4.3]
throughput_rps = [612, 486, 598]

packet_outcomes = {"HTTP inspected": 71, "HTTPS metadata": 22, "Non-HTTP": 7}

inspected = 18432
blocked = 1144
flagged_passive = 1097

AGENT = "Defensive Agent - network interception (proxy & sniffer)"
TITLE = "Network Interception Performance"


def main():
    banner(AGENT, TITLE)
    kv("Requests processed (proxy)", inspected)
    kv("Malicious requests blocked", blocked)
    kv("Proxy added latency (median)", f"{median_latency_ms[1] - median_latency_ms[0]:.1f} ms")
    kv("Proxy throughput", f"{throughput_rps[1]} req/s")

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 4.8))
    colors = [MUTED, BLUE, TEAL]

    b1 = ax1.bar(modes, median_latency_ms, color=colors, width=0.6)
    ax1.set_ylim(0, max(median_latency_ms) * 1.25)
    ax1.set_yticks([])
    despine(ax1, left=False)
    bar_labels(ax1, b1, fmt="{:.1f}", size=11)
    ax1.set_title("Median latency (ms)")

    b2 = ax2.bar(modes, throughput_rps, color=colors, width=0.6)
    ax2.set_ylim(0, max(throughput_rps) * 1.2)
    ax2.set_yticks([])
    despine(ax2, left=False)
    bar_labels(ax2, b2, fmt="{:.0f}", size=11)
    ax2.set_title("Throughput (req/s)")

    donut(ax3, packet_outcomes, colors=[GREEN, AMBER, MUTED],
          center=f"{blocked:,}", center_sub="blocked", pct=True)
    ax3.set_title("Sniffer coverage")

    save(fig, "network_interception_performance", TITLE,
         subtitle=f"+{median_latency_ms[1] - median_latency_ms[0]:.1f} ms proxy overhead · {blocked:,} threats blocked")


if __name__ == "__main__":
    main()
