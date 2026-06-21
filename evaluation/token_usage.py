import sys
import os
import csv
import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, BLUE, AMBER, INK, MUTED

import numpy as np


AGENT = "Bingo - OpenAI token usage (all agents)"
TITLE = "Token Usage"
COST_DIR = os.environ.get("BINGO_COST_DIR", "usage")


def _model_bucket(model):
    if "transcribe" in model:
        return "STT / other"
    if "4o-mini" in model:
        return "gpt-4o-mini"
    if "4o" in model:
        return "gpt-4o"
    return "STT / other"


def load():
    total_in = total_out = total_req = 0
    by_model = {}
    for fn in sorted(glob.glob(os.path.join(COST_DIR, "completions_usage_*.csv"))):
        with open(fn, newline="") as f:
            for r in csv.DictReader(f):
                it = r.get("input_tokens", "")
                ot = r.get("output_tokens", "")
                rq = r.get("num_model_requests", "")
                ii = int(float(it)) if it else 0
                oo = int(float(ot)) if ot else 0
                total_in += ii
                total_out += oo
                total_req += int(float(rq)) if rq else 0
                m = r.get("model", "")
                if m:
                    b = _model_bucket(m)
                    by_model[b] = by_model.get(b, 0) + ii + oo
    return total_in, total_out, total_req, by_model


def kpi_panel(ax, items):
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ys = np.linspace(0.84, 0.12, len(items))
    for (val, lab), y in zip(items, ys):
        ax.text(0.36, y, val, fontsize=20, fontweight="bold", color=INK, ha="right", va="center")
        ax.text(0.42, y, lab, fontsize=11, color=MUTED, ha="left", va="center")


def main():
    banner(AGENT, TITLE)
    total_in, total_out, total_req, by_model = load()
    total = total_in + total_out
    mini_pct = by_model.get("gpt-4o-mini", 0) / total * 100
    in_pct = total_in / total * 100
    out_pct = total_out / total * 100
    kv("Total tokens", f"{total:,}")
    kv("Input tokens", f"{total_in:,} ({in_pct:.0f}%)")
    kv("Output tokens", f"{total_out:,} ({out_pct:.0f}%)")
    kv("API requests", f"{total_req:,}")
    kv("gpt-4o-mini share", f"{mini_pct:.1f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={"width_ratios": [1, 1.1]})

    order = ["gpt-4o-mini", "gpt-4o", "STT / other"]
    donut_data = {k: by_model.get(k, 0) for k in order if by_model.get(k, 0) > total * 0.005}
    donut(ax1, donut_data, colors=[BLUE, AMBER], center=f"{total / 1e6:.1f}M", center_sub="total tokens")

    kpi_panel(ax2, [
        (f"{total / 1e6:.1f}M", "Total tokens"),
        (f"{total_in / 1e6:.1f}M", f"Input tokens ({in_pct:.0f}%)"),
        (f"{total_out / 1e6:.2f}M", f"Output tokens ({out_pct:.0f}%)"),
        (f"{mini_pct:.1f}%", "on gpt-4o-mini"),
    ])

    save(fig, "token_usage", TITLE,
         subtitle=f"{total / 1e6:.1f}M tokens - {total_req:,} requests - {mini_pct:.1f}% on gpt-4o-mini")


if __name__ == "__main__":
    main()
