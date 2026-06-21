import sys
import os
import csv
import glob
import datetime as dt
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import save, banner, kv, plt, donut, GREEN

AGENT = "Bingo - OpenAI API spend (all agents, gpt-4o-mini standardized)"
TITLE = "API Cost"
COST_DIR = os.environ.get("BINGO_COST_DIR", "usage")


def load():
    months = []
    for fn in sorted(glob.glob(os.path.join(COST_DIR, "cost_*.csv"))):
        datestr = os.path.basename(fn).split("_")[1]
        label = dt.date.fromisoformat(datestr).strftime("%b %y")
        total = 0.0
        with open(fn, newline="") as f:
            for r in csv.DictReader(f):
                v = r.get("amount_value", "")
                if v:
                    total += float(v)
        months.append((label, total))
    return months


def main():
    banner(AGENT, TITLE)
    months = load()
    costs = [m[1] for m in months]
    total = sum(costs)
    kv("Total API cost", f"${total:.2f}")

    fig, ax = plt.subplots(figsize=(7, 5.2))
    donut(ax, {"Total": total}, colors=[GREEN], center=f"${total:.2f}", center_sub="total API cost")

    save(fig, "api_cost", TITLE,
         subtitle="three agents, entire project - standardized on gpt-4o-mini")


if __name__ == "__main__":
    main()
