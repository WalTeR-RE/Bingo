from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

CHARTS_DIR = Path(__file__).parent / "charts"
CHARTS_DIR.mkdir(exist_ok=True)

INK = "#0f172a"
MUTED = "#94a3b8"
GRID = "#eef2f7"

BLUE = "#3b82f6"
GREEN = "#22c55e"
AMBER = "#f59e0b"
RED = "#ef4444"
PURPLE = "#8b5cf6"
TEAL = "#14b8a6"
SLATE = "#94a3b8"

SEVERITY = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "informational": "#94a3b8",
}

CYCLE = [BLUE, GREEN, AMBER, PURPLE, TEAL, RED, "#ec4899", "#06b6d4", "#84cc16", "#a855f7"]

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#cbd5e1",
    "axes.linewidth": 1.0,
    "axes.labelcolor": MUTED,
    "axes.titlecolor": INK,
    "axes.titlesize": 12.5,
    "axes.titleweight": "bold",
    "axes.titlepad": 12,
    "axes.labelsize": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 9.5,
    "text.color": INK,
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.grid": False,
    "grid.color": GRID,
    "grid.linewidth": 1.0,
    "legend.frameon": False,
    "legend.fontsize": 9.5,
})


def ygrid(ax):
    ax.grid(axis="y", color=GRID, linewidth=1.0)
    ax.set_axisbelow(True)


def xgrid(ax):
    ax.grid(axis="x", color=GRID, linewidth=1.0)
    ax.set_axisbelow(True)


def despine(ax, left=True, bottom=True):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    if not left:
        ax.spines["left"].set_visible(False)
        ax.tick_params(left=False)
    if not bottom:
        ax.spines["bottom"].set_visible(False)
        ax.tick_params(bottom=False)


def bar_labels(ax, bars, fmt="{:.0f}", color=INK, size=11, pad=3):
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt.format(h), (b.get_x() + b.get_width() / 2, h),
                    textcoords="offset points", xytext=(0, pad),
                    ha="center", va="bottom", fontsize=size, fontweight="bold", color=color)


def hbar_labels(ax, bars, fmt="{:.0f}", color=INK, size=11, pad=4):
    for b in bars:
        w = b.get_width()
        ax.annotate(fmt.format(w), (w, b.get_y() + b.get_height() / 2),
                    textcoords="offset points", xytext=(pad, 0),
                    ha="left", va="center", fontsize=size, fontweight="bold", color=color)


def donut(ax, data, colors=None, center=None, center_sub=None, pct=True):
    palette = colors or CYCLE[:len(data)]
    kept = [(k, v, palette[i]) for i, (k, v) in enumerate(data.items()) if v]
    labels = [k for k, _, _ in kept]
    values = [v for _, v, _ in kept]
    colors = [c for _, _, c in kept]
    total = sum(values)
    autopct = (lambda p: f"{p:.0f}%") if pct else (lambda p: f"{int(round(p * total / 100))}")
    if len(values) == 1:
        autopct = None
    parts = ax.pie(
        values, colors=colors, startangle=90, counterclock=False,
        autopct=autopct, pctdistance=0.80,
        wedgeprops={"width": 0.42, "edgecolor": "white", "linewidth": 2.5})
    wedges = parts[0]
    autotexts = parts[2] if len(parts) == 3 else []
    for t in autotexts:
        t.set_color("white")
        t.set_fontweight("bold")
        t.set_fontsize(10)
    ax.set(aspect="equal")
    if center is not None:
        ax.text(0, 0.08, center, ha="center", va="center", fontsize=22, fontweight="bold", color=INK)
        if center_sub:
            ax.text(0, -0.16, center_sub, ha="center", va="center", fontsize=9, color=MUTED)
    if len(labels) > 1:
        ax.legend(wedges, labels, loc="upper center", bbox_to_anchor=(0.5, -0.01),
                  ncol=min(3, len(labels)), fontsize=9, handlelength=1.1, columnspacing=1.3,
                  handletextpad=0.5)


def save(fig, name, title, subtitle=None):
    fig.suptitle(title, fontsize=16, fontweight="bold", color=INK, y=0.99)
    if subtitle:
        fig.text(0.5, 0.918, subtitle, ha="center", fontsize=10.5, color=MUTED)
    fig.tight_layout(rect=[0, 0, 1, 0.87 if subtitle else 0.92])
    path = CHARTS_DIR / f"{name}.png"
    fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  chart -> {path.relative_to(Path(__file__).parent.parent)}")
    return path


def banner(agent, title):
    print("=" * 70)
    print(f"[{agent}]  {title}")
    print("=" * 70)


def kv(label, value):
    print(f"  {label:<42} {value}")
