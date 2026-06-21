# evaluation

Scripts that render the result charts used in the Bingo project write-up.

Each script plots metrics recorded during the project's experimentation phase, writes one PNG to `charts/`, and prints the underlying numbers to the console. The scripts **do not run live tests** — the data is embedded in each script (or read from exported CSVs, for the cost charts), so the figures are reproducible offline without bringing the full stack up. The three Bingo agents (Offensive, Defensive, Behavioral) each have their own metrics; see the table below for which script maps to which.

For the project overview and setup, see the [root README](../README.md).

## Run

```bash
pip install -r requirements.txt

python run_all.py                               # generate every chart in SCRIPTS
python xgboost_classification_performance.py    # or one metric at a time
```

`run_all.py` imports and runs the ten per-metric scripts listed in its `SCRIPTS` array. The two cost scripts (`api_cost.py`, `token_usage.py`) are **not** in that list — run them individually. All PNGs land in `evaluation/charts/`.

## Files

| File | Responsibility |
|---|---|
| `run_all.py` | Imports and runs every per-metric script in `SCRIPTS`, then prints the output directory. |
| `_common.py` | Shared chart styling — Matplotlib `Agg` backend, palette/`rcParams`, and helpers (`save`, `donut`, `bar_labels`, `hbar_labels`, `despine`, `ygrid`/`xgrid`, `banner`, `kv`). Creates `charts/`. |
| `requirements.txt` | Python deps for rendering (`matplotlib`, `numpy`). |
| `charts/` | Rendered PNG output (one per script). |

### Per-metric scripts

| Script | Metric | Agent |
|---|---|---|
| `speech_recognition_performance.py` | STT accuracy / WER | Behavioral |
| `intent_routing_accuracy.py` | Intent classification accuracy | Behavioral |
| `user_interaction_performance.py` | Voice-loop latency & task success | Behavioral |
| `xgboost_classification_performance.py` | WAF 9-class payload classification (confusion matrix + per-class F1) | Defensive |
| `threat_threshold_evaluation.py` | Decision-threshold sweep (TPR/FPR/F1) | Defensive |
| `network_interception_performance.py` | Proxy/sniffer latency & coverage | Defensive |
| `target_discovery_performance.py` | Recon/crawl/discovery coverage | Offensive |
| `swarm_execution_evaluation.py` | Parallel exploit-swarm speedup | Offensive |
| `vuln_detection_results.py` | DVWA per-type detection rate | Offensive |
| `false_positive_analysis.py` | Validator precision / FP filtering | Offensive |
| `api_cost.py` | Total OpenAI API spend across all agents | Cross-cutting |
| `token_usage.py` | OpenAI token usage / request mix (gpt-4o-mini share) | Cross-cutting |

## Configuration

`api_cost.py` and `token_usage.py` read exported OpenAI usage CSVs (`cost_*.csv` and `completions_usage_*.csv` respectively) from a directory set by:

- `BINGO_COST_DIR` — path to the folder containing the usage exports (defaults to `usage/` next to the scripts; set it to your own export directory).

All other scripts have their evaluation data embedded inline and take no configuration.
