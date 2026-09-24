# Results

Experiment outputs land here, organized as:

| Directory | Content | Producer |
|---|---|---|
| `logs/` | structured JSON records per run (config snapshot, environment, metrics, checksums, runtimes) | all experiment runners |
| `tables/` | flat CSV tables for paper builds | runners + `scripts/reproduce_tables.py` |
| `figures/` | PNG figures (histograms, entropy, pixel correlation, key sensitivity, runtime) | runners + `scripts/reproduce_figures.py` |
| `analysis/` | ad-hoc `aghc-s128 analyze` / `key-sensitivity` reports | CLI |
| `example_outputs/` | quick-demo outputs (`logs/`, `tables/`, `figures/` beneath it) | `scripts/run_quick_demo.py` |

Notes:

* `logs/`, `tables/`, `figures/`, `analysis/`, `example_outputs/` contents are
  **git-ignored** (regenerable); only the directory scaffolding (`.gitkeep`)
  is committed. For a Zenodo archive, run the pipelines first and export the
  generated artifacts alongside the code snapshot.
* Every log records the runtime environment and input SHA3-256 checksums so
  any table row can be traced to exact inputs and software versions.
* Wall-clock times are hardware-dependent (see `docs/COMPUTATIONAL_ENVIRONMENT.md`).
* Failed statistical checks (e.g. monobit `fail` verdicts) are recorded as-is;
  the pipeline never drops or re-labels them.
