# Paper Results Mapping

Status legend:

* **reproducible** — fully reproducible from data shipped in this repository.
* **[PENDING ORIGINAL INPUT DATA]** — pipeline exists and runs, but the original paper input file is not redistributable and must be supplied by the author (see `data/README.md`, `data/manifest.csv`).
* **[BUTUH INPUT PENULIS]** — requires author-provided information (exact paper numbers, provenance, or dataset rights) before the mapping can be finalized.

This repository **never fabricates paper numbers**. Where original inputs are unavailable, the pipeline produces *demonstration* outputs on synthetic samples; those are clearly labeled and must not be presented as paper results.

`[BUTUH INPUT PENULIS]` Exact table/figure numbering, captions, and reported values of the paper are not embedded in this repository yet. The mapping below uses the structure of the baseline notebook (Modes A/B/C); the author should fill the paper's table/figure identifiers in the rightmost column.

---

## Tables

| Paper table | Baseline source | Script | Config | Input data | Output | Status |
|---|---|---|---|---|---|---|
| Entropy per file (Table entropy) | Mode A `[1]` | `scripts/run_binary_experiments.py` | `configs/binary_experiments.yaml` | `data/sample/*` (+ author datasets under `data/external/`) | `results/tables/binary_experiments_*.csv` | reproducible on samples; `[PENDING ORIGINAL INPUT DATA]` for paper datasets |
| Correlation per file | Mode A `[2]` | `scripts/run_binary_experiments.py` | same | same | same | same |
| NPCR / UACI (plain vs cipher) | Mode A `[3]`/`[4]` | `scripts/run_binary_experiments.py` | same | same | same | same |
| Chi-square | Mode A `[5]` | `scripts/run_binary_experiments.py` | same | same | same | same |
| Monobit results (incl. failures) | Mode A `[6]` | `scripts/run_binary_experiments.py` | same | same | same (column `monobit_verdict_encrypted`) | same — failed results are recorded, never dropped |
| Key sensitivity / NPCR / UACI / bit difference (cipher A vs cipher B) | Mode B | `scripts/run_key_sensitivity.py` | `configs/key_sensitivity.yaml` | `data/sample/sample_text.txt` (+ author file) | `results/tables/key_sensitivity_*.csv` | reproducible on samples; `[PENDING ORIGINAL INPUT DATA]` for paper run |
| Key space / brute-force time | Mode C | `scripts/run_keyspace_analysis.py` | CLI args (charset, length) | none (pure math) | stdout + optional JSON | reproducible; note the 32-bit seed caveat (`docs/KNOWN_ISSUES.md`) |
| Runtime table | timing prints in notebook cells | every runner | all | any input | `encryption_time_seconds` / `decryption_time_seconds` columns | reproducible **on your hardware only**; hardware-dependent, see `docs/COMPUTATIONAL_ENVIRONMENT.md` |

## Figures

| Paper figure | Baseline source | Script | Input | Output | Status |
|---|---|---|---|---|---|
| Histogram original vs encrypted | Mode A `[8]` | `scripts/run_binary_experiments.py` / `run_image_experiments.py` | sample/author files | `results/figures/<stem>_histogram.png` | reproducible on samples; `[PENDING ORIGINAL INPUT DATA]` for paper images |
| Entropy comparison chart | (extension of Mode A) | `scripts/reproduce_figures.py` | `results/logs/*.json` | `results/figures/reproduced_entropy.png` | reproducible |
| Adjacent-pixel correlation scatter | image-specific extension (not in notebook) | `scripts/run_image_experiments.py` | image files | `results/figures/<stem>_pixel_correlation.png` | reproducible on samples; `[PENDING ORIGINAL INPUT DATA]` for paper images |
| Key-sensitivity ciphertext comparison | Mode B histograms | `scripts/run_key_sensitivity.py` | sample/author file | `results/figures/<stem>_key_sensitivity.png` | reproducible on samples |
| Runtime chart | (extension) | `scripts/reproduce_figures.py` | `results/logs/*.json` | `results/figures/reproduced_runtime.png` | reproducible on your hardware |

## Integrity

| Paper item | Baseline source | Where |
|---|---|---|
| SHA3-256 round-trip verification | Mode A v2 integrity check | `aghc-s128 analyze ... --decrypted ...`, `results/**/round_trip_ok` fields, `tests/test_round_trip.py` |

Note: the cipher cell of the notebook printed **MD5**; the analysis cells used **SHA3-256**. This repository standardizes on SHA3-256 (see `docs/BASELINE_IMPLEMENTATION_AUDIT.md` §6 and `docs/KNOWN_ISSUES.md`).

## Aggregate rebuild

```bash
python scripts/reproduce_tables.py                                   # CSV from logs
python scripts/reproduce_figures.py                                  # figures from logs
```

---

`[BUTUH INPUT PENULIS]`

1. Paper table/figure numbers and exact reported values (to compare against reproduced runs).
2. Original input files listed in `data/manifest.csv` with `included_in_repo = no`.
3. Confirmation of which statistical thresholds/ideals quoted in the paper (NPCR > 99%, UACI ≈ 33%, etc.) should be reproduced verbatim.
