# Changelog

All notable changes to this repository are documented here.  Baseline
algorithm behavior is frozen; any change that could affect outputs is called
out explicitly under **Behavior-relevant**.

## [1.0.0] — 2026-09-24

Initial restructured release of the AGHC-S128 reproducibility package,
migrated from the original Google Colab notebook
(`collab/…_SecurityAnalysisS,A,B,C_alya_(works).ipynb`; excluded from the
repository, retained as the author's baseline artifact).

### Added

* `aghc_s128` package: `constants`, `modular_arithmetic`, `key_generation`,
  `residual`, `core` (encrypt/decrypt bytes+files), `integrity` (SHA3-256
  default, MD5 deprecated legacy), `io_utils`, `metadata` (JSON sidecars),
  `metrics` (entropy, adjacent-byte correlation, NPCR, UACI, bit-difference,
  key sensitivity, chi-square, monobit, round-trip integrity),
  `visualization`, `experiments` (YAML-driven runners, MODE C keyspace
  math), `cli` (`aghc-s128 encrypt|decrypt|analyze|key-sensitivity|reproduce|validate`).
* Metadata sidecars `<ciphertext>.aghc-s128.json` storing `n_input`,
  `trial_index`, checksums, and runtime environment — never the password.
* pytest suite (9 files) including regression tests against fixtures
  generated from the frozen baseline reference
  (`tests/baseline_reference.py`): 13 cipher vectors (incl. trial index 5)
  and notebook-formula metric oracles.
* Scripts: quick demo, binary/image experiments, key sensitivity, keyspace
  analysis, environment validation, table/figure aggregation.
* Configs: `quick_demo.yaml`, `binary_experiments.yaml`,
  `image_experiments.yaml`, `key_sensitivity.yaml`,
  `paper_results_mapping.md`.
* Deterministic synthetic samples (`data/generate_samples.py`) and dataset
  registry (`data/manifest.csv`).
* Documentation: baseline audit, reproducibility guide, computational
  environment, dataset sources, known issues, security scope, paper-results
  traceability, Zenodo checklist.
* Thin notebooks (`notebooks/01..04`) that call the installed package — no
  algorithm duplication.

### Behavior-relevant (documented deviations from the baseline notebook)

* **Monobit underflow fixed** (KNOWN_ISSUES K-8): the notebook's unsigned
  numpy `ones - zeros` wrapped around when zeros > ones, forcing p = 0.0;
  the package evaluates the same formula with exact integer arithmetic.
* **Paired metrics no longer silently truncate mismatched lengths**
  (KNOWN_ISSUES K-10): default raises `ValueError`; `allow_truncate=True`
  reproduces notebook numbers (regression-tested).
* **Ciphertext bytes are unchanged** relative to the baseline for identical
  (password, n, input) — verified on all regression vectors.

### Removed (relative to the notebook)

* `google.colab` upload/download flows, `input()` menus, top-level execution
  on import, console printing inside library code.
* Duplicate metric/analysis definitions (four near-identical analysis suites
  collapsed into one implementation).
* "EXCELLENT / Q1-level" verdict strings (statistical evaluations are not
  security claims; see docs/SECURITY_SCOPE.md).

### Fixed (engineering, output-neutral)

* Bare `except:` in the key retry loop → `MatrixNotInvertibleError` only.
* Global `random.seed` pollution → isolated `random.Random` instance with an
  identical stream (regression-verified).
* `bit_difference` Python-loop popcount → vectorized `np.unpackbits`
  (identical values).
* Trial-index transport: metadata sidecar (explicit) with baseline-style
  rediscovery (`trial_index=None`) retained for compatibility.
