# Baseline Implementation Audit — AGHC-S128

Document status: complete (2026-09-24)
Baseline source: `collab/[2]_AI_GHC+Shift128Cipher_(AGHC_S128)+SecurityAnalysisS,A,B,C_alya_(works).ipynb` (Google Colab notebook, 6 code cells). The `collab/` folder is the author's original artifact, is excluded from the Git repository, and is the single source of truth for baseline algorithmic behavior.

Scope: this audit inventories every function in the original notebook, maps it to the refactored module layout, lists duplication, Colab coupling, export artifacts, inconsistencies, frozen behaviors, safe refactorings, and changes that require author approval. It makes no new cryptographic claims.

---

## 1. Old-function → new-module mapping

### Cell 0 — cipher core + interactive menu

| Original function | Behavior preserved in | Notes |
|---|---|---|
| `md5(fname)` | `aghc_s128.integrity.hash_file_md5` (deprecated, legacy-only) | Baseline used MD5 for the encrypt/decrypt console report |
| `logistic_map(seed, size)` | `aghc_s128.key_generation.logistic_map` | r = 3.99, warm-up 1000, `int((x * 10**6) % 256)` — byte-exact port |
| `complete_graph_matrix(N)` | `aghc_s128.key_generation.complete_graph_matrix` | ones − eye, mod 256 |
| `ai_graph_perturbation(N, seed)` | `aghc_s128.key_generation.adaptive_graph_perturbation` | `random.seed(seed)` + `random.randint(0, 255)`; port uses an isolated `random.Random(seed)` instance which yields the identical Mersenne-Twister stream without polluting global RNG state (pure refactor, verified by regression test) |
| `chaos_matrix(N, seed)` | `aghc_s128.key_generation.chaos_matrix` | logistic map reshaped N×N, zero diagonal |
| `generate_ai_graph_key(N, password)` | `aghc_s128.key_generation.build_key_matrix` | SHA-256 password → 8-hex-char (32-bit) numeric seed → x0; K = (A + P + C) mod 256; odd-diagonal fix |
| `mod_inverse_matrix(A, mod=256)` | `aghc_s128.modular_arithmetic.mod_inverse_matrix` | Gauss–Jordan mod 256, pivot valid iff gcd(pivot, 256) == 1, `pow(p, -1, 256)` |
| `generate_valid_key(N, password)` | `aghc_s128.key_generation.generate_valid_key` | trial loop over `password + str(trial)`; bare `except:` replaced by `except MatrixNotInvertibleError` (behavior-identical: only inversion failure triggers retry in the baseline) |
| `shift128_encrypt/decrypt(data)` | `aghc_s128.residual.shift128_encrypt/shift128_decrypt` | `(b ± 128) mod 256` |
| `encrypt_file(fileasli, n_input, password)` | `aghc_s128.core.encrypt_file` / `encrypt_bytes` | split at `size % N`, Hill on the divisible part with reshape `(N, len_hill // N)`, Shift-128 on the tail; prints removed, structured result returned |
| `decrypt_file(fileasli, n_input, password)` | `aghc_s128.core.decrypt_file` / `decrypt_bytes` | baseline re-discovers the trial index from 0; refactored API takes an explicit `trial_index` (from metadata) and keeps `trial_index=None` for baseline-style rediscovery |
| `check_hash(file1, file2)` | `aghc_s128.integrity.compare_file_hashes` | switched to SHA3-256 default; MD5 retained separately as deprecated legacy |
| menu block (`input()`, `files.upload()`, `files.download()`) | `aghc_s128.cli` (argparse) + `notebooks/` | interactive Colab layer removed from core |

### Cell 1 — security analysis v1 (generic binary)

| Original function | Behavior preserved in |
|---|---|
| `load_binary(file_path)` | `aghc_s128.io_utils.read_binary_file` |
| `entropy_analysis(data)` | `aghc_s128.metrics.shannon_entropy` |
| `correlation_analysis(data)` | `aghc_s128.metrics.adjacent_byte_correlation` |
| `avalanche_effect(original, encrypted)` | `aghc_s128.metrics.bit_difference_ratio` (identical formula; renamed because "avalanche" implies a keyed-input-difference experiment the baseline does not perform — see §6) |
| `key_sensitivity(cipher1, cipher2)` | `aghc_s128.metrics.key_sensitivity` |
| `chi_square_analysis(data)` | `aghc_s128.metrics.chi_square_uniformity` |
| `randomness_test(data)` | `aghc_s128.metrics.monobit_frequency_test` |
| `differential_analysis(original, encrypted)` | `aghc_s128.metrics.mean_max_abs_difference` (report-only helper) |
| `show_histogram(original, encrypted)` | `aghc_s128.visualization.plot_histogram_comparison` |
| `complete_analysis(...)` (v1, optional second ciphertext) | orchestrated in `aghc_s128.experiments` |

### Cell 2 — MODE A v1 (adds SHA3-256, NPCR, UACI, monobit)

| Original function | Behavior preserved in |
|---|---|
| `sha3_256_hash(file_path)` | `aghc_s128.integrity.hash_file_sha3_256` |
| `npcr_analysis(a, b)` | `aghc_s128.metrics.npcr` |
| `uaci_analysis(a, b)` | `aghc_s128.metrics.uaci` |
| `monobit_test(data)` | `aghc_s128.metrics.monobit_frequency_test` |
| rest | duplicates of cell 1 (see §2) |

### Cell 3 — MODE A v2 (three-file workflow, integrity check)

| Original function | Behavior preserved in |
|---|---|
| `sha3_256_file(file_path)` | duplicate of cell 2 `sha3_256_hash` |
| `integrity_check(original_file, decrypted_file)` | `aghc_s128.integrity.compare_file_hashes` + `aghc_s128.metrics.round_trip_integrity` |
| `complete_analysis` (v2) | orchestrated in `aghc_s128.experiments.run_binary_experiments` |
| rest | duplicates (see §2) |

### Cell 4 — MODE B (key sensitivity between two ciphertexts)

| Original function | Behavior preserved in |
|---|---|
| `key_sensitivity(cipher1, cipher2)` | duplicate of cell 1 |
| `npcr_analysis` / `uaci_analysis` | duplicates (cipher-vs-cipher usage) |
| `bit_difference(cipher1, cipher2)` | `aghc_s128.metrics.bit_difference_ratio` (vectorized, identical value) |
| `show_histograms(cipher1, cipher2)` | `aghc_s128.visualization.plot_histogram_comparison` |
| `mode_b_analysis(...)` incl. assessment thresholds | `aghc_s128.experiments.run_key_sensitivity`; "Q1-level" phrasing dropped (see §6) |
| upload block | removed (CLI/notebook layer) |

### Cell 5 — MODE C (keyspace / brute-force estimation)

| Original function | Behavior preserved in |
|---|---|
| `CHARSETS` | `aghc_s128.experiments.CHARSETS` |
| `human_time(seconds)` | `aghc_s128.experiments.human_time` |
| `classify_security(entropy_bits)` | kept, but relabeled output "password-entropy classification"; the claim it maps to cipher security is documented as an issue (see §6) |
| `keyspace_analysis(length, charset_size)` | `aghc_s128.experiments.keyspace_analysis` (returns structured dict, no prints) |
| input-driven menu | `scripts/run_keyspace_analysis.py` CLI args |

---

## 2. Duplication inside the original notebook

| Function | Copies | Divergences between copies |
|---|---|---|
| `load_binary` | 4 (cells 1, 3, 4 + inline cell 0 `np.fromfile`) | none |
| `entropy_analysis` | 3 (cells 1, 2, 3) | none |
| `correlation_analysis` | 3 (cells 1, 2, 3) | cells 2–3 guard `len < 2 → 0`; cell 1 would raise — refactored module adopts the guard and documents it |
| `chi_square_analysis` | 3 (cells 1, 2, 3) | variable names only |
| monobit (`randomness_test` / `monobit_test`) | 3 | none (same formula `2·(1 − Φ(|S|/√n))`) |
| `npcr_analysis` | 3 (cells 2, 3 plain-vs-cipher; cell 4 cipher-vs-cipher) | all silently truncate to min length |
| `uaci_analysis` | 3 | cell 2/4 cast to int32, cell 3 to float64 — numerically identical for uint8 inputs |
| `key_sensitivity` | 2 (cells 1, 4) | none |
| `sha3_256_hash` / `sha3_256_file` | 2 | identical chunked hashing |
| histogram plotter | 3 (`show_histogram`, `show_histograms`, cell 3 inline) | titles only |
| `avalanche_effect` (cell 1) vs `bit_difference` (cell 4) | 2 | same formula, different names — unified as `bit_difference_ratio` |

All duplicates collapse to single implementations in `aghc_s128.metrics` / `visualization`.

## 3. Dependencies used by the baseline

Runtime: `numpy`, `scipy` (`scipy.stats`: `chisquare`, `pearsonr`, `norm`), `matplotlib`, Python stdlib (`hashlib`, `os`, `time`, `random`, `math`). Platform: `google.colab.files` (upload/download only). No cryptography libraries are used — all primitives are hand-rolled.

## 4. Google-Colab-specific blocks (separated from core)

1. `from google.colab import files` — cells 0–4.
2. `files.upload()` prompts — every analysis cell.
3. `files.download(...)` — cell 0 menu.
4. `input()` menu flows — cells 0–5 (mode selection, n, password, charset, optional files).
5. Top-level execution on import: every cell executes its upload/menu flow immediately; there is no importable module.
6. Matplotlib `plt.show()` interactive calls.

None of these exist in `src/aghc_s128/`. They are replaced by the CLI, scripts, and thin notebooks.

## 5. Export / executability problems in the notebook-as-source

The notebook is the only algorithmic reference; it was authored interactively. Issues found:

1. **Redefinition shadowing** — cells 1→2→3 redefine `complete_analysis`, `entropy_analysis`, etc. with evolving semantics; only the last definition per notebook run is effective. A flat `.py` export would run *all* upload prompts sequentially and hang.
2. **Bare `except:` in `generate_valid_key`** (cell 0) — swallows every exception (including e.g. `KeyboardInterrupt` inherited behavior of the era, `MemoryError`), making non-invertibility retry indistinguishable from real bugs.
3. **Top-level side effects** — upload/`input()`/`plt.show()` at module scope make the file non-importable without Colab.
4. **Silent truncation** — NPCR/UACI/key-sensitivity/bit-difference/avalanche truncate mismatched lengths to `min(len)` without warning; comparing files of different sizes yields plausible-looking but ill-defined numbers.
5. **Saved output blob** — the committed notebook output shows a decrypt run with `n = 99` (`N = 198`) on a PDF; this is provenance evidence, not a test.
6. **Cell 1 correlation on `len < 2`** raises from `scipy.stats.pearsonr` while cells 2–3 return 0 — inconsistent invalid-input handling.

None of these change the cipher math; the refactored port keeps the math byte-identical and fixes only engineering structure (documented here and in `KNOWN_ISSUES.md`).

## 6. Potential inconsistencies documented (not silently "fixed")

| # | Topic | Observation | Disposition in this repo |
|---|---|---|---|
| 1 | MD5 vs SHA3-256 | Cell 0 reports MD5; cells 2–3 use SHA3-256 for integrity | SHA3-256 is the default everywhere; MD5 kept as deprecated legacy helper, never used in examples |
| 2 | "AI-assisted" terminology | Perturbation is `random.seed(numeric_seed)` + `random.randint` — a seeded PRNG, no learning component | Docs say "adaptive graph perturbation (seeded PRNG)"; the historical name is quoted only when referring to the baseline |
| 3 | `N = 2 × n` | Notebook output confirms n = 99 → N = 198 (not `2^n`) | Spelled `N = 2 × n` everywhere; constants and CLI validate `n_input ≥ 1` |
| 4 | Runtime calculation | Baseline times include key generation + file I/O + matrix printing; not comparable across machines | Times are recorded per phase where feasible and always labeled wall-clock, hardware-dependent |
| 5 | Monobit usage | p-value via `2·(1 − Φ(s))` with pass threshold 0.01 on full-byte stream; NIST SP 800-22 uses erfc form and ≥100 bits — equivalent formula, but a single test is weak evidence | Baseline formula kept; documented as one statistical check, failures are reported, never hidden |
| 6 | "Security" claims vs statistical metrics | Mode B prints "EXCELLENT", "Q1-level cryptographic robustness" from NPCR/UACI thresholds | Removed from library output; `docs/SECURITY_SCOPE.md` states these are statistical evaluations, not proofs |
| 7 | Keyspace analysis | MODE C computes `charset^length` — the password alphabet space, not the effective key space (perturbation + chaos derive from a 32-bit numeric seed; see KNOWN_ISSUES) | Function kept and clearly labeled "password space estimation"; the 32-bit seed bottleneck is documented |
| 8 | UACI ideals on non-image data | "Ideal ~33%" is an image-encryption benchmark quoted for arbitrary binary files | Reported without the image-specific ideal unless input is an image |
| 9 | Trial-index transport | Baseline decryption re-runs key search from trial 0 (deterministic, so correct, but O(trials) and implicit) | New metadata sidecar stores `trial_index`; `decrypt_bytes(..., trial_index=None)` retains rediscovery for backward compatibility |
| 10 | Logistic map in float64 | `x = 3.99·x·(1−x)` in IEEE-754 double; determinism holds per platform/build in practice but is not guaranteed identical across BLAS-adjacent recompiles | Kept byte-exact (pure Python scalar loop, no vectorization) so any platform difference is observable via test vectors |
| 11 | Adjacent-byte correlation named "correlation" | For images the paper metric is pixel correlation; the notebook computes stream-adjacent bytes | Named `adjacent_byte_correlation`; a separate, explicitly-documented image pixel-correlation helper exists for image inputs only |

## 7. Frozen baseline behaviors (must not change)

1. `K = (A + P + C) mod 256`, then odd-diagonal adjustment (`+1 mod 256` if even).
2. `N = 2 × n_input`; split point `residual = size % N`.
3. Hill reshape orientation `plaintext[:len_hill].reshape(N, len_hill // N)` (C order) for both encryption and decryption.
4. `C_hill = (K @ P_hill) mod 256`; `P_hill = (K_inv @ C_hill) mod 256`.
5. Perturbation draw order: `random.seed(numeric_seed)`, loop `i < j` row-major, one `randint(0, 255)` per pair, even → `+1`, mirrored symmetric, diagonal 0.
6. Logistic map: r = 3.99, 1000 warm-up iterations, `int((x * 10**6) % 256)`.
7. Chaos matrix: row-major reshape of the stream, then zero diagonal.
8. Password → seed: `sha256(password)[:8]` hex → int; `x0 = (seed % 10**6) / 10**6`; fallback `x0 = 0.54321` iff zero.
9. Trial passwords: `password + str(trial)`, trial starting at 0, retry only on non-invertibility.
10. Shift-128 residual: `(b + 128) mod 256` / `(b − 128) mod 256`.
11. Gauss–Jordan modular inversion with odd-pivot search and `pow(pivot, −1, 256)`.
12. Metric formulas: entropy, adjacent-byte Pearson, NPCR, UACI (÷255), bit-difference ratio, chi-square vs uniform, monobit p-value — exactly as in cells 1–4.

## 8. Safe refactorings applied (no output change)

- Isolated `random.Random` instance instead of global `random.seed` (identical stream; regression-tested).
- Bare `except:` → `except MatrixNotInvertibleError` (retry semantics preserved).
- Removed `print`/`input`/Colab calls from library code; results returned as dataclasses/dicts.
- Vectorized `bit_difference` popcount (`np.unpackbits` + sum) — identical integer result.
- Unified duplicate metric implementations; adopted the cells 2–3 `len < 2 → 0.0` correlation guard.
- Metadata sidecar JSON written next to ciphertext (new, additive; does not alter ciphertext bytes).
- Explicit `ValueError` on length-mismatched metric inputs by default, with `allow_truncate=True` to reproduce the notebook's silent-truncation numbers exactly.

## 9. Changes requiring author approval (NOT applied)

1. Replacing the 32-bit seed reduction (SHA-256 → first 8 hex chars) with a wider seed.
2. Making Shift-128 residual key-dependent (currently a fixed, self-inverse, key-independent transform).
3. Storing/deriving trial index differently in a new *file format* (would break ciphertext compatibility is not at stake since the sidecar is additive, but changing *encryption* semantics would be).
4. Changing UACI/NPCR ideals or pass thresholds used in the paper's tables.
5. Replacing the logistic-map float arithmetic or the Python `random` perturbation PRNG.
6. Any change to `N = 2 × n`.

## 10. Regression evidence

`tests/test_regression_baseline.py` plus `tests/baseline_reference.py` (verbatim port of cell 0's crypto functions) and `tests/fixtures/test_vectors.json` (generated by running the baseline reference) verify byte-identical ciphertexts, identical key matrices, identical trial indices, and identical metric values between baseline and refactored implementation. Generation script: `tests/fixtures/generate_test_vectors.py`. Status: **no divergence detected** on all generated vectors (see test file for the exact assertion set).

`[BUTUH INPUT PENULIS]` items are collected in `docs/PAPER_RESULTS_TRACEABILITY.md` and `data/README.md` (original paper datasets, exact paper tables/figures numbers, author metadata for CITATION.cff).
