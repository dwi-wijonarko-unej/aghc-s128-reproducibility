# Known Issues

This file documents every known limitation, inconsistency, and baseline
defect found while restructuring the original Colab notebook into this
repository.  Items are **documented, not silently fixed**: the default
behavior reproduces the baseline wherever the baseline is well-defined.

## Baseline algorithm — documented properties (not bugs to fix silently)

### K-1. `N = 2 × n`, not `2^n`
The effective Hill-matrix dimension is twice the user parameter
(`N = 2 * n_input`).  The original notebook output confirms this
(`n = 99 → N = 198`).  Any prose or notation that could be read as `2^n` is
wrong; this repository always spells it `N = 2 × n`.

### K-2. Password trial concatenation
Key generation retries with candidate passwords `password + "0"`,
`password + "1"`, ... until the matrix is invertible mod 256.  The winning
trial index is part of the *effective key*: decryption must regenerate the
same trial.  The baseline re-discovers it by re-running the search from 0
(deterministic, correct, but implicit and O(trials)); this repository
additionally stores `trial_index` in the metadata sidecar and keeps
`trial_index=None` for baseline-style rediscovery.

### K-3. SHA-256 digest reduced to a 32-bit seed
`numeric_seed = int(sha256(password)[:8], 16)` — at most 2^32 distinct
perturbation seeds regardless of password entropy.  Consequently the
*effective* key space of the derived key material is bounded by ~2^32 (before
considering collisions), far below the password-alphabet space estimated by
the notebook's MODE C keyspace analysis (`charset^length`).  The keyspace
tool is therefore labeled "password space estimation", with an explicit
caveat in its output.

### K-4. Logistic map in floating point
The chaos stream is `x = 3.99·x·(1−x)` in IEEE-754 doubles.  The port keeps
the pure-Python scalar loop (no vectorization) so the rounding sequence is
reproducible per platform; cross-platform bit-identity is expected (same
operation order, no FMA in the scalar loop) but is not formally guaranteed —
regression vectors (tests/fixtures) make any divergence visible.

### K-5. Residual Shift-128 is constant and self-inverse
The trailing `size % N` bytes are transformed by `(b + 128) mod 256` — a
fixed, key-independent, self-inverse permutation.  It provides **no
independent cryptographic protection** and is reproduced only because it is
part of the baseline algorithm.  For files smaller than `N` the *entire*
ciphertext is just Shift-128 of the plaintext (recoverable without any key).

### K-6. Python `random` (Mersenne Twister) for the perturbation
The "adaptive/AI-assisted" perturbation is a seeded Mersenne-Twister stream
(`random.seed(numeric_seed)`, `randint(0, 255)` per edge).  It is
deterministic and reproducible, but it is not a CSPRNG and there is no
learning component despite the historical "AI-assisted" naming.

## Inconsistencies between notebook components

### K-7. MD5 (cipher cell) vs SHA3-256 (analysis cells)
The cipher cell printed MD5 digests; the analysis cells verify SHA3-256.
This repository standardizes on **SHA3-256** everywhere and keeps MD5 only as
a clearly-deprecated legacy helper (`aghc_s128.integrity.hash_file_md5`).

### K-8. Monobit unsigned-underflow defect (fixed, deviation documented)
The notebook computed `abs(ones - zeros)` on **numpy unsigned** integers.
When zeros > ones this underflows to ~1.8×10^19, forcing the p-value to
exactly `0.0` ("NOT RANDOM") even for well-balanced data.  Example from the
regression fixtures: a stream with 244 ones / 268 zeros gets notebook
`p = 0.0` instead of the correct `p ≈ 0.2888`.  This repository evaluates
the same formula with exact integer arithmetic (the formula the notebook
intended).  This is the **only numerical deviation** from the baseline
analysis code and is pinned by
`tests/test_metrics.py::test_monobit_no_unsigned_underflow` and
`tests/test_regression_baseline.py::test_monobit_matches_notebook_except_documented_underflow`.

### K-9. Monobit results vary per file — failures are expected sometimes
Monobit is a single, weak frequency test.  Some inputs (especially small or
structured ones) legitimately produce `p ≤ 0.01`.  The runners record
`pass`/`fail` verdicts verbatim; failures are never dropped, re-run away, or
re-labeled.  The fixed underflow (K-8) makes verdicts *more* trustworthy than
the notebook's, which could report `fail` for balanced data.

### K-10. Silent length truncation in paired metrics (default changed)
NPCR/UACI/key-sensitivity/bit-difference truncated mismatched inputs to
`min(len)` without any warning.  The library default now raises
`ValueError` on length mismatch; `allow_truncate=True` reproduces the
notebook numbers exactly (regression-tested).  Length-mismatched
comparisons were ill-defined anyway — ciphertexts of the same plaintext
always have equal length in this scheme.

### K-11. Correlation guard inconsistency
Cell 1 of the notebook let `scipy.stats.pearsonr` raise on inputs < 2 bytes;
cells 2–3 returned 0.  The library adopts the guard (0.0 for < 2 bytes).
Constant inputs yield `nan` (scipy semantics), same as the notebook.

### K-12. "AI-assisted" / "Q1-level" terminology vs implementation
The notebook prints qualitative verdicts ("EXCELLENT", "Q1-level
cryptographic robustness") from metric thresholds.  Those strings are removed
from the library: entropy/NPCR/UACI/correlation/chi-square/monobit are
**statistical evaluations**, not proof of security
(see `docs/SECURITY_SCOPE.md`).

### K-13. UACI "~33% ideal" quoted for non-image data
The 33% reference is an image-encryption benchmark.  Library output reports
the number without the image ideal unless the input is an image.

### K-14. Runtime numbers are hardware- and load-dependent
Notebook timings (e.g. "0.5429 seconds" in the committed output) include
key generation, file I/O, and printing.  This repository times phases with
`time.perf_counter()` and labels them wall-clock; results differ across
machines and Colab sessions by design.  Runtimes are recorded, never
compared against paper values as pass/fail.

### K-15. `except:` in baseline retry loop
`generate_valid_key` used a bare `except:` (swallowing *any* error).  The
port catches `MatrixNotInvertibleError` only — retry semantics preserved,
genuine errors now surface.  Behavior-identical for key generation because
matrix inversion was the only failing call in that block.

## Data and provenance

### K-16. MRI / PDF dataset provenance unverified
The paper's MRI images and PDF test document are not redistributed; their
licensing, consent status, and checksums are pending from the authors
(`data/manifest.csv`, `[BUTUH INPUT PENULIS]`).  Until verified, pipelines
covering them run only on synthetic samples and are marked
`[PENDING ORIGINAL INPUT DATA]` in `configs/paper_results_mapping.md`.

### K-17. Notebook output blob is provenance, not a test
The committed notebook output (decrypt run, `n = 99`, `N = 198`, MD5 pair)
documents a historical run; it cannot be re-executed and is not used as a
regression oracle.  Regression oracles are generated from the extracted
baseline reference (`tests/baseline_reference.py`).

## Engineering notes (safe refactors, verified by tests)

* Isolated `random.Random` instance replaces the global `random.seed` —
  identical Mersenne-Twister stream, no global RNG pollution.
* `bit_difference` popcount vectorized (`np.unpackbits`) — identical values.
* Empty input is defined behavior: empty ciphertext, trivial round trip
  (the notebook would produce the same empty file).
* Duplicate function definitions across notebook cells collapsed to single
  implementations (see `docs/BASELINE_IMPLEMENTATION_AUDIT.md` §2).
