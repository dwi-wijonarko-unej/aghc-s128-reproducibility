# AGHC-S128 Reproducibility Package

**Adaptive Graph Hill Cipher with Shift-128 Residual Processing (AGHC-S128)**
— a clean, testable, reproducible re-implementation of the research cipher
originally developed in a Google Colab notebook, prepared for GitHub release
and Zenodo archiving.

> **Disclaimer.** This repository is a *research reproducibility artifact*.
> AGHC-S128 is a research prototype.  The statistical evaluations included
> here (entropy, correlation, NPCR, UACI, chi-square, monobit) do **not**
> constitute a complete cryptographic security proof, and good scores do not
> demonstrate resistance to known-plaintext, chosen-plaintext, side-channel,
> brute-force, or structural attacks.  **Do not use this cipher to protect
> production or sensitive data.**  See [docs/SECURITY_SCOPE.md](docs/SECURITY_SCOPE.md).

## Method summary (baseline, preserved exactly)

* Input is treated as a byte stream (`uint8`).
* The user supplies `n`; the effective Hill-matrix dimension is
  **`N = 2 × n`** (two times `n` — *not* `2^n`).
* The byte stream is split: the main part (length divisible by `N`) is
  encrypted with a Hill-like matrix multiplication modulo 256; the trailing
  `size % N` bytes are transformed by **Shift-128** (`(b ± 128) mod 256`).
* Key matrix construction: `K = (A + P + C) mod 256` where
  * `A` — complete-graph adjacency matrix (off-diagonal 1, diagonal 0),
  * `P` — adaptive graph perturbation (seeded Mersenne-Twister stream from a
    password-derived seed),
  * `C` — logistic-map chaos matrix (r = 3.99, 1000 warm-up iterations),
  followed by an odd-diagonal adjustment.
* The key is retried as `password + "0"`, `password + "1"`, … until `K` is
  invertible modulo 256 (Gauss–Jordan with `pow(pivot, -1, 256)`).
* Integrity hashing defaults to **SHA3-256** (MD5 exists only as a
  deprecated legacy helper).

Every behavioral detail — RNG draw order, reshape orientation, trial retry —
is frozen and verified byte-for-byte against the original notebook by the
regression suite (`tests/test_regression_baseline.py`).

## Installation

Requires Python ≥ 3.10.

```bash
git clone <repository-url>
cd aghc-s128-reproducibility

# venv + pip (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # package + `aghc-s128` CLI
pip install -e .[test]             # + pytest
# or conda:
# conda env create -f environment.yml && conda activate aghc-s128
```

## Quick start

```bash
# environment + algorithm self-check
aghc-s128 validate

# full pipeline on a shipped sample (encrypt -> decrypt -> verify -> metrics -> figures)
python scripts/run_quick_demo.py
```

## Encrypt / decrypt (CLI)

Passwords are never passed as command-line arguments (shell-history safety):
use an environment variable or an interactive prompt.

```bash
export AGHC_PASSWORD='your-test-password'

# encrypt (writes sample.txt.enc + sample.txt.enc.aghc-s128.json sidecar)
aghc-s128 encrypt data/sample/sample_text.txt --n 8 --output /tmp/sample.txt.enc

# decrypt: n and trial index are read from the sidecar; verify round trip
aghc-s128 decrypt /tmp/sample.txt.enc --output /tmp/sample.txt.out --verify
```

Programmatic use:

```python
from aghc_s128 import encrypt_bytes, decrypt_bytes

data = open("data/sample/sample_text.txt", "rb").read()
enc = encrypt_bytes(data, n_input=8, password="demo")
dec = decrypt_bytes(enc.ciphertext, n_input=8, password="demo",
                    trial_index=enc.trial_index)
assert dec.plaintext_sha3_256 == enc.plaintext_sha3_256
```

## Statistical analysis

```bash
# Mode A: original vs encrypted (+ optional decrypted for integrity)
aghc-s128 analyze data/sample/sample_text.txt /tmp/sample.txt.enc \
    --decrypted /tmp/sample.txt.out --output-dir results/analysis

# Mode B: key sensitivity between two ciphertexts (different passwords)
aghc-s128 key-sensitivity cipherA.bin cipherB.bin --output-dir results/analysis
```

Metrics: Shannon entropy, adjacent-byte correlation, NPCR, UACI, bit
difference, chi-square uniformity, monobit frequency, SHA3-256 round-trip
integrity.  Monobit `fail` verdicts are recorded as-is — never dropped.

## Tests

```bash
python -m pytest tests/
```

Includes component tests, round-trip tests across size classes, metadata
privacy tests, CLI smoke tests, and **baseline regression tests** against
frozen vectors generated from the original notebook implementation.

## Repository structure

```
aghc-s128-reproducibility/
├── src/aghc_s128/        # core package (no Colab, no input(), no prints)
├── scripts/              # runnable experiment pipelines
├── configs/              # YAML experiment configs + paper-results mapping
├── data/                 # synthetic samples + dataset manifest (+ external/, git-ignored)
├── results/              # experiment outputs (logs / tables / figures)
├── notebooks/            # thin Colab/Jupyter notebooks calling the package
├── tests/                # pytest suite + baseline reference + fixtures
└── docs/                 # audit, reproducibility, known issues, security scope, …
```

## Reproducing the paper

The pipeline reproduces the notebook's Modes A/B/C end-to-end.  Which paper
tables/figures can be reproduced *fully* depends on the availability of the
original datasets (not redistributed — see
[configs/paper_results_mapping.md](configs/paper_results_mapping.md) for the
status of each item, `data/README.md` for dataset policy):

```bash
export AGHC_PASSWORD='test-password'
python scripts/run_binary_experiments.py
python scripts/run_image_experiments.py
AGHC_PASSWORD_A='key-A' AGHC_PASSWORD_B='key-B' python scripts/run_key_sensitivity.py
python scripts/run_keyspace_analysis.py --charset ascii95 --length 16
python scripts/reproduce_tables.py
python scripts/reproduce_figures.py
```

Notebooks (`notebooks/01..04`) run the same package API on Google Colab or
locally — they never duplicate the algorithm.

## Dataset policy

Only deterministic **synthetic** samples are committed.  Original paper
datasets (USC-SIPI images, MRI data, PDF documents) are not redistributed
until licensing/consent is verified; obtain them from the sources listed in
[docs/DATASET_SOURCES.md](docs/DATASET_SOURCES.md) and register them in
`data/manifest.csv`.

## Citation

`[BUTUH INPUT PENOLIS — DOI & metadata]` This section and `CITATION.cff`
will be updated with the paper reference and the Zenodo DOI once the
repository is archived:

```bibtex
@software{aghc_s128_reproducibility_2026,
  title  = {AGHC-S128 Reproducibility Package},
  author = {AGHC-S128 research team},
  year   = {2026},
  url    = {https://github.com/PLACEHOLDER/aghc-s128-reproducibility},
  doi    = {10.5281/zenodo.PLACEHOLDER}
}
```

## License

MIT — see [LICENSE](LICENSE).

## Security scope & limitations

Research prototype; statistical tests are not a security proof; the residual
Shift-128 transform is constant and key-independent.  Full statement:
[docs/SECURITY_SCOPE.md](docs/SECURITY_SCOPE.md).  Known issues and baseline
inconsistencies: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).
