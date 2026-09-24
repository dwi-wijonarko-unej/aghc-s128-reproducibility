# Computational Environment

## Reference development environment

| Component | Version |
|---|---|
| OS | Linux (WSL2, x86_64) |
| Python | 3.10+ required; developed and validated on 3.14 |
| numpy | ≥ 1.24 (validated on 2.3.x) |
| scipy | ≥ 1.10 (validated on 1.17.x) |
| matplotlib | ≥ 3.7 (validated on 3.10.x) |
| PyYAML | ≥ 6.0 |

Exact versions of *your* run are recorded in every experiment log under
`runtime_environment` (see `aghc_s128.metadata.runtime_environment_summary`).

## Hardware notes

* No GPU, no BLAS-level parallelism is *required*: the Hill stage uses numpy
  integer matmul (multithreaded BLAS may or may not be used for `np.dot`),
  and key generation uses scalar loops.
* Wall-clock runtimes depend on CPU, storage, and load; treat them as
  metadata, not as comparable constants (KNOWN_ISSUES K-14).
* If you publish benchmark numbers, record CPU model, RAM, and Python/BLAS
  configuration alongside them.

## Recreating the environment

### venv + pip (recommended)

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # bounded versions
pip install -e .                     # installs the aghc-s128 package + CLI
```

For a fully pinned snapshot, use `pip freeze > constraints.txt` on a working
environment and reinstall with `pip install -c constraints.txt -e .`.

### conda

```bash
conda env create -f environment.yml
conda activate aghc-s128
```

### Google Colab

```python
!pip install -e .        # after cloning/uploading the repository
!aghc-s128 validate      # environment + algorithm self-check
```

or use the prepared notebooks in `notebooks/` (each has an optional setup
cell).  Colab's preinstalled numpy/scipy/matplotlib already satisfy the
requirements in most runtimes.

## Validation

```bash
python scripts/validate_environment.py    # or: aghc-s128 validate
```

prints the environment summary and runs deterministic self-checks
(key determinism, inverse correctness, Shift-128 full byte round trip,
end-to-end round trip).
