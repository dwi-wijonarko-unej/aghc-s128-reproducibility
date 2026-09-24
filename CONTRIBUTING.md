# Contributing

Thank you for improving this reproducibility artifact.  The overriding rule:
**baseline algorithm behavior is frozen.**  Changes that alter ciphertexts
or metric values require explicit documentation and author approval.

## Ground rules

1. **Do not change the cipher.**  `K = (A + P + C) mod 256`, `N = 2 × n`,
   the odd-diagonal adjustment, the reshape orientation
   `(N, len_hill // N)`, Shift-128 `(b ± 128) mod 256`, Gauss–Jordan mod-256
   inversion, the trial-password scheme `password + str(trial)`, and every
   metric formula are fixed by the baseline (see
   `docs/BASELINE_IMPLEMENTATION_AUDIT.md` §7).
2. **Regression suite must stay green** (`python -m pytest tests/`).
   If your change intentionally alters outputs, you must: document it in
   `docs/KNOWN_ISSUES.md` + `CHANGELOG.md`, regenerate
   `tests/fixtures/test_vectors.json` via the provided script, and show the
   diff in your pull request.
3. **No Colab in core.**  `src/aghc_s128/` must never import
   `google.colab`, call `input()`, or print from library code (CLI and
   notebooks are the interface layers).
4. **No secrets, no real passwords.**  Test vectors only.
5. **No invented paper numbers.**  Pipelines only write values they computed
   (see `docs/PAPER_RESULTS_TRACEABILITY.md`).

## Workflow

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[test]
python -m pytest tests/
```

* Keep functions small and documented; centralize baseline parameters in
  `constants.py` — never hardcode `256`, `3.99`, `1000`, `128`, `0.54321`.
* New metrics/visualizations: return structured data, accept an explicit
  output path, never open interactive UIs.
* New experiments: drive them from a YAML config in `configs/` and record
  logs/tables/figures under `results/`.

## Reporting problems

Open an issue with: environment summary (`aghc-s128 validate`), minimal
reproduction (password may be a throwaway test vector — never a real one),
and the relevant log JSON from `results/logs/`.

## Security-sensitive findings

Cryptanalysis results (e.g. known-plaintext breaks) are legitimate research
here — report them as issues/PRs with a demo script.  Do read
`docs/SECURITY_SCOPE.md` for the existing scope statement first.
