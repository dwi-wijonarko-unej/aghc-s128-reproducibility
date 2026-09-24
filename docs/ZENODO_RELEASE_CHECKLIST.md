# Zenodo Release Checklist

Work through every item before creating a GitHub release / Zenodo deposit.
Do not modify a release that already has a DOI — issue a new version instead.

## Repository readiness

- [ ] Repository is **public** on GitHub and the default branch is protected
      (or at least stable).
- [ ] `README.md` renders correctly (badges, quick start, structure tree).
- [ ] `LICENSE` present (MIT) and referenced from `pyproject.toml`.
- [ ] `CITATION.cff` present with real author metadata
      (`[BUTUH INPUT PENULIS]` placeholders replaced — ORCID iDs, affiliation,
      paper DOI once published).
- [ ] `CHANGELOG.md` updated for the release version.
- [ ] No secrets anywhere: no real passwords (only public test vectors),
      no tokens, no private paths (grep the tree and git history).

## Code quality gates

- [ ] `python -m pytest tests/` — all tests green on the release machine.
- [ ] `aghc-s128 validate` passes.
- [ ] `python scripts/run_quick_demo.py` completes with `round trip ok: True`.
- [ ] Dependency bounds in `requirements.txt` / `environment.yml` /
      `pyproject.toml` agree with each other.
- [ ] Optional: attach `pip freeze` output of the release environment as
      `results/logs/environment_<version>.txt` for exact pinning.

## Data policy

- [ ] `data/manifest.csv` complete: every referenced dataset has a row with
      checksum and licensing status.
- [ ] No unverified-license or personal data committed (check `data/external/`
      is empty in git; `.gitkeep` only).
- [ ] Sample files regenerate deterministically
      (`python data/generate_samples.py` → identical SHA3-256).

## Versioning & release

- [ ] Version bumped consistently in `pyproject.toml` and
      `aghc_s128/constants.py` (`ALGORITHM_VERSION`).
- [ ] Git tag created: `git tag -a v1.0.0 -m "AGHC-S128 reproducibility release"`.
- [ ] GitHub Release created from the tag with release notes taken from
      `CHANGELOG.md`.

## Zenodo deposit (via GitHub integration or web upload)

- [ ] Zenodo GitHub integration enabled for the repository, or upload the
      tagged source archive manually.
- [ ] Deposit metadata: title, authors (match CITATION.cff), description,
      license MIT, keywords (reproducibility, cryptography research,
      statistical evaluation), related identifiers (paper DOI if available).
- [ ] Access right: open.
- [ ] **Publish** the deposit → DOI issued.
- [ ] Add the DOI to `README.md` badge/section and to `CITATION.cff`
      (`preferred-citation` / `identifiers`) — this requires a *new commit /
      release version*; never rewrite the already-archived release.
- [ ] Record the DOI in `CHANGELOG.md`.

## Post-release invariants

- [ ] Never force-push, delete, or modify the tagged release commit.
- [ ] Corrections go into a new version (bump, tag, release, deposit).
- [ ] Keep `docs/PAPER_RESULTS_TRACEABILITY.md` updated with any
      paper-vs-reproduced comparisons added after release.
