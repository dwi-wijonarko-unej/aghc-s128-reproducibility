# Data

## What is distributed

`data/sample/` ships three **synthetic** files generated deterministically by
`data/generate_samples.py` (no external datasets, no licensing constraints):

| File | Size (bytes) | SHA3-256 |
|---|---|---|
| `sample_text.txt` | 5112 | `ecff9dc219a37899c51bcea25f9e74e7a80f8e10be4c7f22c9a5b7b2edee11bc` |
| `sample_binary.bin` | 4096 | `b855022c9ef1b11b3db29bab28fac7476131ca8e2b23b97612f0a7525a111a9d` |
| `sample_image.png` | 5074 | `27f71c98f31718e7b2f4817fa0a52f17f9184bcebbe1c2f9453ce21bf5630c44` |

All tests and the quick demo run on these samples alone — no downloads
required. Regenerate them with:

```bash
python data/generate_samples.py
```

## What is NOT distributed

Original research datasets referenced by the paper are **not** redistributed
until their licenses are verified by the authors. In particular:

* **USC-SIPI image database** images (e.g. Lena, Baboon, peppers) —
  USC-SIPI permits academic research use but redistribution terms must be
  verified before shipping copies in a public repository.
* **MRI data** — likely patient-derived; provenance and ethics/consent
  status must be confirmed before any redistribution. `[BUTUH INPUT PENULIS]`
* **PDF test documents** (e.g. the `202214326212_encrypted.pdf` seen in the
  original notebook output) — may contain personal data; not redistributed.

See `data/manifest.csv` for the machine-readable registry (checksums,
sources, licensing status) and `configs/paper_results_mapping.md` for how
each pending dataset maps to paper tables/figures.

## Placing external datasets

```bash
data/external/<your-file>.png        # put files here (git-ignored)
# then reference them in configs, e.g.:
#   inputs:
#     - data/external/4.1.05.tiff
```

`data/external/` is ignored by Git (`.gitignore`); nothing inside it will be
committed accidentally. Record every added file in `data/manifest.csv`
(including its SHA3-256, computed with `aghc-s128`'s integrity helpers or
`sha3sum -a 256 <file>`), and only mark `included_in_repo = yes` after
verifying the license permits redistribution.

## Dataset policy

1. No dataset with unclear licensing or personal data is committed.
2. For non-redistributable files, the repository stores only: filename,
   source URL, checksum, and size — enough to obtain and verify the file
   legally.
3. Experiment configs never hardcode absolute local paths; datasets live
   under `data/` and results under `results/`.
