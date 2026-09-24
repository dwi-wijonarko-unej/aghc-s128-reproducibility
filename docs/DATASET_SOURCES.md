# Dataset Sources

Summary of every dataset referenced by the baseline work, its redistribution
status, and how to obtain it legally.  Machine-readable registry:
`data/manifest.csv`.

## Shipped with the repository (synthetic, MIT)

| Dataset | Files | Generator |
|---|---|---|
| Synthetic samples | `data/sample/sample_text.txt`, `sample_binary.bin`, `sample_image.png` | `data/generate_samples.py` (deterministic) |

These carry no licensing constraints and exist so that **all tests, the quick
demo, and every pipeline run without downloads**.

## Not redistributed

| Dataset | Used for | Source | Redistribution status |
|---|---|---|---|
| USC-SIPI misc. images (Lena, Baboon, peppers, etc.) | image encryption tables/figures | https://sipi.usc.edu/database/ | academic-use imagery; verify USC-SIPI terms before committing copies — until then place under `data/external/` (git-ignored) `[BUTUH INPUT PENULIS]` |
| MRI images | medical-image experiments | author collection | likely patient-derived; requires provenance + ethics/consent confirmation before any redistribution `[BUTUH INPUT PENULIS]` |
| PDF test document (e.g. `202214326212*.pdf`, 399 274 bytes per notebook output) | binary-file experiments | author collection | may contain personal data; not redistributed `[BUTUH INPUT PENULIS]` |

## Workflow for adding a dataset

1. Obtain the file legally from its source.
2. Place it under `data/external/` (git-ignored).
3. Compute its SHA3-256 (`python -c "from aghc_s128.integrity import hash_file_sha3_256 as h; print(h('<file>'))"`).
4. Add/refresh its row in `data/manifest.csv` (checksum, size, license,
   `included_in_repo`).
5. Reference it from the relevant config under `inputs:`.
6. Only mark `included_in_repo = yes` after the license is verified to permit
   redistribution; then move it to `data/sample/` (or keep the path and
   un-ignore explicitly) and commit.

## Traceability

Every experiment log records the SHA3-256 of each processed input, so a
table row produced from an external dataset can always be traced back to the
exact bytes — even when those bytes are not in the repository.
