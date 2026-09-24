"""Generate the deterministic synthetic sample files in ``data/sample/``.

Run from the repository root:

    python data/generate_samples.py

The samples are fully synthetic (no external datasets, no licensing
constraints) so tests and the quick demo run without any download.  The
generator is deterministic: identical inputs produce identical files with
the SHA3-256 checksums recorded in ``data/manifest.csv``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np

SAMPLE_DIR = Path(__file__).resolve().parent / "sample"

TEXT_CONTENT = (
    "AGHC-S128 reproducibility sample\n"
    "Adaptive Graph Hill Cipher with Shift-128 Residual Processing\n"
    "This synthetic text file exists so that the quick demo and the test\n"
    "suite can run without external datasets. It contains no sensitive\n"
    "data. Byte distribution is intentionally text-like (limited alphabet)\n"
    "so entropy comparisons between original and encrypted are meaningful.\n"
    "The five boxing wizards jump quickly. 0123456789 repeat.\n" * 12
)


def sha3(path: Path) -> str:
    return hashlib.sha3_256(path.read_bytes()).hexdigest()


def main() -> None:
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    text_path = SAMPLE_DIR / "sample_text.txt"
    text_path.write_text(TEXT_CONTENT, encoding="ascii")

    binary_path = SAMPLE_DIR / "sample_binary.bin"
    rng = np.random.default_rng(20260924)
    payload = rng.integers(0, 256, size=4096, dtype=np.uint8)
    binary_path.write_bytes(payload.tobytes())

    image_path = SAMPLE_DIR / "sample_image.png"
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        y, x = np.mgrid[0:96, 0:96]
        base = ((x * 2 + y) % 256).astype(np.uint8)
        pattern = (
            base
            + 40 * np.sin(x / 6.0)
            + 40 * np.cos(y / 8.0)
            + 30 * ((x > 40) & (x < 60))
            + 20 * ((y > 20) & (y < 40))
        )
        image = np.clip(pattern, 0, 255).astype(np.uint8)
        plt.imsave(image_path, image, cmap="gray", vmin=0, vmax=255)
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(f"matplotlib is required to build the sample image: {exc}")

    for path in (text_path, binary_path, image_path):
        print(f"{path.name:20s} {path.stat().st_size:>8d} bytes  sha3-256={sha3(path)}")


if __name__ == "__main__":
    main()
