"""Figure generation for AGHC-S128 experiments.

All functions save to an explicit ``output_path`` and return that path.
No function calls ``plt.show()`` or otherwise opens an interactive UI;
figures are closed after saving to keep memory bounded in batch runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Union

import matplotlib

matplotlib.use("Agg", force=False)  # headless-safe; respects an active backend
import matplotlib.pyplot as plt
import numpy as np

from .metrics import adjacent_byte_correlation

__all__ = [
    "plot_histogram_comparison",
    "plot_entropy_comparison",
    "plot_correlation_scatter",
    "plot_key_sensitivity_comparison",
    "plot_runtime",
]

PathLike = Union[str, Path]
DEFAULT_DPI = 150


def _arrays(data_a, data_b):
    a = np.asarray(data_a, dtype=np.uint8)
    b = np.asarray(data_b, dtype=np.uint8)
    if a.ndim != 1 or b.ndim != 1:
        raise ValueError("expected 1-D byte arrays")
    return a, b


def plot_histogram_comparison(
    data_a,
    data_b,
    output_path: PathLike,
    *,
    label_a: str = "Original",
    label_b: str = "Encrypted",
    title: str = "Byte histogram comparison",
    xlabel: str = "byte value",
    ylabel: str = "frequency",
    dpi: int = DEFAULT_DPI,
) -> Path:
    """Side-by-side 256-bin histograms of two byte streams."""
    a, b = _arrays(data_a, data_b)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for axis, data, label in ((axes[0], a, label_a), (axes[1], b, label_b)):
        axis.hist(data, bins=256, color="steelblue", edgecolor="none")
        axis.set_title(f"{label} histogram")
        axis.set_xlabel(xlabel)
        axis.set_ylabel(ylabel)
        axis.set_xlim(0, 255)
    fig.suptitle(title)
    fig.tight_layout()
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=dpi)
    plt.close(fig)
    return target


def plot_entropy_comparison(
    labels: Sequence[str],
    entropies: Sequence[float],
    output_path: PathLike,
    *,
    title: str = "Shannon entropy comparison",
    ylabel: str = "entropy (bits/byte)",
    dpi: int = DEFAULT_DPI,
) -> Path:
    """Bar chart of entropy values (e.g., original vs encrypted per file)."""
    if len(labels) != len(entropies):
        raise ValueError("labels and entropies must have the same length")
    fig, axis = plt.subplots(figsize=(max(6, 1.2 * len(labels)), 5))
    positions = np.arange(len(labels))
    axis.bar(positions, entropies, color="steelblue")
    axis.axhline(8.0, color="crimson", linestyle="--", linewidth=1, label="ideal (8.0)")
    axis.set_xticks(positions)
    axis.set_xticklabels(labels, rotation=30, ha="right")
    axis.set_ylabel(ylabel)
    axis.set_title(title)
    axis.set_ylim(0, 8.6)
    axis.legend()
    fig.tight_layout()
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=dpi)
    plt.close(fig)
    return target


def plot_correlation_scatter(
    image,
    output_path: PathLike,
    *,
    direction: str = "horizontal",
    max_points: int = 200_000,
    title: Optional[str] = None,
    dpi: int = DEFAULT_DPI,
) -> Path:
    """Scatter plot of adjacent-pixel value pairs of a 2-D image.

    IMAGE-SPECIFIC analysis — this helper is an explicit extension for image
    inputs and was **not** part of the baseline notebook (which only measured
    stream-adjacent bytes).  Pixel pairs are sampled along the given
    direction from a grayscale 2-D array; for RGB input the first channel is
    used.  Subsamples uniformly when more than ``max_points`` pairs exist.

    Directions: ``horizontal`` ``(x, x+1)``, ``vertical`` ``(y, y+1)``,
    ``diagonal`` ``(x, y) vs (x+1, y+1)``.
    """
    img = np.asarray(image)
    if img.ndim == 3:
        img = img[:, :, 0]
    if img.ndim != 2:
        raise ValueError(f"expected a 2-D (grayscale) image, got shape {img.shape}")
    if direction not in {"horizontal", "vertical", "diagonal"}:
        raise ValueError(f"unknown direction: {direction!r}")

    if direction == "horizontal":
        left, right = img[:, :-1].ravel(), img[:, 1:].ravel()
    elif direction == "vertical":
        left, right = img[:-1, :].ravel(), img[1:, :].ravel()
    else:
        left, right = img[:-1, :-1].ravel(), img[1:, 1:].ravel()

    if left.size > max_points:
        indices = np.linspace(0, left.size - 1, max_points).astype(np.int64)
        left, right = left[indices], right[indices]

    pair_correlation = float(np.corrcoef(left.astype(np.float64), right.astype(np.float64))[0, 1])

    fig, axis = plt.subplots(figsize=(6, 6))
    axis.scatter(left, right, s=1, alpha=0.15, color="steelblue", edgecolors="none")
    axis.set_xlabel("value of pixel (x, y)")
    axis.set_ylabel(f"value of adjacent pixel ({direction})")
    axis.set_title(
        title or f"Adjacent-pixel correlation ({direction}): r = {pair_correlation:.4f}"
    )
    fig.tight_layout()
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=dpi)
    plt.close(fig)
    return target


def plot_key_sensitivity_comparison(
    cipher_a,
    cipher_b,
    output_path: PathLike,
    *,
    label_a: str = "Ciphertext A (key A)",
    label_b: str = "Ciphertext B (key B)",
    metrics: Optional[dict] = None,
    title: str = "Key sensitivity: ciphertext comparison",
    dpi: int = DEFAULT_DPI,
) -> Path:
    """Overlaid histograms of two ciphertexts plus mode-B metric annotations."""
    a, b = _arrays(cipher_a, cipher_b)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    axes[0].hist(a, bins=256, color="steelblue")
    axes[0].set_title(label_a)
    axes[0].set_xlabel("byte value")
    axes[0].set_ylabel("frequency")
    axes[0].set_xlim(0, 255)
    axes[1].hist(b, bins=256, color="darkorange")
    axes[1].set_title(label_b)
    axes[1].set_xlabel("byte value")
    axes[1].set_xlim(0, 255)

    annotation = ""
    if metrics:
        parts = [f"{key} = {value:.4f}" for key, value in metrics.items()]
        annotation = "\n".join(parts)
    fig.suptitle(title + (f"\n{annotation}" if annotation else ""))
    fig.tight_layout()
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=dpi)
    plt.close(fig)
    return target


def plot_runtime(
    labels: Sequence[str],
    times_seconds: Sequence[float],
    output_path: PathLike,
    *,
    title: str = "Runtime",
    ylabel: str = "wall-clock time (s)",
    dpi: int = DEFAULT_DPI,
) -> Path:
    """Bar chart of wall-clock runtimes (hardware-dependent, see docs)."""
    if len(labels) != len(times_seconds):
        raise ValueError("labels and times must have the same length")
    fig, axis = plt.subplots(figsize=(max(6, 1.2 * len(labels)), 5))
    positions = np.arange(len(labels))
    axis.bar(positions, times_seconds, color="steelblue")
    axis.set_xticks(positions)
    axis.set_xticklabels(labels, rotation=30, ha="right")
    axis.set_ylabel(ylabel)
    axis.set_title(title)
    fig.tight_layout()
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=dpi)
    plt.close(fig)
    return target


_ = adjacent_byte_correlation  # available for callers building richer plots
