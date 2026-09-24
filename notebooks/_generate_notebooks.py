"""Generate the thin AGHC-S128 notebooks.

Run from the repository root:  python notebooks/_generate_notebooks.py

The notebooks are deliberately thin: every algorithmic step calls the
installed ``aghc_s128`` package (same code path as local scripts/CLI).  No
algorithm is duplicated in notebook cells.
"""

from __future__ import annotations

import json
import nbformat
from pathlib import Path

HERE = Path(__file__).resolve().parent

SETUP_LOCAL = """\
# --- Setup (local / Jupyter) -------------------------------------------
# Option A: repository checked out locally
#   pip install -e .            (run once in the repo root, outside Jupyter)
# Option B: pip install from a released wheel / archive
#   %pip install aghc-s128==1.0.0
#
# This cell only configures paths; nothing is executed on import of the package.
"""

SETUP_COLAB = """\
# --- Optional: Google Colab setup ---------------------------------------
# Run this cell ONLY on Google Colab. It installs the package from the
# repository; everything else in the notebook then uses the same code as a
# local installation.
#
# From GitHub:
# !git clone https://github.com/PLACEHOLDER/aghc-s128-reproducibility.git
# %cd aghc-s128-reproducibility
# !pip install -e .
#
# Or from an uploaded archive (Workspace sidebar -> upload), then:
# !pip install /content/aghc-s128-reproducibility
#
# Google Drive is NOT required. To use Drive anyway (optional):
# from google.colab import drive
# drive.mount('/content/drive')
"""


def code(source: str):
    return nbformat.v4.new_code_cell(source)


def markdown(source: str):
    return nbformat.v4.new_markdown_cell(source)


def build_notebook(title: str, intro: str, cells) -> nbformat.NotebookNode:
    notebook = nbformat.v4.new_notebook()
    notebook.metadata.update(
        {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3"},
        }
    )
    header = f"# {title}\n\n{intro}"
    notebook.cells = [markdown(header), code(SETUP_LOCAL), code(SETUP_COLAB), *cells]
    return notebook


def nb1():
    cells = [
        markdown("## 1 — Validate the environment"),
        code("import aghc_s128\nfrom aghc_s128.cli import main\nprint('aghc_s128 version:', aghc_s128.__version__)\nmain(['validate'])"),
        markdown("## 2 — Quick reproduction on a sample file\n"
                 "Password here is a **public demo test vector**, never a real secret."),
        code(
            "from pathlib import Path\n"
            "from aghc_s128 import encrypt_bytes, decrypt_bytes\n"
            "from aghc_s128.io_utils import read_binary_file\n"
            "\n"
            "sample = Path('data/sample/sample_text.txt')\n"
            "if not sample.exists():\n"
            "    sample = Path('sample_text.txt')  # fallback: upload your own\n"
            "\n"
            "password = 'aghc-s128-demo'\n"
            "plaintext = read_binary_file(sample)\n"
            "enc = encrypt_bytes(plaintext, n_input=8, password=password)\n"
            "dec = decrypt_bytes(enc.ciphertext, n_input=8, password=password,\n"
            "                    trial_index=enc.trial_index)\n"
            "print('size             :', plaintext.size)\n"
            "print('effective N      :', enc.effective_n, ' (N = 2 x n)')\n"
            "print('hill / residual  :', enc.hill_length, '/', enc.residual_length)\n"
            "print('trial index      :', enc.trial_index)\n"
            "print('round trip ok    :', dec.plaintext_sha3_256 == enc.plaintext_sha3_256)\n"
            "print('ciphertext sha3  :', enc.ciphertext_sha3_256)"
        ),
        markdown("## 3 — Mode A metrics at a glance (same library as the CLI)"),
        code(
            "from aghc_s128 import metrics\n"
            "m = {\n"
            "    'entropy_original':  metrics.shannon_entropy(plaintext),\n"
            "    'entropy_encrypted': metrics.shannon_entropy(enc.ciphertext),\n"
            "    'corr_original':     metrics.adjacent_byte_correlation(plaintext),\n"
            "    'corr_encrypted':    metrics.adjacent_byte_correlation(enc.ciphertext),\n"
            "    'npcr_percent':      metrics.npcr(plaintext, enc.ciphertext),\n"
            "    'uaci_percent':      metrics.uaci(plaintext, enc.ciphertext),\n"
            "    'bit_diff_percent':  metrics.bit_difference_ratio(plaintext, enc.ciphertext),\n"
            "}\n"
            "for key, value in m.items():\n"
            "    print(f'{key:20s} {value:.4f}')"
        ),
    ]
    return build_notebook(
        "AGHC-S128 — 01 Quick Reproduction",
        "Fastest end-to-end reproduction: environment check, encrypt/decrypt "
        "round trip with metadata, and headline statistical metrics. "
        "Everything calls the `aghc_s128` package — the notebook contains no "
        "algorithm code. Statistical metrics are evaluations, not a security "
        "proof (docs/SECURITY_SCOPE.md).",
        cells,
    )


def nb2():
    cells = [
        markdown("## 1 — Image experiment via the packaged runner\n"
                 "Uses `configs/image_experiments.yaml`. Byte-stream metrics follow the "
                 "baseline; the adjacent-pixel correlation figure is an explicit "
                 "image-specific extension."),
        code(
            "from aghc_s128.experiments import load_config, run_image_experiments\n"
            "config = load_config('configs/image_experiments.yaml')\n"
            "config['password'] = 'aghc-s128-demo'  # public test vector\n"
            "payload = run_image_experiments(config)\n"
            "print('round trips ok:', sum(r['round_trip_ok'] for r in payload['runs']),\n"
            "      '/', len(payload['runs']))\n"
            "print('outputs:', payload['outputs'])"
        ),
        markdown("## 2 — Metrics table for the processed images"),
        code(
            "rows = [{'input': r['input'], **r['metrics']} for r in payload['runs']]\n"
            "try:\n"
            "    import pandas as pd  # optional dependency, pretty display only\n"
            "    display(pd.DataFrame(rows))\n"
            "except ImportError:\n"
            "    for row in rows:\n"
            "        print(row)"
        ),
        markdown("Monobit verdicts are reported as computed — `fail` results are kept."),
    ]
    return build_notebook(
        "AGHC-S128 — 02 Image Security Analysis (statistical evaluation)",
        "Mode A statistical evaluation on image files: encrypt/decrypt round "
        "trip, entropy/correlation/NPCR/UACI/chi-square/monobit, histograms, "
        "and an adjacent-pixel correlation figure. Original paper images are "
        "not redistributed — see data/README.md.",
        cells,
    )


def nb3():
    cells = [
        markdown("## 1 — Binary experiment via the packaged runner"),
        code(
            "from aghc_s128.experiments import load_config, run_binary_experiments\n"
            "config = load_config('configs/binary_experiments.yaml')\n"
            "config['password'] = 'aghc-s128-demo'  # public test vector\n"
            "payload = run_binary_experiments(config)\n"
            "print('round trips ok:', sum(r['round_trip_ok'] for r in payload['runs']),\n"
            "      '/', len(payload['runs']))\n"
            "print('outputs:', payload['outputs'])"
        ),
        markdown("## 2 — Metrics table"),
        code(
            "rows = [{'input': r['input'], **r['metrics']} for r in payload['runs']]\n"
            "try:\n"
            "    import pandas as pd  # optional dependency, pretty display only\n"
            "    display(pd.DataFrame(rows))\n"
            "except ImportError:\n"
            "    for row in rows:\n"
            "        print(row)"
        ),
        markdown("## 3 — Integrity check (SHA3-256 round trip)"),
        code(
            "for run in payload['runs']:\n"
            "    print(run['input'], '->', 'OK' if run['round_trip_ok'] else 'FAILED')"
        ),
    ]
    return build_notebook(
        "AGHC-S128 — 03 Binary Security Analysis (statistical evaluation)",
        "Mode A statistical evaluation over arbitrary binary files (text, "
        "binaries, documents): same metrics, histograms, and SHA3-256 "
        "integrity verification as the CLI/scripts.",
        cells,
    )


def nb4():
    cells = [
        markdown("## 1 — Mode B: key sensitivity (two passwords, one plaintext)"),
        code(
            "from aghc_s128.experiments import load_config, run_key_sensitivity\n"
            "config = load_config('configs/key_sensitivity.yaml')\n"
            "config['password_a'] = 'aghc-s128-demo-key-A'  # public test vectors\n"
            "config['password_b'] = 'aghc-s128-demo-key-B'\n"
            "payload = run_key_sensitivity(config)\n"
            "for key, value in payload['metrics'].items():\n"
            "    print(f'{key:40s} {value:.4f}')\n"
            "print('figure:', payload['outputs']['figure'])"
        ),
        markdown("Interpretation note: high key sensitivity / NPCR / bit difference "
                 "indicate the two ciphertexts differ; they are statistical "
                 "observations, not a security proof."),
        markdown("## 2 — Mode C: password key-space estimation"),
        code(
            "from aghc_s128.experiments import keyspace_analysis\n"
            "result = keyspace_analysis(password_length=16, charset_size=95)\n"
            "print('keyspace     :', result['keyspace_scientific'])\n"
            "print('entropy bits :', round(result['password_entropy_bits'], 2))\n"
            "print('classification:', result['password_entropy_classification'])\n"
            "print()\n"
            "print(result['caveat'])"
        ),
    ]
    return build_notebook(
        "AGHC-S128 — 04 Key Sensitivity & Key Space",
        "Mode B (ciphertext-A vs ciphertext-B under different passwords) and "
        "MODE C (password key-space / brute-force time estimation, with the "
        "32-bit seed caveat).",
        cells,
    )


def main() -> None:
    for name, notebook in (
        ("01_quick_reproduction.ipynb", nb1()),
        ("02_image_security_analysis.ipynb", nb2()),
        ("03_binary_security_analysis.ipynb", nb3()),
        ("04_key_sensitivity_and_keyspace.ipynb", nb4()),
    ):
        target = HERE / name
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(notebook, handle, indent=1)
            handle.write("\n")
        print(f"wrote {target}")


if __name__ == "__main__":
    main()
