# Security Scope and Limitations

## What this is

AGHC-S128 (Adaptive Graph Hill Cipher with Shift-128 Residual Processing) is
a **research prototype** cipher described in an academic paper and originally
implemented in a Google Colab notebook.  This repository is a
**reproducibility artifact**: it re-implements the baseline algorithm
faithfully, with tests, metadata, and experiment pipelines.

**Do not use this implementation to protect production data, personal data,
secrets, or anything of value.**  Use standard, peer-reviewed cryptography
(AES-GCM, ChaCha20-Poly1305, age, GPG, etc.) instead.

## What the metrics are — and are not

The analyses in `aghc_s128.metrics` (Shannon entropy, adjacent-byte
correlation, NPCR, UACI, bit-difference ratio, chi-square, monobit
frequency) are **statistical evaluations** of ciphertext byte distributions.

Good-looking values (entropy ≈ 8, correlation ≈ 0, NPCR ≈ 99.6%, UACI ≈ 33%,
chi-square p > 0.05) indicate the output *resembles* uniform noise.  They do
**not** constitute a security proof and specifically say nothing definitive
about resistance to:

* **known-plaintext / chosen-plaintext attacks** — the Hill stage is linear
  modulo 256: with `N` known plaintext/ciphertext block pairs an attacker can
  solve for the key matrix (classic Hill-cipher cryptanalysis applies);
* **structural cryptanalysis** of the key schedule (SHA-256 → 32-bit seed →
  Mersenne-Twister perturbation + logistic-map chaos; see KNOWN_ISSUES K-3,
  K-4, K-6);
* **brute force over the effective key space** — bounded by the 32-bit seed
  reduction, not by password length (KNOWN_ISSUES K-3);
* **side-channel attacks** (timing, cache, power), which were never
  evaluated;
* **implementation-level attacks** (fault injection, buffer handling in
  downstream consumers).

## Residual Shift-128 transform

The trailing `size % N` bytes are "encrypted" with `(b + 128) mod 256` — a
constant, key-independent, self-inverse transform.  It is part of the
baseline algorithm and is reproduced faithfully, but it offers **no
cryptographic protection by itself**.  Files smaller than `N` bytes are
transformed *only* by it and are trivially recoverable without any key.

## Integrity hashing

SHA3-256 round-trip checks verify *reproduction fidelity* (decrypt(encrypt(x))
== x).  They are not a MAC: an attacker who can modify both the ciphertext
and the sidecar can forge "valid" metadata.  MD5 appears only as a deprecated
legacy helper for compatibility with the original notebook.

## Terminology policy for this repository

Avoid: "secure", "provably secure", "Q1-ready", "resistant to attacks",
"cryptographically proven" — when describing results of these statistical
tests.

Prefer: "statistical evaluation", "reproducibility implementation",
"baseline algorithm", "research prototype".

## If you still want to study it

This code is well-suited for: classroom exploration of Hill-cipher variants,
reproduction of the paper's statistical tables, and cryptanalysis research
(e.g., demonstrating the linear known-plaintext weakness empirically).  Any
such findings should be reported as research results, not as reasons to
deploy the cipher.
