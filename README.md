# FABS: Fast Attribute-Based Signatures

This repository contains the Python artifact for the paper  
**“FABS: Fast Attribute-Based Signatures”** (USENIX Security 2026).

The paper proposes highly efficient Attribute-Based Signature (ABS) schemes
supporting **Monotone Span Program (MSP)** policies. The proposed constructions
achieve **linear-time key generation and signing**, and require only **two
pairing operations in verification**, which is the best known efficiency among
MSP-based ABS schemes. Our schemes are built on **Type-III pairings**, support
**large universes**, **arbitrary attributes**, and **adaptive unforgeability**.
To the best of our knowledge, this is the **first open-source implementation**
of MSP-based ABS schemes.

In addition to our proposed **KP-ABS** and **SP-ABS** schemes, this artifact also
includes implementations of two representative prior works for comparison:
- **RD16**: Large-universe KP-ABS [1]
- **KCGD14**: ABS with user-controlled linkability [2]

---

## 1. Environment and Dependencies

### Platform
- Ubuntu 22.04
- Python 3.9.16

### Cryptographic Library
This project depends on the **Charm-Crypto library** (version 0.50).

> **Note:** Charm relies on native cryptographic libraries (e.g., GMP, PBC,
> OpenSSL) and may not compile on newer Linux systems due to OpenSSL version
> incompatibilities. We recommend Ubuntu 20.04 / 22.04 with Python 3.9.

---

## 2. Installing Charm-Crypto

Charm is an external dependency and is **not included** in this repository.

### Option 1: Install from the official Charm repository (recommended)

Clone Charm and check out version 0.50:

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
git checkout 0.50
