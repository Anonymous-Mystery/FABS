# FABS: Fast Attribute-Based Signatures

This repository contains the Python artifact for the paper  **“FABS: Fast Attribute-Based Signatures”** (USENIX Security 2026).

The paper proposes highly efficient Attribute-Based Signature (ABS) schemes supporting Monotone Span Program (MSP) policies. The proposed constructions
achieve linear-time key generation and signing, and require only two pairing operations for verification, which is the best known efficiency among
MSP-based ABS schemes. Our schemes are built on Type-III pairings, support large universes, arbitrary attributes, and adaptive unforgeability.
To the best of our knowledge, this is the first open-source implementation of MSP-based ABS schemes.

In addition to our proposed KP-ABS and SP-ABS schemes, this artifact also includes implementations of two representative prior works for comparison:
- RD16: Large-universe KP-ABS [1]
- KCGD14: ABS with user-controlled linkability [2]


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

Charm is an external dependency and **not included** in this repository.

### Option 1: Install from the official Charm repository (recommended)

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
git checkout 0.50
Create and activate a virtual environment (recommended for reproducibility):

bash
python3 -m venv charm-env
source charm-env/bin/activate
Install Charm:

bash
pip install .
You can verify the installation by running:

bash
python -c "from charm.toolbox.pairinggroup import PairingGroup; print('Charm installed')"
3. Running the FABS Artifact
After Charm is installed and the virtual environment is activated, return to
the FABS project directory.

3.1 Functional Correctness Test
To test the correctness of all four ABS schemes (our KP-ABS, our SP-ABS, RD16,
and KCGD14), run:

bash
python Run.py
This script:

Executes Setup, KeyGen, Signing, and Verification for each scheme

Prints whether each generated signature verifies successfully

This demonstrates the functional correctness of the implementations.

3.2 Performance Benchmarking
To measure the runtime performance of the schemes, run:

bash
python Measurements.py
This script benchmarks the four schemes across the following algorithms: Setup, Key Generation, Signing, Verification

The results are printed to the console and correspond to the performance claims made in the paper.

Switching Between KP-ABS and SP-ABS Experiments
At the end of Measurements.py, the main benchmarking loop contains:

python
for policy_size in policy_sizes:
    for attr_size in attr_sizes:
        policy_str, attr_list = create_policy_string_and_attribute_list(
            attr_size, policy_size
        )
        # run_kp(pairing_group, len(attr_list) + 1, attr_list, policy_str, msg)
        run_sp(pairing_group, attr_universe, attr_list, policy_str, msg)

To benchmark both KP-ABS and SP-ABS, uncomment run_kp(...)
To benchmark only KP-ABS, uncomment run_kp(...) and comment out run_sp(...)
To benchmark only SP-ABS, keep the code as-is
This allows direct performance comparison between KP and SP settings.

4. Code Structure
Run.py
Functional test script for correctness verification

Measurements.py
Benchmarking script for runtime measurements

Scheme implementation files
Contain the implementations of our ABS schemes and prior work baselines

Inline comments and function definitions in the scripts explain the purpose of
each component and algorithmic step.

5. References
[1] Y. S. Rao and R. Dutta,
Efficient Attribute-Based Signature and Signcryption Realizing Expressive Access Structures, International Journal of Information Security, 2016.
[2] A. El Kaafarani, L. Chen, E. Ghadafi, J. Davenport, Attribute-Based Signatures with User-Controlled Linkability, ACNS 2014.
