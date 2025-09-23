This is the code for the paper "FABS: Fast Attribute-Based Signatures".

This paper proposes fast ABS schemes that supports Monotone Span Programs (MSP) type of policies. They achieve the best computational efficiency among MSP-based ABS schemes. In specific, the proposed ABS schemes acheive linear-time key generation, signing, and verification, and only requires 2 pairings in verification. Apart from this, our schemes are constructed on Type-III pairings, they support large universes, arbitrary attributes, and adaptive unforgeability. This is the first open-source implementation in the MSP-based ABS field.

The code uses the Charm library in Python. In addition to our ABS schemes, we also implement the large universe KP-ABS scheme in RD16[1] and KCGD14[2] as a comparison.

The schemes have been tested with Charm 0.50 and Python 3.9.16 on Ubuntu 22.04. (Note that Charm may not compile on newer Linux systems due to the incompatibility of OpenSSL versions 1.0 and 1.1.).

Manual Installation
Charm 0.50 can also be installed directly from [this] (https://github.com/JHUISI/charm) page, or by running

pip install -r requirements.txt
Once you have Charm, run

make && pip install . && python samples/run_cp_schemes.py


[1] Rao Y S, Dutta R. Efficient attribute-based signature and signcryption realizing expressive access structures. International Journal of Information Security, 2016 81-109.
[2] Ali El Kaafarani, Liqun Chen, Essam Ghadafi & James Davenport. Attribute-Based Signatures with User-Controlled Linkability. International Conference on Cryptology and Network Security, 2014, 256-269.
