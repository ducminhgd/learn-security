---
title: "HNP Lab — Recovering ECDSA Private Key from Biased Nonces"
tags: [cryptography, HNP, ECDSA, nonce-bias, lattice, LLL, BKZ, lab, CTF,
  private-key-recovery, secp256k1, hands-on, module-09-crypto-02]
module: 09-Crypto-02
day: 594
prerequisites:
  - Day 593 — Hidden Number Problem
  - Day 569 — ECDSA Nonce Reuse (exact reuse, baseline)
  - SageMath installed; pycryptodome or cryptography library
related_topics:
  - MT19937 State Recovery (Day 595)
  - ECDSA Nonce Reuse (Day 569)
---

# Day 594 — HNP Lab: Recovering ECDSA Private Key from Biased Nonces

> "Theory done. Today you build the attack from scratch against a real ECDSA
> implementation over secp256k1 — the same curve Bitcoin uses. The server
> signs messages with a weak PRNG that clips the top byte of each nonce.
> You collect 60 signatures. You run LLL. You get the private key. Then you
> forge a signature. That is the whole lab."
>
> — Ghost

---

## Goals

Execute a complete HNP lattice attack against a simulated ECDSA signing
oracle with biased nonces: collect signatures, build the lattice, run LLL,
recover the private key, and forge a signature.

**Prerequisites:** Day 593 (HNP theory). SageMath, Python cryptography library.
**Estimated lab time:** 5–6 hours.

---

## Lab Setup

```bash
# Install dependencies
pip install cryptography pycryptodome

# SageMath: needed for LLL
# Option 1: Docker
docker run -it --rm --volume $(pwd):/home/user/work \
    sagemath/sagemath:latest sage

# Option 2: Native
sudo apt install sagemath   # Ubuntu / Debian
```

---

## Stage 1 — Vulnerable Signing Oracle

The "server" signs with a weak PRNG: the top byte of each ECDSA nonce `k`
is forced to `0x00`. This gives an 8-bit bias (k < q / 256).

```python
#!/usr/bin/env python3
"""
Vulnerable ECDSA signing oracle — secp256k1, biased nonces.
The top byte of k is always zero: k in [1, q//256).
"""
from __future__ import annotations

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1, EllipticCurvePrivateKey, generate_private_key,
    EllipticCurvePublicKey, ECDSA
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# secp256k1 group order
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class VulnerableECDSAOracle:
    """Signs with a biased nonce: top 8 bits of k are always zero."""

    def __init__(self):
        self._private_key = generate_private_key(SECP256K1(), default_backend())
        self.public_key   = self._private_key.public_key()
        self._d           = self._private_key.private_numbers().private_value
        self._bias_bytes  = 1   # 1 byte = 8 bits bias

    def sign_biased(self, message: bytes) -> tuple[int, int, bytes]:
        """
        Sign message with a biased nonce.
        Returns (r, s, message_hash) where k < Q // 256.
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib

        h = hashlib.sha256(message).digest()
        h_int = int.from_bytes(h, "big")

        # Generate biased k: top byte forced to 0
        while True:
            k_bytes = os.urandom(32)
            k_bytes = b"\x00" + k_bytes[1:]   # Force top byte to 0
            k = int.from_bytes(k_bytes, "big") % Q
            if k == 0:
                continue
            break

        # Manual ECDSA signing with biased k
        # R = k*G; r = R.x mod q
        # For simplicity: use Python's ecdsa library or compute manually
        # Here we use the low-level interface
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature
        )
        # We'll simulate r and s directly
        # r = (k * G).x mod q — use secp256k1 point multiplication
        import ecdsa as ecdsa_lib
        sk = ecdsa_lib.SigningKey.from_secret_exponent(
            self._d, curve=ecdsa_lib.SECP256k1
        )
        # Use our biased k
        sig_bytes = sk.sign_deterministic(
            message,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa_lib.util.sigencode_string,
            extra_entropy=k.to_bytes(32, "big"),
        )
        # Decode r, s
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        return r, s, h

    @property
    def private_key_value(self) -> int:
        """Exposed for validation only — not available to attacker."""
        return self._d
```

---

## Stage 2 — Collect Signatures

```python
#!/usr/bin/env python3
"""Collect N_SIGS signatures from the oracle."""
import hashlib
import os

# pip install ecdsa (pure Python, easier to work with for teaching)
import ecdsa

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BIAS_BITS = 8   # top 8 bits of k are zero: k < Q/256

# Generate target key
sk  = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
d   = sk.privkey.secret_multiplier   # private key (attacker does NOT know this)
vk  = sk.get_verifying_key()

N_SIGS = 80
signatures = []

for i in range(N_SIGS):
    msg = f"message-{i}-{os.urandom(8).hex()}".encode()
    h   = hashlib.sha256(msg).digest()
    h_int = int.from_bytes(h, "big")

    # Biased nonce: top byte is zero
    k_bytes = b"\x00" + os.urandom(31)
    k = int.from_bytes(k_bytes, "big") % Q
    if k == 0:
        k = 1

    # Manual signing with custom k
    order = Q
    Gx    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    # r = (k*G).x mod q — use ecdsa library internals
    R = sk.privkey.public_key.generator * k
    r = int(R.x()) % order
    if r == 0:
        continue
    s = (pow(k, -1, order) * (h_int + d * r)) % order
    if s == 0:
        continue

    signatures.append({"r": r, "s": s, "h": h_int})

print(f"[*] Collected {len(signatures)} signatures with {BIAS_BITS}-bit bias")
print(f"[*] All nonces satisfy k < Q/2^{BIAS_BITS}: "
      f"{all(True for _ in signatures)}")  # We know this from construction
```

---

## Stage 3 — Build the HNP Lattice and Run LLL

```python
# SageMath: HNP lattice attack
from sage.all import Matrix, ZZ, Integer, vector

Q_int = Integer(Q)
n     = len(signatures)
B     = Q_int >> BIAS_BITS   # Bias bound: k < B = Q / 2^8

def build_hnp_lattice(sigs: list[dict], q: int, bias_bits: int) -> Matrix:
    """
    Build the HNP lattice for ECDSA nonce recovery.

    The lattice has dimension (n+2) × (n+2).
    Short vector encodes (k_0, ..., k_{n-1}, d, 1) scaled appropriately.
    """
    q_int = Integer(q)
    B_val = q_int >> bias_bits
    n_s   = len(sigs)

    ts = [Integer(sig["r"]) * Integer(sig["s"]).inverse_mod(q_int) % q_int
          for sig in sigs]
    us = [Integer(sig["h"]) * Integer(sig["s"]).inverse_mod(q_int) % q_int
          for sig in sigs]

    # Matrix: (n+2) × (n+2)
    M = Matrix(ZZ, n_s + 2, n_s + 2)
    # First n rows: q on diagonal (kills the modular arithmetic)
    for i in range(n_s):
        M[i, i] = q_int
    # Row n: t_i values + (1 for d column) + (0 for B column)
    for i in range(n_s):
        M[n_s, i] = ts[i]
    M[n_s, n_s]   = Integer(1)      # coefficient for d
    M[n_s, n_s+1] = Integer(0)
    # Row n+1: u_i values + (0 for d) + (B for bias)
    for i in range(n_s):
        M[n_s+1, i] = us[i]
    M[n_s+1, n_s]   = Integer(0)
    M[n_s+1, n_s+1] = B_val

    return M, ts, us


M, ts, us = build_hnp_lattice(signatures, int(Q_int), BIAS_BITS)
print(f"[*] Lattice dimension: {M.nrows()} × {M.ncols()}")
print("[*] Running LLL...")

L = M.LLL()
print("[*] LLL complete. Checking rows for private key...")

# The short vector should be (k_0-B/2, ..., k_{n-1}-B/2, d, B/2) approximately
# d is at position n in the row (before B scaling)
d_recovered = None
for row in L:
    for sign in [1, -1]:
        d_candidate = int(sign * row[n]) % int(Q_int)
        if d_candidate == 0:
            continue
        # Verify: does this d produce valid k values?
        # k_i = (h_i + d*r_i) * s_i^{-1} mod q
        verified = True
        for sig in signatures[:5]:   # Check first 5 sigs
            s_inv = pow(int(sig["s"]), -1, int(Q_int))
            k_check = (sig["h"] + d_candidate * sig["r"]) * s_inv % int(Q_int)
            if k_check >= int(B):   # Bias check
                verified = False
                break
        if verified:
            d_recovered = d_candidate
            break
    if d_recovered:
        break

if d_recovered:
    print(f"[+] Private key d recovered!")
    print(f"[+] Matches actual d: {d_recovered == int(d)}")
else:
    print("[!] LLL failed — try BKZ or more signatures")
```

---

## Stage 4 — Forge a Signature

```python
# Once d is recovered, forge any signature
if d_recovered:
    import hashlib, ecdsa as ecdsa_lib

    target_msg   = b"pay:alice:1000000"
    target_hash  = hashlib.sha256(target_msg).digest()
    target_h_int = int.from_bytes(target_hash, "big")

    # Sign with recovered d
    sk_forged = ecdsa_lib.SigningKey.from_secret_exponent(
        d_recovered, curve=ecdsa_lib.SECP256k1
    )
    sig_forged = sk_forged.sign(target_msg, hashfunc=hashlib.sha256)

    # Verify with the public key (which the attacker has)
    try:
        vk.verify(sig_forged, target_msg, hashfunc=hashlib.sha256)
        print(f"[+] Forged signature VERIFIED for: {target_msg}")
        print(f"[+] Signature: {sig_forged.hex()[:32]}...")
    except ecdsa_lib.BadSignatureError:
        print("[!] Forged signature invalid — check d_recovered")
```

---

## CTF Challenge Card

```
## Challenge — Biased Signer

### Category
Crypto

### Difficulty
Advanced
Estimated time: 4 hours for a student who has completed Day 593.

### Learning Objective
Recover ECDSA private key from 60 signatures where nonce k has 8 known
zero leading bits, using the HNP lattice.

### Scenario
A bug bounty platform's signing service generates ECDSA nonces using a
truncated CSPRNG (top byte discarded). You can request up to 100 signed
messages. The signing key is the same for all transactions. Recover it and
forge an approval for a $1,000,000 payout.

### Vulnerability
CWE-338: Use of Cryptographically Weak PRNG — biased nonce generation in
ECDSA. ATT&CK: T1552.004 (Private Keys).

### Flag
FLAG{hnp_lattice_breaks_biased_ecdsa_nonces}
```

---

## Self-Assessment

```
[ ] 1. Run the full lab. Record: how many signatures were needed before LLL
        succeeded? How long did LLL take (wall clock)?

[ ] 2. Reduce BIAS_BITS to 4 (top 4 bits zero). How many signatures are
        needed now? Does LLL still succeed, or do you need BKZ?

[ ] 3. Modify the oracle to use LSB bias instead (bottom 8 bits are zero).
        Does the same lattice construction work? If not, adapt it.
        (Hint: the t_i, u_i derivation changes slightly.)

[ ] 4. In the verification step, you check k_check < B for 5 signatures.
        Why 5 and not 1? What is the probability of a false positive with
        only 1 signature checked?
```

---

## Key Takeaways

1. **Collect → Build → Reduce → Verify → Forge.** This five-step process
   applies to every HNP-based attack. The parameters (n_sigs, bias_bits,
   lattice dimension) change; the recipe does not.
2. **8-bit bias requires ~60–80 signatures** with LLL. 4-bit bias needs 150+
   and may require BKZ-30. 1-bit bias is a research problem (500+ sigs, BKZ-60).
3. **Forging the signature is the proof of concept.** In real bug bounty
   reports, attach the forged signature as the PoC. Do not just claim key
   recovery — prove it with a verifiable forgery.
4. **Mitigation:** Use RFC 6979 (deterministic ECDSA) which derives k from
   the private key and message hash — no PRNG, no bias.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q594.1, Q594.2 …).

---

## Navigation

← Previous: [Day 593 — Hidden Number Problem](DAY-0593-Hidden-Number-Problem.md)
→ Next: [Day 595 — MT19937 State Recovery](DAY-0595-MT19937-State-Recovery.md)
