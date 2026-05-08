---
title: "Post-Quantum Cryptography Preview — Why the Algorithms Change"
tags: [cryptography, post-quantum, PQC, lattice, LWE, CRYSTALS, Kyber,
  Dilithium, NIST, quantum-threat, Shor, module-09-crypto-02]
module: 09-Crypto-02
day: 606
prerequisites:
  - Day 586 — Lattice Basics (SVP, CVP)
  - Day 587 — LLL Algorithm
  - Day 593 — Hidden Number Problem (ECDSA lattice attacks)
related_topics:
  - LWE-based Crypto (Day 607)
  - Crypto Catch-Up (Day 609)
  - Crypto Competency Check (Day 610)
---

# Day 606 — Post-Quantum Cryptography Preview

> "Shor's algorithm runs in polynomial time on a quantum computer and factors
> integers. That kills RSA. It also computes discrete logs — that kills DH
> and ECDH. Every public-key scheme we have used for 40 years falls in one
> algorithm. The good news: lattice-based schemes survive. The bad news: you
> need to understand why, because the attacks you just learned DO NOT work
> against properly parameterised lattice schemes. Today you learn the difference
> between 'vulnerable lattice' and 'safe lattice'."
>
> — Ghost

---

## Goals

Understand the quantum threat to classical cryptography (Shor's algorithm),
survey the NIST PQC standardised schemes, and grasp why LWE-based schemes
are secure against the lattice attacks from Days 586–605.

**Prerequisites:** Days 586–587 (lattice basics, LLL).
**Estimated study time:** 3–4 hours (conceptual — no labs today).

---

## Stage 1 — The Quantum Threat

### Shor's Algorithm (1994)

Peter Shor showed that a quantum computer can:
- **Factor integers** in `O((log N)^3)` — polynomial time
- **Compute discrete logarithms** in `O((log p)^3)`

**What breaks:**

| System | Classical Security | Quantum Security |
|---|---|---|
| RSA-2048 | ~112 bits | 0 (Shor factors N) |
| ECDH-256 | ~128 bits | 0 (Shor solves DLP) |
| ECDSA-256 | ~128 bits | 0 (Shor solves DLP) |
| DH-3072 | ~128 bits | 0 (Shor solves DLP) |
| AES-128 | 128 bits | ~64 bits (Grover's √ speedup) |
| AES-256 | 256 bits | ~128 bits (Grover) — still safe |
| SHA-256 | 128-bit collision | ~85 bits (Grover on preimage) |

**Timeline:** Current estimates put a cryptographically relevant quantum
computer (CRQC) at 10–15 years away. **Harvest now, decrypt later** attacks
are happening today: adversaries store encrypted traffic expecting to decrypt
it post-CRQC.

### Grover's Algorithm (1996)

Grover's algorithm gives a quadratic speedup for unstructured search:
brute-force over `N` items in `O(√N)` quantum steps. Impact:

- AES-128 → 64-bit effective security (double key sizes)
- SHA-256 → use only for collision resistance (still 128-bit quantum)
- Hash preimage: SHA-256 weakened to 128-bit preimage resistance

**Mitigation:** Double symmetric key sizes (AES-256 instead of AES-128).
Hash functions are largely unaffected for collision resistance.

---

## Stage 2 — NIST PQC Standards (2024)

After a 6-year competition (2016–2022), NIST finalised post-quantum standards:

### FIPS 203 — ML-KEM (Kyber)

**Purpose:** Key Encapsulation Mechanism (replaces RSA/ECDH for key exchange)
**Hard problem:** Module Learning With Errors (Module-LWE)
**Security levels:** ML-KEM-512 (128-bit), ML-KEM-768 (192-bit), ML-KEM-1024 (256-bit)

### FIPS 204 — ML-DSA (Dilithium)

**Purpose:** Digital signatures (replaces ECDSA/RSA for signing)
**Hard problem:** Module Learning With Errors + Module Short Integer Solution
**Variants:** ML-DSA-44 (128-bit), ML-DSA-65 (192-bit), ML-DSA-87 (256-bit)

### FIPS 205 — SLH-DSA (SPHINCS+)

**Purpose:** Hash-based digital signatures (stateless)
**Hard problem:** One-way hash functions (no lattices — different approach)
**Note:** Conservative choice; large signature sizes (~8–50 KB)

### FIPS 206 — FN-DSA (FALCON)

**Purpose:** Compact digital signatures
**Hard problem:** NTRU lattice (hash-to-Gaussian sampling)
**Note:** Smaller signatures than Dilithium but more complex implementation

---

## Stage 3 — Why LWE Is Hard (vs. Why LLL Fails)

### Learning With Errors (LWE)

LWE (Regev 2005) is defined as follows:

Given `n` equations over `Z_q`:
```
b_i = <a_i, s> + e_i   (mod q)
```
where `s ∈ Z_q^n` is a secret vector, `a_i` are random public vectors,
and `e_i` are small "error" terms drawn from a Gaussian distribution with
small standard deviation σ.

**The hard problem:** Given many (a_i, b_i) pairs, recover `s`.

### Why LLL Fails on LWE

Compare LWE to the lattice attacks from Days 586–605:

| Property | Merkle-Hellman / HNP (broken) | LWE (safe) |
|---|---|---|
| Dimension n | 25–100 | 256–1024+ |
| Secret structure | Short vector in Z^n | Short but NOISY |
| Noise | None | Gaussian error ~ σ = √n |
| Short vector ratio | λ_1 / λ_2 ≪ 1 (exploitable gap) | No gap (Gaussian heuristic tight) |
| LLL success? | Yes (n ≤ 150) | No (n ≥ 256 effectively) |

**The key insight:** In LWE, the error term `e_i` prevents the direct lattice
embedding that makes Merkle-Hellman, HNP, and Coppersmith work. The secret
IS a short vector, but the noise prevents distinguishing it from random
vectors without exponential effort.

```python
#!/usr/bin/env python3
"""
LWE sample generation — illustrating why the problem is hard.
Even with 1000 samples and n=256, recovering s is infeasible classically.
"""
from __future__ import annotations
import random
import math


def sample_lwe(n: int, q: int, sigma: float, n_samples: int) -> dict:
    """
    Generate LWE samples: (A, b) where b = A*s + e mod q.
    Returns: secret s, samples A (matrix), b (vector).
    """
    rng = random.SystemRandom()

    # Secret vector s ∈ Z_q^n (small entries for "binary" or "ternary" LWE)
    s = [rng.randint(0, 1) for _ in range(n)]   # Binary secret

    # Generate samples
    A = [[rng.randint(0, q - 1) for _ in range(n)]
         for _ in range(n_samples)]

    # Error terms: Gaussian with std dev sigma, rounded to int
    def gaussian_sample() -> int:
        e = round(random.gauss(0, sigma))
        return e % q

    b = [(sum(A[i][j] * s[j] for j in range(n)) + gaussian_sample()) % q
         for i in range(n_samples)]

    return {"s": s, "A": A, "b": b, "n": n, "q": q, "sigma": sigma}


# Demo: show that even a 64-dim LWE instance looks random
params = sample_lwe(n=64, q=3329, sigma=3.2, n_samples=100)
print(f"[*] n={params['n']}, q={params['q']}, σ={params['sigma']}")
print(f"[*] Secret s[:8]:  {params['s'][:8]}")
print(f"[*] First row A:   {params['A'][0][:8]}...")
print(f"[*] First b value: {params['b'][0]}")
print(f"\n[*] Without knowing s, b appears uniformly random over Z_{params['q']}")
print(f"[*] This is the LWE hardness assumption.")
print(f"\n[*] Kyber-768 uses n=256, q=3329, 3 polynomial rings → 768 total dimensions")
print(f"[*] LLL on 768-dim lattice: impractical. BKZ-400: state of the art, still 2^100+ work")
```

---

## Stage 4 — Hybrid PQC Deployment

The current standard practice during the transition period:

```
TLS 1.3 + Hybrid PQC:
  Key Exchange = X25519 (classical) + ML-KEM-768 (post-quantum)
  → If either is broken, the session is still secure

Why hybrid?
  - Classical: quantum computer doesn't exist yet
  - PQ: new algorithms may have undiscovered weaknesses
  - Belt AND suspenders during the transition
```

**Already deployed:**
- Google Chrome: X25519Kyber768 (2023)
- Cloudflare: ML-KEM in TLS 1.3 (2024)
- Signal: PQXDH (post-quantum X3DH) (2023)

---

## Attacker Perspective: What Still Works vs. What Does Not

| Attack | Against Classical | Against PQC |
|---|---|---|
| RSA padding oracle | ✓ | N/A (no RSA) |
| ECDSA nonce bias (HNP) | ✓ | N/A (Dilithium doesn't use nonces) |
| LLL on Merkle-Hellman | ✓ | ✗ (dimension too large) |
| Implementation bugs (DFA, timing) | ✓ | ✓ Still applies |
| Key confusion / protocol bugs | ✓ | ✓ Still applies |
| Side-channel on Gaussian sampling | N/A | ✓ New attack surface |
| Invalid ciphertext decryption oracle | ✓ | ✓ LWE decryption oracles exist |

**The most important insight for attackers:** Post-quantum schemes have new
attack surfaces. Gaussian sampling side-channels, decryption failure oracles,
and implementation bugs in polynomial arithmetic are the new battleground.

---

## Key Takeaways

1. **Shor's algorithm breaks RSA and ECDSA, not AES.** Symmetric crypto needs
   only key doubling (AES-256). All public-key crypto needs to be replaced.
2. **LWE security rests on the same lattice math you studied** — but at
   dimensions where LLL fails (n ≥ 256) and with deliberate noise that prevents
   the embeddings you used for HNP and Coppersmith.
3. **NIST has standardised four PQC algorithms.** ML-KEM (Kyber) replaces ECDH.
   ML-DSA (Dilithium) replaces ECDSA. Both are lattice-based. Know their names.
4. **The transition is happening NOW.** Browser TLS already uses hybrid PQC.
   If you work on cryptographic systems, PQC migration is an active engineering
   problem — not a future concern.

---

## Exercises

```
1. Shor's algorithm requires ~4000 stable logical qubits to factor RSA-2048.
   Current record: ~1000 physical qubits (noisy). Research: what is the
   estimated ratio of physical-to-logical qubits needed? When might RSA-2048
   be at risk?

2. ML-KEM-768 uses 3 polynomial rings of dimension 256 over Z_3329.
   Compute the total "effective" lattice dimension and compare to the LLL
   threshold where attacks become impractical.

3. The LWE sample generator above uses binary secrets (s_i ∈ {0,1}).
   Some LWE variants use ternary secrets (s_i ∈ {-1, 0, 1}). Does this
   change the security analysis significantly? Research Module-LWE vs LWE.

4. Write a migration plan for a hypothetical web application currently using
   RSA-2048 for signatures and ECDH-256 for key exchange. List:
   - Which FIPS standards to adopt
   - Migration timeline
   - Hybrid approach during transition
   - Backward compatibility concerns
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q606.1, Q606.2 …).

---

## Navigation

← Previous: [Day 605 — Crypto CTF Sprint Day 8](DAY-0605-Crypto-CTF-Sprint-Day-8.md)
→ Next: [Day 607 — LWE and Kyber Internals](DAY-0607-LWE-Kyber-Internals.md)
