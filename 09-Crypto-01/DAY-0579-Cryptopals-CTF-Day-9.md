---
title: "Cryptopals CTF Practice — Day 9: Set 6 Part 4 (Bleichenbacher PKCS#1 v1.5)"
tags: [cryptography, cryptopals, CTF, RSA, bleichenbacher, PKCS1-v1.5,
  padding-oracle, interval-arithmetic, adaptive-chosen-ciphertext, set-6,
  challenge-47, challenge-48, CWE-310]
module: 09-Crypto-01
day: 579
prerequisites:
  - Day 578 — Cryptopals CTF Day 8 (DSA tampering, RSA parity oracle)
  - Day 561 — CBC Padding Oracle (same oracle pattern, different cipher)
related_topics:
  - Cryptopals CTF Day 10 (Day 580)
  - CBC Padding Oracle (Day 561)
---

# Day 579 — Cryptopals CTF Practice: Day 9

> "Bleichenbacher's 1998 paper is a masterclass in how to extract a full secret
> from an oracle that leaks one bit: conformant or not. The CBC padding oracle
> from Day 561 is the same idea in a symmetric cipher. If you understood that
> one, this one will click. If you didn't, today is the day you understand both."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 6 Challenges 47 and 48: the Bleichenbacher
PKCS#1 v1.5 RSA padding oracle attack. Challenge 47 is the simplified
version (single interval, small key). Challenge 48 is the complete
attack with interval arithmetic for a 768-bit key.

**Prerequisites:** Challenges 41–46 complete; Day 561 (CBC padding oracle —
the same "oracle narrows an interval" pattern).
**Estimated lab time:** 6 hours.
**Resource:** https://cryptopals.com/sets/6

---

## Background: PKCS#1 v1.5 Encryption Padding

RSA-PKCS#1 v1.5 encryption pads the message `m` as:

```
0x 00 02 [8+ random non-zero bytes] 00 [message bytes]
```

The resulting block has exactly `k` bytes (the key size in bytes).

An oracle that tells you whether a ciphertext decrypts to a block starting
with `0x00 02` gives you a single bit per query. Bleichenbacher showed in
1998 that this is enough to decrypt any ciphertext in `~2^20` queries.

**Formal statement:** Let `B = 2^(8(k-2))`. A PKCS-conformant ciphertext `c`
decrypts to a plaintext `m ∈ [2B, 3B-1]`. The attack maintains a set of
intervals `M` and narrows it by finding blinding factors `s` such that
`c · s^e mod n` is also conformant.

---

## Challenge 47 — Bleichenbacher (Simplified, Single Interval)

The simplified version assumes the initial ciphertext is already conformant
(guaranteed by the way we construct the oracle), and that the interval set
remains a single interval throughout. This holds for small keys (256 bits).

```python
#!/usr/bin/env python3
"""
Challenge 47: Bleichenbacher PKCS#1 v1.5 padding oracle, simplified version.
Single interval; works with 256-bit RSA keys.
"""
from __future__ import annotations

import math
import os
from typing import NamedTuple

import gmpy2
from Crypto.Util.number import getPrime


# ── Key generation ─────────────────────────────────────────────────────────────

def gen_rsa_pkcs1(bits: int = 256) -> tuple[tuple[int, int], tuple[int, int], int]:
    """Generate RSA keypair. Returns (pub, priv, k) where k is key size in bytes."""
    e = 3
    while True:
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        if p == q:
            continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) == 1:
            d   = int(gmpy2.invert(e, phi))
            k   = (n.bit_length() + 7) // 8
            return (e, n), (d, n), k


# ── PKCS#1 v1.5 padding ────────────────────────────────────────────────────────

def pkcs1_pad(msg: bytes, k: int) -> bytes:
    """Pad message to k bytes using PKCS#1 v1.5 type-2."""
    pad_len = k - len(msg) - 3
    assert pad_len >= 8, "Message too long for key size"
    padding = b""
    while len(padding) < pad_len:
        b = os.urandom(1)
        if b != b"\x00":
            padding += b
    return b"\x00\x02" + padding + b"\x00" + msg


def pkcs1_unpad(block: bytes) -> bytes | None:
    """Remove PKCS#1 v1.5 padding. Returns None if invalid."""
    if len(block) < 11 or block[0:2] != b"\x00\x02":
        return None
    try:
        sep = block.index(b"\x00", 2)
    except ValueError:
        return None
    if sep < 10:   # At least 8 bytes of non-zero padding
        return None
    return block[sep + 1:]


# ── Oracle ─────────────────────────────────────────────────────────────────────

_oracle_calls = 0


def pkcs1_oracle(c: int, priv: tuple[int, int], k: int) -> bool:
    """Return True iff decrypt(c) is PKCS#1 v1.5 conformant."""
    global _oracle_calls
    _oracle_calls += 1
    d, n  = priv
    m     = pow(c, d, n)
    block = m.to_bytes(k, "big")
    return block[0:2] == b"\x00\x02"


# ── Bleichenbacher attack (simplified, single interval) ────────────────────────

def bleichenbacher_simple(c: int, pub: tuple[int, int],
                           oracle_fn, k: int) -> int:
    """
    Simplified Bleichenbacher: assumes single interval and that c is already
    conformant. Narrows the interval until [lo, hi] collapses to the plaintext.
    """
    e, n = pub
    B    = 2 ** (8 * (k - 2))
    B2   = 2 * B
    B3   = 3 * B

    # Step 1: c is already conformant, so initial interval is [2B, 3B-1]
    lo = B2
    hi = B3 - 1
    s  = math.ceil(n / B3)   # Smallest s where c*s^e mod n is conformant

    while lo < hi:
        # Find next s such that c' = c * s^e mod n is conformant
        c_new = (c * pow(s, e, n)) % n
        while not oracle_fn(c_new):
            s     += 1
            c_new = (c * pow(s, e, n)) % n

        # Narrow interval: m ∈ [ceil((2B + r*n)/s), floor((3B-1 + r*n)/s)]
        new_lo, new_hi = None, None
        r_lo = math.ceil((lo * s - B3 + 1) / n)
        r_hi = math.floor((hi * s - B2) / n)
        for r in range(r_lo, r_hi + 1):
            candidate_lo = math.ceil((B2 + r * n) / s)
            candidate_hi = math.floor((B3 - 1 + r * n) / s)
            interval_lo  = max(lo, candidate_lo)
            interval_hi  = min(hi, candidate_hi)
            if interval_lo <= interval_hi:
                if new_lo is None or interval_lo < new_lo:
                    new_lo = interval_lo
                if new_hi is None or interval_hi > new_hi:
                    new_hi = interval_hi

        lo, hi = new_lo, new_hi
        s += 1

    return lo


# ── Demo ───────────────────────────────────────────────────────────────────────

pub, priv, K = gen_rsa_pkcs1(256)
e, n = pub

plaintext = b"kick it"
padded    = pkcs1_pad(plaintext, K)
m_int     = int.from_bytes(padded, "big")
ciphertext = pow(m_int, e, n)

print(f"[*] Key: {n.bit_length()} bits, k={K} bytes")
print(f"[*] Plaintext: {plaintext!r}")

oracle = lambda c: pkcs1_oracle(c, priv, K)
recovered_int = bleichenbacher_simple(ciphertext, pub, oracle, K)
recovered_padded = recovered_int.to_bytes(K, "big")
recovered_plain  = pkcs1_unpad(recovered_padded)

print(f"[+] Recovered: {recovered_plain!r}")
print(f"[+] Oracle calls: {_oracle_calls}")
assert recovered_plain == plaintext
print("[+] Challenge 47 passed")
```

---

## Challenge 48 — Bleichenbacher (Complete, Interval Set)

The complete attack handles arbitrary keys (768 bits) and multiple intervals.
The interval set `M` can split into multiple disjoint ranges. The step-3
phase searches for an `s` that eliminates one interval, and continues until
one interval remains.

```python
#!/usr/bin/env python3
"""
Challenge 48: Bleichenbacher complete implementation with interval arithmetic.
Handles 768-bit keys and multiple concurrent intervals.
"""
from __future__ import annotations

import math
from typing import NamedTuple

import gmpy2

# Assumes gen_rsa_pkcs1, pkcs1_pad, pkcs1_oracle from challenge 47.


class Interval(NamedTuple):
    lo: int
    hi: int


def union_intervals(M: list[Interval]) -> list[Interval]:
    """Merge overlapping intervals."""
    if not M:
        return []
    M_sorted = sorted(M, key=lambda x: x.lo)
    merged   = [M_sorted[0]]
    for iv in M_sorted[1:]:
        if iv.lo <= merged[-1].hi + 1:
            merged[-1] = Interval(merged[-1].lo, max(merged[-1].hi, iv.hi))
        else:
            merged.append(iv)
    return merged


def narrow_intervals(M: list[Interval], s: int, n: int, B: int) -> list[Interval]:
    """Compute new interval set after finding conformant s."""
    B2  = 2 * B
    B3  = 3 * B
    new_M: list[Interval] = []
    for a, b in M:
        r_lo = math.ceil((a * s - B3 + 1) / n)
        r_hi = math.floor((b * s - B2) / n)
        for r in range(r_lo, r_hi + 1):
            lo = max(a, math.ceil((B2 + r * n) / s))
            hi = min(b, math.floor((B3 - 1 + r * n) / s))
            if lo <= hi:
                new_M.append(Interval(lo, hi))
    return union_intervals(new_M)


def bleichenbacher_complete(c: int, pub: tuple[int, int],
                             oracle_fn, k: int) -> int:
    """
    Full Bleichenbacher attack with interval set M.
    Three phases:
      Step 2a: find initial s (linear scan from n/3B)
      Step 2b: if multiple intervals, scan s from s_prev+1
      Step 2c: if single interval, use sub-range search (faster)
    """
    e, n = pub
    B    = 2 ** (8 * (k - 2))
    B2   = 2 * B
    B3   = 3 * B

    # Step 1: start with conformant ciphertext
    M   = [Interval(B2, B3 - 1)]
    s   = math.ceil(n / B3)
    i   = 1

    while True:
        # ── Step 2: find new s ────────────────────────────────────────────────
        if i == 1:
            # Step 2a: scan upward from n/3B
            while not oracle_fn((c * pow(s, e, n)) % n):
                s += 1
        elif len(M) > 1:
            # Step 2b: multiple intervals — linear scan
            s += 1
            while not oracle_fn((c * pow(s, e, n)) % n):
                s += 1
        else:
            # Step 2c: single interval — targeted search
            a, b     = M[0].lo, M[0].hi
            r        = math.ceil(2 * (b * s - B2) / n)
            s_found  = False
            while not s_found:
                s_lo = math.ceil((B2 + r * n) / b)
                s_hi = math.floor((B3 - 1 + r * n) / a)
                for s_try in range(s_lo, s_hi + 1):
                    if oracle_fn((c * pow(s_try, e, n)) % n):
                        s       = s_try
                        s_found = True
                        break
                r += 1

        # ── Step 3: narrow M ──────────────────────────────────────────────────
        M = narrow_intervals(M, s, n, B)

        # ── Step 4: check if done ─────────────────────────────────────────────
        if len(M) == 1 and M[0].lo == M[0].hi:
            return M[0].lo

        i += 1


# ── Demo (768-bit key takes several minutes — use 512 for testing) ─────────

pub, priv, K = gen_rsa_pkcs1(512)   # Use 768 for full challenge
e, n = pub

plaintext = b"Bleichenbacher"
padded    = pkcs1_pad(plaintext, K)
m_int     = int.from_bytes(padded, "big")
ciphertext = pow(m_int, e, n)

_oracle_calls_48 = 0

def counting_oracle(c: int) -> bool:
    global _oracle_calls_48
    _oracle_calls_48 += 1
    return pkcs1_oracle(c, priv, K)

print(f"[*] Key: {n.bit_length()} bits, k={K} bytes")
recovered_int    = bleichenbacher_complete(ciphertext, pub, counting_oracle, K)
recovered_padded = recovered_int.to_bytes(K, "big")
recovered_plain  = pkcs1_unpad(recovered_padded)

print(f"[+] Recovered: {recovered_plain!r}")
print(f"[+] Oracle calls: {_oracle_calls_48}")
assert recovered_plain == plaintext
print("[+] Challenge 48 passed — complete Bleichenbacher implemented")
```

---

## The ROBOT Attack (2018) — Real-World Bleichenbacher

ROBOT (Return Of Bleichenbacher's Oracle Threat) found that 27 of the top 100
HTTPS sites were still vulnerable to Bleichenbacher's 1998 attack in 2018 —
twenty years later.

Affected vendors: F5, Citrix, Cisco, Palo Alto Networks. The root cause: TLS
implementations that used RSA key exchange (TLS_RSA cipher suites) and had
subtle timing differences or error code differences when the PKCS#1 v1.5
padding was invalid. See CVE-2017-17382 through CVE-2017-17461.

**The fix:** Disable RSA key exchange in TLS. Force DHE or ECDHE (forward
secrecy). The PKCS#1 v1.5 padding oracle only applies to RSA key exchange —
it does not affect RSA signatures.

---

## Self-Assessment

```
[ ] 1. In step 2c of the complete attack, the search range for s is derived from
        the current interval [a, b]. Why does a smaller interval produce a
        smaller search range? Work through the math.

[ ] 2. The simplified attack calls the oracle O(n/B) times in step 2.
        The complete attack's step 2c calls the oracle far fewer times.
        What is the expected speedup for a 768-bit key vs a 256-bit key?

[ ] 3. The ROBOT attack worked in 2018 on real TLS servers. If the server uses
        TLS_RSA cipher suites, what exactly does the attacker decrypt? What
        value would they recover and what can they do with it?

[ ] 4. RSA-OAEP is immune to Bleichenbacher. Explain why: what property of
        OAEP means that no oracle exists even in principle?
```

---

## Key Takeaways

1. **Bleichenbacher is an adaptive chosen-ciphertext attack (CCA2).** The
   attacker submits chosen ciphertexts to the oracle and uses the responses
   to narrow a set of intervals. After `~2^20` queries, the plaintext is
   completely recovered.
2. **The attack is still relevant.** ROBOT (2018) proved that major TLS vendors
   were vulnerable 20 years after the original paper. Disabled cipher suites
   accumulate. Legacy code paths survive code reviews.
3. **The fix is disabling RSA key exchange, not patching the oracle.** Any
   implementation of RSA-PKCS#1 v1.5 decryption leaks information through
   timing or error codes. The only safe approach is to not use it for key
   transport.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q579.1, Q579.2 …).

---

## Navigation

← Previous: [Day 578 — Cryptopals CTF Day 8](DAY-0578-Cryptopals-CTF-Day-8.md)
→ Next: [Day 580 — Cryptopals CTF Day 10](DAY-0580-Cryptopals-CTF-Day-10.md)
