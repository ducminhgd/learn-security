---
title: "Cryptopals CTF Practice — Day 7: Set 6 Part 2 (DSA Key Recovery)"
tags: [cryptography, cryptopals, CTF, DSA, nonce-reuse, key-recovery,
  known-nonce, repeated-r, set-6, challenge-43, challenge-44]
module: 09-Crypto-01
day: 577
prerequisites:
  - Day 576 — Cryptopals CTF Day 6 (Set 6 Part 1)
  - Day 569 — ECDSA Nonce Reuse (same maths, different curve)
related_topics:
  - Cryptopals CTF Day 8 (Day 578)
  - ECDSA Nonce Reuse (Day 569)
---

# Day 577 — Cryptopals CTF Practice: Day 7

> "DSA and ECDSA share the same fatal flaw: the nonce k is load-bearing.
> Reuse it once and you hand the attacker your private key. The PS3 used a
> constant k for years. The Cryptopals data file for challenge 44 is a real
> capture of exactly that mistake."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 6 Challenges 43 and 44: DSA private-key recovery from
a known signing nonce (Ch.43) and from a set of messages signed with a repeated
nonce — detected only by matching `r` values (Ch.44).

**Prerequisites:** Sets 1–5 complete; Day 569 (ECDSA nonce reuse).
**Estimated lab time:** 3 hours.
**Resource:** https://cryptopals.com/sets/6

---

## DSA Primer (3 minutes)

Before touching the challenges, let these equations settle in:

```
Key generation:
  Domain: (p, q, g) — large prime p, 160-bit prime q | p-1, g = h^((p-1)/q) mod p
  Private key: x ← rand [1, q-1]
  Public key:  y = g^x mod p

Sign(m, x, k):          ← k is the secret per-message nonce
  r = (g^k mod p) mod q
  s = k⁻¹ · (H(m) + x·r) mod q
  signature = (r, s)

Verify(m, y, r, s):
  w  = s⁻¹ mod q
  u1 = H(m) · w mod q
  u2 = r · w mod q
  v  = (g^u1 · y^u2 mod p) mod q
  valid ↔ v == r
```

The nonce `k` must be secret, random, and never reused. If any of those
conditions fails, the private key `x` is recoverable.

---

## Challenge 43 — DSA Key Recovery from Known Nonce

If you know `k`, the private key falls out immediately from the signing equation:

```
s  = k⁻¹ · (H(m) + x·r) mod q
s·k = H(m) + x·r  mod q
x   = (s·k − H(m)) · r⁻¹  mod q
```

The Cryptopals challenge provides a specific message and signature where `k`
was chosen in the range `[0, 2¹⁶)`. Brute-force all 65 536 candidates.

```python
#!/usr/bin/env python3
"""
Challenge 43: DSA private-key recovery from a subspace of k values.
The nonce k was chosen from [0, 2^16) — brute-force it and check whether
the recovered private key matches the published public key.
"""
from __future__ import annotations

import hashlib

import gmpy2


# ── DSA domain parameters (from Cryptopals) ──────────────────────────────────

P = int(
    "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1",
    16,
)
Q = 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
G = int(
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
    "9fc95302291",
    16,
)

# Published public key
Y = int(
    "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
    "bb283e6633451e535c45513b2d33c99ea17",
    16,
)

# Published message + signature from the challenge
MSG_HEX = (
    "For those that envy a MC it can be hazardous to your health\n"
    "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
)
R = 548099063082341131477253921760299949438196259240
S = 857042759984254168557880549501802188789837994940

# SHA-1 hash of the message (Cryptopals uses SHA-1 for DSA)
MSG_HASH = int(hashlib.sha1(MSG_HEX.encode()).hexdigest(), 16)


def recover_x_from_k(k: int) -> int:
    """Given signing nonce k, recover the DSA private key x."""
    r_inv = int(gmpy2.invert(R, Q))
    x     = ((S * k - MSG_HASH) * r_inv) % Q
    return x


def verify_recovered_key(x: int) -> bool:
    """Check that g^x mod p mod q matches the published public key y."""
    y_check = pow(G, x, P)
    return y_check == Y


# ── Brute-force k over [0, 2^16) ─────────────────────────────────────────────

print("[*] Brute-forcing k in [0, 2^16) …")
found_x: int | None = None

for k in range(2**16):
    # Verify r first: (g^k mod p) mod q must equal R
    r_check = pow(G, k, P) % Q
    if r_check != R:
        continue
    x = recover_x_from_k(k)
    if verify_recovered_key(x):
        found_x = x
        print(f"  [+] Found k = {k}")
        print(f"  [+] Private key x = {hex(found_x)}")
        # Cryptopals expects the SHA-1 of the hex-encoded x
        x_hex_hash = hashlib.sha1(hex(found_x)[2:].encode()).hexdigest()
        print(f"  [+] SHA1(hex(x)) = {x_hex_hash}")
        # Expected: 0954edd5e0afe5542a4adf012611a91912a3ec16
        assert x_hex_hash == "0954edd5e0afe5542a4adf012611a91912a3ec16", (
            "Hash mismatch — wrong x"
        )
        break

assert found_x is not None, "Key not found — check the brute-force range"
print("[+] Challenge 43 passed")
```

---

## Challenge 44 — DSA Nonce Recovery from Repeated Nonce

A repeated `k` produces the same `r` value. The Cryptopals data file
(`44.txt`) contains 11 message/signature pairs, some sharing the same
`k` (and therefore the same `r`).

Given two signatures `(r, s1)` and `(r, s2)` for messages with hashes `h1` and `h2`:

```
s1 = k⁻¹(h1 + x·r) mod q
s2 = k⁻¹(h2 + x·r) mod q

s1 - s2 = k⁻¹(h1 - h2) mod q
k       = (h1 - h2) · (s1 - s2)⁻¹ mod q
```

Then recover `x` as in challenge 43.

```python
#!/usr/bin/env python3
"""
Challenge 44: Detect repeated DSA nonces by matching r values,
recover k, then recover the private key x.
"""
from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass

import gmpy2


@dataclass
class DsaRecord:
    msg:  str
    s:    int
    r:    int
    m:    int   # H(msg) as integer


def load_challenge_44() -> list[DsaRecord]:
    url  = "https://cryptopals.com/static/challenge-data/44.txt"
    with urllib.request.urlopen(url) as f:
        raw = f.read().decode()

    records: list[DsaRecord] = []
    lines = [ln.strip() for ln in raw.strip().splitlines() if ln.strip()]
    assert len(lines) % 4 == 0, "Unexpected format"
    for i in range(0, len(lines), 4):
        msg_line = lines[i]
        s_line   = lines[i + 1]
        r_line   = lines[i + 2]
        m_line   = lines[i + 3]

        msg = msg_line[len("msg: "):]
        s   = int(s_line[len("s: "):])
        r   = int(r_line[len("r: "):])
        m   = int(m_line[len("m: "):], 16)

        # Validate: m should equal SHA1(msg)
        assert m == int(hashlib.sha1(msg.encode()).hexdigest(), 16), (
            f"Hash mismatch at index {i}"
        )
        records.append(DsaRecord(msg=msg, s=s, r=r, m=m))
    return records


def find_repeated_r(records: list[DsaRecord]) -> list[tuple[DsaRecord, DsaRecord]]:
    """Return all pairs of records that share the same r (= same k)."""
    from collections import defaultdict
    by_r: dict[int, list[DsaRecord]] = defaultdict(list)
    for rec in records:
        by_r[rec.r].append(rec)
    pairs = []
    for r, recs in by_r.items():
        if len(recs) >= 2:
            for i in range(len(recs)):
                for j in range(i + 1, len(recs)):
                    pairs.append((recs[i], recs[j]))
    return pairs


def recover_k_from_pair(a: DsaRecord, b: DsaRecord, q: int) -> int:
    """Recover nonce k from two messages signed with the same k."""
    # k = (h1 - h2) * modinv(s1 - s2, q) mod q
    num   = (a.m - b.m) % q
    denom = (a.s - b.s) % q
    k     = (num * int(gmpy2.invert(denom, q))) % q
    return k


def recover_x_from_nonce(k: int, rec: DsaRecord, q: int) -> int:
    r_inv = int(gmpy2.invert(rec.r, q))
    x     = ((rec.s * k - rec.m) * r_inv) % q
    return x


# ── Main attack ───────────────────────────────────────────────────────────────

records = load_challenge_44()
print(f"[*] Loaded {len(records)} records")

pairs = find_repeated_r(records)
print(f"[*] Found {len(pairs)} repeated-r pair(s)")
assert pairs, "No repeated r — check the data file"

for a, b in pairs:
    k = recover_k_from_pair(a, b, Q)
    x = recover_x_from_nonce(k, a, Q)

    if pow(G, x, P) == Y:
        print(f"[+] Valid private key: x = {hex(x)}")
        x_hex_hash = hashlib.sha1(hex(x)[2:].encode()).hexdigest()
        print(f"[+] SHA1(hex(x)) = {x_hex_hash}")
        # Expected: ca8f6f7c66fa362d40760d135b763eb8527d3d52
        assert x_hex_hash == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
        print("[+] Challenge 44 passed — key recovered from repeated nonce")
        break
```

---

## Set 6 / Challenges 43–44 Self-Assessment

```
[ ] 1. In challenge 43, brute-forcing k takes O(2^16) operations. If the
        implementer had chosen k from [0, 2^32) instead, the brute-force would
        be infeasible. What is the correct way to generate k? Name the RFC.

[ ] 2. In challenge 44, the repeated nonce is detected by matching r values.
        Is it possible for two different k values to produce the same r?
        Under what conditions? Is that a realistic concern?

[ ] 3. After recovering x in challenge 44, you can forge any DSA signature for
        any message. Write the three-line signing function that does this.

[ ] 4. RFC 6979 deterministically derives k from the private key and the message
        hash using HMAC-DRBG. Explain why this is secure even though k is
        deterministic — i.e., why does determinism not make k predictable?
```

---

## Key Takeaways

1. **Nonce k is load-bearing.** In both DSA and ECDSA, the security of the
   private key depends entirely on the secrecy and uniqueness of `k`. A single
   leaked or repeated `k` hands the attacker `x` in closed form — no discrete
   log required.
2. **Repeated nonces leave an observable fingerprint.** Same `k` → same `r`.
   An analyst with two signatures over a log file can compute the set of
   `r` values in `O(n)` and detect collisions immediately.
3. **RFC 6979 solves the problem.** Deterministic nonce derivation from
   `HMAC-DRBG(key, message)` eliminates the RNG attack surface entirely.
   Challenge 43 (brute-forceable range) represents real hardware RNG failures —
   the PS3 used a constant k.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q577.1, Q577.2 …).

---

## Navigation

← Previous: [Day 576 — Cryptopals CTF Day 6](DAY-0576-Cryptopals-CTF-Day-6.md)
→ Next: [Day 578 — Cryptopals CTF Day 8](DAY-0578-Cryptopals-CTF-Day-8.md)
