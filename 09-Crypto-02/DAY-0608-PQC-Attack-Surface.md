---
title: "PQC Attack Surface — Implementation Bugs and Transition Risks"
tags: [cryptography, post-quantum, PQC, attack-surface, implementation-bugs,
  hybrid, decryption-failure, timing, protocol, liboqs, module-09-crypto-02]
module: 09-Crypto-02
day: 608
prerequisites:
  - Day 607 — LWE and Kyber Internals
  - Day 598 — Cache Timing Attacks
  - Day 597 — Differential Fault Analysis
related_topics:
  - Crypto Catch-Up (Day 609)
  - Crypto Competency Check (Day 610)
---

# Day 608 — PQC Attack Surface: Implementation Bugs and Transition Risks

> "Post-quantum algorithms are mathematically new and production implementations
> are young. That combination is historically the most dangerous window in
> cryptographic engineering. Every new algorithm has implementation bugs. Many
> have side-channels. Some have protocol-level vulnerabilities that nobody
> thought to look for because the algorithms didn't exist 10 years ago.
> This is where offensive crypto researchers will work for the next decade.
> Today you get a map of that terrain."
>
> — Ghost

---

## Goals

Survey the known attack surface of PQC implementations: decryption failure
oracles, timing side-channels in NTT and sampling, hybrid protocol risks,
and the practitioner's toolkit for auditing PQC libraries.

**Prerequisites:** Days 606–607, Day 598 (timing attacks), Day 597 (DFA).
**Estimated study time:** 3 hours.

---

## Attack Class 1 — Decryption Failure Oracle

### Background

ML-KEM is designed with **implicit rejection**: if decapsulation detects a
malformed ciphertext, it returns a pseudo-random key derived from the input
rather than an error. This prevents the classic "tell me if decryption
succeeded" oracle.

**But:** Some implementations leak the rejection via:
- Timing difference between normal and rejected decapsulation
- Different code paths in constant-time check
- Error codes in a wrapper library exposing the rejection

```python
#!/usr/bin/env python3
"""
Simulated decryption failure oracle timing measurement.
Demonstrates how a timing difference in PQC decapsulation leaks information.
"""
import time
import statistics


def kyber_decapsulate_vulnerable(sk: bytes, ct: bytes) -> tuple[bytes, float]:
    """
    Simulated vulnerable Kyber decapsulation with timing side-channel.
    Real impl would use liboqs; this simulates the timing difference.
    """
    import hashlib

    t0 = time.perf_counter_ns()

    # Simulated: valid ciphertext → full decapsulation path
    # Invalid: short-circuits early with pseudo-random output
    ct_hash = hashlib.sha256(ct).digest()
    is_valid = ct_hash[0] < 200   # Simulated: 78% valid, 22% "failure"

    if is_valid:
        # Full path: re-encrypt and compare (slower)
        time.sleep(0.000050)   # 50μs for re-encapsulation
        key = hashlib.sha256(sk + ct + b"valid").digest()
    else:
        # Short path: return PRF output (faster)
        time.sleep(0.000010)   # 10μs
        key = hashlib.sha256(sk + ct + b"reject").digest()

    t1    = time.perf_counter_ns()
    return key, (t1 - t0) / 1000   # Return (key, time_us)


def detect_decapsulation_oracle(sk: bytes, valid_ct: bytes,
                                invalid_ct: bytes, n: int = 200) -> dict:
    """
    Measure timing for valid vs invalid ciphertexts.
    Returns statistical summary.
    """
    valid_times   = [kyber_decapsulate_vulnerable(sk, valid_ct)[1]   for _ in range(n)]
    invalid_times = [kyber_decapsulate_vulnerable(sk, invalid_ct)[1] for _ in range(n)]

    return {
        "valid_median_us":   statistics.median(valid_times),
        "invalid_median_us": statistics.median(invalid_times),
        "difference_us":     statistics.median(valid_times) - statistics.median(invalid_times),
        "detectable":        abs(statistics.median(valid_times) -
                                  statistics.median(invalid_times)) > 5,
    }


import os
sk       = os.urandom(32)
valid_ct = bytes([i % 256 for i in range(1088)])    # Simulated valid CT (Kyber-768 size)
bad_ct   = bytes([0] * 1088)                         # Simulated invalid CT

result = detect_decapsulation_oracle(sk, valid_ct, bad_ct)
print(f"[*] Valid CT median:   {result['valid_median_us']:.1f} μs")
print(f"[*] Invalid CT median: {result['invalid_median_us']:.1f} μs")
print(f"[*] Difference:        {result['difference_us']:.1f} μs")
print(f"[+] Oracle detectable: {result['detectable']}")
```

### Real Cases

- **NTRU-HRSS (NIST Round 2):** Decryption failure rate 2^{-136}; some
  implementations had non-constant-time failure path.
- **Kyber-512:** Decryption failure probability ~2^{-139}. If an oracle
  could detect failures, ~1000 queries recover the private key via adaptive
  chosen ciphertext.
- **Saber:** Similar analysis applies.

---

## Attack Class 2 — NTT Timing Side-Channel

The Number Theoretic Transform butterfly step involves a conditional Montgomery
reduction. If not implemented in constant time, the modular reduction timing
leaks coefficient bits:

```python
# Vulnerable NTT butterfly (branching on conditional)
def butterfly_vulnerable(a: int, b: int, w: int, q: int) -> tuple[int, int]:
    """Cooley-Tukey butterfly — timing leak in conditional."""
    t    = (w * b) % q     # Multiply
    bfly_a = a + t
    bfly_b = a - t
    # Conditional reduction — BRANCH on value → timing leak!
    if bfly_a >= q:
        bfly_a -= q
    if bfly_b < 0:
        bfly_b += q
    return bfly_a, bfly_b


# Constant-time butterfly (no branches)
def butterfly_constant_time(a: int, b: int, w: int, q: int) -> tuple[int, int]:
    """
    Constant-time butterfly using arithmetic masking.
    No branches on secret-dependent values.
    """
    t      = (w * b) % q
    bfly_a = a + t
    bfly_b = a - t
    # Branchless conditional reduction using bit manipulation
    mask_a = -(bfly_a >> 63) & q      # If bfly_a < 0: mask = q; else: 0
    mask_b = -((q - bfly_b - 1) >> 63) & q  # If bfly_b >= q: mask = q; else: 0
    return (bfly_a - mask_b) % q, (bfly_b + mask_a) % q
```

---

## Attack Class 3 — Protocol-Level Hybrid Risks

The transition period introduces hybrid schemes where both classical and
post-quantum keys are used. New risks:

```
Risk 1: Key confusion
  If the same secret is used as both an ECDH seed and a Kyber input,
  a classical break (ECDH) could reveal the PQ secret.

Risk 2: Downgrade attack
  If the server supports both classical-only and hybrid mode,
  an attacker forces a classical-only session.
  Mitigation: Mandatory hybrid negotiation (no fallback to classical).

Risk 3: PQ key reuse
  Kyber keys are designed for single-use (IND-CCA2 security requires fresh
  ciphertext per session). Reusing a Kyber ciphertext with a different key
  breaks correctness; reusing across sessions may weaken security.

Risk 4: Harvest now, decrypt later
  Attacker captures classical TLS sessions today.
  When CRQC arrives: run Shor on the captured DH/ECDH exchange → decrypt.
  Mitigation: Deploy hybrid PQC immediately (already done by Chrome, Cloudflare).
```

```python
#!/usr/bin/env python3
"""
Demonstrate hybrid key exchange downgrade detection.
"""
def negotiate_session(client_supports: list[str],
                      server_supports: list[str]) -> str:
    """
    Negotiate the highest security key exchange.
    Vulnerable version: falls back to classical if PQ unavailable.
    """
    # Priority order: hybrid PQ > PQ-only > classical
    priority = ["ML-KEM-768+X25519", "ML-KEM-768", "X25519", "ECDH-P256"]

    for alg in priority:
        if alg in client_supports and alg in server_supports:
            return alg
    return "NONE"


def negotiate_session_secure(client_supports: list[str],
                             server_supports: list[str]) -> str:
    """
    Secure version: refuses classical-only sessions.
    """
    pq_required = ["ML-KEM-768+X25519", "ML-KEM-768"]
    for alg in pq_required:
        if alg in client_supports and alg in server_supports:
            return alg
    raise ValueError("DOWNGRADE_REJECTED: no PQC algorithm in common")


# Downgrade scenario
client = ["ML-KEM-768+X25519", "X25519", "ECDH-P256"]
server_modern   = ["ML-KEM-768+X25519", "ML-KEM-768", "X25519"]
server_legacy   = ["X25519", "ECDH-P256"]   # No PQC
attacker_strips = ["X25519", "ECDH-P256"]   # Attacker strips PQC from client hello

print(f"[*] Normal negotiation: {negotiate_session(client, server_modern)}")
print(f"[*] Legacy server:      {negotiate_session(client, server_legacy)}")
print(f"[!] Attacker strips PQC: {negotiate_session(attacker_strips, server_modern)}")

try:
    negotiate_session_secure(attacker_strips, server_modern)
except ValueError as e:
    print(f"[+] Secure negotiation blocks downgrade: {e}")
```

---

## Practitioner Toolkit: Auditing PQC Libraries

| Tool | Purpose | Notes |
|---|---|---|
| `liboqs` | Reference PQC implementations | C, Python bindings |
| `pqclean` | Clean, auditable PQC code | No assembly — readable |
| `CIRCL` | Cloudflare's Go PQC library | Production-ready |
| `Bouncy Castle` | Java PQC implementations | FIPS-compliant |
| `valgrind --tool=memcheck` | Memory safety | Check for uninitialized reads |
| `valgrind --tool=callgrind` | Instruction count | Find conditional branches on secrets |
| `dudect` | Constant-time testing | Statistical timing analysis |
| `ctgrind` | Constant-time verification | Tracks secret-dependent branches |
| `SUPERCOP` | Benchmarking + correctness | Cross-implementation comparison |

```bash
# Example: test liboqs Kyber timing with dudect
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && cmake -B build && cmake --build build

# Run dudect on Kyber-768 decapsulation
# (See liboqs test harness: tests/kat_kem.c)
./build/tests/kat_kem ML-KEM-768

# Check constant-time with valgrind
valgrind --tool=memcheck --track-origins=yes \
    ./build/tests/kat_kem ML-KEM-768 2>&1 | grep "Conditional jump"
```

---

## Key Takeaways

1. **PQC algorithms are new; their implementations are not hardened.**
   Classical crypto libraries went through 30 years of attacks, fixes, and
   audits. PQC libraries are 3–5 years old. The implementation attack surface
   is wide open.
2. **Constant-time is even harder for PQC.** NTT butterflies, Gaussian
   sampling, and rejection sampling all require careful constant-time
   implementation. Many early libraries have timing leaks.
3. **Hybrid protocol design is tricky.** Downgrade attacks, key reuse across
   schemes, and confusion between PQ and classical key material create
   new attack vectors at the protocol layer.
4. **This is the next frontier for offensive crypto research.** If you find
   a timing side-channel in a major PQC library implementation, that is a
   high-severity CVE against every server that deploys it.

---

## Exercises

```
1. Clone pqclean (github.com/PQClean/PQClean). Find the Kyber-768
   decapsulation function. Identify where implicit rejection occurs.
   Is it constant-time? How do you know?

2. Run dudect against the liboqs ML-KEM-768 decapsulation. Report
   the t-statistic after 10,000 measurements. Is the implementation
   constant-time?

3. Design a protocol where an ECDH session key is safely combined with
   a Kyber shared secret into a single master secret. What KDF function
   should you use? What are the input domain-separation requirements?

4. The NIST PQC competition had several "broken" submissions. Research
   what happened to Rainbow (multivariate) and SIKE (supersingular
   isogeny). Why were they eliminated?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q608.1, Q608.2 …).

---

## Navigation

← Previous: [Day 607 — LWE and Kyber Internals](DAY-0607-LWE-Kyber-Internals.md)
→ Next: [Day 609 — Crypto Catch-Up and Review](DAY-0609-Crypto-Catch-Up.md)
