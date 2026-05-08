---
title: "Cache Timing Attacks — Flush+Reload, Prime+Probe, and Spectre"
tags: [cryptography, side-channel, timing, cache, Flush+Reload, Prime+Probe,
  Spectre, Meltdown, constant-time, ASLR-bypass, microarchitecture,
  CWE-208, module-09-crypto-02]
module: 09-Crypto-02
day: 598
prerequisites:
  - Day 563 — Timing Attacks (network-level timing)
  - Day 597 — Differential Fault Analysis
  - Basic computer architecture: CPU cache hierarchy (L1/L2/L3, cache lines)
related_topics:
  - Differential Fault Analysis (Day 597)
  - LCG and LFSR Attacks (Day 599)
---

# Day 598 — Cache Timing Attacks: Flush+Reload, Prime+Probe, and Spectre

> "Day 563 taught you to measure timing over a network — milliseconds of
> jitter revealing password lengths. Today we go to the hardware level.
> Nanoseconds. Cache lines. The CPU's own memory hierarchy leaks secrets
> it was never supposed to touch. Flush+Reload broke AES on co-hosted VMs.
> Spectre broke every Intel chip released in the last decade. The attack
> surface is not the code — it is the silicon."
>
> — Ghost

---

## Goals

Understand the cache hierarchy, the Flush+Reload and Prime+Probe techniques,
and how they enable cross-process secret recovery. Understand Spectre at the
conceptual level and know the defences.

**Prerequisites:** Day 563 (timing basics), basic CPU architecture.
**Estimated study time:** 3–4 hours (concept-heavy; code demos require x86 Linux).

---

## Stage 1 — The Cache Hierarchy

### Memory Timing Profile (Approximate, Modern x86)

| Memory Level | Latency | Size |
|---|---|---|
| CPU register | 0 cycles | 16–32 bytes |
| L1 cache | 4 cycles (~1 ns) | 32–64 KB |
| L2 cache | 12 cycles (~4 ns) | 256 KB – 1 MB |
| L3 cache | 40–70 cycles (~15 ns) | 8–64 MB |
| DRAM | 200–300 cycles (~80 ns) | GBs |

**The secret:** If an attacker can measure whether a memory access is fast
(cache hit) or slow (cache miss), they can infer WHICH memory address was
accessed by another process — even across process boundaries in shared
L3 cache.

```
Observer's view of timing:
  - Access fast (<10 cycles) → data in cache → victim recently accessed it
  - Access slow (>150 cycles) → cache miss   → victim did NOT access it recently
```

---

## Stage 2 — Flush+Reload

### Algorithm

Flush+Reload exploits **shared memory** between attacker and victim (e.g., a
shared library like OpenSSL's AES tables, or a shared file mapping):

```
Repeat:
  1. FLUSH: clflush(address)    ← evict target address from ALL cache levels
  2. WAIT:  sleep briefly        ← allow victim to execute (and possibly access address)
  3. RELOAD: measure time to read address
             - Fast (cache hit)  → victim accessed address since flush
             - Slow (cache miss) → victim did NOT access address
```

By flushing and reloading the AES S-Box lookup table addresses, an attacker
infers which table entries were accessed during AES encryption → leaks the key.

```c
/* Minimal Flush+Reload in C (Linux x86-64, requires shared memory) */
#include <stdint.h>
#include <x86intrin.h>   /* __rdtsc, _mm_clflush */
#include <stdio.h>
#include <stdlib.h>

#define CACHE_LINE_SIZE  64
#define PROBE_ARRAY_SIZE 256   /* One slot per byte value */

/* Probe array: one cache line per possible byte value */
static uint8_t probe_array[PROBE_ARRAY_SIZE * CACHE_LINE_SIZE];

/* Flush entire probe array from cache */
void flush_probe_array(void) {
    for (int i = 0; i < PROBE_ARRAY_SIZE; i++) {
        _mm_clflush(&probe_array[i * CACHE_LINE_SIZE]);
    }
}

/* Time access to one probe slot */
uint64_t time_access(int index) {
    volatile uint8_t *ptr = &probe_array[index * CACHE_LINE_SIZE];
    uint64_t t_start, t_end;
    _mm_mfence();
    t_start = __rdtsc();
    (void)*ptr;   /* Access — triggers cache hit or miss */
    _mm_mfence();
    t_end = __rdtsc();
    return t_end - t_start;
}

/*
 * In a full F+R attack against AES:
 * - probe_array maps to the same physical pages as the AES T-tables
 * - After victim encrypts, reload each entry: fast = accessed by victim
 * - The 8 bits of the key XOR the first plaintext byte determine which
 *   T-table entry was accessed: entry = PT[0] XOR k[0]
 * - Observe which index was fast → recover PT[0] XOR k[0]
 *   If PT[0] is known → k[0] is recovered
 */
```

### Practical Impact

| Target | Technique | Result |
|---|---|---|
| AES on same host | Flush+Reload | Full 128-bit key in ~2^22 encryptions |
| RSA square-and-multiply | Flush+Reload | Full private key bits |
| ECDSA nonce | Prime+Probe | Partial bits → HNP (Day 593) |
| AES-NI hardware | Requires different approach | AES-NI not table-based |

---

## Stage 3 — Prime+Probe

### Algorithm

Prime+Probe works **without shared memory** — it exploits cache set conflicts
in the **Last-Level Cache (LLC)**:

```
Repeat:
  1. PRIME:  Fill a cache set with attacker-controlled data
              (access addresses that map to the same LLC set as the target)
  2. WAIT:   Let victim run
  3. PROBE:  Re-access the same addresses; measure time:
              - Fast → victim did NOT evict our data → target not accessed
              - Slow → victim evicted our lines → victim accessed the target set
```

This works across **VMs on the same physical host** — a significant cloud
computing threat (Yarom & Falkner 2014, Zhang et al. 2012).

```python
#!/usr/bin/env python3
"""
Prime+Probe concept demonstration (pure Python — timing only, no true cache control).
This shows the MEASUREMENT APPROACH; real P+P requires inline assembly or C.
"""
import time
import array


# Simulate a cache set with 8 lines × 64 bytes each
CACHE_SET_SIZE = 8
CACHE_LINE     = 64
probe_region   = array.array("B", [0] * (CACHE_SET_SIZE * CACHE_LINE * 256))


def measure_access_time(addr_offset: int) -> float:
    """Measure time (ns) to access a specific offset in probe region."""
    start = time.perf_counter_ns()
    _ = probe_region[addr_offset]   # Access
    end   = time.perf_counter_ns()
    return end - start


# In a real P+P implementation:
# 1. Prime: access all 8 lines of the target cache set with our data
# 2. Trigger victim execution (signal, shared memory, network packet)
# 3. Probe: re-access all 8 lines; sum access times
# 4. High sum → victim evicted our lines → victim accessed that cache set

# Conceptual example:
print("[*] Simulating Prime+Probe cache set timing measurement")
print("    (Real implementation requires x86 cache set address computation)")
print("    Key insight: evicted lines = slow reload = victim accessed that set")
print("    Attack AES: map each cache set to specific T-table[byte_value]")
print("    Result: same analysis as F+R, no shared memory needed")
```

---

## Stage 4 — Spectre (Brief)

### The Vulnerability Class

**Spectre** (CVE-2017-5753, CVE-2017-5715) exploits **CPU speculative
execution** to read arbitrary memory — including kernel memory — from
user-space.

The key idea:

```
1. CPU speculatively executes code along a "wrong" branch (before the branch
   condition is resolved).
2. The speculative execution accesses a victim memory address — which loads
   data into cache.
3. When the CPU realises the branch was wrong, it discards the computed results —
   but the CACHE STATE CHANGE REMAINS.
4. Attacker uses F+R or P+P to observe which cache lines were loaded.
5. This reveals the memory content, even though the speculative execution
   was "discarded".
```

```c
/* Spectre variant 1 conceptual code (victim gadget):
   The attacker trains the branch predictor so the CPU speculatively
   executes the secret access even when x >= array1_size. */

uint8_t array1[16];   /* Small, accessible */
uint8_t array2[256 * 512];   /* Probe array */
uint8_t secret_data[] = "SECRET_KEY_1234";   /* Out-of-bounds target */

/* Victim function — this gadget is exploited */
uint8_t victim_function(size_t x) {
    if (x < sizeof(array1)) {            /* Branch: x in bounds? */
        /* CPU speculatively executes this even when x is out-of-bounds */
        return array2[array1[x] * 512];  /* Loads array2[secret] into cache */
    }
    return 0;
}

/*
 * Attack:
 * 1. Train CPU: call victim_function(valid_x) many times → branch predictor
 *    learns "condition is usually true"
 * 2. Call victim_function(secret_offset) with out-of-bounds offset pointing
 *    to secret_data
 * 3. CPU speculatively accesses array2[secret_data[0] * 512] → cache loaded
 * 4. Flush+Reload on array2: which slot is fast? → reveals secret_data[0]
 */
```

### Mitigations

| Mitigation | Coverage | Cost |
|---|---|---|
| Retpoline | Spectre variant 2 (BTI) | ~5% IPC for some workloads |
| LFENCE | Spectre variant 1 | Must be inserted at every gadget |
| Site isolation (browsers) | JS Spectre | Limits timer resolution |
| IBRS/STIBP/IBPB | Branch prediction isolation | ~10–30% on some CPUs |
| Physical separation | All cache attacks | Impractical (performance) |

---

## Constant-Time Programming

The fundamental defence against cache timing attacks on crypto:

```python
#!/usr/bin/env python3
"""
Constant-time operations: avoid secret-dependent branches and memory access patterns.
"""
import ctypes
import os


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    Prevents timing leakage from early-exit comparison.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def constant_time_select(condition: int, a: int, b: int) -> int:
    """
    Select a if condition != 0, else b — without branching.
    Used in constant-time arithmetic.
    """
    # Expand condition to all-ones (if true) or all-zeros (if false) mask
    mask = -condition & 0xFFFFFFFF   # If condition=1: mask=0xFFFFFFFF
    return (a & mask) | (b & ~mask & 0xFFFFFFFF)


# Vulnerable: timing leak in HMAC verification
def hmac_verify_vulnerable(expected: bytes, actual: bytes) -> bool:
    return expected == actual   # Python str == exits on first mismatch!

# Correct: use secrets.compare_digest (constant-time)
import hmac
def hmac_verify_correct(expected: bytes, actual: bytes) -> bool:
    return hmac.compare_digest(expected, actual)   # Always runs all bytes


# Test constant_time_compare
a = b"correct_hmac_value"
b_val = b"wrong___hmac_value"
print(f"[*] Constant-time compare (equal):   {constant_time_compare(a, a)}")
print(f"[*] Constant-time compare (unequal): {constant_time_compare(a, b_val)}")
print("[*] Timing should be identical for both calls (verify with perf)")
```

---

## Key Takeaways

1. **Cache attacks exploit microarchitecture, not algorithms.** AES is
   mathematically secure. Its table-based software implementation leaks
   key bits through cache access patterns. AES-NI (hardware AES) removes
   this attack vector.
2. **Flush+Reload requires shared memory; Prime+Probe does not.** P+P
   works across VMs on the same physical host — a cloud computing threat
   that is still partially unmitigated.
3. **Spectre is unfixed by design.** The performance cost of full mitigation
   is unacceptable. Modern OS and browsers apply partial mitigations (timer
   jitter, site isolation). High-value targets (cloud HSMs, SGX enclaves)
   require additional hardware isolation.
4. **Constant-time programming is the software defence.** All
   security-critical comparisons, AES lookups (or AES-NI), and branch
   conditions must not depend on secret values. Use `hmac.compare_digest()`,
   `secrets.compare_digest()`, and prefer AES-NI over table-based AES.

---

## Exercises

```
1. Install pysca (Python side-channel analysis toolkit):
   pip install scared
   Run the provided AES trace analysis on simulated power traces.
   Report the recovered key byte.

2. Write a function that converts a standard AES S-Box lookup table
   to a constant-time implementation using bitsliced operations.
   (Hint: operate on all 8 bits of the byte simultaneously with masks.)

3. Spectre requires a "gadget" — a code pattern where speculative execution
   causes a secret-dependent cache load. Search the Linux kernel source
   for LFENCE instructions. Why are they placed where they are?

4. Describe the threat model difference between Flush+Reload and Prime+Probe.
   For which cloud deployment scenarios is each relevant?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q598.1, Q598.2 …).

---

## Navigation

← Previous: [Day 597 — Differential Fault Analysis](DAY-0597-Differential-Fault-Analysis.md)
→ Next: [Day 599 — LCG and LFSR Attacks](DAY-0599-LCG-LFSR-Attacks.md)
