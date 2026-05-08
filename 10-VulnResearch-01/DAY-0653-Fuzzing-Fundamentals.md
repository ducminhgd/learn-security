---
title: "Fuzzing Fundamentals — AFL++ and libFuzzer"
tags: [vulnerability-research, fuzzing, AFL++, libFuzzer, coverage-guided,
  crash-triage, seed-corpus, sanitizers, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 653
prerequisites:
  - Day 652 — Code Audit Lab
related_topics:
  - Fuzzing Lab (Day 654)
  - Coverage-Guided Fuzzing (Day 655)
---

# Day 653 — Fuzzing Fundamentals: AFL++ and libFuzzer

> "Auditing finds bugs in code paths you think about. Fuzzing finds bugs
> in code paths you did not think about. The two together cover the full
> attack surface. A good fuzzer with a good corpus and enough compute time
> will find bugs that a team of senior engineers would miss in a week of
> manual review. Today you learn to set one up."
>
> — Ghost

---

## Goals

Understand what coverage-guided fuzzing is and how it works. Set up AFL++ on a
target binary. Set up libFuzzer for a library function. Build a seed corpus.
Configure AddressSanitizer integration. Triage a crash to a root cause.

**Prerequisites:** Day 652.
**Estimated study time:** 4 hours.

---

## How Coverage-Guided Fuzzing Works

```
COVERAGE-GUIDED FUZZING — CORE CONCEPT
════════════════════════════════════════════════════════════════════════

TRADITIONAL (dumb) FUZZING:
  Generate random bytes → feed to program → crash? → log it
  Problem: rarely reaches deep code paths because random bytes are rarely valid input

COVERAGE-GUIDED FUZZING:
  1. Instrument the binary (add code to record which branches were taken)
  2. Start with a seed corpus (small set of valid inputs)
  3. Mutate a seed input (flip bits, insert bytes, splice inputs)
  4. Feed mutated input to target
  5. Did the mutated input exercise a NEW code path (new coverage)?
     YES → add to corpus (this input is "interesting")
     NO  → discard
  6. Repeat millions of times per second

WHY THIS IS POWERFUL:
  The corpus grows to represent diverse program states.
  The fuzzer automatically navigates past input parsing into deeper logic.
  Crashes are reproducible (the input that caused the crash is saved).

KEY METRICS:
  Executions per second:  target ≥ 1,000 exec/s for efficiency
  Coverage (edges found):  grows over time, plateaus when saturated
  Corpus size:            grows as new paths are discovered
  Crashes found:          the output we care about
```

---

## Stage 1 — AFL++ Setup and Configuration

```bash
# Install AFL++
sudo apt-get install afl++
# OR build from source:
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make && sudo make install

# Verify:
afl-fuzz --version

# ══════════════════════════════════════
# STEP 1: Compile target with AFL++ instrumentation
# ══════════════════════════════════════

# For C target:
CC=afl-clang-fast CXX=afl-clang-fast++ \
    CFLAGS="-g -fsanitize=address,undefined" \
    ./configure && make -j$(nproc)

# For a single file:
afl-clang-fast -g -fsanitize=address,undefined target.c -o target_fuzz

# ══════════════════════════════════════
# STEP 2: Create seed corpus
# ══════════════════════════════════════

mkdir -p corpus/
# Start with minimal valid inputs that exercise different code paths:
echo "valid_input_1" > corpus/seed1.txt
echo "valid_input_2" > corpus/seed2.txt
# For binary formats: provide smallest valid files
cp /usr/share/doc/libjpeg/example.jpg corpus/  # example for JPEG fuzzer

# ══════════════════════════════════════
# STEP 3: Start fuzzing
# ══════════════════════════════════════

afl-fuzz \
    -i corpus/          \  # input seed directory
    -o output/          \  # output directory (crashes go here)
    -m 1024             \  # memory limit (MB)
    -- ./target_fuzz @@    # @@ = placeholder for input file path

# The fuzzer UI shows:
# - exec speed, coverage, crashes, hangs
# - corpus count (how many interesting inputs found)
```

---

## Stage 2 — libFuzzer Setup

libFuzzer is built into LLVM/clang and is better for library functions.

```c
/* fuzzer_target.c — libFuzzer harness template */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "target_library.h"   /* the library you are fuzzing */

/* libFuzzer calls this function with generated input */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Prevent zero-size or oversized inputs if needed */
    if (size < 4 || size > 65536) return 0;

    /* Call the function you want to fuzz */
    /* Example: a parser that takes a buffer + length */
    parse_header(data, size);

    return 0;  /* 0 = no error; crash = bug found */
}
```

```bash
# Compile the harness with libFuzzer and ASan:
clang \
    -g \
    -fsanitize=address,fuzzer \
    fuzzer_target.c \
    target_library.c \
    -o fuzzer_binary

# Run libFuzzer:
./fuzzer_binary \
    corpus/          \   # initial seed corpus
    -max_len=65536   \   # maximum input size
    -timeout=10      \   # timeout per test case (seconds)
    -jobs=4          \   # parallel fuzzing jobs
    -workers=4

# libFuzzer output:
# #N  NEW  cov: NNN  ft: NNN  corp: NNN  ...
# crash artifacts saved to: crash-<hash>
```

---

## Stage 3 — Seed Corpus Strategy

```python
#!/usr/bin/env python3
"""
Seed corpus strategy for common target types.
"""
from __future__ import annotations

CORPUS_STRATEGIES = {
    "File format parser (e.g. PDF, PNG, JPEG)": {
        "seeds": [
            "Minimal valid file (smallest file that parses without error)",
            "Empty file (0 bytes)",
            "File with each optional feature present (one per seed)",
            "Files from test suites of the format library",
        ],
        "sources": [
            "Wikipedia sample files",
            "Format specification example files",
            "Real-world files from public datasets",
            "Files from similar parser's test suite",
        ],
        "tip": "Avoid large files — fuzzer mutation is more effective on small inputs",
    },
    "Network protocol parser": {
        "seeds": [
            "Valid protocol packets (captured from legitimate traffic)",
            "Minimal packets for each message type",
            "Request/response pairs from the protocol spec",
        ],
        "sources": [
            "Wireshark sample captures",
            "Protocol RFC examples",
            "Test vectors from protocol test suites",
        ],
        "tip": "Use AFL's network fuzzing templates or modify to read from stdin",
    },
    "Command-line argument parser": {
        "seeds": [
            "Each valid flag combination as a separate seed",
            "Empty argument list",
            "Maximum-length arguments",
        ],
        "sources": [
            "Tool's own test suite command invocations",
            "Man page examples",
        ],
        "tip": "Wrap argv parsing: write a harness that reads args from a file",
    },
    "Compression/decompression": {
        "seeds": [
            "Empty file compressed",
            "Single byte compressed",
            "Short string compressed",
            "Already-compressed files from format's own test suite",
        ],
        "tip": "Use afl-cmin to deduplicate large initial corpora",
    },
}

# Corpus minimisation — remove redundant seeds:
CORPUS_MINIMISATION = """
# After initial fuzzing run, minimise the corpus:
# afl-cmin: remove seeds that don't add unique coverage
afl-cmin -i output/queue/ -o corpus_min/ -- ./target_fuzz @@

# afl-tmin: minimise individual seeds to smallest triggering input
afl-tmin -i corpus/seed.txt -o corpus/seed_min.txt -- ./target_fuzz @@

# Why minimise?
# - Smaller seeds = faster mutation
# - Fewer redundant seeds = more time on unique paths
# - Smaller crash inputs = easier root cause analysis
"""

print("[*] SEED CORPUS STRATEGIES")
for target_type, strategy in CORPUS_STRATEGIES.items():
    print(f"\n  [{target_type}]")
    print(f"  Seeds:")
    for s in strategy["seeds"][:3]:
        print(f"    → {s}")
    print(f"  Tip: {strategy['tip']}")

print("\n[*] CORPUS MINIMISATION:")
print(CORPUS_MINIMISATION)
```

---

## Stage 4 — Crash Triage

```python
#!/usr/bin/env python3
"""
AFL++ crash triage workflow.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def triage_crash(binary: str, crash_input: str) -> dict:
    """
    Triage an AFL++ crash: reproduce, get stack trace, classify.
    """
    result = {
        "crash_input": crash_input,
        "reproducible": False,
        "crash_type": "UNKNOWN",
        "crash_address": None,
        "stack_trace": [],
        "asan_summary": "",
    }

    # Run with AddressSanitizer enabled:
    try:
        proc = subprocess.run(
            [binary, crash_input],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            result["reproducible"] = True
            stderr = proc.stderr

            # Parse ASan output
            if "AddressSanitizer" in stderr:
                result["crash_type"] = "ASAN"
                for line in stderr.splitlines():
                    if "heap-buffer-overflow" in line:
                        result["crash_type"] = "HEAP_BUFFER_OVERFLOW"
                    elif "stack-buffer-overflow" in line:
                        result["crash_type"] = "STACK_BUFFER_OVERFLOW"
                    elif "use-after-free" in line:
                        result["crash_type"] = "USE_AFTER_FREE"
                    elif "heap-use-after-free" in line:
                        result["crash_type"] = "HEAP_USE_AFTER_FREE"
                    elif "SEGV" in line:
                        result["crash_type"] = "SEGFAULT"
                    if "#" in line and "in " in line:
                        result["stack_trace"].append(line.strip())

    except subprocess.TimeoutExpired:
        result["crash_type"] = "HANG"

    return result


CRASH_CLASSIFICATION = {
    "HEAP_BUFFER_OVERFLOW": {
        "exploitability": "HIGH",
        "description": "Read/write past end of heap allocation",
        "common_root_cause": "Missing bounds check before memcpy/strcpy",
    },
    "STACK_BUFFER_OVERFLOW": {
        "exploitability": "HIGH (if write)",
        "description": "Read/write past end of stack variable",
        "common_root_cause": "strcpy, gets, or sprintf with unbounded input",
    },
    "USE_AFTER_FREE": {
        "exploitability": "HIGH",
        "description": "Memory used after free() was called",
        "common_root_cause": "Missing NULL assignment after free; complex lifetime",
    },
    "SEGFAULT": {
        "exploitability": "MEDIUM (depends on address)",
        "description": "Invalid memory access",
        "common_root_cause": "NULL dereference, out-of-bounds, UAF",
    },
    "HANG": {
        "exploitability": "LOW (DoS)",
        "description": "Infinite loop or very slow execution",
        "common_root_cause": "ReDoS, infinite loop on malformed input",
    },
}

print("[*] CRASH CLASSIFICATION")
for crash_type, info in CRASH_CLASSIFICATION.items():
    print(f"\n  {crash_type}")
    print(f"    Exploitability: {info['exploitability']}")
    print(f"    Root cause:     {info['common_root_cause']}")
```

---

## Key Takeaways

1. **AFL++ and libFuzzer are complementary, not competing.** AFL++ works best
   on programs that take a file as input (`./target @@`). libFuzzer works best
   on library functions you can call directly from a harness. Choose based on
   the target's interface — most production use combines both.
2. **Seed corpus quality determines fuzzer efficiency.** A fuzzer started with
   no seeds wastes hours discovering basic valid input structure. A fuzzer started
   with 20 minimal, diverse valid inputs begins finding deep bugs within minutes.
   Spend time on the corpus before you start the fuzzer.
3. **Always fuzz with AddressSanitizer enabled.** Without ASan, many memory safety
   bugs cause no crash — they corrupt memory silently and the program continues.
   With ASan, every out-of-bounds access terminates with a full diagnostic.
   The performance cost (2–3×) is worth the bug detection gain.
4. **Triage crashes immediately — do not let them pile up.** AFL++ may generate
   dozens of crashes. Many are duplicates triggered by the same root cause.
   Triage each one with `afl-tmin` + stack trace comparison within 24 hours
   of finding it. Grouped crashes → one root cause → one CVE.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q653.1, Q653.2 …).

---

## Navigation

← Previous: [Day 652 — Code Audit Lab](DAY-0652-Code-Audit-Lab.md)
→ Next: [Day 654 — Fuzzing Lab](DAY-0654-Fuzzing-Lab.md)
