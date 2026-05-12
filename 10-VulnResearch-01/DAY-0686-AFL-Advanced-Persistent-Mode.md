---
title: "AFL++ Advanced — Persistent Mode and Custom Mutators"
tags: [fuzzing, afl++, persistent-mode, custom-mutator, vulnerability-research,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 686
prerequisites:
  - Day 653 — Fuzzing Fundamentals
  - Day 655 — Coverage-Guided Fuzzing
  - Day 664 — VulnResearch Practice Sprint Day 1
related_topics:
  - Day 691 — libFuzzer Harness Engineering
  - Day 700 — Module 10 Competency Check
---

# Day 686 — AFL++ Advanced: Persistent Mode and Custom Mutators

> "The default AFL++ configuration gets you bugs. The advanced configuration
> gets you bugs faster — on targets that would time out, crash, or evade
> standard instrumentation. Today you stop using AFL++ like a beginner and
> start using it like a researcher who needs to finish before the CVE window
> closes."
>
> — Ghost

---

## Goals

Understand and implement AFL++ persistent mode (`__AFL_LOOP`) to increase
throughput by 10–100×. Build a custom Python mutator that generates
structured-but-malformed input targeting a specific parsing function. Run
both against a real open-source target and compare crash rates.

**Prerequisites:** Days 653, 655, 664.
**Estimated study time:** 4 hours.

---

## 1 — Why Default AFL++ Is Not Enough

Standard AFL++ launches the target binary once per test case:

```
fork() → execve(target) → feed input → wait for exit → repeat
```

The overhead of process creation and dynamic linker costs microseconds each —
but at 1,000–10,000 executions per second, that adds up. Real targets with
complex initialisation (database engines, PDF parsers, TLS libraries) may only
achieve 50–200 exec/sec with the default `fork()` model.

**Persistent mode** eliminates the per-execution process creation overhead.
The target binary runs in a loop, resetting state between iterations.
Throughput jumps to 10,000–100,000+ exec/sec on lightweight targets.

---

## 2 — Persistent Mode: `__AFL_LOOP`

### 2.1 Modifying Source for Persistent Mode

Add `__AFL_LOOP(iterations)` around the parsing function you want to fuzz.
AFL++ handles the rest.

```c
/* persistent_target.c — wrap the parsing function */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Target parsing function — intentionally vulnerable */
static int parse_record(const uint8_t *buf, size_t len) {
    if (len < 4) return -1;
    uint16_t field_len = (buf[0] << 8) | buf[1];
    uint16_t count     = (buf[2] << 8) | buf[3];
    /* BUG: field_len * count can overflow */
    size_t total = (size_t)field_len * count;
    char *workspace = malloc(total);        /* BUG: zero-size or huge malloc */
    if (!workspace) return -2;
    memcpy(workspace, buf + 4, total);      /* BUG: reads past input */
    free(workspace);
    return 0;
}

int main(void) {
    uint8_t buf[4096];
    ssize_t n;

    /* __AFL_LOOP tells AFL++ to reset and reuse this process */
    while (__AFL_LOOP(10000)) {
        n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            parse_record(buf, (size_t)n);
        }
        /* reset any global state here if needed */
    }
    return 0;
}
```

Build with AFL++ instrumentation:

```bash
# Persistent mode requires afl-clang-fast (LLVM instrumentation)
AFL_USE_ASAN=1 afl-clang-fast -O1 -g persistent_target.c -o target_persistent

# Compare with standard fork mode
AFL_USE_ASAN=1 afl-clang-fast -O1 -g persistent_target.c \
    -DNO_PERSISTENT -o target_fork
```

### 2.2 Deferred Initialisation (`__AFL_INIT`)

Some targets perform expensive one-time initialisation (loading config files,
initialising a scripting engine). Do that work once, then call `__AFL_INIT()`
to fork after initialisation. All subsequent AFL iterations skip the init cost.

```c
int main(int argc, char **argv) {
    /* expensive initialisation — runs once */
    engine_init();
    load_config("/etc/myapp/config.json");

    __AFL_INIT();   /* snapshot here — forks only start from this point */

    while (__AFL_LOOP(10000)) {
        /* per-iteration parsing logic */
        process_input(stdin);
    }
    return 0;
}
```

### 2.3 Throughput Comparison

```bash
# Create a minimal seed corpus
mkdir seeds
python3 -c "import struct; open('seeds/s1','wb').write(struct.pack('>HH',4,3)+b'A'*12)" 
python3 -c "import struct; open('seeds/s2','wb').write(struct.pack('>HH',0,0))"

# Run fork-mode for 60 seconds
timeout 60 afl-fuzz -i seeds -o out_fork -- ./target_fork @@
grep "execs_per_sec" out_fork/fuzzer_stats

# Run persistent-mode for 60 seconds
timeout 60 afl-fuzz -i seeds -o out_persistent -- ./target_persistent
grep "execs_per_sec" out_persistent/fuzzer_stats
```

---

## 3 — Shared Memory Fuzzing (`__AFL_FUZZ_TESTCASE_BUF`)

For the very highest throughput, AFL++ can pass test cases directly via shared
memory, eliminating all I/O:

```c
#include <stdint.h>
#include <stdlib.h>

/* AFL++ shared memory API */
#ifdef __AFL_FUZZ_TESTCASE_LEN
  __AFL_FUZZ_INIT();
#endif

int main(void) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    while (__AFL_LOOP(100000)) {
        uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t   len = __AFL_FUZZ_TESTCASE_LEN;
        parse_record(buf, len);
    }
#else
    /* fallback for non-AFL builds */
    uint8_t buf[4096];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n > 0) parse_record(buf, (size_t)n);
#endif
    return 0;
}
```

Build with:

```bash
AFL_USE_ASAN=1 afl-clang-fast -O2 -g shm_target.c -o target_shm
```

Throughput improvement over stdin-read persistent mode: 2–5×.

---

## 4 — Custom Mutators

The default AFL++ mutator (bit flips, arithmetic, splicing) works well for
unstructured binary formats. For structured formats (TLV, ASN.1, compressed
data, custom protocols), mutation of random bytes generates mostly invalid
input that the parser rejects before reaching the vulnerable code path.

Custom mutators let you mutate at the semantic level — change a length field
while keeping the structure valid, fuzz enum values without breaking the
framing, or generate test cases that pass checksum validation.

### 4.1 Python Custom Mutator API

```python
#!/usr/bin/env python3
"""
Day 686 — Custom AFL++ mutator for TLV records.
Targets the parse_record() function: two big-endian uint16_t fields
followed by payload bytes.

AFL++ calls:
  init()          — once at startup
  fuzz(buf, add_buf, max_size) → new_buf  — called per mutation
"""
from __future__ import annotations

import os
import random
import struct


def init(seed: int) -> None:
    """Seed the RNG from AFL's seed for reproducibility."""
    random.seed(seed)


def fuzz(buf: bytes, add_buf: bytes, max_size: int) -> bytes:
    """
    Mutate a TLV record.

    Format: [field_len: u16be] [count: u16be] [payload: field_len*count bytes]
    Strategy: prefer edge-case values that trigger integer overflows.
    """
    # Parse existing input
    if len(buf) < 4:
        return buf

    field_len, count = struct.unpack_from(">HH", buf)
    payload = buf[4:]

    # Pick a mutation strategy
    strategy = random.randint(0, 5)

    if strategy == 0:
        # Integer overflow: field_len * count overflows uint32 (> 0xFFFFFFFF)
        field_len = random.choice([0xFFFF, 0x8001, 0x4001, 0x1001])
        count     = random.choice([0xFFFF, 0x8001, 0x4001, 0x1001])

    elif strategy == 1:
        # Off-by-one: count one more than payload accommodates
        if field_len > 0:
            count = len(payload) // field_len + 1

    elif strategy == 2:
        # Zero-size allocation: field_len=0 or count=0
        if random.random() < 0.5:
            field_len = 0
        else:
            count = 0

    elif strategy == 3:
        # Large single field, zero count
        field_len = 0xFFFF
        count = 1
        payload = os.urandom(4)          # tiny actual payload

    elif strategy == 4:
        # Splice: take payload from add_buf if available
        if len(add_buf) > 4:
            payload = add_buf[4:]

    # strategy == 5: no change (preserve valid cases for coverage)

    out = struct.pack(">HH", field_len & 0xFFFF, count & 0xFFFF) + payload
    return out[:max_size]
```

### 4.2 Activating the Custom Mutator

```bash
export AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/mutator.py
export AFL_CUSTOM_MUTATOR_ONLY=0    # 0 = combine with AFL's own mutations
                                    # 1 = use only your mutator

afl-fuzz -i seeds -o out_custom -- ./target_persistent
```

### 4.3 Comparing Coverage

```bash
# Coverage after 5 minutes with each approach
afl-cov -d out_fork   --coverage-cmd "afl-showmap -o /dev/null -- ./target_fork @@" \
        --code-path . --overwrite

afl-cov -d out_custom --coverage-cmd "afl-showmap -o /dev/null -- ./target_persistent" \
        --code-path . --overwrite

# Or simply compare map densities:
wc -l out_fork/fuzzer_stats out_custom/fuzzer_stats
grep "bitmap_cvg" out_fork/fuzzer_stats out_custom/fuzzer_stats
```

---

## 5 — Parallel Campaigns

AFL++ is single-threaded. For multi-core machines, run parallel instances:

```bash
# Primary instance (generates new seeds, -M flag)
afl-fuzz -i seeds -o out -M primary -- ./target_persistent &

# Secondary instances (explore with different strategies, -S flag)
afl-fuzz -i seeds -o out -S secondary1 \
    -p explore -- ./target_persistent &
afl-fuzz -i seeds -o out -S secondary2 \
    -p exploit -- ./target_persistent &

# On 8-core machine: 1 primary + 7 secondaries
for i in $(seq 3 8); do
    afl-fuzz -i seeds -o out -S "secondary${i}" \
        -- ./target_persistent &
done

# Monitor all instances
watch -n 5 afl-whatsup out/
```

---

## 6 — Lab Exercise

**Target:** Pick any small C parser from `lib` in `10-VulnResearch-01/samples/`
or choose a fresh open-source target (e.g., `libpng`, `zlib`, `miniz`).

```
AFL++ ADVANCED LAB CHECKLIST

Target: _______________________________
Format: _______________________________ (binary / text / TLV)

PERSISTENT MODE:
  [ ] Modified source with __AFL_LOOP(10000)
  [ ] Built with afl-clang-fast + ASan
  [ ] Seed corpus created (min 5 valid samples)
  [ ] Fork-mode throughput: _______ exec/sec
  [ ] Persistent-mode throughput: _______ exec/sec
  [ ] Throughput improvement: ______× faster

CUSTOM MUTATOR:
  [ ] Identified format structure (fields, lengths, checksums)
  [ ] Wrote Python mutator targeting edge-case values
  [ ] Activated with AFL_CUSTOM_MUTATOR_LIBRARY
  [ ] Bitmap coverage with mutator: _______ edges
  [ ] Bitmap coverage without: _______ edges
  [ ] Improvement: _______% more coverage

PARALLEL CAMPAIGN:
  [ ] 1 primary + N-1 secondary instances on all cores
  [ ] afl-whatsup shows all instances sync-ing
  [ ] Crashes found in _______ minutes: _______

RESULTS:
  Unique crashes: _______
  Crash types (from ASan): _______________________________
  Most interesting crash: ________________________________
```

---

## Key Takeaways

1. **Persistent mode is not optional for serious research.** A 10–100× throughput
   increase means finding the same bug in 6 minutes instead of 10 hours. On a
   7-day research sprint, that is the difference between finding one bug and
   finding ten.
2. **Custom mutators are a force multiplier on structured formats.** AFL's
   default bit-flip strategy treats a TLV length field the same as payload
   bytes. Your mutator knows the semantics — it can generate `field_len * count
   = 0x100000001` specifically because that overflows a 32-bit multiply.
3. **Shared memory mode (`__AFL_FUZZ_TESTCASE_BUF`) is the ceiling.** When you
   need maximum throughput and your target is library code with no I/O, shared
   memory eliminates every I/O bottleneck. Use it for competitive VRP targets
   where speed matters.
4. **Parallel campaigns multiply cores into coverage.** Each secondary instance
   uses a different mutation strategy. Coverage compounds across instances.
   `afl-whatsup` is your dashboard — if an instance shows 0 exec/sec it is
   dead and needs investigation.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q686.1, Q686.2 …).

---

## Navigation

← Previous: [Day 685 — Module Competency Check Preparation](DAY-0685-Module-Competency-Check-Preparation.md)
→ Next: [Day 687 — CodeQL Taint Analysis: Writing Queries](DAY-0687-CodeQL-Taint-Analysis.md)
