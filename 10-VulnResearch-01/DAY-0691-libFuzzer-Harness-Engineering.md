---
title: "Fuzzing Harness Engineering with libFuzzer"
tags: [fuzzing, libfuzzer, harness, vulnerability-research, asan, coverage,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 691
prerequisites:
  - Day 653 — Fuzzing Fundamentals
  - Day 655 — Coverage-Guided Fuzzing
  - Day 686 — AFL++ Advanced: Persistent Mode
related_topics:
  - Day 700 — Module 10 Competency Check
---

# Day 691 — Fuzzing Harness Engineering with libFuzzer

> "AFL++ feeds a binary. libFuzzer talks directly to a function. That is the
> difference. When your target is a library with no main(), when it uses
> callbacks and complex initialisation, or when you want to fuzz a specific
> API surface without touching the rest — libFuzzer is the right tool. The
> hard part is writing the harness that isolates the function you care about
> and nothing else."
>
> — Ghost

---

## Goals

Write libFuzzer harnesses for three scenarios: a simple parser function, a
stateful API with initialisation, and a multi-input structured format. Use
FuzzedDataProvider to generate typed structured inputs. Integrate with
SanitizerCoverage to measure harness quality.

**Prerequisites:** Days 653, 655, 686.
**Estimated study time:** 4 hours.

---

## 1 — libFuzzer vs AFL++: When to Use Each

| Criterion | libFuzzer | AFL++ |
|---|---|---|
| Target type | Library function (no `main`) | Standalone binary |
| Integration | Compile-time (LLVM) | Compile-time or QEMU |
| Throughput | Very high (in-process) | High (fork or persistent) |
| Structured input | `FuzzedDataProvider` built-in | Custom mutator needed |
| Corpus management | Merges automatically | Manual or `afl-cmin` |
| Parallel scaling | `-jobs=N -workers=N` | `-M`/`-S` multi-instance |
| Best for | Narrow API surface | Whole-binary testing |

Use libFuzzer when you know exactly which function you want to stress. Use
AFL++ when you want to discover which code path crashes the binary.

---

## 2 — The Minimal libFuzzer Harness

Every libFuzzer harness is a single C/C++ function:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Call the function under test with fuzzer-generated input */
    /* Return 0 always — returning non-zero signals a special condition */
    return 0;
}
```

Build and run:

```bash
# Compile: link against libFuzzer, enable sanitisers
clang -fsanitize=fuzzer,address,undefined \
      -g -O1 \
      harness.c libtarget.a \
      -o fuzz_target

# Create an initial corpus
mkdir corpus
echo "AABB" > corpus/seed1

# Run
./fuzz_target corpus/ -max_len=4096 -timeout=10 &
```

---

## 3 — Harness Pattern 1: Simple Parser

**Target:** A function that parses a binary record format.

```c
/* Target library function — DO NOT MODIFY */
extern int parse_packet(const uint8_t *buf, size_t len);

/* libFuzzer harness */
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Guard against zero-length inputs (optional — depends on target) */
    if (size == 0) return 0;

    /* Call the target function */
    parse_packet(data, size);

    /* Never return non-zero unless you want libFuzzer to treat it
       as a special "interesting" corpus entry */
    return 0;
}
```

### 3.1 Building Against a Real Library

```bash
# Example: fuzz zlib's inflate() function
# Build zlib with ASan + coverage instrumentation
git clone https://github.com/madler/zlib.git
cd zlib
CC="clang -fsanitize=fuzzer-no-link,address" ./configure
make -j4

# Write the harness
cat > fuzz_inflate.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t out[65536];
    uLongf out_len = sizeof(out);
    /* uncompress returns an error code — we do not check it;
       we are looking for crashes, not logic errors */
    uncompress(out, &out_len, data, (uLong)size);
    return 0;
}
EOF

clang -fsanitize=fuzzer,address -g -O1 \
      fuzz_inflate.c libz.a \
      -o fuzz_inflate
```

---

## 4 — Harness Pattern 2: Stateful API with Initialisation

When the target requires setup before the fuzzer input is processed, use
`LLVMFuzzerInitialize` for one-time setup and `LLVMFuzzerTestOneInput` for
the per-input loop:

```c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "mylib.h"      /* target library header */

static mylib_context_t *ctx = NULL;

/* Called once at startup — before any fuzzer input */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    ctx = mylib_create_context();
    if (!ctx) abort();

    /* Load a fixed config that exercises the most code paths */
    mylib_set_option(ctx, MYLIB_OPT_STRICT, 1);
    return 0;
}

/* Called once per fuzzer input */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!ctx) return 0;

    /* Reset parser state without destroying/recreating the context */
    mylib_reset(ctx);

    /* Process the fuzzer input */
    mylib_parse(ctx, data, size);

    return 0;
}
```

**Why `mylib_reset()` instead of recreating the context?** Recreating the
context in `LLVMFuzzerTestOneInput` adds allocation overhead and slows
throughput. Reset the state instead. If the library has no reset function,
structure the code so initialisation-heavy objects are created in
`LLVMFuzzerInitialize` and parsing-only objects are created/destroyed in
`LLVMFuzzerTestOneInput`.

---

## 5 — Harness Pattern 3: FuzzedDataProvider for Structured Input

`FuzzedDataProvider` (from `<fuzzer/FuzzedDataProvider.h>`) generates typed
values from the raw fuzzer bytes. Essential for targets that expect structured
data in specific fields.

```cpp
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "image_lib.h"

/* Target: process_image(width, height, depth, data_ptr, data_len) */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    FuzzedDataProvider fdp(data, size);

    /* Generate structured fields */
    uint16_t width  = fdp.ConsumeIntegralInRange<uint16_t>(0, 8192);
    uint16_t height = fdp.ConsumeIntegralInRange<uint16_t>(0, 8192);
    uint8_t  depth  = fdp.PickValueInArray<uint8_t>({1, 8, 16, 24, 32});

    /* Remaining bytes are the image payload */
    std::vector<uint8_t> pixels = fdp.ConsumeRemainingBytes<uint8_t>();

    /* Call the target */
    process_image(width, height, depth,
                  pixels.data(), pixels.size());

    return 0;
}
```

### 5.1 FuzzedDataProvider Methods Reference

```cpp
/* Integer types */
fdp.ConsumeIntegral<T>()                 /* any value of type T */
fdp.ConsumeIntegralInRange<T>(min, max)  /* inclusive range */

/* Floating point */
fdp.ConsumeFloatingPoint<T>()

/* Booleans */
fdp.ConsumeBool()

/* Enums / arrays */
fdp.PickValueInArray({v1, v2, v3})       /* pick one value from array */

/* Strings */
fdp.ConsumeRandomLengthString(max)       /* printable ASCII string */
fdp.ConsumeBytesAsString(n)              /* n bytes as std::string */

/* Raw bytes */
fdp.ConsumeBytes<uint8_t>(n)             /* exactly n bytes */
fdp.ConsumeRemainingBytes<uint8_t>()     /* all remaining bytes */
```

---

## 6 — Measuring Harness Quality

A good harness covers the code you want to fuzz. Measure with
`llvm-cov` or `lcov`:

```bash
# Build with coverage instrumentation (no fuzzer linkage — separate step)
clang -fprofile-instr-generate -fcoverage-mapping \
      -g -O0 \
      harness.c libtarget.a \
      -o harness_cov

# Run corpus through the coverage binary
for f in corpus/*; do
    ./harness_cov "$f" 2>/dev/null
done

# Generate report
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov show ./harness_cov -instr-profile=default.profdata \
    --format=html > coverage_report.html

# Summary
llvm-cov report ./harness_cov -instr-profile=default.profdata
```

Target: your harness should cover ≥ 60% of lines in the parsing function.
If coverage is low, the harness is feeding data that gets rejected before
reaching the interesting code. Add `FuzzedDataProvider` to generate inputs
that pass early validation.

---

## 7 — Lab Exercise

```
libFUZZER HARNESS LAB

Target library: _______________________________
Function to fuzz: _____________________________
Input format: _________________________________

HARNESS v1 (raw bytes):
  File: ________________
  Build command: ________________
  Initial throughput: _______ exec/sec
  Coverage (lines in target function): _______%
  Crashes in 10 min: _______

HARNESS v2 (with FuzzedDataProvider):
  Changes made: ________________________________
  New coverage: _______%
  New throughput: _______ exec/sec
  New crashes: _______

BEST CRASH:
  ASan error: ________________________________
  Crash input size: _______ bytes
  Bug class (CWE): ___________________________
  Reproducible with ./harness < crash_input: Y / N
```

---

## Key Takeaways

1. **libFuzzer runs in-process — throughput is higher but crashes terminate
   the fuzzer.** AFL++ forks a new process per input, so a crash does not
   stop the campaign. For libFuzzer: if the crash is a hard `SIGSEGV` and not
   an ASan soft abort, the fuzzer terminates. Use `-fork=N` mode or AFL++ for
   targets that commonly hard-crash.
2. **`LLVMFuzzerInitialize` is the right place for expensive setup.** Moving
   library initialisation out of `LLVMFuzzerTestOneInput` and into the init
   function can improve throughput 10× on targets with expensive startup.
3. **`FuzzedDataProvider` bridges the gap between bytes and semantics.** Raw
   fuzzing cannot reliably generate a valid PNG header + IDAT chunk. A
   FuzzedDataProvider harness that generates a valid header and fuzzes only
   the payload can reach parsing code that raw fuzzing never touches.
4. **Coverage tells you what the harness is not reaching.** A harness with
   20% coverage is leaving 80% of the attack surface unexplored. If coverage
   is low, the target is rejecting most inputs before reaching interesting
   code. Add more structure to the harness to pass validation gates.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q691.1, Q691.2 …).

---

## Navigation

← Previous: [Day 690 — Advanced YARA Rule Engineering](DAY-0690-Advanced-YARA-Engineering.md)
→ Next: [Day 692 — Variant Analysis: From One CVE to a Bug Class Sweep](DAY-0692-Variant-Analysis.md)
