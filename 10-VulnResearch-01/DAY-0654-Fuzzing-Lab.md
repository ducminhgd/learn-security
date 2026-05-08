---
title: "Fuzzing Lab — Fuzz a Real Parsing Library"
tags: [vulnerability-research, fuzzing, AFL++, libFuzzer, lab,
  crash-triage, finding-report, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 654
prerequisites:
  - Day 653 — Fuzzing Fundamentals
related_topics:
  - Coverage-Guided Fuzzing (Day 655)
  - CVE Reproduction Lab (Day 657)
---

# Day 654 — Fuzzing Lab: Fuzz a Real Parsing Library

> "Setting up a fuzzer is a half-hour task. Running it overnight is trivial.
> The hard part is writing a harness that actually reaches the interesting code,
> choosing a corpus that gives the fuzzer a fighting chance, and triaging the
> crashes that come out to something actionable. That is today's lab."
>
> — Ghost

---

## Goals

Select a small C library that parses a file format. Write a libFuzzer harness.
Compile with AFL++ instrumentation. Build a seed corpus. Run the fuzzer for at
least 30 minutes. Triage any crashes found. Document one finding.

**Prerequisites:** Day 653.
**Estimated study time:** 5–6 hours (lab).

---

## Target Selection

```bash
# OPTION A: libpng (PNG image parser) — classic fuzzing target
git clone https://github.com/glennrp/libpng.git
cd libpng && ./configure && make -j$(nproc)
# Good because: widely used, documented, has prior CVEs as reference

# OPTION B: libyaml (YAML parser) — good for format fuzzing
git clone https://github.com/yaml/libyaml
cd libyaml && ./bootstrap && ./configure && make -j$(nproc)

# OPTION C: cJSON (lightweight JSON parser) — small, easy harness
git clone https://github.com/DaveGamble/cJSON
cd cJSON && cmake . && make

# OPTION D: zlib (compression library) — decompress path
# Usually already installed: locate libz.a

# OPTION E: Choose your own — any small C library that:
#   - Accepts external data (file, network, string)
#   - Has < 20,000 lines of code
#   - Is NOT already being fuzzed by OSS-Fuzz (check: google.github.io/oss-fuzz/)

TARGET_NAME: ____________________________________________
TARGET_URL:  ____________________________________________
TARGET_LOC:  ______________ lines of code
```

---

## Sprint 1 — Harness Writing (90 minutes)

### Understanding the Target API

```bash
# Identify the parsing entry point:
grep -rn "parse\|load\|decode\|read" include/*.h | head -30
man <library_function>

# Read the example programs in the library:
ls examples/ || ls demo/ || ls test/
cat examples/example.c | head -50
```

```
TARGET API:
  Library name: _____________________________________________
  Main parsing function: ____________________________________
  Function signature:
    ___________________________________________________________
  Input type: file path / buffer + length / FILE* / other
  Include headers needed: ___________________________________
```

### Writing the Harness

```c
/* fuzz_target.c — libFuzzer harness */
/*
 * Adjust the #includes and function call to match your target library.
 * This template works for buffer-based parsers.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include your target library header */
/* #include "cjson/cJSON.h"     — example for cJSON */
/* #include "yaml.h"            — example for libyaml */
/* #include "png.h"             — example for libpng */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;      /* Skip empty inputs */
    if (size > 1024 * 1024) return 0;  /* Skip huge inputs */

    /* ── REPLACE THIS SECTION WITH YOUR TARGET LIBRARY CALL ── */

    /* Example: cJSON */
    /* char *buf = strndup((const char *)data, size); */
    /* cJSON *json = cJSON_Parse(buf); */
    /* cJSON_Delete(json); */
    /* free(buf); */

    /* Example: libyaml */
    /* yaml_parser_t parser; */
    /* yaml_parser_initialize(&parser); */
    /* yaml_parser_set_input_string(&parser, data, size); */
    /* yaml_event_t event; */
    /* while (yaml_parser_parse(&parser, &event)) { */
    /*     yaml_event_delete(&event); */
    /*     if (event.type == YAML_STREAM_END_EVENT) break; */
    /* } */
    /* yaml_parser_delete(&parser); */

    /* ── END TARGET SECTION ── */

    return 0;
}
```

### Compilation

```bash
# With libFuzzer (recommended — easier to iterate):
clang \
    -g \
    -fsanitize=address,fuzzer \
    fuzz_target.c \
    -I <target_include_dir> \
    <target_lib.a or -l<target>> \
    -o fuzzer

# Verify it links and runs:
./fuzzer -help=1
echo "Hello" > corpus/seed1.txt
./fuzzer corpus/ -runs=100   # Quick sanity check

# WITH AFL++ (alternative — better for coverage visualisation):
afl-clang-fast \
    -g \
    -fsanitize=address,undefined \
    fuzz_target_afl.c \
    -I <target_include_dir> \
    <target_lib.a> \
    -o target_afl
# Note: AFL harness reads from stdin or file, not LLVMFuzzer API
```

```
HARNESS COMPILATION:
  Command used: _____________________________________________
  Compiled successfully: Y / N
  Errors encountered (if any):
    ___________________________________________________________
  Test run (./fuzzer corpus/ -runs=100):
    Crashes in first 100 runs: Y / N
    Exec speed: _______________ exec/s
```

---

## Sprint 2 — Corpus Building and Fuzzing (2–3 hours)

```bash
# ══════════════════════════════════════
# BUILD SEED CORPUS
# ══════════════════════════════════════

mkdir -p corpus_seeds/

# For JSON target:
echo '{}' > corpus_seeds/empty.json
echo '{"key": "value"}' > corpus_seeds/simple.json
echo '{"a": [1, 2, 3]}' > corpus_seeds/array.json
echo '{"nested": {"x": true, "y": null}}' > corpus_seeds/nested.json

# For YAML target:
echo '---' > corpus_seeds/empty.yaml
echo 'key: value' > corpus_seeds/simple.yaml
printf 'list:\n  - item1\n  - item2\n' > corpus_seeds/list.yaml

# For binary format (PNG): copy real PNG files
cp /usr/share/pixmaps/*.png corpus_seeds/ 2>/dev/null || \
    wget -O corpus_seeds/test.png https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png

# ══════════════════════════════════════
# RUN THE FUZZER
# ══════════════════════════════════════

# libFuzzer (run for 30+ minutes):
./fuzzer \
    corpus_seeds/      \
    -max_len=65536     \
    -timeout=10        \
    -artifact_prefix=crashes/ \
    2>&1 | tee fuzzer_output.log &

# Check progress every 5 minutes:
tail -f fuzzer_output.log | grep -E "(NEW|REDUCE|crash)"

# AFL++ alternative:
afl-fuzz \
    -i corpus_seeds/   \
    -o afl_output/     \
    -m 1024            \
    -- ./target_afl @@ \
    2>&1 | tee afl_output.log
```

```
FUZZING SESSION:
  Start time: _________________
  End time:   _________________
  Duration:   _______ minutes

  libFuzzer stats (from output):
    Executions: _______________
    Exec speed: _______________ exec/s
    Corpus size: ______________ inputs
    Coverage (edges): __________
    Crashes found: ____________

  AFL++ stats (if used):
    Total paths: ______________
    Unique crashes: ___________
    Hangs: ___________________
```

---

## Sprint 3 — Crash Triage (1 hour)

```bash
# ══════════════════════════════════════
# REPRODUCE EACH CRASH
# ══════════════════════════════════════

ls crashes/   # libFuzzer saves crashes here
# OR
ls afl_output/crashes/

# Reproduce with full ASan output:
./fuzzer crashes/crash-<hash> 2>&1 | head -50

# Minimise the crash input:
./fuzzer crashes/crash-<hash> -minimize_crash=1 \
    -artifact_prefix=crashes/min_ 2>&1

# OR with AFL:
afl-tmin -i afl_output/crashes/id-<N> -o crashes/minimised.txt \
    -- ./target_afl @@

# Compare crashes — are they the same root cause?
# Run each crash and compare the first 3 frames of the stack trace
```

```
CRASH TRIAGE:

Total crashes found: _______
Unique root causes (after dedup): _______

CRASH 1:
  Input file: _______________________________________________
  Minimised input (hex or text, ≤ 50 bytes):
    ___________________________________________________________
  Stack trace (top 5 frames):
    #0 _________________ in _________________ <file>:<line>
    #1 _________________ in _________________ <file>:<line>
    #2 _________________ in _________________ <file>:<line>
    #3 _________________ in _________________ <file>:<line>
    #4 _________________ in _________________ <file>:<line>
  Crash type: HEAP_BUFFER_OVERFLOW / STACK_OVERFLOW / UAF / SEGFAULT
  Exploitability: HIGH / MEDIUM / LOW (DoS)
  Root cause (from source): ___________________________________

CRASH 2 (if any):
  (repeat above)
```

---

## Finding Report (if crash found)

```
FUZZING FINDING REPORT
Lab Day 654 — Target: _______________________ Version: ______

TITLE: [CWE-NNN] <Crash type> in <function()>

SEVERITY: Critical / High / Medium / Low

DESCRIPTION:
  A fuzzing campaign against <target> using libFuzzer + ASan
  discovered a <crash type> in <function>() when processing
  a malformed <format> input.

PROOF OF CONCEPT:
  Reproduction command:
    ./fuzzer <crash_input_file>
  OR:
    ./target_binary < <crash_input_file>

  Crash output (first 20 lines of ASan output):
  ___________________________________________________________
  ___________________________________________________________

ROOT CAUSE:
  File: _______________________ Line: ______
  Vulnerable code:
    ___________________________________________________________
  Explanation: _______________________________________________

IMPACT:
  An attacker supplying a crafted <format> file to an application
  using <target> library can cause:
  □ Denial of Service (crash)
  □ Information disclosure (heap memory leak)
  □ Remote code execution (if write primitive confirmed)

REMEDIATION:
  ___________________________________________________________

CVSS v3:
  AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H → 6.5 Medium (DoS example)
```

---

## Key Takeaways

1. **The harness is the most important investment.** A poor harness that only
   reaches 10% of the library's code will run for a week and find nothing. A
   well-designed harness that exercises all major code paths finds bugs in hours.
   Spend 30% of your lab time on the harness, not on just running the fuzzer.
2. **Exec speed is the fuzzer's health metric.** Below 500 exec/s: your harness
   has overhead (file I/O inside the loop, network calls, memory leaks). Above
   10,000 exec/s: the fuzzer is working efficiently. Optimise until you are in
   the thousands.
3. **30 minutes of fuzzing is enough for a lab exercise but not for research.**
   Real vulnerability research runs fuzzers continuously for days to weeks. The
   lab teaches the setup process; production fuzzing finds the deep bugs. Set
   up the lab, then let it run overnight if you want real results.
4. **Crash deduplication saves hours.** AFL++ and libFuzzer save every unique
   crash, but "unique" is defined by input hash, not by root cause. Ten crash
   files might all be the same stack buffer overflow triggered by different inputs.
   Compare stack traces before triaging — group duplicates before investigating.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q654.1, Q654.2 …).

---

## Navigation

← Previous: [Day 653 — Fuzzing Fundamentals](DAY-0653-Fuzzing-Fundamentals.md)
→ Next: [Day 655 — Coverage-Guided Fuzzing](DAY-0655-Coverage-Guided-Fuzzing.md)
