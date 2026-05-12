---
title: "Continuous Fuzzing — OSS-Fuzz Architecture, Writing a Fuzz Target, ClusterFuzz"
tags: [fuzzing, oss-fuzz, clusterfuzz, libfuzzer, continuous-fuzzing, vulnerability-research,
  module-12-postghost]
module: 12-PostGhostLevel
day: 739
prerequisites:
  - Day 653 — Fuzzing Fundamentals
  - Day 691 — libFuzzer Harness Engineering
related_topics:
  - Day 740 — Security Research Lab Design
---

# Day 739 — Continuous Fuzzing: OSS-Fuzz and Production Fuzzing Pipelines

> "The difference between fuzzing a target once and finding a bug, and fuzzing a
> target continuously and finding every bug, is infrastructure. One good fuzz target
> running on a cluster for 90 days finds things that a two-hour local run never
> could. OSS-Fuzz is Google's public infrastructure for doing this. Use it."
>
> — Ghost

---

## Goals

Understand the OSS-Fuzz architecture and what makes it different from local
fuzzing. Write a fuzz target suitable for OSS-Fuzz submission. Understand
ClusterFuzz internals. Know how to write a project integration and what to
expect when you find a bug through OSS-Fuzz.

**Prerequisites:** Days 653, 691.
**Estimated study time:** 3 hours.

---

## 1 — OSS-Fuzz Architecture

```
OSS-FUZZ OVERVIEW

What it is:
  Google's free continuous fuzzing service for open-source projects.
  Runs fuzz targets at scale 24/7 on Google's infrastructure.
  Reported 10,000+ bugs in 1,000+ projects as of 2025.

How it works:
  1. Project maintainer (or contributor) submits a project configuration
     containing fuzz target(s) to github.com/google/oss-fuzz
  2. OSS-Fuzz builds the project nightly using sanitizers:
     AddressSanitizer, MemorySanitizer, UBSan, Coverage
  3. Fuzzing runs continuously using libFuzzer and AFL++ as engines
  4. Crashes are deduplicated (symbolised stacktrace-based)
  5. Bugs are filed privately to the project's bug tracker
  6. 90-day disclosure timeline begins

What runs it:
  ClusterFuzz   Google's internal fuzzing platform (now open-source)
  Each fuzz target gets a separate VM with dedicated CPU/memory
  Runs use persistent mode + fork server for maximum throughput

Why it matters for researchers:
  Contributing a fuzz target to OSS-Fuzz:
  - Runs on Google infrastructure (much faster than a laptop)
  - Any bugs found credit you as the reporter
  - CVE is assigned automatically when a valid bug is reported
  - You can monitor crashes via oss-fuzz.com
```

### 1.1 OSS-Fuzz vs Local Fuzzing

```
COMPARISON

                    Local AFL++/libFuzzer    OSS-Fuzz
CPU cores:          4–16 (your machine)      256–1024+ per project
Corpus sharing:     None                     Central corpus across all runs
Duration:           Hours to days            Continuous (months+)
Sanitizers:         One at a time            MSan + ASan + UBSan in parallel
Crash dedup:        Manual                   Automated stacktrace clustering
Bug tracking:       Manual                   Auto-filed to Monorail/JIRA
Your time cost:     Active monitoring needed Submit once; results come to you

STRATEGIC IMPLICATION:
  A local run finds obvious crashes (easy bugs).
  OSS-Fuzz finds deep-path bugs that require millions of executions
  to trigger — the kind of bugs that lead to exploitable CVEs.
  A fuzz target submitted to OSS-Fuzz is a permanent research investment.
```

---

## 2 — Writing an OSS-Fuzz Project Integration

### 2.1 Required Files

```
OSS-FUZZ PROJECT STRUCTURE

oss-fuzz/projects/[project-name]/
├── Dockerfile          Build environment definition
├── build.sh            How to compile the project + fuzz targets
├── project.yaml        Metadata (language, maintainers, fuzzing_engines)
└── [fuzz_target].cc    The actual fuzz target(s)
```

### 2.2 Example: Fuzzing libexpat (XML parser)

```dockerfile
# Dockerfile — defines the build environment
FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER your@email.com

# Install build dependencies
RUN apt-get install -y autoconf libtool

# Clone the target project
RUN git clone --depth 1 https://github.com/libexpat/libexpat

# Copy our fuzz target into the container
COPY fuzz_expat_parse.cc $SRC/
COPY build.sh $SRC/
```

```bash
#!/bin/bash
# build.sh — compile the project with sanitizers and link fuzz target

set -e
cd $SRC/libexpat/expat

# Build with address sanitizer (OSS-Fuzz sets $CFLAGS, $CXXFLAGS automatically)
./buildconf.sh
./configure --prefix="$WORK"
make -j$(nproc) install

# Compile the fuzz target
$CXX $CXXFLAGS -std=c++17 \
    -I "$WORK/include" \
    "$SRC/fuzz_expat_parse.cc" \
    -o "$OUT/fuzz_expat_parse" \
    "$WORK/lib/libexpat.a" \
    $LIB_FUZZING_ENGINE
```

```cpp
// fuzz_expat_parse.cc — the fuzz target itself
// Must follow the libFuzzer LLVMFuzzerTestOneInput signature

#include <stdint.h>
#include <stddef.h>
#include "expat.h"

// Forward declaration of a simple handler
static void XMLCALL start_handler(void *data, const XML_Char *name,
                                   const XML_Char **atts) {}
static void XMLCALL end_handler(void *data, const XML_Char *name) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create parser, set handlers, parse the fuzzer-provided input
    XML_Parser parser = XML_ParserCreate(nullptr);
    if (!parser) return 0;

    XML_SetElementHandler(parser, start_handler, end_handler);

    // Parse: errors are expected and valid — we are looking for crashes
    XML_Parse(parser, reinterpret_cast<const char *>(data),
              static_cast<int>(size), /*isFinal=*/1);

    XML_ParserFree(parser);
    return 0;   // Return 0 always — non-zero means "discard input"
}
```

```yaml
# project.yaml
homepage: https://libexpat.github.io/
language: c++
sanitizers:
  - address
  - memory
  - undefined
fuzzing_engines:
  - libfuzzer
  - afl
  - honggfuzz
main_repo: https://github.com/libexpat/libexpat
```

### 2.3 Initial Seed Corpus

```bash
# Create minimal seed corpus directory
mkdir corpus_expat

# Add valid XML files as seeds (helps reach deeper code paths faster)
echo '<?xml version="1.0"?><root/>' > corpus_expat/seed_minimal.xml
echo '<a><b attr="val">text</b></a>' > corpus_expat/seed_nested.xml
echo '<!DOCTYPE x [<!ENTITY e "v">]><x>&e;</x>' > corpus_expat/seed_entity.xml

# Compress corpus for submission
zip -r corpus_expat.zip corpus_expat/
```

---

## 3 — Local Testing Before Submission

```bash
# Test your build locally using the OSS-Fuzz helper script

# Clone oss-fuzz
git clone https://github.com/google/oss-fuzz
cd oss-fuzz

# Copy your project files into place
cp -r ~/my-project projects/libexpat-custom/

# Build the fuzz target container
python3 infra/helper.py build_image libexpat-custom
python3 infra/helper.py build_fuzzers --sanitizer address libexpat-custom

# Run locally for 60 seconds (sanity check before PR)
python3 infra/helper.py run_fuzzer libexpat-custom fuzz_expat_parse -- -max_total_time=60

# Check coverage
python3 infra/helper.py coverage libexpat-custom fuzz_expat_parse

# If it crashes — reproduce the crash
python3 infra/helper.py reproduce libexpat-custom fuzz_expat_parse ./crash-file
```

---

## 4 — What Happens After Submission

```
POST-SUBMISSION TIMELINE

Day 0:  Your PR to oss-fuzz/projects/ is reviewed
        Review checklist: build works, target is non-trivial, no obvious bugs in harness

Day 3:  PR merged; first fuzzing run starts on Google infrastructure

Day 7:  First crash report (if any) filed to OSS-Fuzz issue tracker
        Visible to you via oss-fuzz.com — login with Google account
        Report includes: stacktrace, reproducer file, sanitizer output

Day 7–90:  You and the project maintainer see the crash
           Coordinate fix
           90-day disclosure clock starts

Day 90:  Crash becomes public if unfixed
         CVE is assigned

YOUR CREDIT:
  The OSS-Fuzz bug report includes "Reported by: [your email/handle]"
  When the CVE is issued, the OSS-Fuzz report is the official reference
  Your name is in the NVD entry

ONGOING MONITORING:
  https://oss-fuzz.com → Sign in → Projects → your target
  See: total crashes found, corpus size, coverage metrics
  A good fuzz target with a good seed corpus typically finds
  its first crash within 1–7 days of running on OSS-Fuzz
```

---

## 5 — Choosing Your OSS-Fuzz Target

```
CRITERIA FOR A GOOD FIRST TARGET

Good candidates:
  - C or C++ parser libraries (XML, JSON, image, audio, video, compression)
  - Libraries not yet in OSS-Fuzz: check https://github.com/google/oss-fuzz
    directory for existing projects
  - Libraries with active maintenance (fix turnaround in days not months)
  - Libraries that process untrusted input in security-critical contexts
    (PDF parsers, network protocol decoders, archive extraction)

Check current OSS-Fuzz coverage:
  https://introspector.oss-fuzz.com
  Shows: fuzz target coverage % per function, uncovered code paths
  High-value gaps = functions that handle untrusted input but are 0% covered

Target your contribution:
  Write a harness that exercises the UNCOVERED code paths shown by introspector
  Even if the project is already in OSS-Fuzz, you can add a NEW fuzz target
  targeting a different attack surface (e.g., a different input format)
```

---

## Key Takeaways

1. **OSS-Fuzz is a force multiplier.** One fuzz target running for 90 days on
   Google's infrastructure finds bugs no local campaign can reach without
   dedicated hardware.
2. **The fuzz harness is research.** The quality of your corpus, the code paths
   you cover, and the sanitizer configuration determine what you find.
3. **Contributing to OSS-Fuzz builds a public research record.** Every crash
   found is attributed to your harness and your submission. This is CVE
   pipeline at scale.
4. **Use OSS-Fuzz introspector to find coverage gaps.** Targeting a function
   that handles untrusted input but has zero fuzzer coverage is a high-value
   research bet.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q739.1, Q739.2 …).

---

## Navigation

← Previous: [Day 738 — Purple Team Leadership](DAY-0738-Purple-Team-Leadership.md)
→ Next: [Day 740 — Security Research Lab Design](DAY-0740-Security-Research-Lab-Design.md)
