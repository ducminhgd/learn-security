---
title: "Open-Source Audit Campaign — Scoping and Setup"
tags: [vulnerability-research, code-audit, open-source, attack-surface, setup,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 666
prerequisites:
  - Day 665 — Vulnerability Research Practice Sprint Day 2
  - Day 660 — Static Analysis: Semgrep and CodeQL
  - Day 651 — Source Code Auditing
related_topics:
  - Day 667 — Audit Campaign Day 2: Codebase Navigation
  - Day 670 — Audit Campaign Day 5: Finding Report
---

# Day 666 — Open-Source Audit Campaign: Scoping and Setup

> "The difference between a practice sprint and a real audit is that in a
> real audit you chose the target. That choice is half the work. Pick
> something too large and you wander. Pick something too small and you learn
> nothing. Pick the right target and the bugs find you — because you know
> exactly where to look and you understand what correct behaviour would be."
>
> — Ghost

---

## Goals

Select an appropriate open-source target, scope the audit to a realistic
depth, set up the analysis environment, perform initial triage, and produce
a written audit plan before reading a single function.

**Prerequisites:** Days 651, 660, 665.
**Estimated study time:** 4–5 hours.

---

## 1 — Selecting the Right Target

### Criteria for a Good First Real Target

Not all open-source projects are equal as research targets. Use this checklist
to select a project you will audit over the next five days.

```
TARGET SELECTION CRITERIA

MUST HAVE:
  [ ] Active C or C++ codebase (the language with the highest density of
      memory-safety bugs)
  [ ] Between 5,000 and 50,000 lines of code (smaller = faster; larger = richer)
  [ ] Parses external, attacker-controlled input:
        [ ] File format (image, audio, document, archive, font)
        [ ] Network protocol (TCP, UDP custom, HTTP-like)
        [ ] Configuration or data file (XML, JSON, YAML, binary config)
  [ ] Public git history (so you can do patch diffs later)
  [ ] Security-relevant — a bug here would have real-world impact

NICE TO HAVE:
  [ ] Existing CVE history (confirms the codebase has had bugs before)
  [ ] A public test corpus or sample files (instant fuzzing seed corpus)
  [ ] CMake or Autotools build (straightforward to build with ASan)
  [ ] A GitHub security advisory page (study historical disclosure format)

AVOID (for your first real audit):
  [ ] Projects larger than 200k LOC — too large for a 5-day sprint
  [ ] Projects with no C/C++ code — memory safety bugs are the primary target
  [ ] Projects that require proprietary tooling or licenses to build
  [ ] Production infrastructure you depend on — cognitive conflict
```

### Good Starting Targets by Category

| Category | Suggested Projects | Why |
|---|---|---|
| Image parsing | libpng, libtiff, libjpeg-turbo, stb_image | Dense parsing, known bug history |
| Audio/video | libsndfile, libvorbis, opusfile, minimp3 | Binary format parsing |
| Archive/compression | libarchive, zlib, brotli, lz4 | Integer arithmetic, size fields |
| Network daemons | Nginx (specific modules), dnsmasq, ntpsec | Protocol parsing, state machines |
| Font rendering | FreeType, HarfBuzz | Complex specs, historical CVEs |
| Document parsing | libxml2, expat, poppler | XML/PDF, injection surface |

### Project Selection Worksheet

```
TARGET PROJECT

Name:           _____________________________________________
GitHub URL:     _____________________________________________
Language:       _____________________________________________
LOC (approx):   _____________ (use: cloc --lang=C,C++ .)
Input type:     _____________________________________________
Last commit:    _____________________________________________
Existing CVEs:  Y / N — if yes, list: _______________________
Build system:   cmake / autotools / meson / other: __________

WHY I CHOSE THIS TARGET:
  ___________________________________________________________
  ___________________________________________________________

WHAT BUG CLASSES DO I EXPECT TO FIND BASED ON THE INPUT TYPE?
  1. ________________________________________________________
  2. ________________________________________________________
  3. ________________________________________________________
```

---

## 2 — Environment Setup

### Build with Address Sanitizer and Coverage

Before reading code, you want a build you can fuzz and an ASan build that
crashes loudly on memory errors.

```bash
# Clone the project
git clone https://github.com/[org]/[project].git target-project
cd target-project
git log --oneline | head -20            # note the HEAD commit hash for reproducibility

# Build 1: ASan + debug (for crash analysis)
mkdir build-asan && cd build-asan
cmake .. \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
make -j$(nproc)
cd ..

# Build 2: Coverage-instrumented (for AFL++/libFuzzer)
mkdir build-cov && cd build-cov
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
make -j$(nproc)
cd ..

# Verify ASan build works
echo "[*] Testing ASan build..."
./build-asan/[target-binary] tests/[sample-file] && echo "OK" || echo "CRASH — check above"

# Record build hash for reproducibility
echo "Audit target: $(git rev-parse HEAD)" > ../audit-commit.txt
echo "Build date: $(date -u)" >> ../audit-commit.txt
```

### Autotools Build (alternative)

```bash
# If the project uses autotools:
./autogen.sh 2>/dev/null || autoreconf -fiv

CC=clang CXX=clang++ \
  CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  LDFLAGS="-fsanitize=address,undefined" \
  ./configure --prefix="$(pwd)/install-asan"

make -j$(nproc)
make install
```

### Environment Verification Log

```
BUILD LOG

ASan build:
  Compiler:         _______________________________________
  Build succeeded:  Y / N
  Test file runs:   Y / N
  ASan output on test: ___________________________________

Coverage build (optional but recommended for fuzzing):
  Compiler:         _______________________________________
  Build succeeded:  Y / N

HEAD commit hash:  ________________________________________
Audit start date:  ________________________________________
```

---

## 3 — Codebase Orientation (90 minutes)

Do not read individual functions yet. First, understand the map.

### Step 1 — Get the Size and Shape

```bash
# Line count by file type
cloc --lang=C,C++ . --by-file | sort -t: -k2 -n | tail -30

# Find the biggest files (likely the most complex)
find . -name "*.c" -o -name "*.cpp" | xargs wc -l | sort -n | tail -20

# How many public API functions?
ctags -R --languages=C,C++ --c-kinds=f . && wc -l tags

# Find test files (gives clues about the public API surface)
find . -name "test_*" -o -name "*_test*" -o -name "*_unittest*" | head -20
```

### Step 2 — Find the Entry Points

```bash
# Find the main parsing entry point(s) — functions that accept external input
grep -r "fopen\|fread\|read(\|recv(\|getc\|fgets\|sscanf\|fscanf" \
     --include="*.c" --include="*.h" -l | head -20

# Find public API headers (the surface exposed to callers)
find . -name "*.h" -not -path "*/internal/*" -not -path "*/private/*" | \
  xargs grep -l "extern\|EXPORT\|API" | head -10

# Find where user input first enters the system
grep -r "argv\[1\]\|optarg\|getopt\|command.line\|user.input" \
     --include="*.c" | head -20
```

### Step 3 — Map the Interesting Subsystems

```
CODEBASE MAP

Top 5 largest source files (likely most complex):
  1. ________ ( _____ LOC) — purpose: ____________________
  2. ________ ( _____ LOC) — purpose: ____________________
  3. ________ ( _____ LOC) — purpose: ____________________
  4. ________ ( _____ LOC) — purpose: ____________________
  5. ________ ( _____ LOC) — purpose: ____________________

Public API entry points (files that accept external input):
  1. ______________________________________________________
  2. ______________________________________________________
  3. ______________________________________________________

Subsystems I identified (e.g., "parser", "renderer", "network layer"):
  1. ______________________________________________________
  2. ______________________________________________________
  3. ______________________________________________________
  4. ______________________________________________________

Files I will audit first (most attack surface, biggest, or most complex):
  1. ______________________________________________________
  2. ______________________________________________________
  3. ______________________________________________________
```

---

## 4 — Automated Pre-Scan

Run Semgrep before manual reading. It finds the low-hanging fruit quickly and
tells you what patterns to look for manually.

```bash
# Install semgrep if not installed
pip install semgrep

# Run the C/C++ security ruleset
semgrep --config "p/c" \
        --include="*.c" --include="*.h" --include="*.cpp" \
        --output semgrep-results.json \
        --json .

# Summarise by rule (sorted by frequency)
python3 -c "
import json, collections
data = json.load(open('semgrep-results.json'))
counts = collections.Counter(r['check_id'] for r in data['results'])
for rule, count in counts.most_common(20):
    print(f'{count:4d}  {rule}')
"

# Show only HIGH severity findings
python3 -c "
import json
data = json.load(open('semgrep-results.json'))
for r in data['results']:
    sev = r['extra'].get('severity', 'UNKNOWN')
    if sev in ('ERROR', 'WARNING'):
        path = r['path']
        line = r['start']['line']
        rule = r['check_id'].split('.')[-1]
        msg = r['extra']['message'][:80]
        print(f'[{sev:7}] {path}:{line} — {rule}')
        print(f'         {msg}')
        print()
" | head -80
```

### Semgrep Triage Table

```
SEMGREP FINDINGS TRIAGE

Total findings: _______
After filtering to ERROR/WARNING severity: _______

Rule                            Count   Worth Manual Review?
─────────────────────────────── ─────   ─────────────────────
________________________________  ____   Y / N — reason: ______
________________________________  ____   Y / N — reason: ______
________________________________  ____   Y / N — reason: ______
________________________________  ____   Y / N — reason: ______
________________________________  ____   Y / N — reason: ______

TOP 3 CANDIDATES IDENTIFIED BY SEMGREP:
  1. File: ____________ Line: ______ Rule: ________________
     Snippet: _____________________________________________
     Will investigate: Y / N

  2. File: ____________ Line: ______ Rule: ________________
     Snippet: _____________________________________________
     Will investigate: Y / N

  3. File: ____________ Line: ______ Rule: ________________
     Snippet: _____________________________________________
     Will investigate: Y / N
```

---

## 5 — Audit Plan

Before reading code tomorrow, write down exactly what you will audit.

```
FIVE-DAY AUDIT PLAN

TARGET: ___________________________ Commit: _______________

DAY 666 (today): Scoping, environment setup, Semgrep pre-scan     ✓
DAY 667:         Codebase navigation, entry point mapping, audit
                 function list
DAY 668:         Deep read on top-priority files; manual taint
                 tracking; fuzzing campaign kick-off
DAY 669:         Crash triage; PoC development for any crashes;
                 manual verification of Semgrep candidates
DAY 670:         Write up all findings; produce a disclosure-ready
                 advisory for the strongest finding

PRIORITY AUDIT TARGETS (files / functions):
  1. __________________________________________________________
  2. __________________________________________________________
  3. __________________________________________________________
  4. __________________________________________________________
  5. __________________________________________________________

BUG CLASSES I WILL LOOK FOR:
  [ ] Integer overflow before malloc/read (CWE-190)
  [ ] Missing bounds check before memcpy/strcpy (CWE-122/125/787)
  [ ] Use of unvalidated length field from input
  [ ] Off-by-one in buffer calculations
  [ ] Use-after-free in object lifecycle
  [ ] Uncontrolled format string
  [ ] Command injection via system()/popen()
  [ ] Other: ________________________________________________

DAILY HOURS COMMITMENT:
  Day 667: ______ hours
  Day 668: ______ hours
  Day 669: ______ hours
  Day 670: ______ hours
```

---

## Key Takeaways

1. **Target selection is a skill.** Choosing a project that is small enough
   to finish but complex enough to yield bugs is the first professional
   decision a vulnerability researcher makes. The wrong target wastes days.
   The right target teaches you in hours.
2. **Build before you read.** An ASan build costs 15 minutes to set up and
   saves hours of manual debugging when a crash occurs. Compile instrumented
   on day one; never audit a binary you cannot run and crash.
3. **The Semgrep pre-scan is a triage tool, not a finding list.** Every
   Semgrep hit is a candidate; none are confirmed bugs. The scan tells you
   which files to read manually. It does not tell you which bugs exist.
4. **An audit plan is a forcing function.** Writing down which files you
   will audit and what classes you will look for prevents you from spending
   three days reading everything and finding nothing. Scope is how
   professionals get results.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q666.1, Q666.2 …).

---

## Navigation

← Previous: [Day 665 — VulnResearch Practice Sprint Day 2](DAY-0665-VulnResearch-Practice-Sprint-Day2.md)
→ Next: [Day 667 — Audit Campaign Day 2: Codebase Navigation](DAY-0667-Audit-Campaign-Codebase-Navigation.md)
