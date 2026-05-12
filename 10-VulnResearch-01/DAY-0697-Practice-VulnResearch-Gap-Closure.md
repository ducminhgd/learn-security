---
title: "Targeted Practice — Vulnerability Research Gap Closure"
tags: [vulnerability-research, practice, gap-closure, fuzzing, advisory, cvss,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 697
prerequisites:
  - Day 684 — Module Review and Self-Assessment
  - Days 651–685 (Vulnerability Research sub-module)
related_topics:
  - Day 698 — Final Pre-Gate Full Simulation
  - Day 700 — Module 10 Competency Check
---

# Day 697 — Targeted Practice: Vulnerability Research Gap Closure

> "Same deal as yesterday. You know what your weak skills are. The gate
> will find them if you do not. The difference between a gate pass and
> a gate fail is almost always the same skill — the one the student decided
> not to drill because it was uncomfortable. Do not be that student."
>
> — Ghost

---

## Goals

Consolidate the weakest-rated vulnerability research skills from Day 684.
Run targeted drills for any skill rated below 3.0. End with an updated
rating that reflects genuine improvement.

**Prerequisites:** Day 684 self-assessment (vulnerability research section).
**Estimated study time:** 4 hours (self-directed).

---

## Your Weak Skills

```
YOUR WEAK VULNERABILITY RESEARCH SKILLS (from Day 684):
  1. _______________________________________________  Rating: ___/4
  2. _______________________________________________  Rating: ___/4
  3. _______________________________________________  Rating: ___/4

TODAY'S DRILLS: Work through the drill for each skill ≤ 2.
```

---

## Drill Library

### Drill A — Audit Pipeline Speed (for ratings ≤ 2)

**Goal:** Run the full pipeline from scratch on a new target in 3 hours.
This is a condensed sprint — no notes, no re-reading lessons.

**Estimated time:** 3 hours

```
AUDIT PIPELINE SPEED DRILL

Target: new project not used in any previous sprint
         (choose from: nasm, musl, zlib, stb_image, miniz, libsndfile)

T+00:  Target selected: _______________________________
       Clone and ASan build started

T+20:  Build complete: Y / N
       Semgrep scan started: Y / N
       AFL++ started with seed: Y / N

T+45:  [checkpoint]
       Semgrep findings: ______
       Audit list written (min 5 functions): Y / N

T+90:  [checkpoint]
       Functions manually reviewed: ______
       Candidates found: ______

T+150: [checkpoint]
       AFL++ crashes: ______
       PoC attempted: Y / N

T+180: [final]
       Strongest finding: _______________________________
       CWE: __________ CVSS (rough): __________
       Advisory outline started: Y / N

Pipeline speed vs Day 666 campaign: Faster / Same / Slower
Time spent: _______ hours (target: 3)
Rating after drill: ___/4
```

---

### Drill B — AFL++ Setup and Crash Triage (for ratings ≤ 2)

**Goal:** Configure AFL++ from scratch, fuzz a target for 30 minutes,
triage all crashes. Time yourself.

**Estimated time:** 60 minutes

```
AFL++ SETUP AND CRASH TRIAGE DRILL

Target: any small C parser (build with: AFL_USE_ASAN=1 afl-clang-fast)
Build command: ___________________________________
Seed corpus: _____________________________________ (min 3 seeds)

AFL++ launch command:
  afl-fuzz -i seeds -o out -m none -- ./target @@

Time to first crash: _______ minutes (or "no crash in 30 min")
Total crashes: _______
Unique crashes (after afl-cmin): _______

TRIAGE LOG (for each unique crash):
  Crash 1: ____________________________________________
    ASan error: _______________________________________
    Crash function: ___________________________________
    Input size: _______ bytes
    Bug class (CWE): __________________________________

  Crash 2: ____________________________________________
    ASan error: _______________________________________
    CWE: ______________________________________________

Are crashes reproducible outside AFL? Y / N
  ./target < crash_input  → crash Y / N

Rating after drill: ___/4
```

---

### Drill C — Manual Taint Tracking (for ratings ≤ 2)

**Goal:** Given 3 code snippets, trace the taint path from source to sink
without running the code. Time yourself: 5 minutes per snippet.

**Estimated time:** 30 minutes

```c
// SNIPPET 1: trace the path from fread to memcpy
typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t  depth;
} Header;

uint8_t *load_image(FILE *fp) {
    Header hdr;
    fread(&hdr, sizeof(Header), 1, fp);     // SOURCE: hdr is tainted

    size_t row_size = hdr.width * hdr.depth;
    size_t total    = row_size * hdr.height;

    uint8_t *buf = malloc(total);           // SINK: is total user-controlled?
    fread(buf, total, 1, fp);
    return buf;
}
```

```
Snippet 1 answers:
  Source: _______________________________________
  Taint propagation chain:
    hdr.width (tainted) → row_size = hdr.width * hdr.depth
    row_size (tainted) → total = row_size * hdr.height
    total (tainted) → malloc(total)  ← SINK
  Integer overflow possible? Y / N  Where: _______
  CWE: _____________
  Fix: _____________________________________________
```

```c
// SNIPPET 2: trace from argv to printf
int process_args(int argc, char **argv) {
    if (argc < 2) return -1;
    char msg[64];
    int  n = atoi(argv[1]);            // SOURCE: argv[1]
    if (n > 0 && n < 50) {
        snprintf(msg, sizeof(msg), "Count: %d", n);
        printf(msg);                   // SINK: format string?
    }
    return n;
}
```

```
Snippet 2 answers:
  Is argv[1] used as a format string? Y / N  Explain: ___________
  Is there an integer overflow? Y / N  Explain: _________________
  What CWE applies? _______________________________________________
  Fix: ___________________________________________________________
```

```c
// SNIPPET 3: trace from network recv to strcpy
#define BUF_SIZE 128

struct Conn {
    char username[32];
    int  auth;
    char session[64];
};

void handle_auth(int sockfd, struct Conn *c) {
    char tmp[1024];
    int  n = recv(sockfd, tmp, sizeof(tmp), 0);  // SOURCE
    tmp[n] = 0;
    /* Parse: AUTH <username> */
    if (strncmp(tmp, "AUTH ", 5) == 0) {
        strcpy(c->username, tmp + 5);             // SINK
        c->auth = 1;
    }
}
```

```
Snippet 3 answers:
  CWE: __________ (strcpy with unbounded source)
  What does an attacker control? _________________________________
  Max username length received: ________ bytes
  username field size: ________ bytes
  Overflow amount: ________ bytes
  What is adjacent in the struct after username? _________________
  Can an attacker control c->auth by overflowing username? Y / N
  Fix: ___________________________________________________________
```

```
Snippet drills time: _______ min  (target: 15 min)
Rating after drill: ___/4
```

---

### Drill D — CVSS Scoring (for ratings ≤ 2)

**Goal:** Given three vulnerability descriptions, produce a justified CVSS
v3.1 vector. Target: < 3 minutes per vulnerability.

**Estimated time:** 20 minutes

```
CVSS DRILL

Vulnerability 1:
  "Network-reachable stack buffer overflow in an HTTP server's URL parser.
  No authentication required. Attacker sends a crafted HTTP request.
  Impact: remote code execution as the service user (not root)."

  AV: __  AC: __  PR: __  UI: __  S: __  C: __  I: __  A: __
  Score: _____ — Justification: ________________________________

Vulnerability 2:
  "A local, authenticated attacker on a shared Linux server can exploit a
  race condition in a setuid binary to read 4KB of memory from another
  user's process space."

  AV: __  AC: __  PR: __  UI: __  S: __  C: __  I: __  A: __
  Score: _____ — Justification: ________________________________

Vulnerability 3:
  "A malicious image file triggers a double-free in a desktop image
  viewer. The crash does not produce code execution on modern glibc
  (≥ 2.34). Denial of service only."

  AV: __  AC: __  PR: __  UI: __  S: __  C: __  I: __  A: __
  Score: _____ — Justification: ________________________________

Time taken: _______ min (target: 9 min total)
Rating after drill: ___/4
```

---

### Drill E — Advisory Writing (for ratings ≤ 2)

**Goal:** Write a complete advisory (all sections) for the heap overflow you
found in any previous sprint, in under 30 minutes.

**Estimated time:** 30 minutes

Use the template from Day 659/670. A complete advisory must have:

```
[ ] Title: specific — product, version, function, CWE
[ ] Affected versions: exact range
[ ] Severity: CVSS v3.1 score + vector
[ ] Description: root cause in 3–5 sentences
[ ] Impact: worst-case outcome, plainly stated
[ ] PoC: reproducible input (file or command), ASan output
[ ] Fix: specific code change
[ ] Timeline: discovery → report → patch → disclosure
[ ] Researcher name and contact

Advisory time: _______ min (target: 30 min)
All 9 sections complete: Y / N
Rating after drill: ___/4
```

---

## End-of-Day Re-Rating

```
VULNERABILITY RESEARCH SKILLS — UPDATED RATINGS

Audit pipeline:            ___/4  (was ___/4 on Day 684)
Fuzzer setup (AFL++):      ___/4  (was ___/4)
Network fuzzing (Boofuzz): ___/4  (was ___/4)
Manual taint tracking:     ___/4  (was ___/4)
PoC development:           ___/4  (was ___/4)
CVSS scoring:              ___/4  (was ___/4)
Advisory writing:          ___/4  (was ___/4)
Bug class ID (all 7):      ___/4  (was ___/4)

AVERAGE: ___/4

GATE READINESS:
  [ ] ≥ 3.0 average — ready for Day 698 full simulation
  [ ] < 3.0 average — identify one more targeted drill before gate day
```

---

## Key Takeaways

1. **Vulnerability research skill is not measured in reading — it is measured
   in speed.** The gate gives you 3 hours for the vulnerability research
   component. The drills above simulate components of that 3 hours. If a
   30-minute drill takes you 90 minutes, that is where you will run out of
   time on the gate.
2. **CVSS scoring must be automatic.** At 3 minutes per vulnerability, a
   justified CVSS vector should be routine. If you are still looking up what
   AV:A means, you are not ready. The reference card from Day 684 should be
   fully internalized.
3. **Advisory writing is a professional output.** A good advisory is what
   separates a researcher from a person who found a crash. Every gate and
   every real disclosure requires the same format. Write it fast; write it
   right.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q697.1, Q697.2 …).

---

## Navigation

← Previous: [Day 696 — Targeted Practice: Malware Analysis Gap Closure](DAY-0696-Practice-Malware-Analysis-Gap-Closure.md)
→ Next: [Day 698 — Final Pre-Gate Full Simulation](DAY-0698-Final-PreGate-Simulation.md)
