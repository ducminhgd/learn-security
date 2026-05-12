---
title: "Module 10 Review — Malware Analysis and Vulnerability Research"
tags: [review, self-assessment, module-review, malware-analysis,
  vulnerability-research, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 684
prerequisites:
  - Day 683 — VulnResearch Practice Sprint Day 3
  - Days 611–683 (all Module 10 content)
related_topics:
  - Day 685 — Module Competency Check Preparation
  - Day 700 — Module Competency Check
---

# Day 684 — Module 10 Review: Malware Analysis and Vulnerability Research

> "Before any gate, you sit down and you count what you know and what you
> do not. Not what you have read — what you can do. The gate does not care
> that you read the lesson. It only cares what you can produce under
> pressure, alone, with a clock running."
>
> — Ghost

---

## Goals

Consolidate the full Module 10 body of knowledge. Identify weak areas.
Build a reference card for the Day 700 gate. Perform a self-timed drill
on the highest-probability gate topics.

**Estimated study time:** 4 hours (no coding — study and drill).

---

## 1 — Module 10 Knowledge Map

### Sub-Module A: Malware Analysis (Days 611–650)

```
MALWARE ANALYSIS — COMPLETE TOPIC REFERENCE

STATIC ANALYSIS TOOLS
  PE analysis:    pestudio, Detect-It-Easy, pefile, pe-tree
  String extract: floss, strings, FLARE FLOSS for obfuscated strings
  Import/export:  dumpbin /imports, nm, readelf -d
  Hash:           md5/sha256, ssdeep (fuzzy hash), imphash
  YARA rules:     write pattern → rule → run against sample set

DYNAMIC ANALYSIS TOOLS
  Windows sandbox: Process Monitor (procmon), Process Hacker, Regshot,
                   Wireshark, API Monitor, x64dbg/OllyDbg
  Linux sandbox:   strace, ltrace, pmap, /proc/PID, Wireshark
  Cuckoo sandbox:  automated report: network, filesystem, registry,
                   API calls, dropped files, screenshots

MALWARE FAMILY QUICK REFERENCE
  Agent Tesla:    .NET InfoStealer — dnSpy, SMTP exfil, credential theft
  Mirai:          ELF botnet — XOR decode C2, hardcoded credentials, DDoS
  Cobalt Strike:  Beacon config extraction (cs-decrypt, cs-extractor)
  Office macros:  oledump, olevba, VBA stomping, PS download cradle
  Ransomware:     Hybrid encryption (RSA+AES), shadow copy deletion
  NjRat/Quasar:   .NET RAT — pipe-delimited C2, Protobuf, AES config
  PDF malware:    pdfid, pdf-parser, peepdf, JS stream extraction

MEMORY FORENSICS (Volatility3)
  pslist / pstree:    active processes (can be hidden by rootkit)
  psscan:             scan physical memory (finds hidden processes)
  malfind:            find injected/suspicious memory regions
  netstat:            network connections
  cmdline / dlllist:  process command line and loaded DLLs
  dumpfiles:          extract files from memory
  yarascan:           YARA rules against memory
  filescan:           find file objects in memory

MALWARE ANALYSIS REPORT STRUCTURE
  1. Executive summary (malware family, capability, impact)
  2. Technical analysis (static + dynamic findings)
  3. IOCs (hashes, IPs, domains, file paths, registry keys, mutexes)
  4. MITRE ATT&CK mapping
  5. YARA detection rule
  6. Sigma detection rule
  7. Recommendations
```

### Sub-Module B: Vulnerability Research (Days 651–683)

```
VULNERABILITY RESEARCH — COMPLETE TOPIC REFERENCE

AUDIT PIPELINE (memorise this sequence)
  1. Target selection (small/medium C/C++, parses external input, active)
  2. Build with ASan + UBSan
  3. Codebase orientation (cloc, ctags, entry point grep)
  4. Automated scan (semgrep p/c, grep for sink patterns)
  5. Audit function list (HIGH/MED/LOW priority)
  6. Manual taint tracking (source → sink, function by function)
  7. Fuzzer launch (AFL++, seed corpus from test files)
  8. Crash triage (deduplicate, ASan analysis, GDB confirmation)
  9. PoC development (minimal file/packet)
  10. CVSS scoring
  11. Security advisory
  12. Responsible disclosure

BUG CLASS QUICK REFERENCE
  CWE-122/787  Heap buffer overflow: write past allocation end
    Root cause: Integer overflow before malloc, or missing bounds check
    Fix:        if (b > SIZE_MAX / a) return error; validate size

  CWE-125      OOB read: read past allocation end
    Root cause: Signed/unsigned confusion; missing bounds check on index
    Fix:        Change signed size field to unsigned; add range check

  CWE-190      Integer overflow: arithmetic wraps before size use
    Root cause: uint32 multiplication of user values without overflow check
    Fix:        Multiplication check or use SIZE_MAX / divisor pattern

  CWE-134      Format string: user input as printf format argument
    Root cause: printf(user_input) instead of printf("%s", user_input)
    Fix:        Never pass user data as format argument

  CWE-416      Use-after-free: pointer used after free()
    Root cause: Dangling pointer not NULLed; concurrent access; TOCTOU
    Fix:        Set pointer to NULL after free; use reference counting

  CWE-843      Type confusion: wrong type assumption for memory layout
    Root cause: Missing/bypassable type tag check; JIT optimisation
    Fix:        Re-validate type at point of use; use dynamic_cast

  CWE-121      Stack buffer overflow: write past stack allocation
    Root cause: alloca() or stack array sized by user input without check
    Fix:        Add bounds check; use heap allocation with validated size

TOOLS REFERENCE
  Fuzzing:     AFL++ (file/network), libFuzzer (harness), Boofuzz (network)
  Static:      Semgrep (rules p/c), CodeQL (taint tracking), Sparse (kernel)
  Dynamic:     ASan, UBSan, Valgrind, KASAN (kernel)
  Patch diff:  BinDiff (binary), Diaphora, source diff + git log
  Advisory:    CVSS calculator (nvd.nist.gov), CWE database, MITRE

CVSS v3.1 SCORING QUICK REFERENCE
  AV: N=Network, A=Adjacent, L=Local, P=Physical
  AC: L=Low (always works), H=High (special conditions needed)
  PR: N=None, L=Low (any user), H=High (admin)
  UI: N=None, R=Required (victim must act)
  S:  U=Unchanged, C=Changed (escapes scope)
  CIA: H=High (total loss), L=Low (partial), N=None

  Critical = CVSS 9.0–10.0
  High     = 7.0–8.9
  Medium   = 4.0–6.9
  Low      = 0.1–3.9
```

---

## 2 — Oral Defence Preparation

The Day 700 gate includes an oral defence. Practice these questions out
loud. Time yourself: each answer should be under 90 seconds.

```
ORAL DEFENCE QUESTIONS — MODULE 10

MALWARE ANALYSIS:
  Q1. Walk me through your first 15 minutes with an unknown Windows sample.
      What tools do you run and in what order?

  Q2. You open a PE in pestudio. What tells you this is Cobalt Strike?

  Q3. Explain how Mirai encodes its C2 communication. How do you decode it?

  Q4. You have a memory dump from a compromised host. Walk me through
      finding and extracting a DLL that was injected into lsass.exe.

  Q5. What is the difference between pslist and psscan in Volatility?
      When would you see a discrepancy and why does that matter?

  Q6. Write a YARA rule that detects ransomware based on shadow copy
      deletion behaviour.

VULNERABILITY RESEARCH:
  Q7. I give you a 30,000-line C parsing library. You have 3 hours.
      Walk me through exactly what you do to find a bug.

  Q8. What is an integer overflow vulnerability? Show me a 5-line code
      example and explain the fix.

  Q9. What is the difference between CWE-122 and CWE-787?
      (Hint: they are related but distinct.)

  Q10. I give you a CVE description for a heap buffer overflow. The patch
       is a one-line change. What does that change likely look like?

  Q11. Walk me through writing a Boofuzz harness for a protocol that
       requires authentication before sending commands.

  Q12. Calculate the CVSS v3.1 score for a network-reachable, unauthenticated
       heap buffer overflow that allows RCE. Justify every metric.
```

### Oral Answer Log

```
ORAL ANSWER QUALITY (rate 1–4 after answering each):

Q1: ___ | Q2: ___ | Q3: ___ | Q4: ___ | Q5: ___ | Q6: ___
Q7: ___ | Q8: ___ | Q9: ___ | Q10: ___ | Q11: ___ | Q12: ___

Questions rated 1–2 (need more practice):
  ___________________________________________________________
```

---

## 3 — Timed Drills

### Drill A: Semgrep to Candidate (15 minutes)

Choose any open-source C project you have not seen before.
Run semgrep and produce a triage table with top 5 candidates in 15 minutes.

```
DRILL A RESULT

Project: ____________________________
Semgrep runtime: _______ seconds
Top 5 candidates (list in 5 minutes after scan):
  1. ___________________________________________________________
  2. ___________________________________________________________
  3. ___________________________________________________________
  4. ___________________________________________________________
  5. ___________________________________________________________
Time taken: _______ min (target: 15)
```

### Drill B: Bug Class Identification (10 minutes)

For each code snippet below, identify the CWE, the triggering value,
and the fix.

```c
// Snippet 1:
void copy_msg(char *dst, const char *src) {
    int len = strlen(src);
    if (len < 64) memcpy(dst, src, len + 1);  // ← what is the bug?
}

// Snippet 2:
uint32_t n = read_u32(fp);
char *buf = malloc(n);
fread(buf, n, 1, fp);
for (uint32_t i = 0; i <= n; i++) buf[i] = 0;  // ← what is the bug?

// Snippet 3:
struct obj *o = get_object(id);
process(o);
free(o);
// ... time passes or concurrent call ...
if (o) log_result(o->status);   // ← what is the bug?
```

```
DRILL B ANSWERS

Snippet 1:
  CWE: ________ Trigger: __________________ Fix: ______________

Snippet 2:
  CWE: ________ Trigger: __________________ Fix: ______________

Snippet 3:
  CWE: ________ Trigger: __________________ Fix: ______________
```

---

## 4 — Gate Readiness Summary

```
MODULE 10 GATE READINESS

Date: _____________________________

MALWARE ANALYSIS sub-skills (4 = gate-ready):
  Static analysis:           ___/4
  Dynamic analysis:          ___/4
  .NET decompile:            ___/4
  Cobalt Strike extraction:  ___/4
  Volatility3 workflow:      ___/4
  YARA rule writing:         ___/4
  Malware report writing:    ___/4
  Average:                   ___/4

VULNERABILITY RESEARCH sub-skills:
  Audit pipeline:            ___/4
  Fuzzer setup (AFL++):      ___/4
  Network fuzzing (Boofuzz): ___/4
  Manual taint tracking:     ___/4
  PoC development:           ___/4
  CVSS scoring:              ___/4
  Advisory writing:          ___/4
  Bug class ID (all 7):      ___/4
  Average:                   ___/4

OVERALL MODULE 10 READINESS:
  Average of both averages:  ___/4

GATE DECISION:
  [ ] 3.5–4.0 — READY. Proceed to Day 685 gate preparation.
  [ ] 2.5–3.4 — CLOSE. Targeted drill on lowest-rated skills before gate.
  [ ] Below 2.5 — NEED MORE PRACTICE. Use Days 686–699 for gap closure.

TOP PRIORITY BEFORE GATE (write the 2 weakest skills):
  1. ________________________________________________________
  2. ________________________________________________________
```

---

## Key Takeaways

1. **The review is not optional prep — it is part of the learning.** The
   act of articulating what you know (the oral questions, the written
   reference) forces retrieval, which consolidates memory more than
   re-reading the lesson. Do the drills out loud.
2. **The reference card you build today is yours to keep.** The tool
   command list, the CWE quick reference, the CVSS table — write these
   by hand or in a format you will use in real engagements. Knowledge
   that is only in the lesson file is not knowledge you own.
3. **A rating of 2 on an oral question means prepare more.** A 2 means
   you understand the concept but cannot produce it under pressure. That
   is not good enough for the gate. Find the functions you are unsure of
   and practice saying the answer out loud, not just thinking it.
4. **Two days left in Module 10 before Day 700.** Day 685 is gate
   preparation. Day 700 is the gate. Use Days 686–699 for any targeted
   gap closure that Day 675's self-assessment and today's drills identified.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q684.1, Q684.2 …).

---

## Navigation

← Previous: [Day 683 — VulnResearch Practice Sprint Day 3](DAY-0683-VulnResearch-Practice-Sprint-Day3.md)
→ Next: [Day 685 — Module Competency Check Preparation](DAY-0685-Module-Competency-Check-Preparation.md)
