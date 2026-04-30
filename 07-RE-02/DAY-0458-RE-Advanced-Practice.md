---
title: "RE Advanced Practice — Days 458–480"
tags: [reverse-engineering, practice, flare-on, advanced-crackmes, malware-RE, CTF,
  obfuscation, patch-diffing]
module: 07-RE-02
day: 458
related_topics:
  - CVE Reproduction from Patch Diff (Day 457)
  - RE CTF Sprint (Days 481–489)
  - RE Competency Gate (Day 490)
---

# Days 458–480 — RE Advanced Practice

> "Theory is what you know. Practice is what you can do under pressure.
> These 23 days are not lessons. They are a proving ground. By the time
> you finish, reversing an unknown binary should feel like reading
> someone else's code in a familiar language."
>
> — Ghost

---

## Goals

Consolidate all RE techniques through intensive practice on real challenges.
Move from crackme-level binaries to real-world complexity:
packed, obfuscated, anti-debugged, multi-stage.
Prepare for the RE Competency Gate (Day 490).

**Prerequisites:** All of Days 431–457.
**Time budget:** 6–8 hours per day; 23 days total.

---

## Practice Protocol

Apply this to every binary in this block:

```
Phase 1: Triage (< 10 min)
  file, checksec, strings, readelf/pefile, entropy, imports

Phase 2: Static (primary)
  Ghidra — triage level before opening the decompiler
  Rename functions as you understand them
  Document the algorithm in plain language

Phase 3: Dynamic (when needed)
  GDB for specific value observation
  Frida for hooking comparisons, decryption outputs, anti-debug bypass

Phase 4: Solve
  Extract the flag / reproduce the vulnerability / document the capability

Phase 5: Write-up (mandatory)
  Algorithm, technique, time, what to do faster next time
```

If you spend more than 2 hours on a single binary without progress → consult hints.
Never look at a full walkthrough until you have the flag.

---

## Week 1 (Days 458–464) — Flare-On Challenges

**Platform:** Flare-On (any year, archive at flare-on.com)
**Target difficulty:** Challenges 2–5 from any Flare-On edition.

### Day 458 — Flare-On Challenge 2

**Focus:** Intermediate crackme with encoding/transform.
Apply the full triage + static workflow.
Document: what algorithm, how you identified it, time to solution.

### Day 459 — Flare-On Challenge 3

**Focus:** Multi-architecture or protocol parsing challenge.
If it is a PE, apply Windows API recognition.
If it is an ELF, apply PLT/GOT analysis.

### Day 460 — Flare-On Challenge 4

**Focus:** Obfuscated or anti-debugged binary.
Document every anti-debug technique encountered.
Bypass each one and record the bypass method.

### Day 461 — Flare-On Challenge 4 (Continued if needed)

Most Flare-On challenges 4+ take 2+ days at this stage. That is expected.
Document your progress at end of each day even if unsolved.

### Day 462 — Flare-On Challenge 5

**Focus:** Packed or multi-stage binary.
Apply the unpacking methodology (Day 452) if packed.
Apply deobfuscation if script-based (Day 455).

### Day 463 — Flare-On Write-Up Day

Write clean analysis notes for all challenges completed this week.
Follow the write-up template from Day 449.

### Day 464 — Flare-On Week Retrospective

Review what slowed you down.
Identify one technique that needs drilling this week.
Plan specific practice to close the gap.

---

## Week 2 (Days 465–471) — Real-World Malware Samples

**Platform:** MalwareBazaar, ANY.RUN, VirusTotal (sandbox analysis)
**Environment:** REMnux VM or FlareVM — fully isolated, no network

> **Safety Rule:** Malware analysis always occurs in an isolated VM with no
> network access and no shared clipboard with the host.

### Day 465 — Dropper Analysis (Day 1)

**Target:** A malware dropper (first stage). Common formats: JS, VBS, PS1,
small EXE.

**Tasks:**
1. Static analysis — triage, strings, imports.
2. Identify: what does it drop? Where? How?
3. Extract any embedded payload (base64, XOR-encoded blob).
4. Do NOT execute. Understand statically.

**Write-up:** IoCs, ATT&CK techniques, detection YARA rule.

### Day 466 — Dropper Analysis (Day 2)

Continue from Day 465 or analyse a second dropper.
Focus on the embedded payload (if extracted).

### Day 467 — Loader Analysis

**Target:** A malware loader (second stage). Usually an EXE or DLL that loads
the actual implant.

**Tasks:**
1. Identify the loading mechanism: reflective DLL, process injection,
   shellcode runner.
2. Extract and decrypt the implant if encrypted.
3. Map ATT&CK techniques: T1055 (process injection), T1036 (masquerading),
   T1140 (deobfuscation).

### Day 468 — C2 Communication Analysis

**Target:** A sample with network C2 capability.

**Tasks:**
1. Identify the C2 protocol: HTTP, DNS, raw TCP.
2. Decrypt the C2 traffic (identify the key from the binary).
3. Map the command structure (TLV, JSON, custom protocol).
4. Write a network detection signature (Suricata rule or YARA network rule).

### Day 469 — Ransomware Analysis (Static Only)

**Target:** A ransomware sample.

**Tasks:**
1. Identify the encryption algorithm (AES? RSA?).
2. Find where the key is generated and/or stored.
3. Determine: is decryption possible without the private key?
4. Identify the file extension targeting list.
5. Write a YARA rule that detects this family.

**Safety:** Absolutely no execution. Static + sandbox only.

### Day 470 — Malware Write-Up Day

Write full analysis reports for the samples analysed in Days 465–469.
Use the malware report template (IoCs, ATT&CK, detection, decryption key if
found).

### Day 471 — Malware Week Retrospective

Which analysis was hardest? Why?
Which tool (Ghidra, Frida, strace, CAPA) provided the most insight?
Update your RE pattern reference card with new patterns encountered.

---

## Week 3 (Days 472–478) — Patch Diff Practice Sprint

**CVE targets:** One per day from publicly disclosed, exploitable CVEs with
available patches.

**Daily format:**
```
1. Find pre-patch and post-patch binaries
2. Run Diaphora diff
3. Identify changed functions (top 3 by change delta)
4. Analyse root cause of the vulnerability
5. Write a crash PoC
6. Write a brief report
```

### Day 472 — CVE Sprint Day 1: Local Privilege Escalation

Pick any Linux LPE CVE from 2020–2023 where both versions are available.
Suggestions: CVE-2022-2586, CVE-2021-22555, CVE-2022-32250.

### Day 473 — CVE Sprint Day 2: Remote Code Execution

Pick a network service RCE CVE.
Suggestions: any OpenSSL, libpng, or zlib CVE with binary patch available.

### Day 474 — CVE Sprint Day 3: Command Injection

Command injection in a network service (e.g., DHCP client, DNS resolver,
package manager).

### Day 475 — CVE Sprint Day 4: Logic Bug

A logic bug or authentication bypass CVE.
These require more careful RE — the patch is a single condition change, not a
buffer overflow fix.

### Day 476 — CVE Sprint Day 5: Windows Vulnerability

Any Windows user-mode CVE (kernel32, ntdll, or Windows service).
Analyse the PE diff. Practice Windows-specific RE (IAT, TLS, WinAPI patterns).

### Day 477 — CVE Week Write-Up

Clean write-ups for all five CVE analyses.
Focus on: did your root cause analysis match the advisory? If not, why?

### Day 478 — CVE Week Retrospective

Which CVE was hardest to find from the diff alone?
What information in the advisory was NOT visible from the binary diff?
Update your patch-diffing checklist.

---

## Week 4 (Days 479–480) — Gate Preparation

### Day 479 — RE Gate Dry Run

**Simulated gate:** Pick an unknown crackme from crackmes.one (not previously
seen). Difficulty: 3–4/6.

**Time limit:** 2 hours.

**Success criteria:** Flag or correct password recovered and documented with
a clean write-up.

Do not use hints during the dry run. If you do not solve it in 2 hours,
identify exactly where you got stuck and spend additional time drilling that
skill before Day 490.

### Day 480 — Milestone Day and Module Review

**Milestone:** Review all techniques from Days 431–479.

**Self-assessment:**

| Skill | Confident? | Practice needed? |
|---|---|---|
| 5-min triage protocol | | |
| Ghidra navigation, renaming, XREF | | |
| GDB/Frida dynamic analysis | | |
| Crackme: XOR, hash, multi-stage | | |
| Detect and bypass anti-debug | | |
| Identify packed binary + manual unpack | | |
| Deobfuscate JS/PS script | | |
| Algorithm recognition (AES/SHA/RC4) | | |
| Read PE IAT, detect suspicious imports | | |
| Patch diffing with Diaphora | | |
| CVE PoC from patch diff | | |
| Malware capability analysis | | |

Any box marked "No" needs targeted practice before Day 490.

---

## Key Takeaways (Advanced Practice Block)

1. Real-world binaries are harder than crackmes, but the techniques are
   identical. The difference is volume — more functions, more layers, more
   time required.
2. Malware analysis is not about understanding every instruction. It is about
   understanding capability, mechanism, and IoCs.
3. CVE reproduction from a patch diff is repeatable. Same four steps every
   time: get binaries → diff → find root cause → write PoC.
4. Write-ups are not optional. The write-up forces you to articulate what you
   learned. If you cannot write it, you did not learn it.
5. The gate is a 2-hour unknown binary. If you can reverse a 3/6 crackme in
   under 90 minutes consistently, you are ready.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q458-480.1, …).

---

## Navigation

← Previous: [Day 457 — CVE Reproduction from Patch Diff](DAY-0457-CVE-Reproduction-from-Patch-Diff.md)
→ Next: [Days 481–489 — RE CTF Sprint](DAY-0481-RE-CTF-Sprint.md)
