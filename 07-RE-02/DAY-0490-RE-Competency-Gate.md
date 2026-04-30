---
title: "RE Competency Gate — Reverse Engineering Ready"
tags: [reverse-engineering, competency-gate, assessment, crackme, packed-binary,
  write-up]
module: 07-RE-02
day: 490
related_topics:
  - RE CTF Sprint (Days 481–489)
  - Red Team Operations (Day 491, next module)
  - Binary Exploitation Gate (Day 430)
---

# Day 490 — Reverse Engineering Competency Gate

> "The gate is not a test. It is a confirmation. If you have done the work
> — the crackmes, the malware samples, the CVE reproductions, the CTF sprints
> — you already know you can do this. The gate is just you proving it to
> yourself on an unknown binary."
>
> — Ghost

---

## Gate Overview

**Name:** Reverse Engineering Ready
**Duration:** 4 hours maximum
**Format:** Solo, untimed within the 4-hour window
**Type:** Practical — two binaries, one write-up each

---

## Gate Tasks

### Task 1: Unknown Crackme (2 hours)

**Binary:** Obtain an unseen crackme from crackmes.one.
- Platform: Linux x64
- Difficulty: 3–4 out of 6
- Confirmed by instructor: previously unseen

**Requirements to pass:**
1. Complete the five-minute triage protocol and record findings.
2. Identify the validation algorithm through static analysis in Ghidra.
3. Recover the correct password/key without brute-forcing.
4. Write a clean analysis note (< 500 words):
   - Binary description
   - Algorithm and technique used
   - Assembly evidence (at least one screenshot or code block)
   - Time to solution
   - Real-world parallel: what malware class or obfuscation technique
     does this remind you of?

**Pass criteria:**
- Correct flag/password submitted and confirmed working.
- Write-up clearly explains the algorithm.
- Assembly evidence shows you read the disassembly, not just the decompiler.

---

### Task 2: Packed or Obfuscated Binary (2 hours)

**Binary:** A packed or obfuscated binary provided by the instructor.
Choose one of:

A. **Packed binary** — contains a packed payload that must be extracted and
   analysed.

B. **Obfuscated script** — a multi-layer PowerShell or JavaScript dropper that
   must be fully deobfuscated.

**Requirements to pass:**
1. Detect the obfuscation/packing technique and name it.
2. Unpack/deobfuscate the payload.
3. Identify the payload's primary capability (what it does):
   - For a binary: what does the unpacked program do? Any crypto? Any C2?
   - For a script: what does the final decoded command do?
4. Write a complete IoC report:
   - File hashes (SHA256 of original and unpacked)
   - URLs, IPs, domain names found
   - File paths, registry keys (if Windows)
   - YARA rule that detects the packer OR the payload

**Pass criteria:**
- Packing/obfuscation correctly identified.
- Unpacked/decoded content readable and described accurately.
- At least one working YARA rule that matches the sample.

---

## Grading

| Task | Weight | Pass threshold |
|---|---|---|
| Task 1: Crackme | 50% | Correct answer + complete write-up |
| Task 2: Packed/Obfuscated | 50% | Correct unpack + IoC report with YARA |
| **Overall** | 100% | Both tasks must pass independently |

There is no partial credit. The gate is pass/fail per task.

---

## What Ghost Looks For

### In the Crackme Write-Up

```
Ghost is NOT looking for:
  "I ran ltrace and saw the strcmp argument was 'gh0st_w4s_here'."

Ghost IS looking for:
  "The binary implements a custom comparison loop at FUN_00401156.
   Each byte of the input is compared against the corresponding byte of
   the hardcoded array at 0x00402010 in .rodata. The array decodes to
   'gh0st_w4s_here' when interpreted as ASCII. No transformation is
   applied — this is a direct character comparison.
   
   This pattern is identical to the password storage approach in early
   versions of poorly-coded authentication libraries (e.g., plaintext
   comparison instead of hashing). YARA rule: match 'gh0st_w4s_here'
   string in .rodata."
```

The difference: the second answer shows you understand the mechanism, not just
the result.

### In the IoC Report

```
Ghost is NOT looking for:
  "The binary downloads something."

Ghost IS looking for:
  "The payload is a PowerShell dropper using Invoke-WebRequest to download
   a second-stage binary from http://192.168.1.100/stage2.exe.
   The URL is stored as a base64-encoded string (decoded: see above).
   The second stage is written to %TEMP%\svchost32.exe and executed via
   Start-Process.
   
   MITRE ATT&CK: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer),
   T1036.005 (Match Legitimate Name or Location — svchost32.exe).
   
   YARA rule:
     strings: $url = 'http://192.168.1.100/stage2.exe'
              $encoded = '<base64 of URL>'
     condition: $url or $encoded"
```

---

## Gate Preparation Checklist

Before starting the gate, confirm you can do each of these without notes:

- [ ] Run the five-minute triage protocol on an unknown binary
- [ ] Navigate to main() in a stripped ELF in Ghidra
- [ ] Rename three unknown functions based on their behaviour
- [ ] Read a comparison loop in the Listing (not just the decompiler)
- [ ] Hook `strcmp` with Frida in under 3 minutes
- [ ] Bypass `ptrace` anti-debug with a one-liner Frida script
- [ ] Identify a packed binary by entropy and section name
- [ ] Run `die` and interpret the result
- [ ] Manually unpack a UPX binary in GDB
- [ ] Deobfuscate a base64-encoded PowerShell command in Python
- [ ] Write a YARA rule for a string found in a binary

If any box is unchecked: practice it today before starting the gate.

---

## After the Gate

**If you passed:**

Congratulations. You are **Reverse Engineering Ready**.

You can:
- Reverse unknown binaries under time pressure.
- Identify obfuscation and packing, and defeat it.
- Produce analysis reports that defenders can act on.
- Identify vulnerabilities from patch diffs.

Your next module is Red Team Operations (Day 491).
The RE skills you built here apply directly: payload analysis, AV evasion
understanding, implant capability assessment.

**If you did not pass Task 1:**

Identify exactly where you got stuck. Was it:
- Triage → drill the five-minute protocol on 10 more binaries.
- Algorithm recognition → drill the algorithm recognition sprint (Day 484).
- Reading assembly → practice the assembly reading exercises from Day 434.

Spend 3–5 days drilling the specific gap and re-take the task.

**If you did not pass Task 2:**

Identify the failure point:
- Could not detect packing → drill the entropy and signature detection protocol.
- Could not unpack → drill the manual unpacking lab (Day 452).
- Could not deobfuscate → drill the deobfuscation lab (Day 455).

---

## Key Takeaways

1. The gate tests competency, not completion. Passing means you can do this on
   an unknown target — not that you memorised examples.
2. The write-up is half the grade. A correct answer without explanation is a
   guess. Explanation proves understanding.
3. Speed matters but correctness is mandatory. A wrong answer submitted quickly
   fails. A correct answer submitted slowly passes.
4. The skills tested here (binary triage, algorithm recognition, unpacking,
   YARA writing) are daily work for malware analysts and red teamers.
5. Day 491 starts the Red Team Operations module. RE and exploitation feed each
   other — understanding how payloads are built makes you a better red teamer.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q490.1, Q490.2 …).

---

## Navigation

← Previous: [Days 481–489 — RE CTF Sprint](DAY-0481-RE-CTF-Sprint.md)
→ Next: [Day 491 — Red Team vs Pentest Mindset](../08-RedTeam-01/DAY-0491-Red-Team-vs-Pentest-Mindset.md)
