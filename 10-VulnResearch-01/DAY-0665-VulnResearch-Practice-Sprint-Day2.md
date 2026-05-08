---
title: "Vulnerability Research Practice Sprint — Day 2 (PoC + Advisory)"
tags: [vulnerability-research, lab, practice-sprint, PoC-development,
  security-advisory, CVSS, remediation, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 665
prerequisites:
  - Day 664 — Vulnerability Research Practice Sprint Day 1
  - Day 659 — Writing a Security Advisory
related_topics:
  - Module Review and Competency Check (Day 680+)
---

# Day 665 — Vulnerability Research Practice Sprint: Day 2

> "Yesterday you found something. Maybe a crash, maybe a candidate, maybe
> a confirmed taint path. Today you do the part that separates researchers
> from hunters: you prove it, minimise it, score it, and write the advisory.
> The finding is not a finding until someone else can reproduce it from your
> instructions alone. That is today's standard."
>
> — Ghost

---

## Goals

Develop a working PoC (or confirm DoS) for the best candidate from Day 1.
Minimise the PoC to the smallest possible input. Write a complete security
advisory in the format from Day 659. Score the finding with CVSS v3.1.
Draft a responsible disclosure notification.

**Prerequisites:** Days 664, 659.
**Estimated study time:** 5 hours (unguided lab).

---

## Sprint 1 — PoC Development (120 minutes)

### Confirming the Root Cause

Before writing the PoC, confirm you understand what is happening:

```
ROOT CAUSE ANALYSIS

Target function: ________________________________________________
File:            ________________________________________________
Line:            ________________________________________________

DESCRIBE THE BUG IN ONE SENTENCE:
  ________________________________________________

TRIGGERING CONDITION (what input value causes the bug?):
  Field name / offset: ________________________________________
  Triggering value:    ________________________________________
  Why does this value trigger the bug?
    ________________________________________________

WHAT HAPPENS AT THE VULNERABLE SITE:
  [ ] Buffer of size N is written with M bytes where M > N
  [ ] Integer of type T is multiplied producing value > T_MAX
  [ ] Pointer is used after free() was called
  [ ] User format string is passed to printf family
  [ ] Command string is constructed from user input + shell=True
  [ ] Other: _________________________________________________

IS THIS REACHABLE WITHOUT AUTHENTICATION? Y / N / PARTIAL
  Reasoning: ________________________________________________
```

### PoC Script

```python
#!/usr/bin/env python3
"""
Vulnerability Research Sprint Day 2 — PoC generator.

Fill in the craft_poc() function for your specific finding.
This template handles binary file format bugs.
For network bugs, see the network_poc() function below.
"""
from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path


def craft_file_poc() -> bytes:
    """
    Craft the minimal input that triggers the vulnerability.

    INSTRUCTIONS:
    1. Start with the smallest valid file for the target format.
    2. Identify the field that triggers the bug (from your audit).
    3. Set that field to the triggering value.
    4. Keep all other fields valid.
    5. Test: does the crash occur? If not, re-examine the trigger condition.
    6. Remove bytes: does the crash still occur? If yes, keep removing.
    """
    # ── CUSTOMISE BELOW FOR YOUR TARGET ──────────────────────────
    #
    # Example: binary format with a size field at offset 8 (4 bytes LE)
    # Vulnerability: memcpy(buf[64], data, size) — buf is 64 bytes
    # Trigger: size field >= 64

    # Valid file header
    poc = b""
    poc += b"MAGIC\x00"                  # magic bytes — keep valid
    poc += b"\x01\x00"                  # version — keep valid
    poc += struct.pack("<I", 0xFFFFFFFF) # size field — TRIGGERING VALUE
    poc += b"A" * 64                    # payload (filler up to 64 bytes minimum)

    # ── END CUSTOMISATION ────────────────────────────────────────
    return poc


def craft_network_poc(host: str = "127.0.0.1", port: int = 9999) -> None:
    """
    Craft and send a network PoC to trigger the vulnerability.
    For file-based bugs: ignore this function and use craft_file_poc().
    """
    # ── CUSTOMISE BELOW FOR YOUR TARGET ──────────────────────────
    poc_packet = b""
    poc_packet += struct.pack("<I", 0xFFFF)  # length field — triggering value
    poc_packet += b"\x01"                    # command byte
    poc_packet += b"A" * 0xFFFF             # oversized payload

    # ── END CUSTOMISATION ────────────────────────────────────────
    with socket.create_connection((host, port), timeout=5) as sock:
        print(f"[*] Connected to {host}:{port}")
        sock.sendall(poc_packet)
        print(f"[*] Sent {len(poc_packet)} bytes")
        try:
            response = sock.recv(1024)
            print(f"[*] Response: {response[:50]!r}")
        except (ConnectionResetError, TimeoutError):
            print("[!] Connection reset or timeout — possible crash!")


if __name__ == "__main__":
    output_path = Path(sys.argv[1] if len(sys.argv) > 1 else "poc.bin")
    poc = craft_file_poc()
    output_path.write_bytes(poc)
    print(f"[*] PoC written: {output_path} ({len(poc)} bytes)")
    print(f"[*] Run:  ./vulnerable_binary {output_path}")
    print(f"[*] Run:  ./asan_binary {output_path} 2>&1 | head -40")
    print(f"[*] Goal: AddressSanitizer crash in the target function")
```

```
PoC DEVELOPMENT LOG

Attempt 1:
  Command: _______________________________________________
  Result: ________________________________________________
  Crash? Y / N

Attempt 2 (if adjustments needed):
  What changed: __________________________________________
  Command: _______________________________________________
  Crash? Y / N

Attempt 3 (if adjustments needed):
  What changed: __________________________________________
  Crash? Y / N

CONFIRMED CRASH:
  Command: _______________________________________________
  ASan/crash output (first 10 lines):
    ________________________________________________
    ________________________________________________
    ________________________________________________

  Crash function (from stack trace):
    ________________________________________________

  Does crash function match the vulnerable function from audit? Y / N
```

---

## Sprint 2 — Minimisation (30 minutes)

```bash
# Minimise with libFuzzer's built-in minimiser:
./fuzzer poc.bin -minimize_crash=1 -artifact_prefix=crashes/min_ 2>&1

# OR with afl-tmin:
afl-tmin -i poc.bin -o poc_minimal.bin -- ./asan_binary @@

# Verify minimised PoC still crashes:
./asan_binary poc_minimal.bin 2>&1 | head -5

# Manual minimisation (if tools are unavailable):
# Binary search: remove the second half of the file, test, repeat
python3 -c "
import subprocess, sys
data = open('poc.bin', 'rb').read()
for size in [len(data)//2, len(data)//4, len(data)//8, 32, 16, 8]:
    if size < 4: break
    test = data[:size]
    open('/tmp/test.bin', 'wb').write(test)
    result = subprocess.run(['./asan_binary', '/tmp/test.bin'],
                            capture_output=True, timeout=5)
    crashed = result.returncode != 0
    print(f'  {size:6} bytes: {\"CRASH\" if crashed else \"ok\"}')
"
```

```
MINIMISATION LOG

Original PoC size:   _______ bytes
Minimised PoC size:  _______ bytes
Reduction:           _______ % 
Minimised PoC reproduces crash: Y / N

MINIMISED PoC (hex dump for ≤ 64 bytes, or describe trigger bytes):
  ________________________________________________
  ________________________________________________

KEY BYTES (what bytes/fields are essential?):
  Offset 0x__: _____ (reason: _______________________ )
  Offset 0x__: _____ (reason: _______________________ )
```

---

## Sprint 3 — CVSS Scoring (20 minutes)

```python
#!/usr/bin/env python3
"""
CVSS v3.1 scoring worksheet for your finding.
Work through each metric based on the actual exploit conditions.
"""
from __future__ import annotations

CVSS_WORKSHEET = {
    "AV": {
        "question": "How does the attacker deliver the malicious input?",
        "options": {
            "N": "Via the network (no physical/local access needed)",
            "A": "Via the adjacent network (same LAN/VLAN/Bluetooth)",
            "L": "Locally (requires login or shell on the system)",
            "P": "Physical access to the device",
        },
        "your_choice": "___",
        "justification": "_________________________________________",
    },
    "AC": {
        "question": "Does the attack require special conditions beyond sending the input?",
        "options": {
            "L": "Low — attack works reliably with no special conditions",
            "H": "High — requires race condition, specific configuration, or information",
        },
        "your_choice": "___",
        "justification": "_________________________________________",
    },
    "PR": {
        "question": "Does the attacker need an account on the target system?",
        "options": {
            "N": "No account needed (unauthenticated)",
            "L": "Requires a standard user account",
            "H": "Requires an admin or privileged account",
        },
        "your_choice": "___",
        "justification": "_________________________________________",
    },
    "UI": {
        "question": "Does a victim user need to perform an action for the attack to succeed?",
        "options": {
            "N": "No — server-side bug, no victim interaction needed",
            "R": "Required — victim must open a file, click a link, etc.",
        },
        "your_choice": "___",
        "justification": "_________________________________________",
    },
    "S": {
        "question": "Can the attacker impact components beyond the vulnerable component?",
        "options": {
            "U": "Unchanged — impact confined to the vulnerable component",
            "C": "Changed — attacker can affect other components (e.g. host escape from container)",
        },
        "your_choice": "___",
        "justification": "_________________________________________",
    },
    "C_I_A": {
        "question": "What is the impact on Confidentiality / Integrity / Availability?",
        "options": {
            "H": "High — total loss (all data readable / arbitrary write / complete crash)",
            "L": "Low — partial impact",
            "N": "None — no impact on this metric",
        },
        "confidentiality_choice": "___",
        "integrity_choice":      "___",
        "availability_choice":   "___",
        "justification": "_________________________________________",
    },
}

print("[*] CVSS v3.1 SCORING WORKSHEET")
for metric, data in CVSS_WORKSHEET.items():
    print(f"\n  METRIC: {metric}")
    print(f"  Q: {data['question']}")
    for val, desc in data.get("options", {}).items():
        print(f"    {val}: {desc}")
```

```
CVSS RESULT

AV: ___   AC: ___   PR: ___   UI: ___   S: ___
C: ___    I: ___    A: ___

Vector string: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Calculated score: _______ (use cvss.js or nvd.nist.gov/vuln-metrics/cvss)
Severity: [ ] Critical (9.0–10.0)  [ ] High (7.0–8.9)  [ ] Medium (4.0–6.9)  [ ] Low

Justification for each metric (key ones):
  AV: ___________________________________________
  PR: ___________________________________________
  Impact (C/I/A): _______________________________
```

---

## Sprint 4 — Security Advisory (60 minutes)

Write a full advisory using the format from Day 659. At minimum, fill in
every section. Use the template below as your starting point.

```
SECURITY ADVISORY
=================

TITLE:
  [CWE-NNN] [Vulnerability class] in [Product] [version range]
  Example: [CWE-122] Heap buffer overflow in libfoo <= 2.3.1 parse_header()

ADVISORY ID:    SPRINT-YYYY-665-001
CVE ID:         (N/A — not yet assigned; would request via GitHub Security or MITRE)
CVSS v3.1:      [your score] [Critical/High/Medium/Low]
VECTOR:         CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

DISCOVERED:     [today's date]
AUTHOR:         [your name/handle]

───────────────────────────────────────────────────────────
SUMMARY
───────────────────────────────────────────────────────────
[2–3 sentence summary: product, version, class, attack vector, worst-case impact]

___________________________________________________________
___________________________________________________________
___________________________________________________________

───────────────────────────────────────────────────────────
AFFECTED VERSIONS
───────────────────────────────────────────────────────────
Product: __________________________ Versions: ______________
Fixed version: _______ (if patched) / Not yet patched (as of YYYY-MM-DD)

───────────────────────────────────────────────────────────
VULNERABILITY DETAILS
───────────────────────────────────────────────────────────
CWE: _______________________________________________________
Root cause:
  ___________________________________________________________
  ___________________________________________________________

Vulnerable code (annotated):
  [paste the relevant vulnerable lines here]

Triggering condition:
  ___________________________________________________________

Is the vulnerable code path reachable without authentication?
  Y / N — Reasoning: _______________________________________

───────────────────────────────────────────────────────────
IMPACT
───────────────────────────────────────────────────────────
[Describe: what can the attacker do? Be specific. What data is accessible?
What is the realistic worst-case scenario? Does this affect production deployments?]

___________________________________________________________
___________________________________________________________
___________________________________________________________

───────────────────────────────────────────────────────────
PROOF OF CONCEPT
───────────────────────────────────────────────────────────
Requirements: [list: OS, library version, tools needed]

Setup:
  git clone [repo]
  git checkout [vulnerable_commit]
  [build commands]

Run PoC:
  python3 poc.py [output_file]
  ./vulnerable_binary [output_file]

Expected output:
  [paste first 10 lines of ASan output or crash trace]

───────────────────────────────────────────────────────────
REMEDIATION
───────────────────────────────────────────────────────────
Primary fix: [update to version X.Y.Z if patched; or describe required fix]

Root cause fix (the code change needed):
  [describe or show the fix — the specific check or type change]

Workaround: [if no patch is available; specific config change, if any]

───────────────────────────────────────────────────────────
TIMELINE
───────────────────────────────────────────────────────────
[Today's date]: Vulnerability discovered during research sprint
[Would notify]: Vendor via SECURITY.md contact or security@[domain]
[90-day window]: Public disclosure deadline

───────────────────────────────────────────────────────────
REFERENCES
───────────────────────────────────────────────────────────
Repository: [URL]
Commit audited: [hash]
NVD (if CVE assigned): N/A
CWE: https://cwe.mitre.org/data/definitions/NNN.html
```

---

## Sprint 5 — Responsible Disclosure Draft (20 minutes)

Write the email you would send to the vendor's security contact if this were
a real engagement. Use a professional tone. Include everything the vendor needs
to reproduce the issue.

```
DRAFT DISCLOSURE EMAIL
═══════════════════════════════════════════════════════════════════════

To: security@[vendor].com (or contact from SECURITY.md)
Subject: Security Vulnerability in [Product] <= [version]: [brief class]

Hello [Product] Security Team,

I am writing to report a security vulnerability I discovered in [Product]
version [range] during a research review.

SUMMARY:
[1–2 sentence summary of the finding.]

SEVERITY: [Critical/High/Medium/Low] — CVSS v3.1 [score]
VECTOR: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

AFFECTED VERSIONS: [Product] <= [version]

REPRODUCTION:
  [list exact steps]

IMPACT:
  [1 paragraph on what an attacker can do]

SUGGESTED FIX:
  [describe the correct fix — the specific check or change needed]

I would like to follow a coordinated disclosure process. My default
disclosure timeline is 90 days from this email. If a fix requires more
time, I am happy to discuss an extension for complex patches where clear
progress is demonstrated.

Please confirm receipt of this report and let me know if you need any
additional information to reproduce the issue.

Best regards,
[Your name]
[Contact information]
[PGP key fingerprint, if applicable]

───────────────────────────────────────────────────────────
END DRAFT
───────────────────────────────────────────────────────────

DISCLOSURE PLAN (for lab purposes — do NOT send to vendor without real finding):
  [ ] This is a real finding — I will send the email above to the vendor
  [ ] This is a lab exercise — filing as an internal finding report only
  [ ] The finding is a known/already-fixed issue — noting as learning exercise
```

---

## Day 2 Retrospective

```
SPRINT RETROSPECTIVE

Total time on Day 2: _______ hours

FINDING STATUS:
  [ ] Confirmed bug with working crash PoC
  [ ] Confirmed bug — DoS only (no write primitive)
  [ ] Candidate found — taint path confirmed, PoC not yet working
  [ ] No exploitable bug found — false positive from Day 1 candidate

ADVISORY QUALITY (self-assess):
  Summary is clear and specific:               Y / N
  Root cause is explained (not just symptom):  Y / N
  PoC is reproducible by a stranger:           Y / N
  CVSS vector is justified:                    Y / N
  Remediation is actionable:                   Y / N
  Timeline is documented:                      Y / N

WHAT I LEARNED:
  Most surprising aspect of the finding:
    ________________________________________________

  What slowed me down most?
    ________________________________________________

  What would I do differently next time?
    ________________________________________________

GHOST'S STANDARD: Did you find a real issue in a real project?
  [ ] YES — this is a genuine finding in software used in production
  [ ] NO  — this was a learning exercise on a known-vulnerable practice target
```

---

## Key Takeaways

1. **A PoC is a proof, not a demonstration.** The PoC must be reproducible by
   someone who was not in the room when you found the bug. Every required
   step must be written down — library version, build flags, exact command.
   If someone else cannot reproduce it from your instructions alone, it is
   not a PoC; it is a note about something you saw once.
2. **Minimisation is not optional — it is the analysis.** The process of
   removing bytes from a crash PoC until the crash disappears tells you
   exactly which bytes matter. Those bytes encode the triggering condition.
   When you can articulate "this specific value at this specific offset
   causes the overflow because it controls the length passed to memcpy",
   you understand the bug. Before minimisation, you have a crash. After
   minimisation and analysis, you have a finding.
3. **The CVSS score is your opening argument in a negotiation.** Vendors use
   CVSS to prioritise patch schedules. If you score your Medium as a High or
   Critical, you will be challenged in triage and lose credibility. Score
   precisely and justify every metric. A well-justified Medium gets patched
   on schedule. An overclaimed Critical gets disputed and delayed.
4. **Two days of research on one target teaches you more than two days of
   reading about research.** The theory is in the earlier modules. The
   practice — the target selection, the dead ends, the moment you see the
   crash function and recognize the code you audited — that is the skill.
   Every sprint like this one makes the next target faster to audit and the
   next bug faster to find.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q665.1, Q665.2 …).

---

## Navigation

← Previous: [Day 664 — Vulnerability Research Practice Sprint Day 1](DAY-0664-VulnResearch-Practice-Sprint-Day1.md)
→ Next: [Day 666 — Open-Source Project Audit Campaign Start](DAY-0666-Open-Source-Audit-Campaign.md)
