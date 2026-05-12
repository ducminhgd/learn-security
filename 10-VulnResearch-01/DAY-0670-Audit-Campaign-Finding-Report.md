---
title: "Audit Campaign Day 5 — Finding Report and Disclosure Decision"
tags: [vulnerability-research, code-audit, security-advisory, disclosure,
  report-writing, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 670
prerequisites:
  - Day 669 — Audit Campaign Day 4: PoC Development
  - Day 659 — Writing a Security Advisory
related_topics:
  - Day 671 — Bug Class: Type Confusion (CWE-843)
  - Day 658 — Responsible Disclosure Deep Dive
---

# Day 670 — Audit Campaign Day 5: Finding Report and Disclosure Decision

> "The finding becomes a contribution the moment you write it down so
> clearly that someone else can act on it. Before that, it is just
> something you know. Write it down. Publish it through the right
> channel. That is how the industry gets better — one documented finding
> at a time."
>
> — Ghost

---

## Goals

Write a complete, disclosure-ready security advisory for the strongest
finding from this campaign. Make the disclosure decision. Produce a campaign
retrospective. Set up Day 671.

**Prerequisites:** Day 669 (PoC confirmed, bug summary written).
**Estimated study time:** 4–5 hours.

---

## 1 — Complete Security Advisory

Use the full advisory format from Day 659. This is the final deliverable
from the five-day audit campaign.

```
SECURITY ADVISORY
═══════════════════════════════════════════════════════════════

TITLE:
  [CWE-NNN] [Bug class] in [Project] [version range] [function]

ADVISORY ID:   AUDIT-CAMPAIGN-YYYY-670-001
CVE ID:        (request after disclosure; N/A for lab exercise)
CVSS v3.1:     [calculated score] [Critical/High/Medium/Low]
VECTOR:        CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

DISCOVERED:    [date]
AUDITOR:       [name/handle]
TARGET:        [project name + version / git commit]

───────────────────────────────────────────────────────────────
EXECUTIVE SUMMARY
───────────────────────────────────────────────────────────────
[2–3 sentences. Product, version, what the bug is, attack vector,
worst-case impact.]

_______________________________________________________________
_______________________________________________________________
_______________________________________________________________

───────────────────────────────────────────────────────────────
AFFECTED VERSIONS
───────────────────────────────────────────────────────────────
Product:         ___________________________
Affected:        <= [version or commit hash]
Not affected:    >= [version if patched] / unknown as of [date]

───────────────────────────────────────────────────────────────
VULNERABILITY DETAILS
───────────────────────────────────────────────────────────────
CWE:  _______________

Root cause:
  _______________________________________________________________
  _______________________________________________________________

Vulnerable code (annotated — paste relevant lines with comments):

  File: _________________ Lines: _____–_____
  ─────────────────────────────────────────────────────────────
  [paste 5–15 lines of vulnerable code here; annotate with // comments]
  ─────────────────────────────────────────────────────────────

Taint path:
  1. Source: user-controlled data enters at [function:line]
  2. Propagation: value is stored in [variable] without range check
  3. Sink: value is used as size in [operation] at [function:line]

Triggering condition:
  Field at offset: ___________________________________________
  Triggering value: _________________________________________
  Effect: ___________________________________________________

Reachable without authentication? Y / N
  Reasoning: ________________________________________________

───────────────────────────────────────────────────────────────
IMPACT
───────────────────────────────────────────────────────────────
[Describe the worst-case outcome from an attacker's perspective.
Be specific: "an attacker who supplies a specially crafted [file type]
to a server running [product] can [specific impact]." Do not be vague.]

_______________________________________________________________
_______________________________________________________________
_______________________________________________________________

───────────────────────────────────────────────────────────────
PROOF OF CONCEPT
───────────────────────────────────────────────────────────────
Tested on:
  OS:             ____________________________________________
  Compiler:       ____________________________________________
  Library version: __________________________________________
  ASan:           clang -fsanitize=address,undefined

Build instructions:
  git clone [URL]
  git checkout [commit hash]
  [build commands]

PoC:
  python3 poc_campaign.py poc.bin
  ./build-asan/[binary] poc.bin

Expected output:
  ==NNNN==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
  [paste first 15 lines of ASan output here]

───────────────────────────────────────────────────────────────
REMEDIATION
───────────────────────────────────────────────────────────────
Fix (describe or show the specific code change):

  Current (vulnerable):
    [paste vulnerable code]

  Corrected:
    [paste corrected code with bounds check / type change / validation]

  Explanation:
    ___________________________________________________________

Workaround (if no patch available):
  ___________________________________________________________

───────────────────────────────────────────────────────────────
TIMELINE
───────────────────────────────────────────────────────────────
[date of campaign Day 1]: Audit started
[date Day 4]:             Bug confirmed with working PoC
[date Day 5]:             Advisory drafted
[disclosure date]:        Report submitted to vendor (or N/A for lab)
[90-day deadline]:        Public disclosure if no response

───────────────────────────────────────────────────────────────
REFERENCES
───────────────────────────────────────────────────────────────
Repository: [URL]
Audited commit: [hash]
CWE: https://cwe.mitre.org/data/definitions/NNN.html
Related CVEs (if known): ____________________________________
```

---

## 2 — CVSS Scoring — Final

Score this finding carefully. Refer to Day 659 for metric definitions.

```python
#!/usr/bin/env python3
"""CVSS v3.1 final scoring for the audit campaign finding."""

# Complete these with your actual values:
METRICS = {
    "AV": "__",   # N (Network), A (Adjacent), L (Local), P (Physical)
    "AC": "__",   # L (Low), H (High)
    "PR": "__",   # N (None), L (Low), H (High)
    "UI": "__",   # N (None), R (Required)
    "S":  "__",   # U (Unchanged), C (Changed)
    "C":  "__",   # N, L, H
    "I":  "__",   # N, L, H
    "A":  "__",   # N, L, H
}

vector = (
    f"CVSS:3.1/AV:{METRICS['AV']}/AC:{METRICS['AC']}"
    f"/PR:{METRICS['PR']}/UI:{METRICS['UI']}"
    f"/S:{METRICS['S']}/C:{METRICS['C']}"
    f"/I:{METRICS['I']}/A:{METRICS['A']}"
)
print(f"Vector string: {vector}")
print("Calculate score: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator")
```

```
CVSS FINAL DECISION

AV: ___  AC: ___  PR: ___  UI: ___  S: ___  C: ___  I: ___  A: ___

Vector: CVSS:3.1/___________________________________________
Score:  _______ — Severity: Critical / High / Medium / Low

Key justifications:
  AV rationale:  ______________________________________________
  PR rationale:  ______________________________________________
  Impact rationale (C/I/A): ___________________________________
```

---

## 3 — Disclosure Decision

```
DISCLOSURE DECISION

FINDING STATUS:
  [ ] Real bug, real project, not yet disclosed publicly
  [ ] Known / already-patched CVE (used as a learning exercise)
  [ ] False positive — no security impact
  [ ] DoS-only, low severity — will submit but not treat as critical

IF REAL AND NOT DISCLOSED:
  Vendor contact:
    [ ] SECURITY.md in repository — contact: ___________________
    [ ] GitHub Security Advisories — "Report a vulnerability"
    [ ] HackerOne / Bugcrowd programme: ______________________
    [ ] security@[vendor].com
    [ ] No public contact — will use GitHub private vulnerability reporting

  My disclosure timeline: 90 days from report date

  Have I filed this as a CVE? Y / N
    [ ] Will request via MITRE (https://cve.mitre.org/cgi-bin/cvename.cgi)
    [ ] Will request via GitHub (github.com/orgs/security-lab/discussions)
    [ ] Will not request (low severity / lab exercise)

IF LAB EXERCISE ONLY:
  Summarise what you would do if this were real:
    ___________________________________________________________
    ___________________________________________________________

FINAL STATUS:
  [ ] Submitted to vendor
  [ ] Will submit within [N] days
  [ ] Lab exercise — documented as internal finding only
```

---

## 4 — Campaign Retrospective

Complete this after submitting the advisory.

```
FIVE-DAY AUDIT CAMPAIGN RETROSPECTIVE

Project audited: _____________________________________________
Total hours:     _____________________________________________

FINDINGS SUMMARY
  Confirmed bugs: ______
  Candidates (unconfirmed): ______
  False positives: ______
  DoS only: ______
  Potentially exploitable (RCE/info leak): ______

STRONGEST FINDING:
  Title: ___________________________________________________
  CWE: ________________ CVSS: ____________________________
  Advisory submitted: Y / N / lab only

WHAT WENT WELL:
  ___________________________________________________________
  ___________________________________________________________

WHAT I WOULD DO DIFFERENTLY:
  ___________________________________________________________
  ___________________________________________________________

SKILLS REINFORCED BY THIS CAMPAIGN:
  [ ] Codebase orientation
  [ ] Taint path tracing
  [ ] Integer overflow identification
  [ ] Fuzzer setup and crash triage
  [ ] PoC development
  [ ] CVSS scoring
  [ ] Advisory writing
  [ ] Responsible disclosure process

SKILL GAPS IDENTIFIED (things I was slow at or got wrong):
  ___________________________________________________________
  ___________________________________________________________

TIME DISTRIBUTION:
  Day 666 (scoping):      ______ h
  Day 667 (navigation):   ______ h
  Day 668 (manual read):  ______ h
  Day 669 (PoC):          ______ h
  Day 670 (report):       ______ h
  Total:                  ______ h

GHOST'S STANDARD: Did this campaign produce a real finding?
  [ ] YES — genuine bug in a real project; advisory filed / ready to file
  [ ] PARTIAL — bug found in project but not security-significant
  [ ] NO  — no confirned bug; the audit was learning, not finding
  [ ] NO  — chose a target that was too large; ran out of scope
```

---

## Key Takeaways

1. **Five days is enough to find a real bug.** This campaign proves the
   minimum viable engagement: one week, one focused person, one well-chosen
   target. Professional vulnerability researchers operate at larger scale
   and with more experience, but the same methodology applies. The process
   is what you now have.
2. **The advisory is the deliverable.** The PoC is evidence. The analysis
   is understanding. But the advisory is the deliverable — the document
   that makes the vulnerability actionable for defenders, vendors, and
   the security community. Write it as well as you write code.
3. **Responsible disclosure is not optional.** Real findings in real
   projects affect real users. You have 90 days to give the vendor a
   chance to fix the bug before the community knows about it. That is the
   social contract of vulnerability research. Honor it.
4. **Every audit makes the next one faster.** The first audit takes five
   days and finds one bug. The tenth audit takes three days and finds three.
   The patterns repeat across projects: the same arithmetic errors, the same
   missing bounds checks, the same classes of trust violations. Build the
   pattern library in your head. It compounds.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q670.1, Q670.2 …).

---

## Navigation

← Previous: [Day 669 — Audit Campaign Day 4: PoC Development](DAY-0669-Audit-Campaign-PoC-Development.md)
→ Next: [Day 671 — Bug Class: Type Confusion (CWE-843)](DAY-0671-Bug-Class-Type-Confusion.md)
