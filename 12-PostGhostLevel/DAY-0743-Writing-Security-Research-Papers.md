---
title: "Writing Security Research Papers — Structure, PoC Sections, Venue Selection"
tags: [research-writing, academic-paper, blog-post, conference-talk, usenix, defcon,
  module-12-postghost]
module: 12-PostGhostLevel
day: 743
prerequisites:
  - Day 732 — Building Your Public Profile
  - Day 659 — Writing a Security Advisory
related_topics:
  - Day 744 — CTF Team Strategy
---

# Day 743 — Writing Security Research Papers

> "The research does not count until it is communicated. Every undocumented
> finding is a private trophy. Every published finding advances the field,
> builds your reputation, and — if it is good enough — changes how an entire
> class of systems is built. Write the paper."
>
> — Ghost

---

## Goals

Understand the difference between academic papers, practitioner blog posts, and
conference talks. Know the structure of each format. Be able to write a
complete draft of a practitioner-style research post from a security finding.
Know which venues to target.

**Prerequisites:** Days 732, 659.
**Estimated study time:** 2.5 hours + writing time.

---

## 1 — Three Publication Formats

```
FORMAT COMPARISON

                    ACADEMIC PAPER     PRACTITIONER BLOG   CONFERENCE TALK
Length:             8–16 pages         1000–5000 words     20–60 minutes
Audience:           Researchers        Practitioners       Mixed
Peer review:        Yes (blind)        No                  CFP review
Time to publish:    6–18 months        1 day               3–9 months (CFP)
Citation count:     High (in field)    Low                 High impact/views
Career value:       Academic path      Practitioner path   Both
Primary channel:    USENIX/IEEE/ACM    Personal blog       DEF CON/Black Hat
Requires novel:     Strong novelty     Useful technique    Novel + interesting
```

---

## 2 — The Academic Paper Structure

For practitioners targeting USENIX Security, IEEE S&P, or CCS:

```
ACADEMIC PAPER STRUCTURE

1. ABSTRACT (150–250 words)
   Problem you solve. Method. Key result. Significance.
   Written last. Summarises the entire paper.

2. INTRODUCTION (1–2 pages)
   - The problem: Why does this vulnerability class exist?
   - Your contribution: What did you find/build that others haven't?
   - Paper organisation: "Section 2 covers background; Section 3..."
   - A concrete "teaser" finding or result

3. BACKGROUND (1–2 pages)
   Only what the reader needs to understand your attack.
   Cite prior work. Do not explain things that every reader already knows.
   Typical subsections:
   - Target system architecture
   - Prior attacks in this class (with citations)
   - Threat model

4. ATTACK / METHODOLOGY (2–4 pages)
   The core contribution. Usually the longest section.
   Sub-sections for each phase of the attack.
   Diagrams are required — ASCII or vector.
   Include algorithmic pseudocode for novel algorithms.

5. EVALUATION (1–2 pages)
   How do you know it works?
   - Tested on X versions, Y configurations
   - Performance: how long does exploitation take?
   - Reliability: success rate across N trials
   - CVEs affected (if disclosing)

6. MITIGATION (0.5–1 page)
   Proposed defences. How does the fix work?
   What is the performance cost of the fix?

7. RELATED WORK (1 page)
   What other research is in this space?
   How does your work differ from each prior paper?
   Do not skip this — reviewers check it.

8. CONCLUSION (0.5 page)
   One-paragraph summary. Future work.

9. REFERENCES
   BibTeX format. Cite primary sources (not Wikipedia).
```

### 2.1 Citation Hygiene

```
CITATION RULES

DO:
  Cite the original paper that introduced the technique
  Cite the CVE database entry for specific vulnerabilities
  Cite vendor documentation for system behaviour claims
  Cite related academic work (even work you are superseding)

DO NOT:
  Cite blog posts as primary references for factual claims
  Cite Wikipedia
  Cite your own earlier work without justification
  Omit work that directly contradicts your claims
    (address contradictory work instead)

BIBTEX TEMPLATE:
  @inproceedings{lastname2024title,
    author = {Nguyen, Van A and Tran, Thi B},
    title  = {Type Confusion in V8: From JIT to Sandbox Escape},
    booktitle = {Proceedings of the 33rd USENIX Security Symposium},
    year   = {2024},
    pages  = {1--18},
    address = {Philadelphia, PA, USA}
  }
```

---

## 3 — The Practitioner Blog Post Structure

This is what you will publish 80% of the time.

```
PRACTITIONER POST STRUCTURE

1. HOOK (1–2 paragraphs)
   The most interesting thing about your finding.
   State it immediately. Do not build up to it.
   BAD: "In this post I will explore..."
   GOOD: "This one-line JavaScript snippet crashes Chrome 124. Here's why."

2. BACKGROUND (optional, keep short)
   Only what the reader needs to understand your finding.
   If they need extensive background: link out; don't pad your post.

3. THE DISCOVERY STORY (optional but engaging)
   How did you find it? What made you look here?
   The methodology is often as valuable as the finding.

4. TECHNICAL DETAIL (the core — 50–70% of post length)
   Exact commands, exact code, exact output.
   Screenshots or terminal output where relevant.
   Step-by-step enough that a reader could reproduce it.
   Do not gloss over the hard parts.

5. ROOT CAUSE
   WHY does this bug exist?
   What design decision or programming error enables it?
   This is the section that distinguishes expert analysis from description.

6. IMPACT
   What can an attacker do with this?
   Be honest: a DoS is a DoS. An RCE is an RCE. Don't oversell.

7. FIX
   What was patched? Or what should be patched?
   One correct fix, not a list of options.

8. TIMELINE
   Reported: [date]
   Vendor acknowledged: [date]
   Patch released: [date]
   CVE: CVE-XXXX-XXXXX

9. CONCLUSION
   One paragraph. What did we learn?
```

---

## 4 — Conference CFP Strategy

```
CFP (CALL FOR PAPERS) STRATEGY

CHOOSING A TARGET

Tier 1 (hardest to get into, highest impact):
  DEF CON Main Stage  — flagship hacker conference, ~3000 attendees
  Black Hat USA       — industry focus, vendor attendance
  USENIX Security     — academic/practitioner hybrid, peer-reviewed
  IEEE S&P (Oakland)  — top academic security venue

Tier 2 (realistic first targets):
  DEF CON Villages    — specialized topics (RF, bio, car, etc.)
  BSides [City]       — local conferences, regional audiences
  NULLCON, Hack.lu    — strong practitioner community
  AppSec Global (OWASP) — application security focus

Tier 3 (good for first talk):
  Local BSides        — 30-60 min talks, high acceptance rate
  Internal company talks, security meetups

WRITING A WINNING CFP SUBMISSION

Title:     Specific, intriguing, honest
           BAD:  "Security Issues in Modern Browsers"
           GOOD: "One Line of JS to Crash Chrome: V8 Type Confusion in Maglev"

Abstract:  200–400 words
           Problem statement → Your approach → Key finding → Takeaway
           Must answer: "Why should my attendees spend 45 minutes on this?"

Outline:   Bullet points, 5–10 items, with time estimates
           Shows you have structure, not just an idea

Novelty:   What is new? Prior work does NOT include this technique/finding.

Demo:      "Live demo included" increases acceptance rate significantly
           Pre-recorded fallback is acceptable for technical demos

REALISTIC TIMELINE:
  Write talk (slides + demo): 4–8 weeks
  CFP open period: 3–6 months before conference
  Notification: 6–12 weeks after CFP close
  Conference: give talk
```

---

## 5 — Practical: Draft Your First Research Post

Template for your first post based on any finding from this programme:

```markdown
# [Title — the most interesting thing about your finding]

*Posted: [date] | [CVE if applicable] | [tags]*

---

## TL;DR

[1-3 sentences: what you found and why it matters]

---

## Background

[2-3 paragraphs max: what the reader needs to know]

---

## The Finding

[Technical detail — show the work: code, commands, output]

### Root Cause

[Why does this bug exist?]

### Proof of Concept

```
[Minimal PoC code / commands]
```

Tested on: [version, OS, configuration]
Result: [what happens]

### Impact

[What an attacker can do — honest, calibrated assessment]

---

## Fix

[What was or should be patched]

---

## Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Discovered |
| YYYY-MM-DD | Reported to vendor |
| YYYY-MM-DD | Patch released |
| YYYY-MM-DD | Public disclosure |

CVE: CVE-XXXX-XXXXX

---

## Conclusion

[One paragraph summary]

---

*Questions? Corrections? Reach me at [email/handle]*
```

---

## Key Takeaways

1. **The hook is the most important sentence you write.** If the opening line
   does not make the reader want to continue, the quality of the rest is
   irrelevant.
2. **Show the exact commands and exact output.** Readers who want to reproduce
   your finding will; readers who can't or won't will still trust the research
   because you showed the evidence.
3. **The root cause section is where technical reputation is built.** Anyone
   can describe a bug. Explaining *why* it exists requires deep understanding.
4. **Tier 2 conferences are where most practitioners start.** A BSides talk at
   30% acceptance rate is not failure — it is the same path every practitioner
   at DEF CON followed before their first main stage slot.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q743.1, Q743.2 …).

---

## Navigation

← Previous: [Day 742 — Custom Implant Development](DAY-0742-Custom-Implant-Development.md)
→ Next: [Day 744 — CTF Team Strategy](DAY-0744-CTF-Team-Strategy.md)
