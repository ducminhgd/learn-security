---
title: "Ghost Level Debrief — What You Found, What You Missed, and Why"
tags: [ghost-level, debrief, engagement-review, lessons-learned, module-11-ghost-level]
module: 11-GhostLevel
day: 726
prerequisites:
  - Day 725 — Phase 6: ATT&CK Mapping and Final Report
related_topics:
  - Day 727 — Ghost Level Extended Day 1: Bonus Objectives
  - Day 730 — Ghost Level Competency Gate
---

# Day 726 — Ghost Level Debrief

> "Every engagement ends the same way: you write the report, you submit it,
> and then — if you are doing this right — you spend an hour asking yourself
> what you missed and why. Not to punish yourself. To update your mental model
> so you catch it next time. The debrief is not an afterthought. It is the
> most important part of the learning cycle."
>
> — Ghost

---

## Goals

1. Conduct a structured debrief on the Project SABLE engagement (Days 707–725).
2. Identify findings you discovered — and findings you missed — and root-cause why.
3. Update your personal technique confidence matrix.
4. Extract three reusable lessons that apply to all future engagements.

---

## Prerequisites

- Project SABLE engagement complete (Days 707–725).
- Final report submitted (Day 725).

---

## 1 — The Ghost Debrief Framework

A debrief is not a victory lap. It is a forensic analysis of your own work.

```
DEBRIEF STRUCTURE — 5 QUESTIONS

1. What did you find?
   List every finding from your report.

2. What did you miss?
   Compare your findings with the full solution set (provided below).
   What was in scope that you did not report?

3. Why did you miss it?
   For each missed finding, determine the root cause:
     a) I did not look at this surface at all.
     b) I looked but did not recognise it as vulnerable.
     c) I recognised it but ran out of time.
     d) I had the right technique but applied it incorrectly.

4. What did you do well?
   Name at least two decisions that were correct — technique choice,
   time management, documentation discipline. Reinforce positive patterns.

5. What is the single highest-leverage improvement for next time?
   One thing. Not five. One. The specific change in methodology, tooling,
   or habit that would have the highest impact.
```

---

## 2 — Project SABLE Finding Registry

Complete this registry by comparing your report against the reference. If you
do not have an instructor, use the notes you took during the engagement to
reconstruct what you did and did not investigate.

```
PROJECT SABLE — FULL FINDING REGISTRY

═══════════════════════════════════════════════════════════════════════
FINDING F-01 — sable-web: JWT Algorithm Confusion (None/HS256)
  Severity: Critical
  Location: sable-web authentication endpoint (/api/v1/auth)
  Impact: Authentication bypass, admin-level access
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: forged JWT token + screenshot of admin panel
═══════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════
FINDING F-02 — sable-svc: Stack Buffer Overflow (CVE-class)
  Severity: Critical
  Location: sable-svc TLV message handler, parse_record() function
  Impact: RCE as www-data on sable-svc host
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: pwntools script + reverse shell screenshot
═══════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════
FINDING F-03 — sable-dc: Kerberoastable service account
  Severity: High
  Location: Active Directory — SVC_BACKUP account
  Impact: Lateral movement to backup operator role
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: Impacket output + cracked hash
═══════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════
FINDING F-04 — sable-dc: ADCS ESC1 — SAN Injection
  Severity: Critical
  Location: SableCA certificate template "SableUser"
  Impact: Domain Admin via certificate-based authentication
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: Certipy output + DA ticket proof
═══════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════
FINDING F-05 — sable-iot: Default Web Credential + CGI Injection
  Severity: High
  Location: sable-iot HTTP admin panel, /cgi-bin/ping.cgi
  Impact: OS command execution as root on IoT device
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: curl command + id command output
═══════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════
FINDING F-06 — sable-store: SMB null session + world-readable share
  Severity: Medium
  Location: sable-store, share BACKUP$
  Impact: Access to database backups containing PII + credentials
  Did you find it: Y / N
  If N — root cause: _____________________________________________
  Evidence required: smbclient listing + exfiltrated file
═══════════════════════════════════════════════════════════════════════

YOUR SCORE: ___/6 findings identified
```

---

## 3 — Time Allocation Analysis

```
TIME USAGE ANALYSIS

Fill in how you actually spent the 48 hours (approximate):

Phase 1 — Initial Recon:          _____ hours
Phase 2 — Web Exploitation:       _____ hours
Phase 2 — Post-Web Discovery:     _____ hours
Phase 3 — Network Service:        _____ hours
Phase 4 — AD Attacks:             _____ hours
Phase 5 — IoT Analysis:           _____ hours
Phase 5 — SableStore / Exfil:     _____ hours
Phase 6 — Report Writing:         _____ hours
Other (tools, rabbit holes, etc): _____ hours
TOTAL:                             48 hours

ASSESSMENT:
Was your time well-distributed?
  Over-invested (> 8 hours on one area): ______________________
  Under-invested (< 30 min on one area): ______________________
  Correct balance: Y / N

Biggest time sink that did not produce a finding: _______________
Fastest finding relative to time invested: _____________________
```

---

## 4 — Root Cause Analysis for Missed Findings

For each finding you did NOT report, write a one-paragraph root cause:

```
MISSED FINDING: _______________________________________________

What I did instead:
  _______________________________________________________________
  _______________________________________________________________

Why I did not investigate this surface:
  [ ] Never attempted — out of mental scope
  [ ] Attempted — tool failed and I did not investigate manually
  [ ] Attempted — found the surface but missed the vulnerability
  [ ] Ran out of time — was on the list but not reached
  [ ] Misidentified severity — deprioritised as unlikely

Specific methodology failure:
  _______________________________________________________________
  _______________________________________________________________

What I will do differently on the next engagement:
  _______________________________________________________________
  _______________________________________________________________
```

---

## 5 — Updated Confidence Matrix

Revise your Week 2 confidence matrix based on performance:

```
TECHNIQUE CONFIDENCE — POST-SABLE UPDATE

Rate each 1–4 (same scale as Day 705):
  4 = Executed under time pressure; found the finding
  3 = Executed correctly but slow
  2 = Attempted; error or timeout; did not produce result
  1 = Did not attempt or completely failed

Web Exploitation (JWT, SSRF, API):           ___/4
Binary Exploitation (stack BOF, ROP):        ___/4
Active Directory (BloodHound, ADCS, DCSync): ___/4
Network Service Enumeration:                 ___/4
IoT Analysis (firmware, CGI injection):      ___/4
Data Exfiltration and Evidence:              ___/4
Report Writing (advisory quality):           ___/4

OVERALL ENGAGEMENT SCORE: ___/4
```

---

## 6 — Three Reusable Lessons

Write three lessons that are general enough to apply to any future engagement:

```
LESSON 1 (technique or methodology):
  _______________________________________________________________
  _______________________________________________________________
  Application: What situation triggers this lesson? ____________

LESSON 2 (time management or prioritisation):
  _______________________________________________________________
  _______________________________________________________________
  Application: What situation triggers this lesson? ____________

LESSON 3 (documentation or reporting):
  _______________________________________________________________
  _______________________________________________________________
  Application: What situation triggers this lesson? ____________
```

---

## Key Takeaways

1. **Missed findings are the most valuable part of a debrief.** A missed
   finding is not a failure to punish — it is information about a gap in your
   methodology. The goal is to close that gap before the next engagement, not
   to feel bad about this one.
2. **Time allocation is a skill, not a preference.** Every hour spent past the
   optimal point on one target is an hour stolen from another. The debrief
   reveals whether your time allocation was strategic (evidence-based
   prioritisation) or reactive (chasing whatever was most interesting).
3. **Root-cause analysis at the method level.** "I missed it because I did not
   check for ADCS" is better than "I missed it because I ran out of time." The
   former tells you to add ADCS enumeration to your standard checklist. The
   latter tells you nothing actionable.
4. **The debrief is the bridge between this engagement and the next.** Every
   professional security researcher conducts a post-engagement review. Those
   who skip it repeat the same mistakes indefinitely. Those who do it improve
   measurably with every engagement.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q726.1, Q726.2 …).

---

## Navigation

← Previous: [Day 725 — Phase 6: ATT&CK Mapping and Final Report](DAY-0725-Phase6-ATTACK-Mapping-Final.md)
→ Next: [Day 727 — Ghost Level Extended Day 1: Bonus Objectives](DAY-0727-Ghost-Level-Extended-Day1.md)
