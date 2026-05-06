---
title: "Offshore Practice Day 1 — Speed Engagement: External to DA"
tags: [red-team, offshore, practice, speed-run, external-to-DA, timed-engagement,
  methodology, kill-chain, ATT&CK, exam-prep, OSCP-style, HackTheBox-Offshore]
module: 08-RedTeam-03
day: 539
related_topics:
  - Offshore Lab Episode 4 (Day 538)
  - Offshore Practice Day 2 Checkpoint (Day 540)
  - Offshore Environment Methodology (Day 534)
  - Red Team Competency Check (Day 560)
---

# Day 539 — Offshore Practice Day 1: Speed Engagement

> "Speed is not the enemy of quality in red team operations — it is the evidence
> of quality. A confident operator who understands every step moves faster than
> an insecure one who stops to look things up. Today you measure your speed
> against a complete kill chain. Where you slow down is where your next study
> target is."
>
> — Ghost

---

## Goals

Execute the complete Offshore kill chain (external → internal → DA) under
timed conditions.
Identify personal execution bottlenecks at each phase.
Measure improvement from Episodes 1–4 to this solo speed engagement.
Build discipline around note-taking and documentation under time pressure.

**Prerequisites:** Episodes 1–4 complete. Offshore-style lab environment
with external, DMZ, internal zones, and an AD domain configured.
**Time budget:** 8 hours (full working day — this is an exam-condition day).

---

## Rules of Engagement

```
Rules:
  1. No reference to Episodes 1–4 during the engagement.
     Work from memory. Consult man pages and tool --help only.
  2. All commands must be logged (script -f /tmp/engagement.log).
  3. Note-taking is mandatory — CherryTree, Obsidian, or Markdown.
  4. No sharing answers or methods with other operators during the window.
  5. Mark start time at the beginning of each phase.
  6. If stuck for more than 20 minutes: take a 5-minute break, then
     consult your personal methodology card (one page max).
     Record where you looked and how long you were stuck.

Scope:
  External zone: 10.10.110.0/24 (all hosts in scope)
  Internal zone: 10.10.10.0/24  (all hosts in scope)
  Subsidiary zone: 10.10.50.0/24 (if applicable)
  Cloud: out of scope today

Success levels:
  Bronze: External foothold (shell on any DMZ host)
  Silver: Internal foothold (second beacon on internal host)
  Gold:   Domain Admin in corp.local (DA access, proof collected)
  Platinum: Subsidiary forest DA (if two forests configured)

Time targets (based on Episodes 1–4):
  External foothold:        < 1 hour   from start
  Internal foothold:        < 2 hours  from start
  Domain Admin:             < 5 hours  from start
  Full clean-up:            < 7 hours  from start
```

---

## Phase Timecards (Fill In As You Work)

```
=== PHASE 1: EXTERNAL RECON ===
Start time:  ________
End time:    ________
Duration:    ________

Tools used:
  [ ] masscan
  [ ] nmap
  [ ] ffuf / gobuster
  [ ] nuclei
  [ ] nikto
  [ ] whatweb / wappalyzer
  [ ] other: ____________

Findings:
  Live hosts discovered: ____
  Most interesting host: ____________
  Vulnerability identified: _________________________
  Initial access vector: ___________________________

=== PHASE 2: DMZ FOOTHOLD ===
Start time:  ________
End time:    ________
Duration:    ________

Host compromised: ________________
Access level (user): ________________
PrivEsc path used: ___________________________
Access level (post PrivEsc): ________________
Credentials harvested: ____ credential sets
Pivot deployed: [ ] Chisel  [ ] Ligolo  [ ] SSH -D  [ ] Other
Pivot tested (ping/nmap through it): [ ] Yes  [ ] No

=== PHASE 3: INTERNAL RECON ===
Start time:  ________
End time:    ________
Duration:    ________

Internal hosts discovered: ____
DC identified: ________________
Credential technique used:
  [ ] Config file mining
  [ ] Kerberoasting
  [ ] ASREPRoasting
  [ ] LLMNR/Responder
  [ ] SMB relay
  [ ] Password spray

Credentials gained: ____________________
BloodHound collected: [ ] Yes  [ ] No

=== PHASE 4: DOMAIN COMPROMISE ===
Start time:  ________
End time:    ________
Duration:    ________

Attack path used (from BloodHound): ________________________
Lateral movement technique: ________________________________
Escalation to DA: ____________________________
Proof collected: [ ] Yes  [ ] No
DCSync executed: [ ] Yes  [ ] No
krbtgt captured: [ ] Yes  [ ] No
Golden Ticket generated: [ ] Yes  [ ] No

=== PHASE 5: SUBSIDIARY (if applicable) ===
Start time:  ________
End time:    ________
Duration:    ________

Trust type identified: _______________
SID Filtering status: _______________
Attack method: ______________________
Subsidiary DA achieved: [ ] Yes  [ ] No
Subsidiary proof collected: [ ] Yes  [ ] No

=== CLEANUP ===
Start time:  ________
End time:    ________
Duration:    ________

[ ] All C2 beacons terminated
[ ] All persistence removed
[ ] All created accounts deleted
[ ] All tool files removed from hosts
[ ] All modified attributes restored

=== TOTAL TIME ===
Engagement start:  ________
Engagement end:    ________
Total time:        ________
Achievement level: [ ] Bronze  [ ] Silver  [ ] Gold  [ ] Platinum
```

---

## Post-Engagement Analysis (1 hour after completion)

### Sticking Points Analysis

```
Fill in for each phase where you spent more than the target time:

Phase where I was slowest: ________________________________
What I was doing when I slowed down: ______________________
Root cause (circle one):
  A — Never ran this technique before in the lab
  B — Knew the concept but forgot the exact syntax/flags
  C — Tool error I didn't know how to debug
  D — Conceptual gap — didn't understand why it wasn't working
  E — OPSEC concern caused me to hesitate (good)
  F — Enumeration incomplete — missed a path before trying to exploit

Next action for this gap:
  ___________________________________________________________
```

### Speed Comparison Table

```
Complete this after the engagement:

                    | Ep1-4 time (estimate) | Today's time | Delta
--------------------|----------------------|--------------|---------
External recon      |                      |              |
DMZ foothold        |                      |              |
Privilege escalation|                      |              |
Internal pivot      |                      |              |
AD enumeration      |                      |              |
Domain compromise   |                      |              |
Subsidiary (if run) |                      |              |
Cleanup             |                      |              |
--------------------|----------------------|--------------|---------
TOTAL               |                      |              |

Key question: Which phase had the largest positive delta (you were faster
than expected)?
Answer: _______________________________________________
Reason: _______________________________________________

Which phase had the largest negative delta (you were slower than expected)?
Answer: _______________________________________________
Reason: _______________________________________________
```

### Technique Confidence Update

```
After today's engagement, rate each technique 1–4:
  1 — Cannot execute without notes
  2 — Can execute with notes; miss steps independently
  3 — Can execute without notes; might miss edge cases
  4 — Execute, explain, detect, and remediate

TECHNIQUE                          | PRE-TODAY | POST-TODAY | DELTA
External scan and recon            |           |            |
Web vuln identification            |           |            |
Initial access exploitation        |           |            |
Linux PrivEsc                      |           |            |
Windows PrivEsc                    |           |            |
Credential harvesting (config)     |           |            |
Kerberoasting                      |           |            |
LLMNR/Responder                    |           |            |
SMB relay                          |           |            |
Pivot deployment (Ligolo/Chisel)   |           |            |
BloodHound collection              |           |            |
Attack path execution              |           |            |
DCSync                             |           |            |
Golden Ticket                      |           |            |
Forest trust exploitation          |           |            |
Cleanup                            |           |            |
```

---

## Improvement Target for Practice Day 2

Based on today's analysis, set three specific improvement targets:

```
Improvement 1:
  Technique: _______________________________________________
  Current rating: ___
  Target rating: ___
  Action: ________________________________________________

Improvement 2:
  Technique: _______________________________________________
  Current rating: ___
  Target rating: ___
  Action: ________________________________________________

Improvement 3:
  Technique: _______________________________________________
  Current rating: ___
  Target rating: ___
  Action: ________________________________________________

These three techniques are your Day 540 focus before the final checkpoint.
```

---

## Key Takeaways

1. Speed in an engagement comes from internalised muscle memory, not from
   moving fast. If you are typing quickly but spending 20 minutes looking up
   flag syntax, you are not fast — you have a specific knowledge gap.
2. The sticking points analysis is more valuable than the flags. The flags
   prove you can do it. The sticking points show you where you will fail
   under real engagement conditions with a defender watching.
3. Note-taking under time pressure is a skill. Operators who do not take notes
   during an engagement produce poor deliverables and cannot reproduce their
   findings for the report. Practise taking structured notes while keeping
   your hands moving.
4. Cleanup is a time sink that is consistently underestimated. Real engagements
   require meticulous cleanup documentation — not just "I deleted everything"
   but "I executed the following cleanup commands and verified each action
   with the following verification commands."
5. The engagement is not a test of whether you can do it. You proved that in
   Episodes 1–4. It is a test of whether you can do it under pressure, alone,
   without a safety net. That is what the competency gate (Day 560) will
   measure.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q539.1, Q539.2 …).

---

## Navigation

← Previous: [Day 538 — Offshore Lab Episode 4: Multi-Forest Trust](DAY-0538-Offshore-Lab-Episode-4-Multi-Forest-Trust.md)
→ Next: [Day 540 — Offshore Practice Day 2: Reinforcement and Checkpoint](DAY-0540-Offshore-Practice-Day-2-Checkpoint.md)
