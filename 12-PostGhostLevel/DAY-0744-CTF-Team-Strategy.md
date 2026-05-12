---
title: "CTF Team Strategy — Competition Types, Role Division, Attack-Defense, Write-Ups"
tags: [ctf, competition, team-strategy, attack-defense, write-ups, module-12-postghost]
module: 12-PostGhostLevel
day: 744
prerequisites:
  - Day 730 — Ghost Level Competency Gate
related_topics:
  - Day 745 — Security Engineering Interview Preparation
---

# Day 744 — CTF Team Strategy and Competition Leadership

> "Jeopardy CTFs are how you build and verify individual skills. Attack-defense
> CTFs are how you build team skills. Both matter. But there is a phase in your
> career where playing CTFs solo is the wrong strategy — where contributing to
> a team and raising the capability of people around you compounds your own
> development faster than another solo flag. Know which phase you are in."
>
> — Ghost

---

## Goals

Understand the two major CTF formats and their role in career development.
Know how to structure a high-performance CTF team. Understand competition-time
strategy and decision frameworks. Know how to extract maximum career value from
CTF participation through write-ups.

**Prerequisites:** Day 730.
**Estimated study time:** 2 hours.

---

## 1 — CTF Formats

### 1.1 Jeopardy CTF

```
JEOPARDY FORMAT

Structure:
  Team solves predefined challenges across categories.
  Each challenge has a fixed flag. Submit flag → receive points.
  Categories: Web, Pwn, Reversing, Crypto, Forensics, Misc, OSINT

Typical categories at Ghost Level:
  Pwn:       heap exploitation, kernel, browser
  Reversing: packed binary, anti-debug, algorithm recognition
  Crypto:    lattice, PRNG, padding oracle, ECDSA
  Web:       chain of three web bugs, race condition, deserialization
  Forensics: memory dump, PCAP analysis, steganography

Best competitions:
  DEF CON CTF         (qualifier: top 50 teams advance to in-person finals)
  PlaidCTF            (CMU Plaid Parliament of Pwning)
  Google CTF          (high quality, consistent difficulty)
  HITCON CTF          (Taiwan-based, elite-level challenges)
  UIUCTF              (University of Illinois, research-quality challenges)

Career value:
  DEF CON CTF top-10 finish: visible to every elite security team
  PlaidCTF top-5: equivalent signal to a major CVE for pwn specialisation
  Google CTF participation: demonstrates consistent engagement
```

### 1.2 Attack-Defense CTF

```
ATTACK-DEFENSE FORMAT

Structure:
  Each team receives an identical service running on a dedicated server.
  Teams must:
    DEFEND: patch their own service to resist attacks
    ATTACK: exploit other teams' unpatched services to steal flags
  Points: scored per flag stolen - points lost per flag surrendered
  Round duration: typically 2–5 minutes per tick

Best competitions:
  iCTF (UCSB)              — long-running, educational focus
  RuCTF                    — Russian competition, historically strong
  DEF CON CTF Finals       — the prestige event; 48-hour attack-defense
  FAUST CTF                — Faustian exchange of attack and defense

Why attack-defense matters differently than jeopardy:
  You cannot ignore defense (unlike jeopardy where you only attack)
  Time pressure is constant — every tick matters
  Tooling matters: automated exploit runners, monitoring, patching workflow
  Team communication is critical — jeopardy lets siloed individuals work;
  attack-defense punishes siloed teams

Skills uniquely developed:
  Service source code auditing under time pressure (fast audit → fast patch)
  Building reliable automated exploit scripts (must work every tick)
  Defense without breaking service availability (cannot just take it offline)
  Team synchronisation and communication discipline
```

---

## 2 — Team Structure for High-Performance Jeopardy CTF

```
IDEAL TEAM COMPOSITION (6–8 players)

Role          Player count    Primary skill
Pwn           2               Heap exploitation, kernel, browser
Reversing     1–2             Ghidra/IDA, packers, deobfuscation
Crypto        1–2             Lattice, PRNG, classical attacks
Web           1–2             Full OWASP stack, race conditions, deserialization
Forensics     1               Memory, PCAP, steganography, disk forensics
Floater       1               Strong generalist who picks up easy challenges in any category

ROLES DURING COMPETITION:
  Captain:    Monitors scoreboard, assigns tasks, tracks team progress
              Does NOT primarily solve challenges (bandwidth cost too high)
              Makes "drop and move on" calls when someone is stuck too long
  Solver:     Focused on one challenge at a time
              Communicates progress/blockers in team chat every 30 minutes
  Scribe:     Tracks attempted approaches and partial solutions (wiki/notes)
              Critical when multiple teammates attempt the same challenge

COMMUNICATION PROTOCOL:
  Discord/Slack channel per category + #general
  Format for status update: [CHALLENGE_NAME] [CATEGORY] [status: in-progress/stuck/solved]
  Blocked rule: if stuck > 90 minutes with no progress, escalate to captain
                or switch challenge
```

---

## 3 — Competition-Time Decision Framework

```
THE 3-HOUR RULE (Jeopardy)

T+0h:   All team members browse all challenges.
        Each person claims 1 challenge in their specialty.
        Captain assigns "first blood" targets (easiest per category).

T+1h:   First check-in. What is close to solved? What is stuck?
        Reassign: pull a second player onto any stuck challenge.
        Do not abandon a near-solve; double-down instead.

T+2h:   Second check-in. Are we in the top 10? Top 25?
        If yes: stay on current strategy.
        If no: pivot to unsolved medium-difficulty challenges (better ROI
               than continuing on an unsolvable hard challenge).

T+3h+:  Solve and move. No player spends >3 hours on a single challenge
        without a teammate review and conscious decision to continue.

THE TRIAGE RULE:
  Challenges have four states:
    Green:   solved
    Yellow:  clear path, will solve in <1h
    Orange:  unclear path, needs more time or help
    Red:     probably requires specialised knowledge we do not have

  Captain reviews Orange/Red at T+2h. Move team off Red.
```

---

## 4 — Write-Up Strategy for Career Value

```
THE CTF WRITE-UP ROI CALCULATION

Not every challenge deserves a write-up.
Write up challenges that meet at least ONE of:
  1. Novel technique not commonly documented
  2. Challenge author published reference solution — your approach differs
  3. The solve required a non-obvious insight you want to remember
  4. High-point challenge where few teams solved it

WRITE-UP QUALITY TIERS:

Tier A (portfolio write-ups):
  Solve story + root cause analysis + working exploit + why it matters
  Length: 1000–3000 words
  Publish: your personal blog + link to CTF Time write-ups page

Tier B (quick notes):
  Steps to solve + the key insight
  Length: 200–500 words
  Publish: GitHub Gist or ctftime.org submission

Skip: trivial challenges, obvious techniques, challenges you mostly guessed

PUBLICATION TIMING:
  CTF organisers embargo write-ups until after competition ends.
  Publish within 48 hours of competition close — the write-up is most
  valuable when the community is actively looking for solutions.

LINKING WRITE-UPS TO YOUR PROFILE:
  Submit to CTFtime.org: https://ctftime.org/writeups
  Tag: team name, year, competition, categories
  This creates a public searchable record of your competition history.
```

---

## 5 — Moving from Player to Organiser

```
ORGANISING A CTF CHALLENGE OR COMPETITION

Why to do it:
  Creating a quality challenge requires deeper mastery than solving one.
  Challenge authors are highly respected in the community.
  Organisers get pre-release access to other authors' research.

First step: contribute one challenge to an existing CTF
  Approach a competition you respect → offer to write one challenge
  Typical requirement: working challenge + deployment (Docker compose) +
  full solution documentation for organisers

Challenge quality criteria:
  Unique: not a well-known public exploit (google "ctf [technique]")
  Fair: one intended solution path (multiple unintended paths are a design flaw)
  Instructive: teaches something valuable after the solve
  Documented: setup guide + solution + hints in progression

Example contribution process (Google CTF):
  CTF team blog: security.googleblog.com/ctf
  Open submissions form published ~3 months before competition
  Requires: working challenge file + solution + Docker setup + difficulty rating
```

---

## Key Takeaways

1. **Jeopardy CTF builds individual skill; attack-defense CTF builds team skill.**
   Elite practitioners do both, but at different career phases.
2. **The captain's job is macro, not micro.** A captain who tries to solve
   challenges while managing the team does both poorly. Assign the captain role
   to your best communicator, not your best hacker.
3. **CTF write-ups are portfolio pieces.** A published write-up for a hard
   challenge at a top competition is a permanent, searchable, public record
   of your technical capability.
4. **The 90-minute stuck rule prevents sunk-cost fallacies.** A challenge you
   have been stuck on for 3 hours is almost certainly beyond your current
   knowledge. Get a second pair of eyes or move on.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q744.1, Q744.2 …).

---

## Navigation

← Previous: [Day 743 — Writing Security Research Papers](DAY-0743-Writing-Security-Research-Papers.md)
→ Next: [Day 745 — Security Engineering Interview Preparation](DAY-0745-Security-Interview-Preparation.md)
