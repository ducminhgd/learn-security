---
title: "Milestone 550 — Red Team Module Retrospective and CTF Sprint Preparation"
tags: [red-team, milestone, retrospective, self-assessment, gap-analysis,
  competency-gate, CTF-sprint, skill-matrix, methodology, preparation,
  module-review, 08-RedTeam-03]
module: 08-RedTeam-03
day: 550
related_topics:
  - Red Team Report Writing (Day 549)
  - Red Team CTF Sprint Introduction (Day 551)
  - Competency Gate Day 560 (Day 560)
  - Offshore Lab Episodes (Days 535–538)
  - Practice Days (Days 539–540)
---

# Day 550 — Milestone 550: Red Team Module Retrospective

> "You have spent sixty days learning to break things. Not random things —
> specific things, in a specific order, with a specific purpose. Before you
> walk into the CTF sprint and then the competency gate, stop. Sit with what
> you know and what you do not know. The operator who overestimates their
> skill fails at the gate. The operator who underestimates spends the next
> ten days re-doing things they already know. Honest self-assessment is a
> professional skill. Use it."
>
> — Ghost

---

## Goals

Conduct an honest, evidence-based retrospective of the red team module
(Days 491–549).
Identify genuine skill gaps before the CTF sprint (Days 551–559).
Update your technique confidence matrix.
Prepare a personal study focus list for the CTF sprint.
Review the competency gate requirements for Day 560.

**Prerequisites:** All Days 491–549.
**Time budget:** 3 hours (reflection, no new content).

---

## Part 1 — Module Coverage Review

```
What was covered in Days 491–550:

08-RedTeam-01 (Days 491–510): Advanced Web + API
  D491–D494: Advanced web attacks beyond OWASP Top 10
  D495–D497: API security deep dives (REST, GraphQL, gRPC)
  D498–D500: Authentication bypass, JWT attacks, OAuth misuse
  D501–D503: Advanced SQLi, NoSQLi, second-order injection
  D504–D506: SSRF chains and cloud metadata exploitation
  D507–D509: Deserialization and prototype pollution
  D510:      Module review and competency check

08-RedTeam-02 (Days 511–530): Active Directory
  D511–D513: ADCS attack surface (ESC1–ESC8, PetitPotam)
  D514–D516: Kerberos attacks (AS-REP, Kerberoasting, S4U)
  D517–D519: Post-exploitation, LOLAD, AV/EDR bypass
  D520–D522: C2 framework operations (Sliver, Cobalt Strike)
  D523–D525: Cloud integration (AAD Connect, Azure AD, AWS)
  D526–D528: Multi-forest trusts, ExtraSids
  D529:      Cross-environment attack paths
  D530:      Module competency check

08-RedTeam-03 (Days 531–550): Advanced Practice
  D531–D533: Advanced persistence (WMI, COM hijacking, lab)
  D534–D538: Offshore lab — full kill-chain (4 episodes)
  D539–D540: Practice days and methodology checkpoint
  D541–D542: EDR evasion + custom payload development
  D543–D545: Delegation attacks + shadow credentials + ADCS advanced
  D546–D548: LOLAD/LOLBAS + 3-zone pivoting + full engagement simulation
  D549:      Red team report writing
  D550:      This file — retrospective and CTF prep
```

---

## Part 2 — Technique Confidence Matrix

```
Rate each technique 0–4:
  0 = I have not touched this
  1 = I have read it but not practised
  2 = I have practised it once
  3 = I can execute it without reference material
  4 = I can explain it, execute it, detect it, and adapt it to a new scenario

Score yourself honestly. "3" is the minimum acceptable for a technique
you will be tested on in the competency gate. "4" is operator level.
```

### Red Team Techniques Matrix

```
RECONNAISSANCE
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
OSINT email enumeration (o365spray, theHarvester) | ___ |
Active recon — nmap, masscan flags you know by memory | ___ |
BloodHound collection + graph analysis       | ___ |
Azure tenant enumeration (roadrecon)         | ___ |

INITIAL ACCESS
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
Credential spraying (VPN, OWA) — rate limits | ___ |
Phishing payload delivery                   | ___ |
Web app exploitation → shell (if in scope)  | ___ |

EXECUTION
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
WMIexec, PSexec equivalents                 | ___ |
DCOM MMC20 lateral execution                | ___ |
COM-based scheduled task                    | ___ |

PERSISTENCE
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
WMI event subscription (MOF, via impacket)  | ___ |
COM hijacking (HKCU override)               | ___ |
Registry Run key persistence                | ___ |
Scheduled task via API (no schtasks.exe)    | ___ |

PRIVILEGE ESCALATION
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
Kerberoasting (GetUserSPNs + hashcat)       | ___ |
AS-REP Roasting (no pre-auth accounts)      | ___ |
ADCS ESC1 (certipy req -upn)                | ___ |
ADCS ESC4 (modify template → ESC1)          | ___ |
ADCS ESC6 (CA-level SAN flag)               | ___ |
ADCS ESC9 (UPN manipulation)                | ___ |
Unconstrained delegation + printer bug      | ___ |
Constrained delegation (S4U2Self/Proxy)     | ___ |
RBCD full chain (addcomputer + getST)       | ___ |
Shadow credentials + UnPAC-the-Hash         | ___ |
GenericWrite → ACL abuse path               | ___ |

CREDENTIAL ACCESS
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
DCSync (impacket-secretsdump)               | ___ |
LSASS dump — comsvcs.dll MiniDump           | ___ |
SAM/NTDS extraction                         | ___ |
Impacket secretsdump over SMB              | ___ |

LATERAL MOVEMENT
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
Pass-the-hash (CME, evil-winrm)             | ___ |
Pass-the-ticket (Rubeus + klist)            | ___ |
WMI lateral movement                        | ___ |
DCOM lateral movement                       | ___ |
SMB relay (ntlmrelayx)                      | ___ |
Overpass-the-hash (Rubeus asktgt /rc4)      | ___ |

PIVOTING
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
Ligolo-ng — two-hop setup from memory       | ___ |
Ligolo-ng — three-hop with listener relay   | ___ |
Chisel HTTP tunnel chain                    | ___ |
DNS across proxy (proxy_dns / resolv.conf)  | ___ |
Pivot recovery after hop failure            | ___ |

DEFENCE EVASION
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
AMSI bypass (amsiInitFailed reflection)     | ___ |
ETW patching (EtwEventWrite → ret)          | ___ |
Process injection (VirtualAllocEx + thread) | ___ |
PPID spoofing                               | ___ |
Direct syscalls (SysWhispers concept)       | ___ |
LOLBAS payload delivery (certutil, msiexec) | ___ |

DOMAIN DOMINANCE
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
Golden Ticket (impacket-ticketer -user DA)  | ___ |
Silver Ticket (target service)              | ___ |
Diamond Ticket concept                      | ___ |
ExtraSids attack (cross-forest)             | ___ |
Trust ticket abuse                          | ___ |

CLOUD
Technique                                    | Score | Gap Action
--------------------------------------------|-------|-------------
AAD Connect MSOL account → Azure pivot      | ___ |
roadrecon gather + enumerate tenant         | ___ |
Service Principal credential reset          | ___ |
Azure Key Vault access (az keyvault)        | ___ |
AWS SSRF to metadata + role credential      | ___ |
```

---

## Part 3 — Gap Analysis

```
Review your scores from Part 2.

For every technique scored 0–2:
  → It is a gap.
  → Assign it to a day in the CTF sprint (Days 551–559) as a drill target.
  → Be specific: "Practice Ligolo-ng 3-hop setup from memory on Day 551"

For every technique scored 3:
  → It is adequate. You will not drill it unless a CTF challenge forces it.

For every technique scored 4:
  → It is a strength. Use it in the CTF sprint to save time on hard challenges.

Gap register (fill in):
  Technique | Current Score | Target Score | Study Day
  ----------|--------------|--------------|----------
  _________|    ___        |     ___      |  Day ___
  _________|    ___        |     ___      |  Day ___
  [continue for all gaps]

Priority gaps (score 0 or 1) — these MUST be addressed before Day 560:
  1. ________________________________________________
  2. ________________________________________________
  3. ________________________________________________
```

---

## Part 4 — Methodology Card Review

```
Pull out the methodology card you built on Day 540.
Update it based on everything you have learned since Day 540.

The card should now contain:
  □ Phase 1: Recon — tools and order
  □ Phase 2: Initial access — paths and decision tree
  □ Phase 3: Internal enum — tools in order (CME → BloodHound → manual)
  □ Phase 4: PrivEsc decision tree — what do you check first, second, third?
  □ Phase 5: Lateral movement — priority order of techniques
  □ Phase 6: DA path — what does "DA achieved" look like in your commands?
  □ Phase 7: Post-DA — DCSync, credential capture, persistence
  □ Phase 8: Cloud pivot — MSOL → roadrecon → SP credential → crown jewel
  □ Phase 9: Cleanup — artefacts to remove in order
  □ Pivot chain setup — Ligolo-ng two-hop from memory

If you cannot fill in a section without checking your notes:
  → That section is a gap. Add it to Part 3.
```

---

## Part 5 — Engagement Speed Benchmark

```
From Day 539 (speed engagement) and Day 548 (alternate scenario):

Record your best times for each phase below and compare against target:

Phase                         | Your Best Time | Target Time | Delta
------------------------------|---------------|-------------|------
OSINT + user enumeration      |     ___       |   60 min    | ___
Credential spray (to hit)     |     ___       |   variable  | ___
C2 beacon deployed            |     ___       |   30 min    | ___
BloodHound ingested           |     ___       |   15 min    | ___
DA path identified            |     ___       |   20 min    | ___
DA achieved                   |     ___       |   60 min    | ___
DCSync completed              |     ___       |   10 min    | ___
Azure pivot + crown jewel     |     ___       |   60 min    | ___
Cleanup                       |     ___       |   20 min    | ___

TOTAL:                        |     ___       |  ~5 hours   | ___

If your total time is significantly over 5 hours for the full chain:
  → You are relying on notes too much
  → Your gap analysis from Part 3 should reflect command-recall gaps
  → The CTF sprint (Days 551–559) will fix this through repetition

If your total time is under 5 hours:
  → Use the CTF sprint to extend your versatility, not just your speed
```

---

## Part 6 — CTF Sprint Preparation

```
Days 551–559: Red Team CTF Sprint

Format:
  Each day = one or more CTF challenges in a red team category
  Categories covered: Active Directory, Web + API, Pivoting, Cloud, Evasion
  Difficulty: escalates from Intermediate (Day 551) to Expert (Day 559)

What to bring to the CTF sprint:
  → Your updated methodology card from Part 4
  → Your gap register from Part 3
  → A fresh Kali or Parrot OS VM with your standard toolkit installed
  → A notes file to capture new variations and one-liners you discover

Day 560 — Competency Gate: Red Cell Ready
  Format: 48-hour solo engagement against an unknown lab environment
  Objectives (all must be completed):
    P1: Achieve Domain Admin in the lab domain
    P2: Access the designated "crown jewel" file or secret
    P3: Write a professional-quality finding for the highest-severity
        vulnerability discovered
  
  Assessment criteria:
    → Methodology: did you follow a coherent, documented process?
    → Speed: was the engagement completed within the time window?
    → Accuracy: are your findings accurate and reproducible?
    → Communication: is the finding card professional and clear?
    → Detection awareness: can you name the log event that would have
      caught each technique you used?

  Passing standard:
    → All three objectives completed
    → At least one professional finding card submitted
    → Verbal defence of technique choices (30-minute oral review)

Preparation checklist for Day 560:
  □ Methodology card — complete and memorised
  □ Toolkit — all tools installed and tested in a clean VM
  □ Ligolo-ng — can set up two-hop from memory in < 5 minutes
  □ BloodHound — can collect, import, and run key queries from memory
  □ certipy — can run find + req + auth from memory
  □ Delegation attacks — at least one path executable from memory
  □ DCSync command — from memory
  □ Engagement log template — ready to fill in from minute zero
  □ Finding card template — ready to fill in from minute zero
```

---

## Part 7 — Retrospective Reflection Questions

```
Answer these in writing. Not to me — to yourself.
These are for your own learning, not for scoring.

1. Which single technique from Days 491–549 do you feel most confident in?
   Why? What specifically did you do to build that confidence?
   
   Answer: _______________________________________________________

2. Which single technique do you least want to see in the Day 560 engagement?
   Why? What are you going to do about it in the next nine days?
   
   Answer: _______________________________________________________

3. Name one mistake you made during the Offshore lab episodes that you will
   not make again. What was the mistake? What was the root cause?
   
   Answer: _______________________________________________________

4. If you had to design a blue team detection that would catch YOU specifically
   during an engagement — based on your observed habits and tendencies —
   what would it alert on?
   
   Answer: _______________________________________________________

5. You have been learning to operate as a red teamer for 60+ days.
   What has changed in how you think about systems, networks, and code?
   
   Answer: _______________________________________________________
```

---

## Key Takeaways

1. Sixty days of red team content is not mastery — it is vocabulary. The
   techniques you have covered are the words. Fluency comes from using them in
   unfamiliar contexts without a reference sheet. The CTF sprint and
   competency gate test fluency, not vocabulary size.
2. Honest gap analysis is more valuable than false confidence. An operator who
   knows exactly which three techniques they cannot execute reliably will spend
   the next nine days fixing those three things. An operator who believes they
   know everything will discover the gaps at the worst possible time.
3. Speed is a skill, not a shortcut. The target of five hours for a full chain
   is not arbitrary — it reflects what a professional engagement under time
   pressure requires. Slow execution is a symptom of uncertainty. Uncertainty
   is fixed by repetition of the specific step that causes the slowdown.
4. The report is part of the engagement, not an afterthought. You have now
   written the report (Day 549) and conducted the assessment (Days 535–548).
   In a real engagement, these are inseparable. Every action you take must be
   documented in real time — not reconstructed afterwards.
5. Day 560 is not a test of everything. It is a test of one thing: can you
   execute a coherent, documented, professional red team engagement on an
   unknown target, start to finish, without guidance? If you can do that, you
   are ready for real-world red team work. The curriculum has built every
   component of that ability — this gate verifies they work together.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q550.1, Q550.2 …).

---

## Navigation

← Previous: [Day 549 — Red Team Report Writing Sprint](DAY-0549-Red-Team-Report-Writing-Sprint.md)
→ Next: [Day 551 — Red Team CTF Sprint: Day 1](DAY-0551-Red-Team-CTF-Sprint-Day-1.md)
