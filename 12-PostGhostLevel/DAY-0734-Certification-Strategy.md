---
title: "Certification Strategy — OSEP, OSED, BSCP, PNPT and What Actually Matters"
tags: [certification, oscp, osep, osed, bscp, pnpt, career, module-12-postghost]
module: 12-PostGhostLevel
day: 734
prerequisites:
  - Day 731 — Career Path Planning
related_topics:
  - Day 745 — Security Engineering Interview Preparation
---

# Day 734 — Certification Strategy: What to Pursue and Why

> "Certifications are not skill. Some of them do test real skill, which makes
> them useful signals to employers. Others are resume wallpaper. Knowing which
> is which before you spend $1,500 and three months of study time is the kind
> of intelligence that saves you from wasted effort.
>
> Here is what Ghost actually thinks."
>
> — Ghost

---

## Goals

Understand which certifications align with each career path. Know the honest
value, cost, and time investment for each. Build a certification roadmap that
complements — rather than replaces — real skill development.

**Prerequisites:** Day 731.
**Estimated study time:** 1.5 hours.

---

## 1 — Ghost's Certification Ranking Framework

```
CERTIFICATION VALUE TIERS

Tier 1 — High Signal (employers take this seriously)
  These require actual hands-on exploitation under timed conditions.
  Passing means you can do the work, not just memorise it.

Tier 2 — Moderate Signal (useful but not differentiating)
  Demonstrate competence in a domain. Good for entry/mid level.
  Alone, they do not prove senior-level capability.

Tier 3 — Low Signal (checkbox items)
  Multiple choice, no hands-on component, or trivially obtainable.
  Fine for compliance roles. Irrelevant for technical positions.

Ghost's Rule:
  Any certification that cannot be failed by someone who knows
  the material superficially is Tier 3, regardless of brand.
```

---

## 2 — Certification Profiles

### 2.1 OffSec Certifications (OSCP, OSEP, OSED, OSWE, OSMR)

```
OSCP — Offensive Security Certified Professional
  Tier:       1
  Focus:      Penetration testing fundamentals (web, Linux, Windows)
  Format:     24-hour exam — 6 machines, all-or-nothing pass
  Cost:       $1,499 (Learn One subscription includes 90 days lab)
  Value:      Industry standard for junior/mid pentester roles
  Ghost says: You already have the skill for this. If your target employer
              lists OSCP as a requirement, get it. Otherwise, optional.
              Do not study for OSCP — just take the exam.

OSEP — OffSec Experienced Penetration Tester
  Tier:       1
  Focus:      Active Directory, C2 evasion, custom payloads, lateral movement
  Format:     48-hour exam (10 flags across a network)
  Cost:       $1,499 (Learn One)
  Value:      Strong signal for red team roles
  Ghost says: THIS is the certification for your career path if you chose
              red team. It maps directly to Days 491–560 of this programme.
              Study time: 2–4 weeks review (you know the material).

OSED — OffSec Exploit Developer
  Tier:       1
  Focus:      Windows exploit development: DEP/ASLR bypass, SEH, custom ROP
  Format:     48-hour exam (binary exploitation challenges)
  Cost:       $1,499 (Learn One)
  Value:      Top signal for binary exploitation / VR roles on Windows targets
  Ghost says: Excellent if your chosen path includes Windows exploitation
              or working with Windows-based VR. Maps to Days 366–430 but
              Windows-focused. Requires specific Windows exploitation study
              beyond this programme's Linux focus.

OSWE — OffSec Web Expert
  Tier:       1
  Focus:      White-box web application exploitation (source code review)
  Format:     48-hour exam (two web app challenges)
  Cost:       $1,499 (Learn One)
  Value:      Differentiating for AppSec and web-focused red team roles
  Ghost says: Worth it if your path is AppSec. The source code review
              approach is the most real-world relevant exam format.

OSMR — OffSec macOS Researcher
  Tier:       2
  Focus:      macOS attack surface, kernel extensions, hardening bypass
  Value:      Niche but useful if targeting Mac-heavy environments
```

### 2.2 PortSwigger — BSCP (Burp Suite Certified Practitioner)

```
BSCP — Burp Suite Certified Practitioner
  Tier:       1 (for web specialisation)
  Focus:      All major web vulnerability classes, Burp Suite mastery
  Format:     4-hour timed exam — two apps, chained exploitation required
  Cost:       $99
  Value:      The strongest pure web signal short of OSWE
  Ghost says: Highest ROI certification in security, dollar for dollar.
              $99 for a Tier 1 credential. Do this within 3 months.
              You already have the skills from Days 76–165. Review + take.
```

### 2.3 TCM Security — PNPT (Practical Network Penetration Tester)

```
PNPT — Practical Network Penetration Tester
  Tier:       2
  Focus:      Active Directory, network attacks, report writing
  Format:     5-day exam + 2-day debrief
  Cost:       $399
  Value:      Good entry-level signal; better than CEH/CompTIA for real
              pentesting. Less recognized than OSCP at large organizations.
  Ghost says: If you cannot afford OSCP right now and need something
              on your resume, PNPT is a reasonable choice. Not a substitute
              long-term — plan to add OSCP or OSEP eventually.
```

### 2.4 Certifications to Avoid Prioritising

```
LOWER PRIORITY (not worthless, but not differentiating at Ghost Level)

CEH — Certified Ethical Hacker (EC-Council)
  Tier 3. Multiple choice. Memorisation. No hands-on exam.
  Present in many government/compliance requirements only.
  Ghost says: Do not study for this. If required for a government contract,
              take it as a checkbox. Do not list it first on your resume.

CompTIA Security+
  Tier 3 for technical roles.
  Tier 2 for GRC/compliance/helpdesk paths.
  Ghost says: Fine for building baseline credentials. Not relevant if you
              have Ghost Level completion and a CVE credit.

CISSP — Certified Information Systems Security Professional
  Tier 2 for management roles.
  Requires 5 years of paid experience.
  Ghost says: This is a management credential, not a technical one.
              Not the right focus at this stage of your career.
              Revisit when you manage a security team.

GIAC (GPEN, GWAPT, GCFE, etc.)
  Tier 2 — expensive ($949–$1,399 per exam), open-book.
  Some employers (especially US government/defence) value them.
  Ghost says: Useful in specific markets. Not a priority unless your
              target employer lists a specific GIAC as required.
```

---

## 3 — Recommended Certification Roadmap by Path

```
RED TEAM PATH
  Priority 1: OSEP  (6–8 months after Ghost Level gate)
  Priority 2: OSCP  (if not already held; get it first as baseline)
  Priority 3: CRTO  (Certified Red Team Operator — Covenant C2 focused)
  Skip: CEH, Security+, CISSP (at this stage)

VULNERABILITY RESEARCH PATH
  Priority 1: OSED  (if targeting Windows exploitation)
  Priority 2: No certification needed — CVE credits > any cert in VR
  Priority 3: BSCP  (if doing web-focused VR alongside binary)
  Ghost says: In pure VR, your GitHub, blog, and CVE list IS your
              certification. Invest in research output, not exams.

MALWARE ANALYSIS / TI PATH
  Priority 1: BSCP  (cheap, fast, proves web understanding)
  Priority 2: GREM (GIAC Reverse Engineering Malware) — valued in this
              specific field, especially at threat intel vendors
  Priority 3: OSCP  (general credibility)

APPSEC PATH
  Priority 1: BSCP  ($99, Tier 1 signal, takes 1–2 weeks to prep)
  Priority 2: OSWE  (code review focus, directly relevant)
  Priority 3: OSCP  (general credibility)
```

---

## 4 — The One Ghost Rule on Certifications

```
GHOST'S ONE RULE:

Never study for a certification.
Study to build the skill.
Then take the certification to certify the skill you already built.

Studying OSCP course material is the wrong approach if you have already
done this programme. Your approach is: book the exam, do a 2-week timed
mock on TryHackMe/HTB machines, take the exam.

The certification market exists to help people signal skill they do not
yet have. You have the skill. The certification is just paperwork at this
point. Treat it accordingly.
```

---

## Key Takeaways

1. **BSCP is the highest ROI certification in the market right now at $99
   for a Tier 1 hands-on credential.** Do this first regardless of your path.
2. **OSEP is the right red team certification** — it actually tests the kill
   chain you have built over the last 700 days.
3. **In vulnerability research, your CVE list and public research output
   outrank any certification.** Research output > exam score, always.
4. **Never study for a certification you already have the skill for.** A two-week
   timed mock is all you need after Ghost Level training.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q734.1, Q734.2 …).

---

## Navigation

← Previous: [Day 733 — CVE Credits and Disclosure Pipeline](DAY-0733-CVE-Credits-Disclosure-Pipeline.md)
→ Next: [Day 735 — Threat Intelligence Fundamentals](DAY-0735-Threat-Intel-Fundamentals.md)
