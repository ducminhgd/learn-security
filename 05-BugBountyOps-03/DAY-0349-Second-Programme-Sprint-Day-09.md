---
title: "Second Programme Sprint Day 9 — Community Engagement and Programme Research"
tags: [live-programme, bug-bounty, second-sprint, community, research, practice]
module: 05-BugBountyOps-03
day: 349
related_topics:
  - Second Programme Sprint Day 8 (Day 348)
  - Community and Resources (Day 274)
  - Studying Public Disclosures (Day 271)
---

# Day 349 — Second Programme Sprint Day 9: Community Engagement and Programme Research

---

## Goals

Engage with the bug bounty community to cross-check approaches.
Research the two target programmes for any public information that informs testing.
This is the day between active testing and sprint close — use it for intelligence.

**Time budget:** 3–4 hours.

---

## Programme Research

### Programme 1 — Historical Disclosures

```bash
# HackerOne Hacktivity — filter by programme
# https://hackerone.com/PROGRAMME/hacktivity

# What bugs have been disclosed for this programme?
# Note: duplicate-prone areas (everyone tested these)
```

```
Programme 1 disclosed vulnerabilities:
  Type: ___  Year: ___  Notes for my testing: ___
  Type: ___  Year: ___
  Type: ___  Year: ___

"Crowded" surfaces where duplicates are likely for Programme 1:
  ___

Less-tested surfaces (few disclosures, indicating either clean or overlooked):
  ___
```

### Programme 2 — Technology CVE Research

```bash
# Research known CVEs for the target's tech stack
# Stack identified: ___

# Example: if target uses Spring Boot 2.x
# CVE-2022-22963: Spring4Shell — SpEL injection → RCE
# CVE-2021-22965: Spring Data Commons exposure

# Nuclei template available? Check:
ls ~/nuclei-templates/cves/ | grep FRAMEWORK
```

```
CVEs relevant to Programme 2 tech stack:
  CVE: ___  Affected version: ___  Nuclei template: Y/N
  CVE: ___  Affected version: ___  Nuclei template: Y/N

Version of target software: ___  (detected from: headers / source / error)
Target version matches vulnerable range: Y/N
```

---

## Community Check-In

```
Twitter/X search: "#bugbounty PROGRAMME_NAME"
  Recent tweets about the programme: ___
  Any public research or tools built for this target: ___

Discord community check (if member):
  Channels checked: ___
  Relevant discussions: ___

Write-up sites:
  Pentester.land search for PROGRAMME_NAME: ___
  HackerOne blog posts: ___
```

---

## Gap Analysis Before Sprint Close

```
Surfaces I have NOT tested on Programme 2 (be honest):
  [ ] WebSockets (if present)
  [ ] GraphQL depth (if present)
  [ ] Admin portal (if accessible)
  [ ] Password reset flow complete test
  [ ] 2FA bypass
  [ ] Mobile app (if in scope)

Can I test any of these in Day 350 (final day)?
  Priority: ___
  Time: ___ hours available
```

---

## Research-Driven Finding

```
Based on today's research, new angle to test on Day 350:
  ___  (informed by: CVE / disclosure / community tip)

Hypothesis:
  "The target may be vulnerable to ___ because ___"

Test plan:
  1. ___
  2. ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q349.1, Q349.2 …).

---

## Navigation

← Previous: [Day 348 — Second Programme Sprint Day 8](DAY-0348-Second-Programme-Sprint-Day-08.md)
→ Next: [Day 350 — Second Programme Sprint Day 10](DAY-0350-Second-Programme-Sprint-Day-10.md)
