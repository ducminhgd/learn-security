---
title: "HTB Web Series Day 2 — SSRF and XXE Focus"
tags: [HTB, HackTheBox, CTF, web, SSRF, XXE, practice, methodology, bug-bounty]
module: 05-BugBountyOps-02
day: 292
related_topics:
  - HTB Web Series Day 1 (Day 291)
  - SSRF Fundamentals (Day 113)
  - Blind SSRF and OOB Techniques (Day 115)
  - XXE XML External Entities (Day 085)
---

# Day 292 — HTB Web Series Day 2: SSRF and XXE Focus

> "SSRF and XXE look different on the surface but exploit the same trust:
> the server believes what it is told about where to fetch data from.
> Understanding both deepens your intuition for the third category —
> every server-side fetch vulnerability in production."
>
> — Ghost

---

## Goals

Complete one HTB web challenge featuring SSRF or XXE as the primary vector.

**Time budget:** 4–5 hours.

---

## Pre-Engagement Plan

```
Recommended machines: "SteamCloud", "Undetected", or any with SSRF/XXE tag

My hypothesis:
  Primary surface: ___  (file import / webhook / image loader / XML endpoint)
  First test: ___
  OOB callback tool: interact.sh / Burp Collaborator

Tools:
  Burp Suite Repeater
  interact.sh for OOB detection
  xmllint for payload crafting
```

---

## Engagement Log

### Discovery

```
URL-fetching feature found: ___
Endpoint: ___
Parameter: ___
Content type: ___
```

### SSRF Testing

```
Basic payload:
  http://127.0.0.1/      Result: ___
  http://169.254.169.254/ Result: ___

OOB confirmation:
  Callback received from target: Y/N

Filter bypass needed: Y/N
  Bypass technique: ___
```

### XXE Testing (if XML target)

```
DOCTYPE injection payload:
___

File read result:
___

SSRF via XXE:
___
```

### Flag

```
FLAG{___}
Time to flag: ___ minutes
```

---

## Debrief — Real World Connection

```
1. In a real production application, what feature most commonly introduces this?
   ___

2. How would you detect this SSRF/XXE in a WAF rule or Sigma rule?
   ___

3. If this reached AWS metadata, what would the full exploit chain look like?
   ___

4. One-line fix for SSRF:
   ___
   One-line fix for XXE:
   ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q292.1, Q292.2 …).

---

## Navigation

← Previous: [Day 291 — HTB Web Series Day 1](DAY-0291-HTB-Web-Series-Day-01.md)
→ Next: [Day 293 — HTB Web Series Day 3](DAY-0293-HTB-Web-Series-Day-03.md)
