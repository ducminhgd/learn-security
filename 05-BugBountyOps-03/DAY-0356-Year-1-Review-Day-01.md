---
title: "Year-1 Review Day 1 — Foundation and Offensive Skill Recall"
tags: [Year-1, review, recall, foundation, offensive, gate-prep]
module: 05-BugBountyOps-03
day: 356
related_topics:
  - Report Review Day 5 (Day 355)
  - Foundation Track (Days 1–90)
  - Offensive Track (Days 91–180)
---

# Day 356 — Year-1 Review Day 1: Foundation and Offensive Skill Recall

> "Year one is not the end of the programme. It is the first gate. The
> question it answers is: can you operate independently in an authorised
> engagement? If yes, year two begins. If not, the gaps get fixed before
> year two starts."
>
> — Ghost

---

## Goals

Test recall of foundation and offensive concepts without reference material.
Identify any forgotten fundamentals before the Year-1 Gate.

**Time budget:** 4–5 hours.

---

## Part 1 — Foundation Recall (No Reference)

Write answers from memory. Check correctness afterwards.

```
F-01 — TCP/IP:
  Q: What happens during the TCP 3-way handshake?
  A: ___

  Q: How does DNS resolution work when you visit google.com?
  A: ___

  Q: What is the TLS handshake? At what layer does it operate?
  A: ___

F-02 — Linux:
  Q: What does SUID do? Give an example of a dangerous SUID binary.
  A: ___

  Q: How would you find all SUID binaries on a Linux system?
  A: ___

F-03 — Networking:
  Q: What is ARP? How does ARP spoofing work?
  A: ___

  Q: What is the difference between TCP SYN scan and a full connect scan?
  A: ___

F-04 — Cryptography:
  Q: Why is ECB mode insecure? What attack does it enable?
  A: ___

  Q: What is a CBC padding oracle attack? What does it reveal?
  A: ___

F-05 — Web architecture:
  Q: What is the Same-Origin Policy? What does it prevent?
  A: ___

  Q: What is the difference between a cookie's HttpOnly and Secure flags?
  A: ___

F-06 — Authentication:
  Q: What is the difference between authentication and authorisation?
  A: ___

  Q: What is PKCE and why was it added to OAuth 2.0?
  A: ___
```

---

## Part 2 — Offensive Technique Recall

```
BOLA:
  Q: Explain BOLA in one sentence. Why is it the #1 API vulnerability?
  A: ___

SQLi:
  Q: Write a minimal blind boolean SQLi payload to check if username='admin' exists.
  A: ___

XSS:
  Q: Write an XSS payload that works when user input lands inside an HTML attribute value.
  A: ___

SSRF:
  Q: List three alternative representations of 127.0.0.1 used to bypass SSRF filters.
  A: ___

JWT:
  Q: What is the alg:none attack? Write the curl command to exploit it.
  A: ___

SSTI:
  Q: What payload detects Jinja2 SSTI? What does it output?
  A: ___

AWS IAM:
  Q: What single IAM permission allows an attacker to become admin?
     (There are multiple — name at least two.)
  A: ___
```

---

## Part 3 — Score and Gap Identification

```
Questions answered correctly from memory: ___ / ___
Questions requiring reference: ___
Questions I could not answer: ___

Topics to revisit before Day 365 gate:
  1. ___
  2. ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q356.1, Q356.2 …).

---

## Navigation

← Previous: [Day 355 — Report Review Day 5](DAY-0355-Report-Review-Resubmit-Day-05.md)
→ Next: [Day 357 — Year-1 Review Day 2](DAY-0357-Year-1-Review-Day-02.md)
