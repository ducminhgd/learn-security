---
title: "Security Engineering Interview Preparation — Technical Rounds, System Design, Scenarios"
tags: [interview, career, technical-interview, system-design, red-team-interview,
  module-12-postghost]
module: 12-PostGhostLevel
day: 745
prerequisites:
  - Day 731 — Career Path Planning
related_topics:
  - Day 748 — Methodology Crystallisation
---

# Day 745 — Security Engineering Interview Preparation

> "The interview is a sample of what it will be like to work with you. At a
> good security team, they will not ask you to recite CVE numbers. They will
> give you a scenario and watch how you think through it. They want to know:
> Can you reason about systems you have never seen? Can you explain complex
> things clearly? When you do not know the answer, do you admit it — or
> do you bluff? Bluffing ends the conversation."
>
> — Ghost

---

## Goals

Understand the interview process at elite security teams (FAANG, boutique
consultancies, product security roles). Know how to prepare for technical
rounds, system design interviews, and hands-on challenge rounds. Know how to
present your bug bounty, CTF, and research work effectively.

**Prerequisites:** Day 731.
**Estimated study time:** 2.5 hours + active preparation time.

---

## 1 — Interview Process Overview

```
TYPICAL SECURITY ENGINEERING INTERVIEW PIPELINE

Stage 1: Recruiter Screen (30 min)
  Background, experience, role alignment
  Compensation expectations, availability
  Your job: qualify the role, ask about team structure

Stage 2: Technical Phone Screen (45–60 min)
  Security-specific knowledge questions
  One scenario or problem-solving exercise
  Your job: demonstrate depth, not breadth

Stage 3: Technical Onsite / Virtual (3–5 rounds × 45–60 min)
  Round A: Security knowledge deep-dive
  Round B: Hands-on CTF challenge or reverse engineering session
  Round C: System design (security-flavoured)
  Round D: Behavioural (STAR format)
  Round E: Team fit / culture round

Stage 4: Offer + Negotiation

VARIATIONS BY ROLE:
  Red team:        Heavy on practical (live exploitation), lighter on system design
  Malware analyst: Bring a sample for live analysis during interview
  AppSec:          Code review + threat model + system design
  VR engineer:     CTF-style binary + source audit
  Detection eng:   Write a Sigma rule + explain a SIEM query
```

---

## 2 — Technical Knowledge Questions

Prepare deep answers for these. Not bullet points — actual explanations.

```
SECURITY KNOWLEDGE QUESTION BANK

MEMORY EXPLOITATION:
  Q: Explain tcache poisoning from scratch. How does it differ in glibc 2.34?
  Q: What is FSOP and how does it apply after __free_hook was removed?
  Q: Walk me through a format string exploit that overwrites a GOT entry.

WEB / API:
  Q: Explain HTTP request smuggling — how does a CL.TE desync work?
  Q: What is the difference between a stored XSS and a DOM-based XSS from
     a detection perspective? Write a WAF rule for each.
  Q: How would you test for BOLA (IDOR) in a GraphQL API?

ACTIVE DIRECTORY:
  Q: Explain DCSync — what permission is required and what log event is produced?
  Q: What is a Golden Ticket? How does it differ from a Diamond Ticket?
  Q: Explain ADCS ESC1 step by step — what is being abused and what is the fix?

MALWARE:
  Q: Walk me through your process when you receive an unknown PE sample.
  Q: How does a tcache UAF work in a .NET managed heap? (Different!)
  Q: What is process hollowing and how does Sysmon detect it?

CRYPTOGRAPHY:
  Q: Explain a CBC padding oracle attack from the attacker's perspective.
  Q: What makes ECDSA vulnerable to nonce reuse?
  Q: Why is JWT alg:none a vulnerability? What fix closes it?

DETECTION:
  Q: A Sigma rule fires 1000 times a day. How do you investigate if it is
     catching real attacker activity or just noise?
  Q: What is a detection coverage matrix and how do you measure it?
  Q: An analyst tells you they see a spike in PowerShell activity on 50 hosts.
     Walk me through how you triage this event.
```

---

## 3 — System Design for Security Roles

```
SECURITY SYSTEM DESIGN QUESTIONS

COMMON PROMPT: "Design a threat detection system for a 5,000-endpoint
  organisation that can detect ransomware pre-encryption."

ANSWER FRAMEWORK:
  1. Clarify scope: endpoints only? Network? Cloud?
  2. Data sources: EDR telemetry, Sysmon, DNS logs, proxy logs, NetFlow
  3. Detection logic: what ransomware behaviour is detectable?
     - Rapid file rename/write events (T1486)
     - Shadow copy deletion via vssadmin/wmic (T1490)
     - Unusual process tree (explorer.exe → cmd.exe → vssadmin.exe)
     - Large-volume SMB writes across shares (lateral encryption)
  4. Architecture: SIEM ingest pipeline → correlation rules → alert routing
  5. Response: automated isolation (EDR kill-switch) + SOC ticket
  6. Limitations: what does this NOT catch? (LotL ransomware, slow encryption)

SCORING CRITERIA FOR INTERVIEWERS:
  Did they ask clarifying questions first? → Shows product thinking
  Did they address detection AND response? → Full-cycle thinking
  Did they name limitations honestly? → Security realism, not overselling
  Can they name specific log sources and event IDs? → Real practitioner depth
  Did they consider the false-positive cost? → Operational maturity
```

---

## 4 — Hands-On Rounds

```
HANDS-ON CHALLENGE TYPES BY ROLE

RED TEAM / EXPLOIT DEVELOPMENT:
  "Here is a binary. Find the vulnerability and get a shell."
  Time: 30–90 minutes
  What they look for: methodology, not just outcome
  - How quickly do you identify the binary's protections?
  - What is your first 5 minutes? (file, checksec, strings, ltrace)
  - Do you narrate your thinking out loud? (critical — they are watching process)
  - If you get stuck: do you say so? Ask for a hint?

MALWARE ANALYSIS:
  "Here is a sample. Give me a 5-minute verbal briefing in 10 minutes."
  What they look for:
  - Triage speed: can you identify malware family from static analysis quickly?
  - IOC extraction: do you know which strings matter?
  - ATT&CK mapping: can you name the techniques without the cheat sheet?
  - Confidence calibration: "I believe this is X based on Y, but I have not
    confirmed Z yet."

APPSEC CODE REVIEW:
  "Here is a web application. Find the vulnerabilities."
  400 lines of Python/Go/Java, intentionally vulnerable
  What they look for:
  - Do you look for injection sinks first? (grep for user input touching DB/OS)
  - Do you note false positives correctly? (not every dynamic query is SQLi)
  - Can you assess severity accurately? (a reflected XSS in a logged-in page
    is lower risk than on the login page)

PREPARE BY:
  Practising your narration out loud (talk while you hack — every time)
  Timed sessions: 60 minutes on an unknown binary, announce your findings
  Doing 5 live code reviews on open-source code (find bugs, write them up)
```

---

## 5 — Presenting Your Background

```
HOW TO TALK ABOUT YOUR EXPERIENCE

BUG BOUNTY:
  BAD: "I do bug bounty hunting."
  GOOD: "I focus on API security in web applications. In the last 12 months
        I submitted 7 reports to HackerOne, 3 of which were accepted: two
        BOLA vulnerabilities and one OAuth token leakage in a redirect flow.
        I write all my findings to CVSS 3.1 standards and always include
        a business impact statement."

CTF:
  BAD: "I play CTFs sometimes."
  GOOD: "My primary CTF categories are pwn and reversing. I competed in
        Google CTF 2024 and solved 4/6 pwn challenges, including the kernel
        UAF in the final round. I write up every novel solve — you can see
        my write-ups at [URL]."

THIS PROGRAMME:
  BAD: "I followed an online course for 2 years."
  GOOD: "I completed a structured 730-day programme covering binary exploitation,
        reverse engineering, red team operations, malware analysis, and
        vulnerability research. I passed 7 competency gates requiring live
        demonstrations: writing a working ROP chain, reversing a packed binary,
        reproducing a CVE from patch diff, and conducting a full kill-chain
        engagement. I can walk you through any of these in detail."

CVE CREDITS:
  BAD: "I found a vulnerability once."
  GOOD: "CVE-2025-XXXXX — I found a heap buffer overflow in [library] via AFL++,
        reproduced it with AddressSanitizer, wrote a PoC, and reported it to
        the vendor. 90-day disclosure. Patch shipped in version X.Y.Z."
```

---

## Key Takeaways

1. **Narrate your thinking out loud during hands-on rounds.** Interviewers are
   hiring for process, not just outcome. A wrong answer explained clearly is
   better than a correct answer arrived at silently.
2. **Admit what you do not know.** "I do not know the exact mechanism but I would
   start by investigating X" is a strong answer. "Let me pretend I know" ends
   the process.
3. **Translate your experience into specifics.** "I do bug bounty" means nothing.
   "I submitted 3 accepted reports including two BOLA findings, CVSS 7.5 and 6.8"
   is verifiable and specific.
4. **System design interviews test your ability to think about trade-offs.** There
   is no perfect answer — there is a well-reasoned answer that acknowledges
   what the design cannot do.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q745.1, Q745.2 …).

---

## Navigation

← Previous: [Day 744 — CTF Team Strategy](DAY-0744-CTF-Team-Strategy.md)
→ Next: [Day 746 — OPSEC for Security Researchers](DAY-0746-OPSEC-for-Researchers.md)
