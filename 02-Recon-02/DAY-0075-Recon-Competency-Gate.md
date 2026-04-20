---
title: "Recon Competency Gate — GATE: Recon Ready"
tags: [gate, competency-check, recon, attack-surface-document, assessment,
       passive-recon, active-recon, methodology, bug-bounty, milestone]
module: 02-Recon-02
day: 75
related_topics:
  - Recon Review and Preparation (Day 074)
  - Web Exploitation Track (Days 076–165)
  - Foundation Competency Gate (Day 050)
---

# Day 075 — Recon Competency Gate

## **GATE: Recon Ready**

> "You have 25 days of recon behind you. Today we find out if you can do it
> — not explain it, not describe it, but actually execute it.
> Show me the document. Show me the commands. Show me the findings."
>
> — Ghost

---

## Gate Requirements

To pass this gate you must satisfy **all three** of the following:

### Requirement 1 — Attack Surface Document

Submit a completed attack surface document (template from Day 074) for an
authorised target. The document must include:

```
✓ Scope analysis (programme rules reviewed and noted)
✓ Subdomains discovered (minimum 10 for a non-trivial target)
✓ At least 5 live web services with tech stack identified
✓ Open ports (non-web) and associated service fingerprint
✓ At least 3 content discovery findings (endpoints, backup files, admin panels)
✓ JS analysis: at least 1 endpoint extracted from source code
✓ Prioritised P0/P1 target list with reasoning
✓ nuclei scan results (even if no findings)
```

Acceptable targets:
- A bug bounty programme you are enrolled on (preferred)
- HackTheBox machine (any Easy/Medium rated)
- TryHackMe room with web challenges
- Your own personal lab environment (Day 069 Docker lab or equivalent)

### Requirement 2 — Live Demo

Demonstrate the following without referencing notes:

```
1. Run a two-phase port scan on a target IP:
   Phase 1: masscan full port sweep → extract open ports
   Phase 2: nmap service+script scan on open ports only

2. Run directory fuzzing on a live web service with:
   - Correct wordlist selection (justify your choice)
   - Response size filter set from baseline
   - Output saved as JSON

3. Extract at least one API endpoint from a JavaScript file
   (use LinkFinder or manual grep — your choice)

4. Run nuclei against at least one live URL and interpret the output

5. Identify the technology stack of a target from HTTP headers alone
   (paste headers, name the technologies, explain your reasoning)
```

### Requirement 3 — Oral Knowledge Check

Be prepared to answer (without notes) questions from this list. Ghost will
select five at random:

1. Explain the packet flow of an nmap SYN scan. Why is it called "half-open"?
2. What is the difference between `open`, `filtered`, and `open|filtered` port
   states?
3. A programme has scope `*.target.com`. You find `old-app.target-legacy.com`
   on the same server. Is it in scope? Explain.
4. You run ffuf and get 500 results. They all have the same size as the 404 page.
   What went wrong and how do you fix it?
5. What is a CNAME subdomain takeover? Name the tool that scans for it and the
   resource that lists vulnerable services.
6. Name three things arjun does differently from ffuf.
7. What HTTP header signals that a site is running PHP? How should a hardened
   server handle this?
8. Your nuclei scan returns a High severity finding. What is your next step
   before reporting it?
9. Describe the amass → dnsx → httpx → nuclei pipeline. What does each tool
   contribute?
10. An organisation wants to detect when a researcher is fuzzing their API.
    What log would record this and what pattern would you look for?

---

## Scoring

| Requirement | Pass criteria |
|-------------|---------------|
| Attack Surface Document | All required sections present; findings are genuine |
| Live Demo | All 5 demonstrations completed without external help |
| Oral Check | 4/5 questions answered correctly and completely |

**All three requirements must pass.** A strong document cannot compensate
for a failed demo, and vice versa.

---

## What Happens If You Do Not Pass

No failure — only data.

If you fail a section:
- **Document incomplete:** Identify missing sections. Return to the source
  lesson. Re-run recon. Submit again.
- **Demo difficulty:** Identify which step blocked you. Practice that tool
  in isolation for 2 hours. Retry.
- **Oral question wrong:** The incorrect answer shows a specific gap. Return
  to that lesson. Re-read. Write a one-paragraph explanation in your own
  words. Come back.

There is no time limit for retry. The gate exists so that the next track —
web exploitation — does not collapse because your recon is broken.

---

## Post-Gate: What Comes Next

Passing this gate means you can:

```
✓ Enumerate a target's full attack surface
✓ Build and run an automated recon pipeline
✓ Read and respect programme scope
✓ Identify the most valuable targets in a scope
✓ Detect when others are running recon against you
```

You are now ready to move into **web exploitation** — the phase where you
take the attack surface you have mapped and start breaking things.

```
03-WebExploit-01: Injection Attacks (Day 076)
  ├── SQL Injection
  ├── Command Injection
  ├── SSTI
  └── XXE
```

The first lesson is waiting. But you only go there after this gate passes.

---

## Gate Submission

When you are ready:

1. Prepare your attack surface document.
2. Have a lab target ready for the live demo.
3. Ask Ghost: "I am ready for the Recon gate."
4. Ghost will review the document, observe the demo, and ask the oral questions.

```
Submission checklist:
[ ] Attack surface document is complete and saved
[ ] Lab target is running and accessible
[ ] All tools are installed and tested
[ ] Terminal is open with the output of at least one previous scan
[ ] I can answer the knowledge check questions without notes
```

---

## Competency Gate Record

*(Completed by Ghost upon passing)*

```
Student:      ___________________________
Target used:  ___________________________
Date:         ___________________________

Document:     PASS / FAIL
Demo:         PASS / FAIL
Oral:         PASS / FAIL  (Score: ___ / 5)

Overall:      PASS / FAIL

Notes:
___________________________________________
___________________________________________
___________________________________________

Ghost sign-off: ___________________________
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 074 — Recon Review and Preparation](DAY-0074-Recon-Review-and-Preparation.md)*
*Next: [Day 076 — SQL Injection Fundamentals](../03-WebExploit-01/DAY-0076-SQL-Injection-Fundamentals.md)*
