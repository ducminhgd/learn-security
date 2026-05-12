---
title: "Methodology Crystallisation — Personal Playbook, Knowledge Management, The Ghost Method Variant"
tags: [methodology, personal-playbook, knowledge-management, obsidian, second-brain,
  module-12-postghost]
module: 12-PostGhostLevel
day: 748
prerequisites:
  - Day 730 — Ghost Level Competency Gate
related_topics:
  - Day 749 — Specialization Research Plan
---

# Day 748 — Methodology Crystallisation

> "Experience without a system is stories. Stories are entertaining but they do not
> transfer. The difference between a practitioner with ten years of experience and
> a practitioner with one year of experience repeated ten times is whether they
> extracted lessons and built a methodology. Write yours down. Today."
>
> — Ghost

---

## Goals

Build a personal security methodology document. Implement a knowledge management
system appropriate for a security practitioner. Understand how to maintain and
iterate on your methodology over time.

**Prerequisites:** Day 730.
**Estimated study time:** 3 hours (reflection and writing).

---

## 1 — What a Personal Methodology Is

```
METHODOLOGY vs CHECKLIST vs PROCESS

CHECKLIST:  A list of things to do. Context-free.
            Example: "Run nmap. Run Nikto. Run gobuster."
            Problem: No decision-making. Does not adapt to findings.

PROCESS:    An ordered sequence of steps. Better.
            Example: "Enumerate → Identify candidates → Exploit → Pivot"
            Problem: Still linear. Does not handle uncertainty well.

METHODOLOGY: A reasoning framework that produces appropriate actions
              given the current state of knowledge.
              Example: "I am at this phase. I know X and do not know Y.
                        Given X, the highest-value next action is Z.
                        If Z reveals A, I move to phase Q.
                        If Z reveals B, I pivot to approach R."
              Advantage: handles uncertainty; adapts to novel situations

A personal methodology is built from:
  - The patterns you notice across many engagements
  - The mistakes you made and what they taught you
  - The techniques that worked reliably vs. the ones that were circumstantial
  - A mental model of your target environment (web, AD, binary, etc.)
```

---

## 2 — The Ghost Method: A Reference Architecture

The four-stage method from Day 1 remains the foundation:

```
THE GHOST METHOD (revisited at Day 748)

Stage 1: RECON — What do we know? What do we not know?
  For web: what tech stack, what auth model, what data surfaces?
  For AD: what domains, trusts, privileged accounts, attack paths?
  For binary: what protections, what input surfaces, what memory allocator?

Stage 2: EXPLOIT — Given the most promising attack surface, attack it.
  Prioritise by: severity of vulnerability class × likelihood of presence
  Do the simplest attack first. Escalate complexity if it fails.
  Document every failed attempt — failures constrain the solution space.

Stage 3: DETECT — What evidence did this leave?
  Log analysis. EDR telemetry. Network flows.
  This stage builds defensive empathy — which is what makes better attackers.

Stage 4: HARDEN — What specific change prevents this?
  Not "improve security." The exact line of code, config change, or control.
  One correct answer. If you cannot name it, you do not understand the bug.

HOW TO PERSONALISE THIS:
  Your methodology is built by adding:
  - Your personal "check this first" list for each domain
  - The patterns you reliably find vs. the ones that waste your time
  - Your tool preferences with the flags you actually use
  - Your decision heuristics: "when I see X, I immediately try Y"
```

---

## 3 — Writing Your Personal Methodology Document

```
PERSONAL METHODOLOGY DOCUMENT STRUCTURE

Section 1: My Primary Domain and Focus
  One paragraph: what you specialise in, what environments you are most
  effective in, what your adversary model is.

Section 2: Pre-Engagement Preparation
  For your domain: what do you set up before you start?
  Tools, VMs, credentials, notes template
  OPSEC checklist: scope documentation confirmed?

Section 3: Phase 1 — Initial Orientation (first 30 minutes)
  For your domain, what is your first 30 minutes?
  What do you look at first, in what order, and why?
  What do you decide at the end of this phase?

Section 4: Phase 2 — Enumeration and Surface Mapping
  For your domain: what constitutes a "complete" enumeration?
  What tools + commands? What output do you interpret?
  What are the "high-value" vs "low-value" findings here?

Section 5: Phase 3 — Exploitation
  Decision framework: given what I found, what do I try first?
  Your personal "decision tree" for the 5 most common vulnerability paths
  in your domain.

Section 6: Phase 4 — Depth vs Breadth Decision
  When do you go deeper on one finding vs pivot to another target?
  Your personal heuristic for this.

Section 7: Phase 5 — Post-Exploitation (if applicable)
  Evidence collection, pivoting, persistence, escalation in your domain.

Section 8: Reporting
  Your personal report template (from Day 743 / advisory format)
  CVSS scoring heuristics for your domain
  Impact framing language that you use reliably

Section 9: Lessons Learned Register
  A running list of "what I learned from [engagement]"
  Format: [date] — [what I thought] vs [what was actually true] — [lesson]

Section 10: Tool Reference Card
  Your 20 most-used tools with the exact commands you run most often
  Not documentation — your personal shortcut sheet
```

---

## 4 — Knowledge Management System

```
SYSTEM REQUIREMENTS FOR A SECURITY KM SYSTEM

Must have:
  Search: full-text search across all notes
  Tagging: tag notes by domain, technique, CVE, ATT&CK ID
  Cross-reference: link notes to each other (technique → CVE → exploitation)
  Code blocks: syntax-highlighted command references
  Local storage: sensitive research notes should not be in the cloud

Recommended tools:

OBSIDIAN (recommended):
  Local markdown files, plugin ecosystem, graph view
  Works offline, no cloud dependency
  Plugins to install:
    - Dataview (query your notes like a database)
    - Tag Wrangler (manage tags)
    - Calendar (daily note → research log)
    - Templater (note templates for labs, CVEs, engagements)

NOTION (alternative):
  Better for collaboration (shared team wiki)
  Cloud-based (not ideal for sensitive research)
  Good for structured templates

PLAIN FILES + GREP (minimal):
  Works. Does not require learning a new tool.
  Directory structure = organisation system
  Works with any editor.

WHAT TO PUT IN YOUR KM SYSTEM:
  For every technique you learn:
    - How it works (one paragraph)
    - The minimal exploit / the minimal detection query
    - Real-world CVE or breach it appeared in
    - Your personal notes from when you reproduced it
  For every tool:
    - The flags you actually use
    - The output format and what to look for
    - Edge cases you have encountered
  For every engagement:
    - Timeline and findings (anonymised for personal notes)
    - What worked, what didn't
    - Lessons learned
```

### 4.1 Obsidian Template for a Technique Note

```markdown
---
tags: [technique, t1547-001, persistence, windows]
cwe: CWE-284
att&ck: T1547.001
---

# Registry Run Key Persistence

## How it works
An attacker writes a value to HKCU\...\Run or HKLM\...\Run.
The executable at the specified path is run at logon.

## Minimal exploit
```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /d "C:\temp\malware.exe"
```

## Detection
Sysmon Event ID 13 (RegistryValueSet) on Run key path.
Sigma: reg_key_run_modification.yml

## Real-world appearance
Used by: AsyncRAT, Emotet, AgentTesla, Cobalt Strike (many)
CVE: n/a (configuration weakness)

## My notes
- Easiest persistence. Always check during triage.
- HKCU requires no admin rights.
- HKLM requires admin rights.
- Antivirus frequently suppresses HKLM writes from unsigned binaries.

## See also
- [[WMI Persistence]] for more evasive alternative
- [[Scheduled Task Persistence]] for time-based variant
```

---

## 5 — The Iteration Discipline

```
HOW TO KEEP YOUR METHODOLOGY ALIVE

Bad approach:
  Write methodology document on Day 748.
  Never update it.
  Five years later it references deprecated tools and outdated techniques.

Good approach:
  After every engagement or lab session:
    5 minutes: update one thing in the methodology
    Add one lesson learned
    Update one tool reference
    Link one new technique note

Weekly:
  30 minutes: review the lessons learned register
  Update the "what I tried vs what worked" log

Quarterly:
  Review the methodology document for outdated information
  Add newly mastered techniques
  Remove techniques you no longer use
  Update tool references to current versions

THE COMPOUNDING VALUE:
  A methodology document maintained for 3 years is worth more than
  3 years of raw experience without documentation.
  It externalises your memory, making you faster.
  It surfaces patterns across engagements you would not notice otherwise.
  It is the difference between a practitioner who improves every year
  and one who does the same year repeatedly.
```

---

## Key Takeaways

1. **A methodology is a reasoning framework, not a checklist.** It produces the
   right action given the current state of uncertainty — checklists cannot
   do that.
2. **Obsidian is the recommended KM tool for security practitioners** who value
   local storage, markdown, and a powerful search + link graph. Install it today.
3. **The methodology is only valuable if you update it.** Five minutes after
   every engagement, every lab session, every lesson. Small, consistent updates.
4. **The lessons learned register is the most valuable section.** Every mistake
   you name and extract a lesson from becomes a permanently avoided mistake.

---

## Exercises

1. Write Section 1 and Section 3 of your personal methodology document.
2. Set up an Obsidian vault (or equivalent) with a template for technique notes.
3. Write five technique notes for the five techniques you use most often.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q748.1, Q748.2 …).

---

## Navigation

← Previous: [Day 747 — Incident Response Leadership](DAY-0747-IR-Leadership.md)
→ Next: [Day 749 — Specialization Research Plan](DAY-0749-Specialization-Research-Plan.md)
