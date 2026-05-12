---
title: "Day 741 — Security Research Publication: Write-ups, CVEs, and Conferences"
tags: [research-publication, cve-writing, conference-talk, bug-bounty-report,
  write-up, career, module-12-post-gate]
module: 12-PostGate
day: 741
prerequisites:
  - Day 740 — Milestone 740: Post-Gate Retrospective
  - Day 659 — Writing a Security Advisory (Module 10)
related_topics:
  - Day 742 — Advanced Rootkits and UEFI Implants
---

# Day 741 — Security Research Publication: Write-ups, CVEs, and Conferences

> "The best security researchers in the world are invisible if they do not
> write. A CVE with no write-up is a number in a database. A write-up that
> explains a vulnerability clearly enough that a defender can fix it, and a
> student can learn from it — that is a contribution to the field. Write
> the thing. Publish it. The community improves because of it."
>
> — Ghost

---

## Goals

1. Understand the five publication formats: technical write-up, security
   advisory, CVE report, conference talk, and academic paper.
2. Write a complete, publication-quality write-up for one finding from the
   Ghost Level engagement or Module 12 work.
3. Draft a CVE report and navigate the CVE numbering process.
4. Write a 100-word conference talk abstract for a BSides submission.
5. Understand which platforms pay for security research writing.

---

## 1 — The Five Publication Formats

```
SECURITY RESEARCH PUBLICATION FORMATS

FORMAT 1: TECHNICAL BLOG WRITE-UP
  Audience: Security researchers, developers, CTF players
  Length: 500–5000 words
  Style: First-person narrative; "I found X by doing Y"
  Platforms: Personal blog, GitHub Pages, Medium, dev.to
  Impact: Builds personal brand; teaches the community; SEO for job search

  Examples:
    LiveOverflow blog, lcamtuf (AFL creator), Project Zero blog posts
    Every CTF write-up ever published
  TIME TO WRITE: 2–8 hours for a solid technical write-up

FORMAT 2: SECURITY ADVISORY (vendor-facing)
  Audience: Affected vendor, NVD, downstream users
  Length: 300–1500 words
  Template: See Day 659 advisory format
  Platforms: GitHub Security Advisories, vendor's security mailing list,
             Full Disclosure list (fulldisclosure@seclists.org)
  Impact: Triggers vendor patch; CVE assignment; responsible disclosure record

FORMAT 3: CVE REPORT (via MITRE CNA process)
  Audience: CVE Numbering Authority (CNA), NVD
  Length: 1–2 paragraphs (brief, factual)
  Platforms: cve.org CVE Request form; or via the affected vendor as CNA
  Impact: Permanent public record; cited in vendor advisories and patch notes

FORMAT 4: CONFERENCE TALK / PAPER
  Audience: Security community (technical or mixed)
  Length: 30–45 minute talk; 6–12 page paper
  Platforms: DEF CON, Black Hat, USENIX Security, IEEE S&P, ACM CCS
             BSides (regional, easier to get started)
  Impact: Highest-prestige format; industry career accelerant

FORMAT 5: BUG BOUNTY REPORT
  Audience: Vendor's security team (private, initially)
  Length: 500–2000 words
  Template: HackerOne / Bugcrowd report format
  Impact: Financial reward; public disclosure (optional, after fix)
          HackerOne Hall of Fame; reputation score
```

---

## 2 — The Write-Up Formula

Every good technical security write-up follows this structure:

```
TECHNICAL WRITE-UP STRUCTURE

TITLE: One sentence that states the vulnerability and system.
  Good: "Exploiting a Heap Buffer Overflow in libXXX's PNG Parser"
  Bad: "Cool Bug I Found"

INTRODUCTION (100–200 words):
  - What is the software? Who uses it? Why does it matter?
  - What did you find? (summary of impact)
  - Why is it interesting? (what makes it novel or educational?)

SETUP (50–100 words):
  - How to reproduce the environment
  - Versions, OS, compiler flags used

ROOT CAUSE ANALYSIS (the core section):
  - Walk the reader through the code path step by step
  - Show the vulnerable code with line numbers
  - Explain WHY it is vulnerable (the design assumption that was violated)
  - Code block: show the exact vulnerable function

EXPLOIT DEVELOPMENT:
  - How did you go from bug to PoC?
  - Show the PoC input/script
  - Show the crash output (ASan/GDB/WinDbg)
  - If you developed a full exploit: explain the exploitation technique used

IMPACT:
  - What can an attacker do with this? (RCE? Disclosure? Bypass?)
  - CVSS score with justification
  - ATT&CK technique mapped

TIMELINE:
  - Discovery date
  - Vendor reported date
  - Vendor response date
  - CVE assigned date
  - Fix released date
  - Public disclosure date

FIX:
  - What did the vendor change? (diff or description)
  - Is the fix complete? (are there variants?)

KEY LESSON:
  - One paragraph that generalises the finding
  - "This bug class appears wherever X pattern is used. Look for..."
```

---

## 3 — The CVE Request Process

```
HOW TO GET A CVE ASSIGNED

PATH 1: Via the affected vendor (most common)
  1. Report to vendor security team (security@vendor.com or via their portal)
  2. Vendor triages and confirms
  3. Vendor (if they are a CNA) assigns CVE number themselves
  4. CVE appears in NVD after fix is published

PATH 2: Via MITRE (if vendor is non-responsive)
  1. Report to vendor; wait 14 days (minimum)
  2. If no response or vendor is not a CNA:
     → Submit to MITRE CVE Request: cve.org/ReportRequest/ReportRequestForNonCNAs
  3. Fill in:
     - Vulnerability description
     - Affected version(s)
     - Attack vector and impact
     - Evidence (crash dump, PoC reference)
  4. MITRE assigns CVE number (may take 2–8 weeks)
  5. You coordinate disclosure date with them

PATH 3: Via a Coordinating CNA (faster for known targets)
  - CERT/CC: for critical infrastructure targets
  - GitHub Security: for GitHub-hosted projects
  - Google Project Zero: for Google products

MINIMUM REQUIRED FOR A CVE REQUEST:
  ✓ Affected software and version
  ✓ Reproducible demonstration (PoC or description)
  ✓ Security impact (what can an attacker do?)
  ✓ Contact information (you)

CVE REPORT EXAMPLE:
  "In FooLib 1.2.3 and earlier, the png_read_header() function in
   src/png.c does not validate the width field from the PNG IHDR chunk.
   A crafted PNG file with width=0xFFFFFFFF causes a multiplication
   integer overflow, resulting in a heap buffer allocation of 0 bytes
   followed by a heap buffer overflow when pixel data is written.
   An attacker who can supply a crafted PNG file to an application
   using FooLib can achieve remote code execution. (CWE-190, CWE-122)"
```

---

## 4 — Conference Talk Abstract Template

BSides talks are the entry point for new speakers. Here is the format:

```
BSides [City] [Year] — Talk Submission

TITLE (10 words max):
  _______________________________________________________________

ABSTRACT (100 words):
  Write this as if pitching to both a programme committee AND an attendee.
  Include: what you will cover, why it matters, what the attendee will learn.

  [YOUR ABSTRACT HERE]

SPEAKER BIO (50 words):
  Third person. What you do, what you have researched, what qualifies you to
  give this talk. Do NOT write "I am a student" — write what you have done:
  "Independent security researcher with a focus on [area]. Found and disclosed
  [CVE-X]. Competed in [CTF]. Published [write-ups at URL]."

  [YOUR BIO HERE]

TALK OUTLINE (bullet points, not shown to attendees):
  - (10 min) Setup: what is the system and why does it matter?
  - (15 min) Root cause: the vulnerability, step by step
  - (10 min) Exploitation: PoC demo (live or recorded)
  - ( 5 min) Mitigation and lesson learned

DEMO (Y / N): Y (live demo of PoC on lab system)

AV NEEDS: Standard laptop connection, microphone
```

---

## 5 — Getting Paid to Write

```
PAID SECURITY RESEARCH WRITING

BUG BOUNTY PROGRAMMES:
  Platforms: HackerOne, Bugcrowd, Intigriti, Synack (invitation only)
  Payment: $50 (low-severity, small scope) → $500,000+ (critical, major target)
  Examples of top payouts:
    Google: $31,337 for a single Chromium RCE (cap; actual value varies)
    Apple: $1,000,000 for a full iCloud chain (announced maximum)
    Microsoft: up to $250,000 for Azure vulnerabilities

VULNERABILITY RESEARCH FIRMS:
  ZDI (Zero Day Initiative) — Trend Micro
    Buys unreported vulnerabilities from researchers
    Coordinates disclosure; handles CVE process
    Pays market rate for exploitable bugs in COTS software

SPONSORED RESEARCH:
  Google Project Zero hires researchers (competitive application)
  Trail of Bits, NCC Group, Synacktiv — firms that publish research
  Academic funding for security research papers (NSF, DARPA, DHS)

WRITING PLATFORMS (pay per article):
  Infosec Institute: $200–$400 per accepted technical article
  Hakin9 Magazine: pays for tutorials and research articles
  Dark Reading: editorial submissions (lower pay; high reach)

THE MINIMUM VIABLE FIRST PUBLICATION:
  Write a CTF write-up for a challenge you solved.
  Post it on your personal GitHub Pages blog.
  Submit the link to ctftime.org/writeups for the competition.
  This is free, takes 2 hours, and is the first public record of your work.
```

---

## 6 — Exercise: Write One Thing Today

Select the appropriate exercise for your current output:

**If you have a finding from the Ghost Level engagement:**
Write a complete technical write-up using the structure in Section 2.
Target length: 1000–2000 words. Include code blocks and screenshots.
Publish to a personal blog or GitHub repository.

**If you have a CTF solve from the past 30 days:**
Write a CTF write-up for the challenge.
Explain: what the challenge was, how you approached it, the solution,
and the key lesson. Post to ctftime.org after the CTF window closes.

**If you have no prior public output:**
Write a technical tutorial on any topic from Module 12 (Days 731–741).
Target: 800 words. One concrete code example. One lesson. One takeaway.
Post anywhere public.

---

## Key Takeaways

1. **A write-up is not documentation — it is teaching.** The best write-ups
   explain the REASONING, not just the steps. "I tried X because I thought Y"
   is more valuable than "I ran `aflplusplus -i in -o out ./target @@`." The
   reasoning is what another researcher can reuse; the exact command is
   implementation detail.
2. **The CVE process is more accessible than most researchers assume.** MITRE
   maintains a public request form. Filling it out takes 30 minutes. The main
   barrier is having a confirmed, reproducible, distinct security bug — which
   you now know how to find.
3. **Conference talks are a conversation, not a lecture.** The best BSides and
   DEF CON talks feel like the speaker is sharing something they discovered
   and are genuinely excited about — because they are. Prepare technically.
   But also: remember that the attendee is a human who came to learn something
   useful. That is your obligation.
4. **Publish early, improve iteratively.** Your first write-up will not be as
   good as your tenth. Your tenth will not be as good as your fiftieth. The
   researchers you look up to published their early work too — it was worse
   than what they produce now. The gap between where you are and where you want
   to be closes only by publishing and learning from feedback.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q741.1, Q741.2 …).

---

## Navigation

← Previous: [Day 740 — Milestone 740: Post-Gate Retrospective](DAY-0740-Milestone-740-PostGate-Retrospective.md)
→ Next: [Day 742 — Advanced Rootkits and UEFI Implants](DAY-0742-Advanced-Rootkits-UEFI.md)
