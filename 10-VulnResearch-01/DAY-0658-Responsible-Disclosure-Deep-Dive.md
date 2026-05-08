---
title: "Responsible Disclosure — CVE Process, Coordinated Disclosure, Bug Bounty"
tags: [vulnerability-research, responsible-disclosure, CVE-process, bug-bounty,
  coordinated-disclosure, ethics, CERT, PSIRT, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 658
prerequisites:
  - Day 657 — CVE Reproduction Lab
related_topics:
  - Writing a Security Advisory (Day 659)
  - Ghost Level Operations (Day 701+)
---

# Day 658 — Responsible Disclosure: CVE Process, Coordinated Disclosure, Bug Bounty

> "You found the bug. You built the PoC. Now what? This is where researchers
> get it wrong. Not the technical part — the ethics part. Do you publish
> immediately? Do you sell it? Do you tell the vendor? Do you wait 90 days?
> There are real legal, professional, and ethical stakes. Get this wrong and
> you turn a legitimate finding into a criminal act. Get it right and you
> build a reputation that opens doors for years."
>
> — Ghost

---

## Goals

Understand the full spectrum of disclosure approaches. Know the CVE process
from discovery to publication. Understand bug bounty programme mechanics.
Know the legal landscape (CFAA, Computer Misuse Act). Develop a personal
disclosure ethics framework.

**Prerequisites:** Day 657.
**Estimated study time:** 3 hours.

---

## Disclosure Approaches — The Full Spectrum

```
VULNERABILITY DISCLOSURE SPECTRUM
═══════════════════════════════════════════════════════════════════════

FULL DISCLOSURE (immediate)
  Post everything publicly the day you find it.
  ● Pro: Maximum pressure on vendor to patch quickly
  ● Con: Attackers exploit it before a patch exists
  ● Legal risk: HIGH in some jurisdictions
  ● Modern consensus: Not the default approach
  ● When appropriate: When vendor has been notified and refuses to patch

COORDINATED DISCLOSURE (standard)
  Notify vendor privately → give time to patch → publish after fix
  Timeline: typically 90 days (Google Project Zero standard)
  ● Pro: Vendor can patch before public knows; protects users
  ● Con: Vendor may stall, delay, or ignore disclosure
  ● Legal risk: LOW (good faith research, documented timeline)
  ● Modern consensus: THE default approach for most researchers

BUG BOUNTY PROGRAMME
  Submit through a vendor's official programme (HackerOne, Bugcrowd, etc.)
  ● Pro: Paid, legal framework, structured process
  ● Con: Vendor controls scope and payout; may not cover all software
  ● Legal risk: VERY LOW (explicit authorisation in scope)
  ● When: Vendor has an active programme covering the target

PRIVATE SALE (grey/black market)
  Sell to brokers, governments, or other buyers
  ● Pro: Maximum financial return for the researcher
  ● Con: May enable offensive operations against civilians; legal grey zone
  ● Legal risk: VARIES BY JURISDICTION AND BUYER
  ● Ghost's position: Not recommended for anyone training in this programme

SILENT FIX (vendor only)
  Tell the vendor, they fix it silently with no CVE or credit
  ● Pro: Vendor relationship; reduced exploitation window
  ● Con: Users don't know to patch; no credit for researcher
  ● When: Vendor requests this, researcher agrees as exception
```

---

## Stage 1 — The CVE Process

```python
#!/usr/bin/env python3
"""
CVE process — from discovery to publication.
"""
from __future__ import annotations

CVE_PROCESS = {
    "step_1_discover": {
        "title": "Discover and Confirm",
        "actions": [
            "Reproduce the vulnerability reliably",
            "Determine affected versions (minimum and maximum)",
            "Assess CVSS score and exploitability",
            "Document: root cause, PoC, affected versions",
        ],
        "output": "Internal vulnerability report",
    },
    "step_2_find_contact": {
        "title": "Find the Vendor Security Contact",
        "sources": [
            "SECURITY.md in the project's repository",
            "GitHub: Security → Security Advisories → 'Report a vulnerability'",
            "security@<domain> — most common generic address",
            "Product Security Incident Response Team (PSIRT) page",
            "CERT/CC as intermediary if direct contact fails",
        ],
        "output": "Vendor contact identified",
    },
    "step_3_notify": {
        "title": "Notify the Vendor",
        "what_to_include": [
            "Affected product and version range",
            "Vulnerability class and CWE",
            "Step-by-step reproduction instructions",
            "CVSS score (your assessment)",
            "Suggested fix (if you have one)",
            "Your disclosure timeline (90 days is standard)",
        ],
        "encryption": "Use PGP if the vendor provides a public key (best practice)",
        "output": "Disclosure notification sent with timestamp",
    },
    "step_4_coordinate": {
        "title": "Coordinate During the Fix Window",
        "timeline": {
            "T+0":   "Initial notification sent",
            "T+7":   "Follow-up if no acknowledgement received",
            "T+30":  "Check-in: has a fix been developed?",
            "T+60":  "Check-in: is a release date set?",
            "T+90":  "Default disclosure deadline (publish regardless of patch status)",
            "T+90+": "Extensions only for complex patches with clear progress",
        },
        "escalation": "If vendor is unresponsive: CERT/CC or FIRST as intermediary",
    },
    "step_5_publish": {
        "title": "Publish the Advisory",
        "after_patch_released": [
            "Wait 2–7 days after patch release (allows users to update)",
            "Publish advisory with: CVE ID, CVSS, affected versions, patch link",
            "Release PoC (or detailed technical description) with the advisory",
        ],
        "if_no_patch_at_deadline": [
            "Publish the advisory with a note that no patch is available",
            "Include the PoC — users deserve to know the risk",
            "Document your notification timeline (shows good faith)",
        ],
    },
}

for step_key, step in CVE_PROCESS.items():
    print(f"\n[{step['title'].upper()}]")
    if "actions" in step:
        for a in step["actions"]:
            print(f"  → {a}")
    if "timeline" in step:
        print("  Timeline:")
        for t, desc in step["timeline"].items():
            print(f"    {t:8} {desc}")
    if "what_to_include" in step:
        for item in step["what_to_include"]:
            print(f"  → {item}")
```

---

## Stage 2 — Bug Bounty Programme Mechanics

```python
#!/usr/bin/env python3
"""
Bug bounty programme guide — how to operate effectively.
"""
from __future__ import annotations

BUG_BOUNTY_GUIDE = {
    "major_platforms": {
        "HackerOne":   "https://hackerone.com — largest platform; military, tech, government",
        "Bugcrowd":    "https://bugcrowd.com — strong enterprise presence",
        "Intigriti":   "https://intigriti.com — European focus",
        "Synack":      "https://synack.com — invitation-only, vetted researchers",
        "YesWeHack":   "https://yeswehack.com — French/European platform",
    },
    "before_hacking": [
        "READ the programme scope document completely — test only in-scope targets",
        "CHECK for existing (already-reported) bugs in the programme's hall of fame",
        "UNDERSTAND safe harbour language — does the programme protect you legally?",
        "NOTE any specific rules: no automated scanning? no DoS? no social engineering?",
    ],
    "report_quality_factors": {
        "Reproducibility": "Clear step-by-step reproduction — triage team must reproduce it",
        "Impact statement": "What can an attacker actually do? Be specific and realistic",
        "CVSS score":       "Include your own assessment with vector string",
        "PoC":              "Working PoC or screen recording — proves real impact",
        "Scope":            "Confirm the target is in scope per the programme",
    },
    "common_mistakes": [
        "Testing out-of-scope targets (scope creep = programme violation)",
        "Duplicate reports — check existing findings before submitting",
        "Reporting low-impact findings with inflated severity",
        "Missing reproduction steps — 'it was down when I tested' is not enough",
        "Self-XSS: XSS only exploitable by the victim — typically N/A",
        "Rate limiting on non-critical endpoints — usually informational only",
    ],
    "payout_ranges_typical": {
        "Critical RCE":       "$10,000 – $1,000,000+",
        "High (SQLi, auth bypass)": "$3,000 – $25,000",
        "Medium (IDOR, SSRF)": "$500 – $5,000",
        "Low (open redirect)": "$100 – $500",
        "Informational":      "$0 – $150",
    },
}

print("[*] BUG BOUNTY GUIDE")
print("\nPlatforms:")
for name, url in BUG_BOUNTY_GUIDE["major_platforms"].items():
    print(f"  {name}: {url}")
print("\nBefore hacking:")
for item in BUG_BOUNTY_GUIDE["before_hacking"]:
    print(f"  ✓ {item}")
print("\nCommon mistakes:")
for mistake in BUG_BOUNTY_GUIDE["common_mistakes"][:4]:
    print(f"  ✗ {mistake}")
print("\nTypical payout ranges:")
for category, payout in BUG_BOUNTY_GUIDE["payout_ranges_typical"].items():
    print(f"  {category}: {payout}")
```

---

## Stage 3 — Legal Landscape

```python
#!/usr/bin/env python3
"""
Legal framework for security research — CFAA, Computer Misuse Act, GDPR.
"""
from __future__ import annotations

LEGAL_FRAMEWORK = {
    "US_CFAA": {
        "name": "Computer Fraud and Abuse Act (CFAA)",
        "jurisdiction": "United States",
        "key_provisions": [
            "Prohibits 'exceeding authorised access' to a protected computer",
            "'Protected computer' = essentially any internet-connected computer",
            "No explicit safe harbour for security research in the statute",
        ],
        "researcher_risks": [
            "Testing a system without explicit written permission",
            "Accessing data beyond what is necessary to demonstrate the bug",
            "Using vulnerabilities in ways that could cause harm",
        ],
        "protections": [
            "Bug bounty scope documents (explicit authorisation)",
            "DOJ 2022 policy: good faith security research is not a CFAA priority",
            "Courts have begun narrowing CFAA's scope (Van Buren v. US 2021)",
        ],
    },
    "UK_CMA": {
        "name": "Computer Misuse Act 1990 (CMA)",
        "jurisdiction": "United Kingdom",
        "key_sections": [
            "s1: Unauthorised access to computer material",
            "s2: Unauthorised access with intent to commit further offences",
            "s3: Unauthorised acts impairing operation of computers",
        ],
        "researcher_risks": [
            "Testing without explicit permission is unauthorised under s1",
            "No security research exception in the CMA (unlike some EU laws)",
        ],
        "current_reform": "UK government has proposed (but not yet enacted) a security research exemption",
    },
    "EU_NIS2": {
        "name": "NIS2 Directive + national implementations",
        "jurisdiction": "European Union",
        "relevance": "Requires coordinated vulnerability disclosure for critical infrastructure operators",
        "benefit_to_researchers": "Vendors covered by NIS2 must have a coordinated disclosure process",
    },
    "key_protections": [
        "Work only within explicit written scope (bug bounty T&C or pentest contract)",
        "Document everything: when you found it, what you accessed, what you did NOT access",
        "Notify immediately: don't sit on a critical finding",
        "Never access data beyond what is needed to confirm the vulnerability",
        "Never use vulnerabilities for financial gain or to harm third parties",
    ],
}

print("[*] LEGAL LANDSCAPE FOR SECURITY RESEARCHERS")
for law_key, law in LEGAL_FRAMEWORK.items():
    if isinstance(law, dict) and "name" in law:
        print(f"\n  [{law['name']}] ({law['jurisdiction']})")
        if "key_provisions" in law:
            for p in law["key_provisions"][:2]:
                print(f"    → {p}")
        if "researcher_risks" in law:
            print(f"    Risk: {law['researcher_risks'][0]}")
        if "protections" in law:
            print(f"    Protection: {law['protections'][0]}")

print("\n[!] KEY PROTECTIONS FOR RESEARCHERS:")
for p in LEGAL_FRAMEWORK["key_protections"]:
    print(f"  ✓ {p}")
```

---

## Key Takeaways

1. **Coordinated disclosure at 90 days is the industry standard.** Google Project
   Zero established this norm. It balances vendor time to patch against users' right
   to know about risks. Shorter deadlines (30 days) are appropriate for critical,
   easily exploited vulnerabilities; longer for complex, low-severity issues.
2. **Explicit written scope is your legal protection.** Bug bounty terms of service,
   pentest contracts, and SECURITY.md authorisation are your defences if a
   prosecutor or vendor lawyer comes calling. Test without them and you are relying
   on good faith — which is not a legal defence.
3. **The report quality determines the payout, not the bug severity.** A critical
   RCE with a weak report ("it crashed, not sure how") may be triaged as invalid.
   A medium IDOR with a clear step-by-step reproduction, impact statement, and PoC
   gets paid quickly. Write the report as if the reader has no context.
4. **Never access data you do not need.** The line between security research and
   unauthorised access is often drawn at data access. You need to confirm the bug
   exists — you do not need to download customer records to do that. Access the
   minimum necessary and document that you accessed no more.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q658.1, Q658.2 …).

---

## Navigation

← Previous: [Day 657 — CVE Reproduction Lab](DAY-0657-CVE-Reproduction-Lab.md)
→ Next: [Day 659 — Writing a Security Advisory](DAY-0659-Writing-Security-Advisory.md)
