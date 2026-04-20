---
title: "Recon Review and Preparation — Consolidate All Recon Techniques and Prepare for Gate"
tags: [review, recon, consolidation, gate-preparation, attack-surface-document,
       passive-recon, active-recon, methodology, bug-bounty, competency-check]
module: 02-Recon-02
day: 74
related_topics:
  - All 02-Recon-01 and 02-Recon-02 modules (Days 051–073)
  - Recon Competency Gate (Day 075)
  - Bug Bounty Recon Methodology (Day 072)
---

# Day 074 — Recon Review and Preparation

## Goals

By the end of this lesson you will have:

1. Reviewed every recon technique covered in Days 051–073.
2. Identified any gaps in your understanding and addressed them.
3. Produced a final, polished attack surface document for the Day 075 gate.
4. Demonstrated readiness by explaining each technique and its detection
   without referencing notes.

---

## Prerequisites

All of Days 051–073.

---

## Main Content

> "Day 075 is tomorrow. Tonight you do not learn anything new. Tonight you
> make sure you actually know what you think you know."
>
> — Ghost

---

### 1. Full Recon Curriculum Map

Use this as your review checklist. For each item, ask: Can I do this from
memory? Can I explain why it works? Can I name the detection method?

#### 02-Recon-01 — OSINT and Passive Recon

| Day | Topic | Core skill to verify |
|-----|-------|---------------------|
| 051 | Recon mindset and kill chain | Explain where recon fits in the ATT&CK kill chain |
| 052 | Passive vs active recon, OpSec | Name 3 techniques that leave footprints vs 3 that do not |
| 053 | Google dorks, Shodan, Censys | Write 3 Google dork operators from memory |
| 054 | Domain, DNS, Certificate Transparency | Run `subfinder`, `amass`, and `crt.sh` query |
| 055 | Email, people, LinkedIn OSINT | Use theHarvester; extract metadata from a document |
| 056 | GitHub code recon and secret hunting | Run truffleHog against a repo; explain what it finds |
| 057 | Cloud asset and bucket discovery | Enumerate S3 buckets; explain AWS Block Public Access |
| 058 | Social media and job posting intel | Extract tech stack from a job posting |
| 059 | Attack surface mapping | Structure findings into a coherent map |
| 060 | Passive recon lab | Can you execute a full passive profile from memory? |
| 061 | Reducing attack surface | Recite the DMARC hardening mistake (p=none vs p=reject) |
| 062 | Subdomain takeover | Explain CNAME takeover mechanics; run subjack |

#### 02-Recon-02 — Active Recon and Bug Bounty Scope

| Day | Topic | Core skill to verify |
|-----|-------|---------------------|
| 063 | nmap from first principles | Explain SYN scan packet flow; name 5 port states |
| 064 | nmap service detection, NSE, evasion | Run phase-2 nmap scan; name 5 useful NSE scripts |
| 065 | Directory and endpoint fuzzing | Run ffuf with correct filters; choose right wordlist |
| 066 | Parameter discovery and JS analysis | Run arjun; extract endpoints from a JS file |
| 067 | Web app fingerprinting | Identify tech stack from headers alone (no tools) |
| 068 | Masscan and fast network scanning | Explain stateless scanning; run masscan+nmap pipeline |
| 069 | Active recon lab | Did you complete the full lab? Review your output |
| 070 | Recon automation pipeline | Can you build the amass→httpx→nuclei pipeline? |
| 071 | Bug bounty scope analysis | Identify scope traps in a real programme policy |
| 072 | Bug bounty recon methodology | Describe all 4 phases and their outputs |
| 073 | Detecting recon | Write a Sigma rule for directory fuzzing detection |

---

### 2. Self-Assessment — Knowledge Check

Answer each question. If you cannot answer it confidently, go back to the
relevant lesson before Day 075.

#### Passive Recon

1. What is the difference between passive recon and active recon? Give one
   example of each.

2. What is Certificate Transparency? What tool queries CT logs for subdomains?
   What URL can you use manually?

3. Name three Google dork operators and write a practical example for each.

4. What does DMARC `p=none` mean vs `p=reject`? Why does this matter for
   an attacker?

5. Explain how a CNAME subdomain takeover works in five sentences or fewer.
   What tool scans for this automatically?

---

#### Active Recon

6. What packets does nmap send for a SYN scan? Why does SYN scan require root?

7. Name the five nmap port states and describe what network response corresponds
   to each state.

8. What does `-sV` do? What does `-sC` do? When do you use both together?

9. Explain why masscan is faster than nmap. What does it sacrifice for that
   speed?

10. What is a good command for a phase-2 deep nmap scan given a list of open
    ports found by masscan?

---

#### Web Recon

11. What is the purpose of response filtering in ffuf? Give an example command
    that filters by both status code and response size.

12. What is arjun? How does it detect parameters that are not documented?

13. Name three things you look for when manually analysing a JavaScript file.

14. What HTTP header reveals the PHP version? What header reveals the nginx
    version? What should a hardened server send instead?

15. How does Wappalyzer detect the technology stack? What is it matching against?

---

#### Methodology and Scope

16. Name the four phases of the recon lifecycle (Day 072). What does each
    produce as output?

17. A programme has scope `*.target.com`, excluding `mail.target.com`. You
    discover `internal.mail.target.com`. Is it in scope? Why?

18. What is a safe harbour clause? What does it NOT protect against?

19. You accidentally run your automated pipeline against an out-of-scope
    subdomain. What do you do?

20. Name three canary token types and one placement strategy for each.

---

### 3. Gap Remediation

Based on your self-assessment, return to any lesson you could not confidently
answer. Spend 20–30 minutes on each gap.

```
If you could not answer questions 1–5 → review 02-Recon-01
If you could not answer questions 6–10 → review Days 063, 064, 068
If you could not answer questions 11–15 → review Days 065, 066, 067
If you could not answer questions 16–20 → review Days 071, 072, 073
```

---

### 4. Producing the Gate Attack Surface Document

The Day 075 gate requires you to submit an attack surface document for a
lab target (or a real programme you are authorised on). Use this template:

```markdown
# Attack Surface Document — [Target]

**Submitted by:** [Your name]
**Date:** [Date]
**Target:** [Domain or IP range]
**Programme:** [If applicable]
**Gate:** Recon Ready (Day 075)

---

## Methodology Used

1. Scope analysis: [What scope was confirmed]
2. Passive recon tools: [List tools and sources used]
3. Active recon tools: [List tools and flags used]
4. Duration: [Total time spent]

---

## Subdomains Discovered

| Subdomain | DNS resolves? | Live web service? | Status code |
|-----------|---------------|-------------------|-------------|
| api.target.com | Yes | Yes | 200 |
| staging.target.com | Yes | Yes | 302→200 |
| dev.target.com | Yes | No | — |

Total subdomains discovered: ____
Total live web services: ____

---

## Open Ports and Services

| Host | Port | Service | Version | Notes |
|------|------|---------|---------|-------|
| 10.10.10.5 | 22 | SSH | OpenSSH 8.9 | |
| 10.10.10.5 | 80 | HTTP | nginx 1.24.0 | Redirects to HTTPS |
| 10.10.10.5 | 443 | HTTPS | nginx 1.24.0 | TLS 1.3 |
| 10.10.10.5 | 3306 | MySQL | 8.0.36 | Exposed to internet — HIGH RISK |

---

## Technology Stack

| Component | Version | Notes |
|-----------|---------|-------|
| Web server | nginx 1.24.0 | No version disclosure hardening |
| Backend | PHP 8.1.25 | Disclosed via X-Powered-By |
| CMS | WordPress 6.4.1 | Check CVE-2023-6633 |

---

## Content Discovery Findings

### High-Value Endpoints

| URL | Status | Notes |
|-----|--------|-------|
| /wp-admin/ | 302 | WordPress admin — attempt default creds |
| /api/v1/users | 200 | Returns user list without authentication — CRITICAL |
| /backup.zip | 200 | Backup file exposed — CRITICAL |
| /phpinfo.php | 200 | PHP info page — HIGH |

### Out-of-Scope Findings (if any)

[Document any out-of-scope findings found during recon here for transparency]

---

## JavaScript Analysis Findings

| File | Finding | Severity |
|------|---------|---------|
| /static/app.js | API key: AIzaSy... | HIGH |
| /static/app.js | Endpoint: /api/v2/internal/config | MEDIUM |

---

## nuclei Findings (Manual Verification Required)

| Severity | Template | URL | Verified? |
|----------|---------|-----|-----------|
| HIGH | spring-actuator-env | https://dev.target.com/actuator/env | YES |
| MEDIUM | http-missing-security-headers | https://target.com | YES |

---

## Attack Surface Summary — Prioritised

### P0 — Test Immediately

1. `/api/v1/users` — returns user list without auth → likely BOLA/missing auth
2. `/backup.zip` — backup file exposed → may contain source code, credentials
3. Exposed MySQL on port 3306 → test from external IP, check if auth-free

### P1 — Test Next

1. WordPress login `/wp-admin/` → test default creds, brute-force, auth bypass
2. PHP info page `/phpinfo.php` → extract server configuration details
3. `/api/v2/internal/config` (from JS) → test if accessible, what it returns

### P2 — Test After P0/P1

1. CORS configuration → check if misconfigured for any of the API endpoints
2. TLS configuration → check cipher suites and certificate details
3. HTTP security headers → missing headers identified by nuclei

---

## Self-Assessment

What did I find that surprised me?
[Answer here]

What technique was most valuable?
[Answer here]

What would I do differently on the next target?
[Answer here]
```

---

### 5. Quick Reference — Most Important Commands

Keep this reference for the gate:

```bash
# Passive subdomain enumeration
subfinder -d target.com -all -silent | tee subs.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | python3 -c "..."

# DNS resolution
cat subs.txt | dnsx -silent -a -resp-only | sort -u > ips.txt
cat subs.txt | dnsx -silent -a | awk '{print $1}' | sort -u > resolved.txt

# HTTP probing
cat resolved.txt | httpx -silent -status-code -title -tech-detect -json -o httpx.json

# Port scanning
sudo nmap -sS -sV -sC -p- --open --min-rate 500 -oA nmap_scan <target>

# Fast port + deep service pipeline
sudo masscan <target> -p 0-65535 --rate 1000 -oJ masscan.json
# [extract ports] → nmap -sV -sC -p <open_ports>

# Directory fuzzing
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302,403 \
     -fs <404-size> \
     -o results.json -of json -rate 50

# JS analysis
python3 /opt/LinkFinder/linkfinder.py -i https://target.com -d -o cli

# Parameter discovery
arjun -u https://target.com/api/endpoint -m GET

# nuclei scan
nuclei -l live_urls.txt -t exposures/ -t takeovers/ -severity high,critical -json -o nuclei.json

# Subdomain takeover check
subjack -w resolved.txt -ssl -v -o takeovers.txt
```

---

## Key Takeaways

1. **Day 074 is consolidation day.** Read → recall → test yourself. If you
   cannot recall a technique without notes, that is a gap to fix tonight.
2. **Your attack surface document is the gate deliverable.** It should be
   structured, specific, and prioritised. "I found some endpoints" is not
   an attack surface document.
3. **The gate is not a multiple-choice exam.** Day 075 will ask you to
   demonstrate, not describe. Have your lab running. Have your terminal open.
   Have your tools installed and working.
4. **Recon is a skill, not a checklist.** The techniques matter less than
   the mental model: what are you looking for? Why? How do you know when
   you have found something worth pursuing?
5. **After tomorrow, you move into web exploitation.** Everything in
   02-Recon is infrastructure for the attack phase. A strong attack surface
   document means a stronger exploit path.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 073 — Detecting Recon](DAY-0073-Detecting-Recon.md)*
*Next: [Day 075 — Recon Competency Gate](DAY-0075-Recon-Competency-Gate.md)*
