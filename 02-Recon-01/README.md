---
title: "02-Recon-01 — OSINT and Passive Recon"
tags: [recon, osint, passive-recon, attack-surface, bug-bounty, subdomain, opsec]
module: 02-Recon-01
days: 51–62
---

# Module 02-Recon-01 — OSINT and Passive Recon

> "Before you touch the target, you should know it better than its own IT team does.
> Passive recon is how you build that advantage without making a sound."
>
> — Ghost

---

## Module Goal

Build a complete attack surface profile on any target using only public information —
no packets sent to the target, no accounts touched, no fingerprints left behind.

---

## MITRE ATT&CK Coverage

**Tactic:** Reconnaissance (TA0043)

| Technique | ID | Day |
|---|---|---|
| Gather Victim Network Information | T1590 | 051, 054 |
| Gather Victim Org Information | T1591 | 051, 055, 058 |
| Gather Victim Host Information | T1592 | 053, 057 |
| Search Open Websites/Domains | T1593 | 053, 056 |
| Search Victim-Owned Websites | T1594 | 059 |
| Search Open Technical Databases | T1596 | 053, 054, 057 |
| Phishing for Information | T1598 | 051 |

---

## Lesson Index

| Day | File | Topic | Type |
|---|---|---|---|
| 051 | [DAY-0051](DAY-0051-Recon-Mindset-and-Kill-Chain.md) | Recon mindset, Kill Chain, ATT&CK TA0043, bug bounty scope | Theory |
| 052 | [DAY-0052](DAY-0052-Passive-vs-Active-Recon-and-OpSec.md) | Passive vs active recon, OpSec, legal line | Theory |
| 053 | [DAY-0053](DAY-0053-Google-Dorks-Shodan-and-Censys.md) | Google dorks, Shodan, Censys, search engine recon | Technique |
| 054 | [DAY-0054](DAY-0054-Domain-DNS-and-Certificate-Transparency.md) | WHOIS, DNS enumeration, CT logs, subfinder, amass | Technique |
| 055 | [DAY-0055](DAY-0055-Email-People-and-LinkedIn-OSINT.md) | Email harvesting, LinkedIn OSINT, document metadata | Technique |
| 056 | [DAY-0056](DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md) | GitHub dorking, truffleHog, gitleaks, exposed secrets | Technique |
| 057 | [DAY-0057](DAY-0057-Cloud-Asset-and-Bucket-Discovery.md) | S3/Azure/GCP bucket discovery, cloud asset enumeration | Technique |
| 058 | [DAY-0058](DAY-0058-Social-Media-and-Job-Posting-Intel.md) | LinkedIn tech stack, job posting intel, social media recon | Technique |
| 059 | [DAY-0059](DAY-0059-Attack-Surface-Mapping.md) | Aggregating recon into an attack surface document | Synthesis |
| 060 | [DAY-0060](DAY-0060-Passive-Recon-Lab.md) | **LAB:** Full passive recon on a designated target | Lab |
| 061 | [DAY-0061](DAY-0061-Reducing-Your-Org-Attack-Surface.md) | Blue team: harden passive recon exposure | Defensive |
| 062 | [DAY-0062](DAY-0062-Subdomain-Takeover-and-Dangling-DNS.md) | Subdomain takeover, dangling DNS, CNAME hijack | Exploit + Detect |

---

## Lab

**Goal:** Produce a complete passive attack surface document for the designated lab target.

**Tools used in this module:**

| Tool | Purpose |
|---|---|
| `amass enum -passive` | Subdomain enumeration (passive mode) |
| `subfinder` | Passive subdomain enumeration |
| `theHarvester` | Email + subdomain harvesting |
| `shodan` CLI | Internet-wide host discovery |
| `gitleaks` | Secret scanning in Git repos |
| `truffleHog` | Secret scanning in commit history |
| `exiftool` | Document metadata extraction |
| `s3scanner` | S3 bucket enumeration |
| `subjack` | Subdomain takeover detection |
| `nuclei -t takeovers/` | Automated takeover detection |
| `crt.sh` API | Certificate Transparency log queries |
| `dnsx` | DNS resolution and validation |

---

## Competency Gate (Day 075 — after 02-Recon-02)

You are **Recon Ready** when you can:

1. Build a full attack surface profile (subdomains, IPs, people, tech stack, cloud assets)
   using only passive sources.
2. Identify subdomain takeover candidates and reproduce the takeover in lab.
3. Find at least one exposed secret in a test GitHub organization.
4. Produce an attack surface document in the Ghost format from scratch.

---

*Next module: [02-Recon-02 — Active Recon and Bug Bounty Scope](../02-Recon-02/README.md)*
