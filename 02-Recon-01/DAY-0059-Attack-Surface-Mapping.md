---
title: "Attack Surface Mapping — Aggregating Recon into an Attack Surface Document"
tags: [recon, attack-surface, mapping, methodology, synthesis, prioritisation,
       asdoc, bug-bounty, mindmap, T1594]
module: 02-Recon-01
day: 59
related_topics:
  - Social Media and Job Posting Intel (Day 058)
  - Passive Recon Lab (Day 060)
  - Active Recon (02-Recon-02)
  - MITRE ATT&CK T1594 (Search Victim-Owned Websites)
---

# Day 059 — Attack Surface Mapping

## Goals

By the end of this lesson you will be able to:

1. Aggregate all passive recon data collected across Days 051–058 into a
   coherent attack surface document (ASDoc).
2. Prioritise targets within the attack surface by exploitability, value, and
   coverage gap.
3. Identify the entry points most likely to yield findings before active recon begins.
4. Use a consistent document format that transfers directly to a professional
   pentest report.
5. Identify gaps in your passive recon that active recon (Days 063+) will fill.

---

## Prerequisites

- [Day 051 — Recon Mindset and Kill Chain](DAY-0051-Recon-Mindset-and-Kill-Chain.md)
- [Day 052 — Passive vs Active Recon and OpSec](DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)
- [Day 053 — Google Dorks, Shodan and Censys](DAY-0053-Google-Dorks-Shodan-and-Censys.md)
- [Day 054 — Domain, DNS and Certificate Transparency](DAY-0054-Domain-DNS-and-Certificate-Transparency.md)
- [Day 055 — Email, People and LinkedIn OSINT](DAY-0055-Email-People-and-LinkedIn-OSINT.md)
- [Day 056 — GitHub Code Recon and Secret Hunting](DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md)
- [Day 057 — Cloud Asset and Bucket Discovery](DAY-0057-Cloud-Asset-and-Bucket-Discovery.md)
- [Day 058 — Social Media and Job Posting Intel](DAY-0058-Social-Media-and-Job-Posting-Intel.md)

---

## Main Content

### 1. What Is an Attack Surface?

An attack surface is the sum of all exposed interfaces that an attacker could
potentially interact with to gain unauthorised access, extract data, or cause harm.

For a web application, the attack surface includes:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ATTACK SURFACE COMPONENTS                        │
├─────────────────────────────────────────────────────────────────────┤
│ NETWORK                                                             │
│   IP ranges owned, exposed ports, firewall rules, CDN configuration │
├─────────────────────────────────────────────────────────────────────┤
│ DNS / DOMAIN                                                        │
│   Subdomains, wildcard records, dangling CNAMEs, delegation chains  │
├─────────────────────────────────────────────────────────────────────┤
│ WEB APPLICATIONS                                                    │
│   Login portals, API endpoints, admin panels, public APIs           │
├─────────────────────────────────────────────────────────────────────┤
│ CLOUD ASSETS                                                        │
│   S3 buckets, Azure Blob, GCP storage, serverless functions         │
├─────────────────────────────────────────────────────────────────────┤
│ CODE AND SECRETS                                                    │
│   Public repositories, CI/CD pipelines, exposed secrets             │
├─────────────────────────────────────────────────────────────────────┤
│ PEOPLE                                                              │
│   Employee email addresses, roles, breach exposure, org structure   │
├─────────────────────────────────────────────────────────────────────┤
│ TECHNOLOGY                                                          │
│   Software versions, frameworks, libraries, infrastructure          │
└─────────────────────────────────────────────────────────────────────┘
```

Your job in recon is to fill in every row of this table with specific, actionable
data for your target.

---

### 2. The Attack Surface Document (ASDoc) Format

Every engagement produces an ASDoc. This document is:
- Your working reference during the engagement
- The basis for your final report
- Evidence of methodical, professional work

```markdown
# Attack Surface Document — {Target Organisation}

**Date:** YYYY-MM-DD
**Researcher:** [your name / handle]
**Programme:** [HackerOne / Bugcrowd / private]
**Scope reference:** [link to scope document]
**Classification:** Confidential — Research Only

---

## 1. Scope Summary

**In scope:**
  - *.acmecorp.com
  - api.acmecorp.com
  - mobile app (iOS + Android)

**Out of scope:**
  - legacy.acmecorp.com
  - All third-party integrations

---

## 2. Domain and Network Inventory

| Asset | Type | IP / CNAME | Source | Priority |
|---|---|---|---|---|
| acmecorp.com | Root domain | 203.0.113.10 | DNS | Medium |
| www.acmecorp.com | Web app | 203.0.113.10 | DNS | Medium |
| api.acmecorp.com | API endpoint | 203.0.113.45 | DNS + Shodan | High |
| staging.acmecorp.com | Staging env | 10.0.1.5 | CT log | Critical |
| dev-api.acmecorp.com | Dev API | 203.0.113.99 | CT log | High |
| mail.acmecorp.com | Mail | 203.0.113.20 | MX record | Low |
| vpn.acmecorp.com | VPN portal | 203.0.113.30 | CT log | High |

---

## 3. Technology Stack

| Layer | Technology | Version | Source | Confidence |
|---|---|---|---|---|
| Web server | nginx | 1.18.0 | Shodan banner | High |
| Backend | Python / FastAPI | Unknown | Job postings | Medium |
| Database | PostgreSQL | 14.x | Job postings + SO | Medium |
| CDN/WAF | Cloudflare | — | DNS + headers | High |
| Cloud | AWS | — | Job postings + Shodan | High |
| Container | Kubernetes (EKS) | — | Job postings | Medium |
| CI/CD | GitHub Actions | — | GitHub org | High |

---

## 4. People Intelligence

| Name | Role | Email | Breach Exposure | Notes |
|---|---|---|---|---|
| Sarah Williams | CTO | s.williams@... | YES (2021) | AWS, Go, K8s skills |
| James Lee | VP Security | j.lee@... | NO | SIEM, Splunk |
| John Smith | Platform Eng | j.smith@... | YES (Adobe 2013) | Terraform, AWS |

**Email format:** {first}.{last}@acmecorp.com (8/8 confirmed addresses)
**AD Domain:** ACMECORP (from document metadata)
**Internal username format:** {first_initial}{last} (from metadata)

---

## 5. Cloud Assets

| Asset | Provider | Status | Contents | Source |
|---|---|---|---|---|
| acmecorp-assets | AWS S3 | Public (list) | Marketing images | s3scanner |
| acmecorp-backups | AWS S3 | Forbidden (exists) | Unknown | s3scanner |
| acmecorp-prod-logs | AWS S3 | Forbidden (exists) | Unknown | GrayhatWarfare |

---

## 6. Code and Secrets

| Repository | Platform | Finding | Severity |
|---|---|---|---|
| acmecorp/backend | GitHub | No secrets found | N/A |
| acmecorp/infra | GitHub | Terraform state with RDS endpoint | Medium |
| jsmith/acmecorp-migration | GitHub | Old: AWS key (AKIA...) committed 2021 | High |

---

## 7. High-Priority Targets

Ranked by: (exploitability × value) / visibility to defenders

1. **staging.acmecorp.com** — Staging environment, likely weaker auth, CT-log
   discovered, not in obvious scope documentation. Check if wildcard covers it.
   *Why:* Staging environments often have debug endpoints, relaxed CORS, test accounts.

2. **dev-api.acmecorp.com** — Dev API, discovered via CT log only.
   *Why:* Dev APIs frequently lack production-grade auth. Version might be ahead
   of prod — new features not yet security reviewed.

3. **vpn.acmecorp.com** — VPN portal. Version/product unknown until active recon.
   *Why:* Pulse Secure, Fortinet, Cisco have had recent critical CVEs. If this
   is a known-vulnerable product, it is a direct network entry point.

4. **acmecorp-backups bucket** — Exists, not public. May be world-writable.
   *Why:* A writable backup bucket = potential supply chain vector.

5. **Old AWS key in jsmith repo** — Committed 2021. Check if revoked.
   *Why:* If active, direct AWS console access.

---

## 8. Passive Recon Gaps (To Fill with Active Recon)

| Gap | Why it matters | Active technique to fill it |
|---|---|---|
| Open ports on discovered IPs | Services not visible in Shodan | nmap -sV (Day 063–064) |
| Subdomain live status | CT log entries may not resolve | httpx / massdns (Day 063) |
| API endpoint inventory | No visibility from passive recon | Directory fuzzing (Day 065) |
| JS file endpoint mining | Client-side routes not in DNS | LinkFinder (Day 066) |
| WAF fingerprinting | Cloudflare confirmed, bypass needed | wafw00f (Day 067) |
| TLS version and cipher | Shodan data may be stale | testssl.sh (Day 067) |

---

## 9. Recon Timeline

| Date | Activity | Result |
|---|---|---|
| 2024-01-15 | WHOIS + DNS enumeration | 15 subdomains, MX = Google |
| 2024-01-15 | CT log query (crt.sh) | 23 subdomains total |
| 2024-01-15 | subfinder + amass passive | 31 total (8 new from these tools) |
| 2024-01-16 | Shodan org search | 7 IPs, 2 interesting open ports |
| 2024-01-16 | GitHub org scan | 14 repos, 1 old key in history |
| 2024-01-16 | S3 bucket enumeration | 3 buckets found |
| 2024-01-17 | LinkedIn + job posting analysis | Tech stack mapped |
| 2024-01-17 | Document metadata (5 PDFs) | AD domain confirmed |
```

---

### 3. Prioritisation Framework

Not all attack surface elements are equal. Prioritise using:

```
Priority Score = (Exploitability + Value) × Access

Exploitability: How likely is this to be vulnerable?
  3 = Known CVE or class of misconfiguration
  2 = Common vulnerability category (auth, IDOR, injection)
  1 = Requires specific misconfiguration

Value: How impactful is compromise?
  3 = RCE, full data access, account takeover of privileged user
  2 = Data exposure, partial access, non-critical account takeover
  1 = Information disclosure, minor access

Access: How accessible is this right now?
  2 = Directly accessible
  1 = Requires additional steps to reach
```

**Example scoring:**

| Target | Exploit | Value | Access | Score | Action |
|---|---|---|---|---|---|
| staging.acmecorp.com | 2 | 2 | 2 | 8 | Attack first |
| vpn.acmecorp.com (Pulse) | 3 | 3 | 2 | 12 | Attack first |
| Old AWS key | 2 | 3 | 2 | 10 | Check immediately |
| www.acmecorp.com | 1 | 2 | 2 | 6 | Attack after high-priority |
| acmecorp-backups S3 | 2 | 3 | 1 | 10 | Investigate further |

---

### 4. Building the Mind Map

A visual mind map complements the ASDoc. Use Obsidian, draw.io, or just a
whiteboard. The structure:

```
                          ACMECORP
                              │
          ┌───────────┬───────┴───────┬──────────┐
        DOMAINS      CLOUD         PEOPLE      CODE
          │            │              │           │
    ┌─────┴────┐   ┌───┴───┐    ┌────┴────┐  ┌──┴──┐
   www   staging  S3 buckets  Employees  GitHub  Secrets
   api   dev-api  Azure blob  jsmith    Repos   Old key
   vpn             Firebase   s.williams  CI/CD
```

Visual mapping helps you spot missing connections — like realising that the
GitHub Actions CI/CD accesses the same AWS account as the S3 backups.

---

### 5. Pre-Active-Recon Checklist

Before moving to active recon (Day 063), verify:

- [ ] All subdomains from CT logs + subfinder + amass documented
- [ ] All IP addresses resolved and mapped to services
- [ ] Tech stack documented with confidence ratings
- [ ] Key people identified with emails and breach exposure checked
- [ ] GitHub/code repos scanned for secrets
- [ ] S3/Azure/GCP buckets enumerated
- [ ] Google dorks run (GHDB categories: passwords, sensitive directories, login portals)
- [ ] Shodan search completed for org + hostname + SSL cert
- [ ] ASDoc completed with priority ranking
- [ ] Active recon gaps identified

If all items are checked, you are ready for Day 063.

---

## Key Takeaways

1. **The ASDoc is the engagement artefact, not the tool output.** Raw tool
   output is not intelligence — a structured, prioritised, human-readable document
   is. Produce one every time.
2. **Prioritisation saves time.** Trying to exploit everything in order is
   inefficient. Score and rank. Attack in score order.
3. **Gaps are as valuable as findings.** Knowing exactly what active recon
   needs to fill in is prerequisite to efficient active work.
4. **The attack surface is always larger than the target thinks.** Staging
   environments, old buckets, forgotten subdomains — these are the real estate
   that security teams overlook. They are your first stops.
5. **Mind maps reveal connections that lists do not.** The relationship between
   a CI/CD pipeline and a storage bucket and an employee with breach exposure
   is a kill chain — a list of those three items separately does not show it.

---

## Exercises

### Exercise 1 — ASDoc Template

Using the format from Section 2, create a blank ASDoc template in Markdown.
Include all 9 sections with placeholder rows in each table.

---

### Exercise 2 — Priority Scoring

For the following targets, calculate a priority score using the framework in
Section 3 and rank them:

1. `admin.target.com` — admin panel discovered via CT log, running on port 8443,
   no authentication bypass visible from passive recon.
2. An exposed Firebase database with no authentication — accessible via `.json`.
3. A VPN portal running Pulse Secure (check current CVE list for Pulse Secure).
4. A public S3 bucket containing only product marketing images.
5. An employee email in a 2019 breach where passwords are available on a cracking
   forum (not exfiltrated — just existence known from HIBP).

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 058 — Social Media and Job Posting Intel](DAY-0058-Social-Media-and-Job-Posting-Intel.md)*
*Next: [Day 060 — Passive Recon Lab](DAY-0060-Passive-Recon-Lab.md)*
