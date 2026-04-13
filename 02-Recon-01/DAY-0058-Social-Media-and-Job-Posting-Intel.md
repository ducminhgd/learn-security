---
title: "Social Media and Job Posting Intel — Technology Stack, Org Chart, Timing"
tags: [osint, social-media, job-postings, linkedin, twitter, tech-stack, org-chart,
       T1591, glassdoor, stackoverflow, timing-intelligence]
module: 02-Recon-01
day: 58
related_topics:
  - Cloud Asset and Bucket Discovery (Day 057)
  - Attack Surface Mapping (Day 059)
  - Email People and LinkedIn OSINT (Day 055)
  - MITRE ATT&CK T1591.004 (Identify Roles)
---

# Day 058 — Social Media and Job Posting Intel

## Goals

By the end of this lesson you will be able to:

1. Extract a detailed technology stack from job postings without visiting the target.
2. Reconstruct an organisation's approximate tech architecture from multiple sources.
3. Identify high-value individuals for targeted analysis (T1591.004).
4. Use timing intelligence to understand when an organisation is most vulnerable.
5. Find technology version information from Stack Overflow questions and developer
   community posts.

---

## Prerequisites

- [Day 055 — Email, People and LinkedIn OSINT](DAY-0055-Email-People-and-LinkedIn-OSINT.md)
- [Day 057 — Cloud Asset and Bucket Discovery](DAY-0057-Cloud-Asset-and-Bucket-Discovery.md)

---

## Main Content

### 1. Why Job Postings Are Intelligence Gold

When a company hires, it tells the world exactly what technologies it uses.
Job postings are written by engineers for engineers — they are technically specific
and accurate.

**The paradox:** The same information security teams that spend millions on
endpoint security, SIEM, and threat intelligence publish their entire tech stack
on LinkedIn, Indeed, and their own careers page — free, publicly indexed, and
never expire.

---

### 2. Technology Stack Extraction from Job Postings

#### What to Look For

**Job title + required skills = technology inventory:**

```
Job: Senior Backend Engineer
Requirements:
  - 5+ years experience with Python (Django or FastAPI)
  - PostgreSQL and Redis required; Elasticsearch a plus
  - AWS (EC2, RDS, ElastiCache, S3, SQS)
  - Terraform and Kubernetes
  - CI/CD with GitHub Actions
  - Familiarity with Datadog for observability
  - Experience with OWASP security practices

Intel extracted:
  Backend:      Python (Django/FastAPI)
  Database:     PostgreSQL (primary), Redis (cache), Elasticsearch (search)
  Cloud:        AWS — EC2, RDS, ElastiCache, S3, SQS
  IaC:          Terraform
  Orchestration: Kubernetes
  CI/CD:        GitHub Actions → likely public GitHub org
  Monitoring:   Datadog
  Source control: GitHub (not self-hosted GitLab → less control over repos)
```

This single job posting creates a near-complete architecture map.

#### Where to Find Job Postings

```
1. Company careers page: careers.acmecorp.com
   ↑ Primary source — most detailed, longest postings

2. LinkedIn Jobs: linkedin.com/jobs/search?keywords=acmecorp
   ↑ Often same content as careers page, easier to search

3. Indeed: indeed.com (search by company)
4. Glassdoor: glassdoor.com/Jobs/
5. Hacker News: news.ycombinator.com (search "who is hiring" + company)
6. Remote.co, We Work Remotely, AngelList
```

#### The Recon Dork

```
site:linkedin.com/jobs "acmecorp" engineer
site:indeed.com "acmecorp" security engineer
"acmecorp" "kubernetes" OR "k8s" site:linkedin.com
"careers.acmecorp.com"  # Find careers page if not obvious
```

---

### 3. Reading Job Postings as a Timeline

Job postings accumulate over time. By reading them chronologically, you can trace
a company's technology migration:

```
2019 job: "experience with Ruby on Rails and MySQL"
2021 job: "experience with Python, must be comfortable with both Rails and Python"
2023 job: "Python (Django/FastAPI) required, Rails knowledge a plus"

Timeline interpretation:
  - 2019–2021: Rails/MySQL stack, mid-migration
  - 2021–2023: Python migration underway (Rails still in prod)
  - 2023+: Python primary, Rails legacy still running

Attacker implication:
  - Rails codebase still running in production
  - Legacy Ruby version likely (Rails upgrade cycles are slow)
  - Possible Ruby/Rails CVEs worth investigating
  - Mixed codebase = mixed security review coverage
```

Use Google's date filter to find older job postings:

```
site:linkedin.com "acmecorp" engineer after:2019-01-01 before:2020-12-31
```

---

### 4. LinkedIn — Beyond People

LinkedIn is not just for finding people. The company page reveals:

```
https://www.linkedin.com/company/acmecorp/

Information available:
  - Company size (employee count bracket)
  - Follower count (visibility metric)
  - Recent posts (press releases, product launches)
  - Recent hires in security = awareness of a known problem
  - Recent departures from security = talent drain = reduced coverage
  - Technology skill badges on employee profiles
  - Alumni network → former employees may have retained credentials
```

#### Alumni Intelligence

Former employees are often overlooked in recon. They:
- May have retained API keys, VPN credentials, or access tokens
- Know the internal architecture better than current employees
- Sometimes become competitors and take IP

```bash
# Find former employees via LinkedIn Google dork
site:linkedin.com/in "former" "acmecorp" "engineer"
site:linkedin.com/in "previously" "acmecorp" "security"
site:linkedin.com/in "ex-" "acmecorp"
```

---

### 5. Twitter/X and Developer Communities

Developers post about their work publicly. This is a consistent source of
intelligence on specific technologies, outages, and internal practices.

#### Twitter/X Intelligence

```
# Twitter search (requires a free account or nitter.net)
site:twitter.com "acmecorp" "kubernetes" OR "k8s"
site:twitter.com "acmecorp" "outage" OR "incident"
site:twitter.com from:jsmith "acmecorp"

# What to look for:
# - Incident postmortems (reveals architecture weaknesses)
# - Product launch announcements (new attack surface)
# - Developer complaints ("Finally migrated off PHP 5.6")
# - Conference talk announcements (find technical talks for architecture details)
```

#### Stack Overflow

Developers ask questions about specific technologies when they are stuck.
These questions reveal:
- The exact technology version they are using
- The specific problem they are solving (potential misconfiguration)
- Internal patterns (table names, endpoint paths, error messages)

```bash
# Stack Overflow search
site:stackoverflow.com "acmecorp"
site:stackoverflow.com "acmecorp.com" "error"

# More targeted
site:stackoverflow.com "acmecorp" "django" OR "postgresql"
```

**Example finding:**

```
Stack Overflow question (2022):
"Why is my Django app throwing: OperationalError: FATAL: role "acmecorp_prod_user" 
does not exist"
Asked by user "jsmith-acmecorp"
Tags: django, postgresql, aws-rds

Intel:
  - Database user: acmecorp_prod_user
  - DB: AWS RDS (confirmed)
  - Developer username: jsmith-acmecorp (matches j.smith LinkedIn profile)
```

---

### 6. Timing Intelligence

Understanding when an organisation is most vulnerable is valuable for authorised
red team operations and less relevant for bug bounty — but worth knowing.

**High-vulnerability periods:**

```
ACQUISITION: During M&A, IT teams are overwhelmed integrating systems. 
  Security gaps appear at the junction of old and new environments.
  Signal: LinkedIn announcements, press releases.

LAYOFFS: Security staff are often targeted in layoffs.
  Remaining team is overstretched; monitoring degrades.
  Signal: LinkedIn mass departures, Glassdoor reviews mentioning "understaffed".

MAJOR RELEASES: Engineering focus is on shipping, not security review.
  New attack surface deployed with minimal security testing.
  Signal: Product launches, tech blog posts, App Store updates.

HOLIDAYS: Staff out of office = slower incident response.
  Signal: Company calendar (some are public), annual report cadence.

CONFERENCES: Key security staff are at DEF CON, RSA, etc.
  Signal: Conference speaker lists, company social media.
```

---

### 7. Glassdoor and Anonymous Reviews

Glassdoor reviews from engineers provide uncensored observations about
internal practices, tools, and frustrations.

```
site:glassdoor.com "acmecorp" review

Look for:
  - "We use X and Y for our stack" (tech confirmation)
  - "Security team is a mess / understaffed" (exploitable weakness signal)
  - "Legacy PHP codebase that nobody wants to touch" (vulnerable old code)
  - "All AWS, Kubernetes, microservices" (architecture confirmation)
  - "No real security review process" (quality signal)
```

---

### 8. Building the Technology Intelligence Product

After running all techniques in this lesson, consolidate findings:

```markdown
## Technology Stack Intelligence — AcmeCorp

**Sources:** LinkedIn Jobs (12 postings), StackOverflow (3 questions),
Glassdoor (8 reviews), Twitter (4 relevant posts)

---

### Current Stack (High Confidence)

| Layer | Technology | Confidence | Source |
|---|---|---|---|
| Backend | Python 3.10+, FastAPI | High | 5 job postings |
| Database | PostgreSQL 14 (AWS RDS) | High | SO question + job postings |
| Cache | Redis (AWS ElastiCache) | High | 3 job postings |
| Cloud | AWS (primary) | High | All sources |
| Orchestration | Kubernetes (EKS) | High | 4 job postings |
| CI/CD | GitHub Actions | Medium | 2 job postings |
| Monitoring | Datadog + PagerDuty | Medium | 2 job postings |
| CDN | Cloudflare | High | DNS + job posting |

### Legacy/Transitional (Medium Confidence)

| Layer | Technology | Evidence |
|---|---|---|
| Legacy backend | Ruby on Rails | 2021 job posting, SO question |
| Old DB | MySQL | Pre-2021 job postings |

### Security Stack

| Component | Technology | Confidence |
|---|---|---|
| WAF | Cloudflare | DNS evidence |
| SIEM | Splunk | 2022 security engineer job posting |
| EDR | Unknown | Not mentioned in any public source |
| Bug bounty | HackerOne | Public programme page |

### Timing Intel

- 2023-Q3: Major layoffs (LinkedIn — 8 security team departures noted)
- 2024-Q1: New CTO hired (LinkedIn announcement)
- Upcoming: PyCon sponsorship (tech blog post) — engineers at conference

### Actionable Insights

1. Legacy Rails stack still running → Rails CVE surface worth investigating
2. PostgreSQL on RDS → SSRF to metadata endpoint could yield RDS credentials
3. GitHub Actions CI/CD → supply chain attack surface (malicious PR)
4. Recent security team reduction → reduced monitoring coverage
5. CloudFlare WAF → WAF bypass attempts needed before direct exploitation
```

---

## Key Takeaways

1. **Job postings are the most reliable tech stack source.** Engineers write them,
   engineers vet them — they reflect actual production reality, not marketing copy.
2. **Stack Overflow questions are time-stamped confessions.** A developer asking
   a question about a specific error or version has told you exactly what they
   are running and what problem they were having.
3. **Alumni are overlooked.** Former employees with persistent access (API keys,
   VPN certificates that were not revoked) represent a significant real-world
   attack vector.
4. **Timing intelligence is leverage.** In authorised red team engagements,
   timing your operation during peak vulnerability windows dramatically increases
   success rate and realism.
5. **Glassdoor provides unfiltered intelligence.** Engineers vent honestly in
   reviews. "No real security process" from a 2023 Glassdoor review is more
   useful than any number of security certifications on the website.

---

## Exercises

### Exercise 1 — Tech Stack Reconstruction

1. Find 5 recent (2023–2024) job postings for a company of your choice.
2. For each posting, list every technology explicitly mentioned.
3. Consolidate into a technology stack document using the format in Section 8.
4. Identify: What is the weakest-looking component? What CVEs exist for
   the versions mentioned?

---

### Exercise 2 — Stack Overflow Reconnaissance

1. Search Stack Overflow for `site:stackoverflow.com "acmecorp.com"`.
2. For any results: what technology, what version, what problem were they solving?
3. Cross-reference with the tech stack from Exercise 1.

---

### Exercise 3 — Timeline Reconstruction

1. Find job postings from 2019, 2021, and 2023 for the same company.
2. What changed in their tech stack over that period?
3. What legacy components are likely still running in production?
4. Which legacy component has the worst known CVE history?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 057 — Cloud Asset and Bucket Discovery](DAY-0057-Cloud-Asset-and-Bucket-Discovery.md)*
*Next: [Day 059 — Attack Surface Mapping](DAY-0059-Attack-Surface-Mapping.md)*
