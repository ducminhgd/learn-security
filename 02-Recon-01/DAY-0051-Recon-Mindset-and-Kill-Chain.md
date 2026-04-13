---
title: "Recon Mindset and Kill Chain — TA0043, ATT&CK Recon Techniques, Bug Bounty Scope"
tags: [recon, osint, kill-chain, mitre-attack, TA0043, bug-bounty, mindset, attacker-perspective]
module: 02-Recon-01
day: 51
related_topics:
  - MITRE ATT&CK Reconnaissance Tactic (TA0043)
  - Lockheed Martin Cyber Kill Chain
  - Bug Bounty Scope Reading
  - Passive vs Active Recon (Day 052)
---

# Day 051 — Recon Mindset and Kill Chain

## Goals

By the end of this lesson you will be able to:

1. Explain where reconnaissance sits in both the Cyber Kill Chain and MITRE ATT&CK.
2. Name all MITRE ATT&CK Reconnaissance sub-techniques (T1590–T1598) and give one
   real example for each.
3. Describe the attacker's information goal before launching any active operation.
4. Read a bug bounty scope document and extract: in-scope assets, out-of-scope
   restrictions, and what information you are legally allowed to collect.
5. Explain why poor reconnaissance is the most common reason red team engagements fail.

---

## Prerequisites

- [Day 050 — Foundation Competency Gate](../01-Foundation-05/DAY-0050-Foundation-Competency-Gate.md)
- Understanding of HTTP, DNS, TLS (Days 001–008)
- No recon tools required today — this is mindset and framework only

---

## Main Content

### 1. Why Recon Exists — The Intelligence Principle

Every military operation in history began with intelligence collection. You do not
send troops through a minefield without a map. You do not attack a fortified position
without knowing the garrison size, the patrol schedule, and the supply lines.

Computer network operations are no different.

> "Amateurs hack systems. Professionals hack intelligence. The system falls
> as a consequence of the intelligence." — Ghost

An attacker who spends 80% of their time on reconnaissance and 20% on exploitation
will outperform one who spends 20% on recon and 80% hacking blindly. This is why
APT groups spend weeks — sometimes months — doing pure intelligence collection before
a single exploit packet is sent.

In bug bounty hunting, the same principle applies. The hunters who earn consistently
do not find vulnerabilities by brute-forcing every endpoint. They find them because
they know the target's attack surface more thoroughly than the target's own security
team does.

---

### 2. The Lockheed Martin Cyber Kill Chain

Published in 2011 by Lockheed Martin as a framework for understanding intrusion
campaigns. Seven stages, sequential:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CYBER KILL CHAIN                             │
├──────────────┬──────────────────────────────────────────────────┤
│ Stage 1      │ RECONNAISSANCE                                   │
│              │ Identify target, collect email/IP/domain info    │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 2      │ WEAPONISATION                                    │
│              │ Create exploit + payload (malware, phish doc)    │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 3      │ DELIVERY                                         │
│              │ Transmit weapon to target (email, web, USB)      │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 4      │ EXPLOITATION                                     │
│              │ Execute code on target system                    │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 5      │ INSTALLATION                                     │
│              │ Install backdoor / implant for persistence       │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 6      │ COMMAND & CONTROL (C2)                           │
│              │ Establish outbound channel to attacker           │
├──────────────┼──────────────────────────────────────────────────┤
│ Stage 7      │ ACTIONS ON OBJECTIVES                            │
│              │ Exfil data, ransomware, lateral movement         │
└──────────────┴──────────────────────────────────────────────────┘
```

**Key insight:** The Kill Chain is a defender's model. It describes an intrusion
as a chain — break any link and the intrusion fails. Recon is Stage 1.

**Attacker's insight:** If your recon is wrong, every subsequent stage is built on
a false foundation. Wrong email → phish goes nowhere. Wrong IP range → exploit hits
a cloud WAF. Wrong technology assumption → exploit crashes without code execution.

**Bug bounty translation:** There is no weaponisation or delivery phase in bug
bounty. You go from recon directly to exploitation (with authorisation). Recon
quality still determines everything.

---

### 3. MITRE ATT&CK — Reconnaissance Tactic (TA0043)

MITRE ATT&CK is the industry standard taxonomy for adversary behaviour. The
Reconnaissance tactic (TA0043) was added in ATT&CK v9 (2021) based on real
intrusion campaigns where pre-compromise activity was observed and attributed.

Every technique below maps to actions you will perform in this module:

#### T1590 — Gather Victim Network Information

Collect information about the target's network infrastructure.

| Sub-technique | What attackers collect |
|---|---|
| T1590.001 — Domain Properties | Registrar, creation date, expiry, DNSSEC status |
| T1590.002 — DNS | All DNS records: A, MX, NS, TXT, CNAME, SOA |
| T1590.003 — Network Trust Dependencies | BGP ASN, upstream providers, peering |
| T1590.004 — Network Topology | Traceroute, CDN detection, load balancer fingerprint |
| T1590.005 — IP Addresses | IP ranges assigned to the org via WHOIS/ARIN/RIPE |
| T1590.006 — Network Security Appliances | WAF, IDS/IPS detection via response anomalies |

**Day coverage:** Days 053, 054

---

#### T1591 — Gather Victim Org Information

Collect information about the target organisation itself.

| Sub-technique | What attackers collect |
|---|---|
| T1591.001 — Determine Physical Locations | HQ, offices, data centers — social engineering prep |
| T1591.002 — Business Relationships | Partners, vendors, subsidiaries — supply chain targets |
| T1591.003 — Identify Business Tempo | High-stress periods (acquisitions, layoffs) — phishing timing |
| T1591.004 — Identify Roles | CISO, sysadmin, finance — targeted phishing personas |

**Day coverage:** Days 055, 058

---

#### T1592 — Gather Victim Host Information

Collect information about hosts the target operates.

| Sub-technique | What attackers collect |
|---|---|
| T1592.001 — Hardware | Server types from job ads, firmware versions |
| T1592.002 — Software | OS, web server, frameworks from headers/error pages |
| T1592.003 — Firmware | IoT and embedded device firmware versions |
| T1592.004 — Client Configurations | Browser, plugin requirements from job ads |

**Day coverage:** Days 053, 067 (in 02-Recon-02)

---

#### T1593 — Search Open Websites/Domains

Use publicly accessible websites and search engines to collect information.

| Sub-technique | What attackers collect |
|---|---|
| T1593.001 — Social Media | LinkedIn org chart, employee list, tech stack hints |
| T1593.002 — Search Engines | Google dorks for exposed files, login portals, configs |
| T1593.003 — Code Repositories | GitHub: credentials, internal URLs, architecture |

**Day coverage:** Days 053, 056, 058

---

#### T1594 — Search Victim-Owned Websites

Collect information from the target's own public web presence.

Robots.txt, sitemap.xml, changelog files, `/.well-known/`, job postings on
the company website — all reveal internal paths, technologies, and processes.

**Day coverage:** Day 059

---

#### T1596 — Search Open Technical Databases

Query public technical databases that aggregate information about internet-facing hosts.

| Sub-technique | What attackers collect |
|---|---|
| T1596.001 — DNS/Passive DNS | Historical DNS records, old subdomains |
| T1596.002 — WHOIS | Registrant info, historical registrant data |
| T1596.003 — Digital Certificates | Subdomains from CT logs (crt.sh) |
| T1596.004 — CDNs | CDN origin IPs from CT log SAN fields |
| T1596.005 — Scan Databases | Shodan, Censys — open ports, banners, vulns |

**Day coverage:** Days 053, 054

---

#### T1597 — Search Closed Sources

Purchase or access threat intelligence feeds, dark web data, or breach databases.
This is the domain of well-funded teams. In bug bounty context: HaveIBeenPwned
for credential exposure awareness.

**Day coverage:** Day 055 (breach data awareness)

---

#### T1598 — Phishing for Information

Craft lures to elicit information from the target — not in scope for passive recon,
but important to understand as an escalation path.

| Sub-technique | Purpose |
|---|---|
| T1598.001 — Spearphishing Service | Phish via social media DMs |
| T1598.002 — Spearphishing Attachment | Macro-enabled doc to harvest NTLM/credentials |
| T1598.003 — Spearphishing Link | Fake login page to harvest credentials |

**NOT covered in passive recon — covered in social engineering module.**

---

### 4. The Attacker's Intelligence Objective

Before starting any operation, a professional attacker has five intelligence questions
to answer:

```
┌───────────────────────────────────────────────────────────────┐
│ 1. SCOPE        What is the target's internet-facing footprint?│
│                 Subdomains, IPs, cloud assets, APIs            │
├───────────────────────────────────────────────────────────────┤
│ 2. TECHNOLOGY   What software is running?                      │
│                 Web servers, frameworks, CMS, libraries        │
├───────────────────────────────────────────────────────────────┤
│ 3. PEOPLE       Who works there? Who has privileged access?    │
│                 Emails, roles, LinkedIn, breach exposure       │
├───────────────────────────────────────────────────────────────┤
│ 4. PROCESS      How do they operate?                           │
│                 CI/CD exposure, dev practices, GitHub activity │
├───────────────────────────────────────────────────────────────┤
│ 5. HISTORY      What did they have that they forgot about?     │
│                 Old subdomains, archived pages, deleted repos  │
└───────────────────────────────────────────────────────────────┘
```

Every tool and technique in this module answers one or more of these five questions.

---

### 5. Reading a Bug Bounty Scope Document

A bug bounty scope document is your legal contract. Reading it wrong gets your
report rejected, your account banned, or in extreme cases — a lawyer's letter.

#### What to Extract

**Example scope document excerpt (HackerOne format):**

```
In Scope:
  *.example.com
  api.example.com
  mobile.example.com (iOS and Android apps)

Out of Scope:
  legacy.example.com
  partners.example.com
  Physical security tests
  Social engineering of employees
  DDoS / volumetric attacks
  Automated scanning of out-of-scope assets

Special Rules:
  Do not test on production user data
  Do not exfiltrate real data — stop at PoC
  Rate limiting: max 10 requests/second
```

#### Your Extraction Checklist

When you receive a scope document, answer these before touching anything:

1. **What is in scope?** List every domain and IP range explicitly.
2. **Does `*.example.com` cover all subdomains?** Usually yes — but confirm.
3. **Are third-party services in scope?** (e.g., Salesforce CRM, Zendesk support
   — usually NOT in scope unless explicitly stated)
4. **What testing activities are prohibited?** (DDoS, social engineering,
   physical access, credential stuffing against real accounts)
5. **What is the data handling rule?** (Stop at PoC, do not exfiltrate)
6. **Is there a safe harbour clause?** (Protects you from CFAA/CMA prosecution
   if you act in good faith within scope)

#### Ghost's Warning

> Programs without a safe harbour clause mean the company has not committed to
> not prosecuting you. If there is no safe harbour, treat every finding with
> extreme caution. Some companies use VDPs (Vulnerability Disclosure Programs)
> instead of bug bounty — they promise not to sue but pay nothing. Know the
> difference before you start.

---

### 6. Real-World Context — Recon in Documented Breaches

#### SolarWinds (2020) — SUNBURST

The Cozy Bear (APT29) operators spent months in reconnaissance before inserting
a backdoor into the SolarWinds Orion build pipeline. Their recon identified:

- SolarWinds as a common software in US government networks (T1591.002 — supply chain)
- The build infrastructure as an accessible target (T1592)
- The certificate signing process as something they needed to mimic (T1596.003)

Recon quality is why the attack remained undetected for 9+ months.

#### Capital One (2019) — Paige Thompson

The attacker used SSRF to reach the AWS EC2 metadata endpoint. Before executing
the SSRF, she had enumerated Capital One's cloud infrastructure through:

- LinkedIn to identify the tech stack (AWS, Kubernetes)
- GitHub to find open-source projects that revealed architecture
- Shodan to identify exposed WAF instances

The recon phase took days. The SSRF exploit itself took minutes.

---

## Key Takeaways

1. **Reconnaissance is the highest-leverage phase.** Investment here multiplies the
   effectiveness of everything that follows. Skipping it is how red teamers get caught
   and bug hunters waste days on dead ends.
2. **MITRE ATT&CK TA0043 is your taxonomy.** When you collect a piece of intelligence,
   know which technique you are performing. This helps you communicate findings and
   understand what defenders are monitoring for.
3. **The Kill Chain makes defenders think linearly. That is their weakness.** A defender
   watching for exploitation often misses the recon phase entirely because it generates
   no alerts. Passive recon is invisible from inside the target.
4. **A scope document is not optional reading.** It is the boundary between authorised
   research and criminal trespass. Know it before you start. Know it again when you think
   you found something interesting.
5. **Five intelligence questions.** Scope, Technology, People, Process, History. Every
   tool in this module answers one or more.

---

## Exercises

### Exercise 1 — ATT&CK Mapping

For each recon action, identify the ATT&CK technique ID and sub-technique ID:

1. You query `crt.sh` for `%.target.com` and get 47 subdomains.
2. You search LinkedIn for employees with "DevOps" in their title at Target Corp.
3. You search Shodan for `org:"Target Corp"` and find three open MongoDB instances.
4. You look at the target's GitHub organisation and find a `.env` file committed
   six months ago with a database password.
5. You check `robots.txt` and find `/internal-admin/` in the Disallow list.

---

### Exercise 2 — Scope Document Analysis

Read the following scope document and answer the questions below:

```
Program: AcmeCorp Bug Bounty
Platform: HackerOne

In Scope:
  *.acmecorp.com
  10.0.0.0/8 (internal — VPN access required, provided to approved hunters)
  AcmeCorp iOS app (com.acmecorp.app)
  AcmeCorp Android app (com.acmecorp.android)

Out of Scope:
  legacy.acmecorp.com
  vendor.acmecorp.com
  acmecorp.zendesk.com
  Any third-party services integrated with AcmeCorp
  Automated scanners (Nikto, Nessus, etc.)
  Physical security / social engineering
  Denial of service attacks

Rewards:
  Critical (RCE, SQLi): $5,000–$15,000
  High (auth bypass, IDOR with impact): $1,000–$5,000
  Medium: $500–$1,000
  Low/Info: At discretion

Safe Harbour: AcmeCorp will not pursue legal action against researchers
  acting in good faith within these guidelines.
```

1. You discover `dev.acmecorp.com` is running an old version of Struts. Is it
   in scope?
2. A login page at `vendor.acmecorp.com` accepts the same credentials as
   `app.acmecorp.com`. Is this reportable?
3. The iOS app makes API calls to `api.acmecorp.com`. Is `api.acmecorp.com`
   in scope even though it is not explicitly listed?
4. You find `legacy.acmecorp.com` is running Apache 2.2 with a known RCE CVE.
   What do you do?
5. Does this program have a safe harbour clause? What does that mean for you?

---

## Questions

<!-- Use this section to log your questions as you study. -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 050 — Foundation Competency Gate](../01-Foundation-05/DAY-0050-Foundation-Competency-Gate.md)*
*Next: [Day 052 — Passive vs Active Recon and OpSec](DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)*
