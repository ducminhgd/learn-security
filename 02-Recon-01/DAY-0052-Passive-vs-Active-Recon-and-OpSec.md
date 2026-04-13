---
title: "Passive vs Active Recon and Operational Security"
tags: [recon, passive-recon, active-recon, opsec, legal, CFAA, CMA, footprints, anonymity]
module: 02-Recon-01
day: 52
related_topics:
  - Recon Mindset and Kill Chain (Day 051)
  - Google Dorks, Shodan and Censys (Day 053)
  - Computer Fraud and Abuse Act (CFAA)
  - Computer Misuse Act (CMA)
---

# Day 052 — Passive vs Active Recon and OpSec

## Goals

By the end of this lesson you will be able to:

1. Precisely define passive reconnaissance and active reconnaissance with examples
   of each.
2. List the specific actions that create a footprint on the target's systems.
3. Explain the legal boundary between passive recon and unauthorised access in
   three major jurisdictions (US, UK, EU).
4. Apply operational security practices during a bug bounty engagement.
5. Choose the correct tool category (passive vs active) for a given intelligence
   collection task.

---

## Prerequisites

- [Day 051 — Recon Mindset and Kill Chain](DAY-0051-Recon-Mindset-and-Kill-Chain.md)

---

## Main Content

### 1. The Hard Distinction

Most people describe passive recon as "not touching the target." That is mostly
right but imprecise. The correct definition:

> **Passive reconnaissance:** Intelligence collection that does not send any
> packets to the target's systems and does not interact with the target's
> services directly.

> **Active reconnaissance:** Intelligence collection that involves direct
> interaction with the target's systems — sending probes, queries, or requests
> that the target's infrastructure receives and may log.

The key word is **infrastructure**. Querying a third-party database (Shodan,
crt.sh, VirusTotal) that *already has* information about your target is passive —
those queries never reach the target. Sending an HTTP request to the target's
server is active — the target's web server logs your IP address and request.

---

### 2. The Footprint Map

Every action you take during recon either leaves a footprint at the target or
it does not. Know which is which before you act.

```
╔══════════════════════════════════════════════════════════════════╗
║                     PASSIVE (no footprint at target)            ║
╠══════════════════════════════════════════════════════════════════╣
║  crt.sh subdomain query       → query hits crt.sh server        ║
║  Shodan host search            → query hits Shodan server        ║
║  WHOIS lookup                  → query hits registrar server     ║
║  Google/Bing dork              → query hits search engine        ║
║  theHarvester (passive mode)   → queries search engines + APIs  ║
║  GitHub public repo analysis   → query hits GitHub API          ║
║  LinkedIn profile viewing *    → complex (see Section 4)        ║
║  Web Archive / Wayback Machine → query hits archive.org         ║
║  VirusTotal passive DNS        → query hits VirusTotal          ║
║  SecurityTrails DNS lookup     → query hits SecurityTrails      ║
╠══════════════════════════════════════════════════════════════════╣
║                     ACTIVE (leaves footprint at target)         ║
╠══════════════════════════════════════════════════════════════════╣
║  nmap port scan               → packets reach target's firewall ║
║  HTTP request to target.com   → target's web server logs it     ║
║  DNS query to target's NS     → target's nameserver logs it     ║
║  Zone transfer attempt        → target's DNS logs the AXFR      ║
║  Subdomain brute force        → DNS resolvers at target get hit ║
║  Directory fuzzing (ffuf)     → target's app server logs it     ║
║  Nikto / Nessus scan          → target's IDS will flag it       ║
╚══════════════════════════════════════════════════════════════════╝
```

\* LinkedIn viewing: anonymous viewing is passive, but LinkedIn shows "X people
viewed your profile" to premium members. Use incognito + LinkedIn's private mode
setting to reduce exposure.

---

### 3. The Legal Framework

Before you touch anything — understand the law. This is not optional. Ignorance
of the CFAA got people federal charges. Know where the line is.

#### United States — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030

The CFAA is the primary US law governing computer access. Key provisions:

- **§ 1030(a)(2):** Intentional unauthorised access to obtain information from
  a protected computer. Misdemeanour for first offence; felony for repeat or
  financial gain.
- **§ 1030(a)(5):** Knowingly causing damage to a protected computer. Includes
  DDoS, vulnerability scanners that cause service disruption.

**"Authorised access"** is the critical term. A bug bounty program's scope
document is evidence of authorisation. Without it, any interaction with a
target system could be argued as unauthorised under CFAA.

**Important landmark:** *Van Buren v. United States* (2021, Supreme Court)
narrowed CFAA — accessing systems you are authorised to access (even for
wrong reasons) is not a CFAA violation. But accessing systems outside your
authorised scope (e.g., out-of-scope assets in a bug bounty) remains risky.

**Practical rule:** If it is not in scope, do not touch it — not even passively
directed queries. The safe harbour protects in-scope work; it does not cover
"I was curious about their staging server."

---

#### United Kingdom — Computer Misuse Act 1990 (CMA)

Three main offences:

| Section | Offence | Penalty |
|---|---|---|
| S.1 | Unauthorised access to computer material | Up to 2 years |
| S.2 | Unauthorised access with intent to commit further offences | Up to 5 years |
| S.3 | Unauthorised acts with intent to impair computer operation | Up to 10 years |

The CMA is broader than the CFAA. Even accessing a login page and probing for
usernames can be argued as S.1 if there is no authorisation.

**Authorisation under CMA:** Same as CFAA — the scope document. Some UK legal
scholars argue that public websites are implicitly authorised for viewing, but
this has never been definitively tested for security research.

---

#### European Union — NIS2 Directive + national laws

The EU does not have a single cybercrime law. Most EU states implement the
Budapest Convention on Cybercrime, which criminalises unauthorised access
similarly to the CFAA/CMA.

The NIS2 Directive (2022) focuses on critical infrastructure protection and
does not create individual liability for researchers, but national transpositions
vary.

**Practical rule for EU researchers:** Apply the strictest national law for
your jurisdiction + the scope document. When in doubt: do not.

---

#### The Safe Harbour Clause — What It Actually Means

A safe harbour clause in a bug bounty program is a company's legal commitment
that they will not pursue prosecution against researchers acting in good faith
within the defined scope.

**What safe harbour does NOT cover:**
- Actions outside the defined scope
- Exfiltrating real user data (even as PoC)
- DDoS or availability attacks
- Accessing systems beyond what is needed to demonstrate the vulnerability
- Sharing the vulnerability publicly before the disclosure window

**Ghost's bottom line:** Safe harbour is a shield only while you are inside the
scope lines. The moment you stray outside them, you are exposed.

---

### 4. Operational Security (OpSec) for Researchers

OpSec is about controlling what information you generate and who can see it.
Even legitimate bug bounty hunters practice OpSec — not to evade defenders
(which would be counterproductive) but to:

1. Avoid exposing your home IP address to a target that might retaliate.
2. Keep different engagements separated (no bleed between targets).
3. Maintain professionalism — a sloppy researcher who spray-scans without care
   causes collateral damage and gets programmes shut down.

#### Browser Hygiene

```
Rule: One browser profile per engagement.

Rationale: Cookies, localStorage, and browser fingerprints from previous
targets can inadvertently reveal your identity or cross-contaminate sessions.

Practice:
- Firefox with uBlock Origin + Canvas Fingerprint Defender
- Private/incognito window for each passive recon session
- No personal Google account logged in during research
- Separate browser profile for each active bug bounty program
```

#### VPN and Network Separation

```
For passive recon:
- Your home ISP is fine for pure database queries (Shodan, crt.sh)
- A VPN adds a layer of separation but is not mandatory for passive work

For active recon (Day 063+):
- Use a VPS or VPN endpoint that is not tied to your home address
- Dedicated VPS (DigitalOcean, Linode) per engagement is best practice
- Never use the same exit node for multiple unrelated targets
```

#### Research Environment

```
Host OS:  macOS / Linux (your daily driver — keep clean)
          │
          ├── VM 1: Kali Linux (bug bounty tools, Burp, recon tooling)
          │         Snapshot before each engagement. Rollback after.
          │
          └── VM 2 (optional): Windows (for Windows-specific tools, AV testing)

Docker: For isolated tooling that does not need a full VM
Network: VM uses NAT or bridged, never host-only during active recon
```

#### Note-Taking and Artefact Management

```
Tool: Obsidian (local), or a private Git repo (encrypted)

Structure per target:
  TargetName/
    ├── scope.md          ← Copy of scope document
    ├── subdomains.txt    ← Discovered subdomains
    ├── ips.txt           ← Resolved IPs
    ├── people.md         ← Employee data, emails
    ├── tech_stack.md     ← Identified technologies
    ├── findings/
    │   ├── FINDING-001.md
    │   └── FINDING-002.md
    └── screenshots/

Never store target data on a cloud service without encryption.
Never share target data with anyone not on the engagement.
```

---

### 5. A Taxonomy of Passive Recon Tools

You will use these across Days 053–059. Categorised here for reference:

| Category | Tools | What they query |
|---|---|---|
| Search engines | Google, Bing, DuckDuckGo | Search engine indices |
| Certificate logs | crt.sh, Censys, Facebook CT | CT log databases |
| DNS / Subdomain | subfinder, amass (passive) | DNS databases, APIs |
| Passive DNS | VirusTotal, SecurityTrails, CIRCL | Historical DNS records |
| Internet scanning | Shodan, Censys, FOFA | Pre-collected port scans |
| WHOIS | whois CLI, ViewDNS, DomainTools | Registrar databases |
| Code repos | GitHub search, GitLab search | Public code indices |
| People/email | theHarvester, Hunter.io, phonebook.cz | Search engines + email data |
| Document metadata | FOCA, exiftool | Local file analysis |
| Web archives | Wayback Machine (archive.org) | Historical web snapshots |
| Breach data | HaveIBeenPwned API | Breach databases |

---

### 6. When Passive Becomes Active — The Grey Zone

Two commonly confused scenarios:

**Scenario 1: DNS resolution**

```bash
# PASSIVE: Ask a third-party service to resolve it
curl "https://api.hackertarget.com/hostsearch/?q=target.com"
# → Your query hits hackertarget.com, NOT target.com

# ACTIVE: Resolve directly
dig A target.com @8.8.8.8
# → This is a DNS query to Google DNS (8.8.8.8) asking about target.com
# → Google resolves it → query hits target.com's authoritative nameserver
# → target.com's nameserver LOGS the query
```

**Scenario 2: HTTP HEAD request "just to check headers"**

This is active recon. The target's web server receives the request and logs:
- Your IP address
- Timestamp
- Request method and path
- User-Agent string

There is no such thing as a "quick check" that does not leave a footprint.

---

## Key Takeaways

1. **Passive means third-party intermediary, not just "harmless."** If your query
   reaches the target's infrastructure, it is active — even if you only asked
   for the headers.
2. **The law is jurisdiction-specific but the principle is universal:** No
   authorisation = no touching. The scope document is your authorisation.
3. **OpSec is professionalism, not paranoia.** Maintaining clean environments
   and separating engagements produces better work and protects both you and
   the programme.
4. **Know your tools' mode.** Most tools have passive and active modes. Always
   verify which mode you are running before starting. `amass -passive` is very
   different from `amass -active`.
5. **The grey zone is real.** DNS queries, HTTP HEAD requests, even clicking a
   link in a Google search result can send referrer headers to the target. Stay
   aware of what your browser and tools are actually doing.

---

## Exercises

### Exercise 1 — Classification

For each action, state: passive or active, and why.

1. You search `site:target.com filetype:pdf` in Google.
2. You run `nmap -sn 192.168.1.0/24` against target.com's IP range.
3. You query `curl "https://crt.sh/?q=%.target.com&output=json"`.
4. You open `https://target.com/robots.txt` in Firefox.
5. You run `subfinder -d target.com -silent` (subfinder uses passive APIs only
   by default).
6. You run `amass enum -active -d target.com`.
7. You search for "target.com" on Shodan.
8. You run `dig axfr target.com @ns1.target.com`.
9. You read a cached version of target.com's page on Google Cache.
10. You run `theHarvester -d target.com -b google -l 100`.

---

### Exercise 2 — OpSec Setup

Set up your research environment:

1. Create a dedicated Firefox profile named `bugbounty`.
2. Install: uBlock Origin, FoxyProxy Standard, Cookie AutoDelete.
3. Set Firefox to never remember history in this profile.
4. Take a Kali Linux VM snapshot and label it `clean-baseline`.
5. Create a folder structure for a hypothetical target following the template
   in Section 4.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 051 — Recon Mindset and Kill Chain](DAY-0051-Recon-Mindset-and-Kill-Chain.md)*
*Next: [Day 053 — Google Dorks, Shodan and Censys](DAY-0053-Google-Dorks-Shodan-and-Censys.md)*
