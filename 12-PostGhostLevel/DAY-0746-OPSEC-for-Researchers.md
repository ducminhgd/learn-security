---
title: "OPSEC for Security Researchers — Infrastructure Attribution, Anonymous Lab, Legal Separation"
tags: [opsec, operational-security, research-infrastructure, legal-separation,
  anonymity, module-12-postghost]
module: 12-PostGhostLevel
day: 746
prerequisites:
  - Day 052 — Passive vs Active Recon and OpSec
related_topics:
  - Day 747 — Incident Response Leadership
---

# Day 746 — OPSEC for Security Researchers

> "The irony of this field: the people who understand how attackers are tracked
> are sometimes careless about their own exposure. A researcher who runs malware
> from their home IP, registers their research infrastructure under their real
> identity, and stores samples on their personal Dropbox is building a threat
> to themselves. You are not a threat actor — but you handle threat-actor tooling,
> and that comes with responsibility for your own protection."
>
> — Ghost

---

## Goals

Understand the specific OPSEC considerations for security researchers (not
attackers — defenders and researchers). Know how to set up isolated research
infrastructure. Understand the legal and personal risks of insecure research
practices. Know how to maintain separation between your research identity and
personal identity.

**Prerequisites:** Day 52.
**Estimated study time:** 2 hours.

---

## 1 — Why Researcher OPSEC Is Different

```
THE RESEARCHER THREAT MODEL

You are not a threat actor. But you:
  - Handle live malware samples
  - Run network-active exploit tools
  - Probe targets (within scope, but still)
  - Operate infrastructure that overlaps with attacker patterns
  - Publish research that certain vendors or state actors may find unwelcome

YOUR ADVERSARIES:

1. Automated systems (antivirus, ISP, cloud provider):
   Scanning your traffic, flagging malware samples, suspending accounts
   Mitigation: isolated networks, encrypted storage, research accounts

2. Threat intelligence platforms:
   OSS-Fuzz bugs, bug bounties, CVE submissions — all contain your email
   If that email links to your home IP, your home IP becomes queryable
   Mitigation: separate research email, VPS-based research origin

3. Hostile vendors:
   Some vendors respond to vulnerability reports with legal threats (rare)
   Having a clear documented timeline and scope letter is your protection
   Mitigation: CVD best practices (Day 733), legal advice before publishing

4. Law enforcement (edge case):
   If you run an exploit tool against a scope-unclear target, or store
   samples without clear research context, there is a legal risk
   Mitigation: documented authorization, clear research context, legal advice

5. Peer attribution:
   Threat intelligence researchers may attribute your infrastructure to
   "unknown actor" if your tools and TTPs look like a threat actor
   This is embarrassing, not dangerous — but document your work clearly
```

---

## 2 — Research Infrastructure Separation

```
THE SEPARATED IDENTITY MODEL

Research persona:
  Email:    research-handle@proton.me  (NOT your real Gmail)
  Username: [handle]-research           (NOT your real name)
  GitHub:   github.com/[handle]-sec     (separate from personal GitHub)
  Domain:   [handle]-research.com      (registered via privacy-protected registrar)

Personal persona:
  Email:    personal@gmail.com
  LinkedIn: real name, real employer
  GitHub:   github.com/[real_name]

RULE: Research persona never connects to personal identity in any public record.

Why this matters:
  Your research involves targets that may not be happy about your findings.
  Separation means a hostile vendor contacting "your" research email cannot
  trivially cross-reference your employer via public records.
  (This is a professional protection, not an anonymity scheme.)
```

### 2.1 Infrastructure Registration

```
RESEARCH VPS SETUP

VPS provider (not your personal cloud account):
  Use a dedicated cloud account (new AWS account, Hetzner, Vultr)
  Registered with research email, paid with a prepaid card or crypto
    (Note: tax implications of crypto vary; consult an accountant)
  Never mix research infrastructure with personal projects

Domain registration:
  Use a privacy-protecting registrar: Njalla, Porkbun (with WHOIS privacy)
  Research domain should NOT contain your real name
  Renew annually; letting domains expire leaks attribution information

DNS:
  Use Cloudflare DNS (free, hides origin IP)
  For active research: put all public-facing endpoints behind Cloudflare

IP rotation:
  For passive OSINT: use Tor browser or a residential proxy
  For active research (authorised scope): document in scope letter
  Never route unauthorised active scans through a VPS you care about keeping
```

### 2.2 Malware Sample Handling Infrastructure

```
MALWARE STORAGE SECURITY

Never:
  - Store unencrypted samples on cloud storage (Google Drive, Dropbox)
  - Email malware samples without encryption (ZIP with password is NOT sufficient)
  - Push samples to a public GitHub repository
  - Store samples on a machine connected to your home/corporate network
    without isolation

Always:
  - LUKS2 encrypted volume (Linux) or VeraCrypt volume (Windows) for samples
  - Transfer samples via encrypted channel (SFTP to isolated lab VM only)
  - Maintain an index of what you have and why (documented research context)
  - Use a naming convention that shows context: [hash]-[family]-[date].bin

If subpoenaed or questioned:
  "I maintain a research collection of malware samples for the purpose of
   developing detection signatures. All samples are stored encrypted on
   isolated systems not connected to the internet. I have written
   documentation of the research purpose for each collection."
  This is your legal protection — the documentation, not the fact of possession.
```

---

## 3 — Network OPSEC During Research

```
WHAT LEAVES A TRACE

Active scanning (nmap, masscan):
  → ISP sees outbound SYN packets to a range of IPs
  → Target sees scan origin IP in server logs
  → If outside scope: this is the CFAA violation vector
  RULE: only active scan in-scope targets; document scope letter

Bug bounty testing:
  → Burp Suite traffic comes from your IP unless proxied
  → Targets may log your IP against your finds
  → This is normal and expected for in-scope work
  → If you need anonymity from the target: use a rented research VPS

Vulnerability research (fuzzing):
  → Fuzzing is local (no network trace)
  → PoC development and testing: target server logs your IP
  → When running against a network target for final PoC confirmation:
     use your dedicated research VPS (never your home IP)

Submitting to bug bounty platforms:
  → Your IP is logged against your account on first login
  → Use a consistent IP (research VPS) for all platform interactions
  → This is identity consistency, not anonymity — the platform knows who you are

WHEN TO ROUTE THROUGH TOR:
  For passive OSINT where you do not want the target to know you are looking
  NOT for active exploitation or tool interaction
    (Tor exit nodes are often blocked by security-conscious targets)
    (Tor exit nodes appear in threat intelligence databases)
```

---

## 4 — Legal Protections

```
YOUR LEGAL PROTECTION CHECKLIST

1. Written scope documentation for every active engagement
   "I am authorised to test the following targets..." signed by someone
   at the organisation. For bug bounty: the programme policy IS your scope.
   Keep a copy indefinitely.

2. Clean research context documentation for malware work
   "I maintain these samples for the purpose of [signature development,
    incident response support, academic research]. The collection is
    secured by [encryption method]."

3. Disclosure timeline for every vulnerability you report
   Every email, every response, every extension request — documented.
   This is your protection against a vendor claiming you acted in bad faith.

4. EFF's guide for security researchers:
   https://www.eff.org/issues/coders/vulnerability-reporting-faq
   Review this before your first report to a new programme or vendor.

5. Legal advice before:
   - Publishing a vulnerability without vendor coordination
   - Conducting research outside a defined bug bounty scope
   - Storing malware from a law enforcement target (even for analysis)
   - Publishing research about a nation-state tool

6. Do not operate as a sole researcher when targeting high-profile vendors:
   Large organisations have legal teams. Having an institution,
   company, or co-author adds legitimacy and distributes legal exposure.
```

---

## Key Takeaways

1. **OPSEC for researchers is about legal protection and professional
   separation, not anonymity.** You are not a threat actor; you are a
   professional handling sensitive tooling and findings.
2. **Isolate research infrastructure from personal identity at every layer:**
   email, GitHub, VPS registration, domain registration.
3. **Written scope documentation is your single most important legal protection.**
   No scope document = no legal protection if something goes wrong.
4. **Malware samples require encrypted, isolated storage with documented research
   context.** "I had it for research" is not a defence; a documented research
   programme is.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q746.1, Q746.2 …).

---

## Navigation

← Previous: [Day 745 — Security Engineering Interview Preparation](DAY-0745-Security-Interview-Preparation.md)
→ Next: [Day 747 — Incident Response Leadership](DAY-0747-IR-Leadership.md)
