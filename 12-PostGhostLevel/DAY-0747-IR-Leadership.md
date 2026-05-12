---
title: "Incident Response Leadership — Running an Engagement, Tabletop Exercises, Retainer Scoping"
tags: [incident-response, ir-leadership, tabletop, retainer, forensics, module-12-postghost]
module: 12-PostGhostLevel
day: 747
prerequisites:
  - Day 641 — Volatility3 Fundamentals
  - Day 648 — Malware Analysis Module Review
related_topics:
  - Day 748 — Methodology Crystallisation
---

# Day 747 — Incident Response Leadership

> "The call comes in at 2 a.m. The client's CISO says: 'We think we have been
> breached. We don't know how long.' Your job at that moment is not panic, not
> improvisation, and not heroics. Your job is to run a systematic process that
> collects the right evidence, stops the bleeding, and produces a clear timeline
> of what happened. Calm methodology under pressure is the senior IR skill."
>
> — Ghost

---

## Goals

Understand the structure and phases of an incident response engagement.
Know how to scope an IR retainer. Be able to run a tabletop exercise for
non-technical executives. Understand the handoff between IR and hardening.

**Prerequisites:** Days 641, 648.
**Estimated study time:** 2.5 hours.

---

## 1 — Incident Response Phases

```
NIST SP 800-61 IR LIFECYCLE

1. PREPARATION
   Policies, playbooks, tools pre-staged, retainer agreements in place.
   Most clients fail here. Most breaches are worsened by it.

2. DETECTION AND ANALYSIS
   Identify the scope, timeline, and nature of the incident.
   This is the phase where forensic skills matter most.

3. CONTAINMENT, ERADICATION, AND RECOVERY
   Stop the bleeding, remove attacker presence, restore services.
   Sequencing matters: contain before you eradicate, or the attacker
   destroys evidence and moves.

4. POST-INCIDENT ACTIVITY
   Lessons learned, report, hardening recommendations, litigation support.
```

---

## 2 — The First 24 Hours: IR Lead Checklist

```
INITIAL RESPONSE CHECKLIST (first 24 hours as IR lead)

WITHIN 1 HOUR OF CALL:
  [ ] Establish incident severity (P1/P2/P3/P4) — see severity matrix below
  [ ] Confirm scope: how many hosts? which systems affected?
  [ ] Confirm containment decisions: is the attacker currently active?
  [ ] Identify legal/regulatory obligations (GDPR, HIPAA, SEC 4-day rule)
  [ ] Establish a secure out-of-band communication channel
      (assume email is compromised if mail server is affected)

WITHIN 4 HOURS:
  [ ] Identify forensic evidence preservation priorities
      → Volatile: running processes, network connections, logged-in users
      → Semi-volatile: logs (may rotate), memory dumps
      → Non-volatile: disk images, backup copies
  [ ] Pull network logs from SIEM/proxy for the suspected intrusion window
  [ ] Identify patient zero (first compromised host)
  [ ] Identify all hosts with lateral movement from patient zero
  [ ] Issue containment decision (do NOT isolate before imaging volatile data)

WITHIN 24 HOURS:
  [ ] Initial forensic timeline from logs and endpoint telemetry
  [ ] Attacker presence confirmed or denied on each identified host
  [ ] Preliminary scope report to client: "here is what we know, here is
      what we do not know, here is our plan for the next 48 hours"
  [ ] Evidence preservation complete for key hosts

SEVERITY MATRIX:
  P1: Confirmed ransomware/wiper active; data exfiltration confirmed;
      critical infrastructure affected → all hands, 24/7
  P2: Active attacker with DA or domain persistence, not yet exfil confirmed
  P3: Malware detected, isolated, no confirmed lateral movement
  P4: Suspicious activity under investigation, no confirmed breach
```

---

## 3 — Forensic Collection Priorities

```
EVIDENCE COLLECTION ORDER (most volatile first)

1. Memory dump (if host still running)
   Windows: winpmem.exe -o hostname-memory.dmp
   Linux:   LiME kernel module → /tmp/hostname-memory.dmp
   Value: captures running processes, network connections, encryption keys,
          malware decrypted in memory

2. Network connections and process list (snapshot)
   netstat -anop / ss -antp (Linux)
   Get-NetTCPConnection / Get-Process (Windows)
   Value: live C2 connections, suspicious processes

3. Running process images (if malware likely in-memory only)
   Process dump with procdump.exe -ma [pid] or create_dump
   Value: capture fileless malware before it terminates

4. Log collection (before rotation)
   Windows: Security.evtx, System.evtx, Sysmon.evtx
   Linux:   /var/log/auth.log, syslog, journal, /var/log/secure
   Collect logs for the suspected intrusion window + 30 days prior

5. Disk image (if host is to be preserved for legal)
   FTK Imager, dd, dcfldd
   Hash the image (MD5 + SHA256) immediately after creation
   Store on write-protected media if for litigation

6. Artefact triage (if you cannot full-image)
   Prefetch: C:\Windows\Prefetch\
   ShimCache: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
   MFT: ntfs-3g parse or Windows MFT scanner
   Lateral movement: Event 4624 (successful logon), 4625 (failed), 4648
   Scheduled tasks: C:\Windows\System32\Tasks\
```

---

## 4 — Tabletop Exercise for Executives

The most effective IR preparation for non-technical leaders.

```
TABLETOP EXERCISE DESIGN

PURPOSE:
  Test the decision-making process, not technical response.
  Executives will not respond with forensic tools. They will:
  - Decide when to call law enforcement
  - Decide whether to pay ransom
  - Decide what to communicate to customers and regulators
  - Approve or block technical containment decisions

FORMAT:
  Participants: CISO, CTO, CEO, Legal, Communications/PR, key IT leads
  Duration: 2–3 hours
  Facilitator: You (IR lead)
  Format: inject-based scenario — present events, ask decisions

SAMPLE SCENARIO INJECTS:
  T+00: "We have received an alert from our EDR. Ransomware encryptor is active
        on 12 servers. Encrypted files are .0x777 extension. Encryption is ongoing."
  → Decision: Do we isolate all affected hosts? What are the business consequences?

  T+30: "The attacker has posted a listing on their TOR leak site showing 5 GB
         of your financial records. They are demanding $2M in Bitcoin."
  → Decision: Do we contact law enforcement? Do we pay? Who do we notify?

  T+2h: "We have confirmed the attacker had access for 21 days. Our backup
          system is also encrypted — the attacker moved laterally to it."
  → Decision: Do we notify customers? When? What do we say?

  T+4h: "Law enforcement asks for 48 hours of confidentiality before we notify
          customers while they investigate."
  → Decision: Is this legally permissible? What is our regulatory obligation?

DEBRIEF QUESTIONS:
  - Which decision took the longest? Why?
  - Where did we not have documented playbooks?
  - Who was not at this table who should have been?
  - What single action, taken 6 months ago, would have changed the outcome?
```

---

## 5 — IR Retainer Scoping

```
RETAINER AGREEMENT COMPONENTS

What an IR retainer covers:
  On-call response (24/7, [X] hour SLA)
  Forensic evidence collection and analysis
  Malware analysis and IOC development
  DFIR timeline reconstruction
  Executive briefing and reporting
  Litigation support (optional add-on)
  Post-incident hardening recommendations (usually scoped separately)

How to scope a retainer:
  1. Estimate the organisation's risk profile:
     Industry (healthcare, finance → higher risk → higher retainer)
     Size (number of endpoints, geographic footprint)
     Existing security maturity (SIEM coverage, EDR coverage)

  2. Define the service hours:
     24/7 with [X]-hour response SLA
     Typical retainer SLA tiers: 1h / 4h / 8h

  3. Define incident hours pre-paid:
     "40 hours of IR included in retainer, additional at $350/hr"
     Unused hours: some retainers roll over, some expire annually

  4. Define deliverables:
     Incident report (timeline, IOCs, findings)
     Malware samples and YARA rules (if applicable)
     Recommended remediations

  5. Pricing reference (2025):
     Boutique firm: $25,000–$80,000/year retainer
     Big 4 / Mandiant: $100,000–$500,000+/year
     Solo practitioner: $10,000–$30,000/year
     Hourly break-glass (no retainer): $350–$600/hr
```

---

## Key Takeaways

1. **Containment before evidence collection is a mistake.** Isolating a host
   before imaging memory destroys the most valuable forensic artifact.
   Contain after you image, not before.
2. **The tabletop exercise surfaces decision-making gaps, not technical gaps.**
   The technical team knows what to do. The tabletop tests whether leadership
   can make containment, communication, and legal decisions under pressure.
3. **The IR retainer conversation is a business conversation, not a technical
   one.** Lead with risk, regulatory obligations, and business continuity —
   not with forensic tool lists.
4. **The post-incident report is the most valuable deliverable.** A clear
   timeline with root cause analysis, evidence, and specific remediations is
   the document that justifies the retainer cost to every stakeholder.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q747.1, Q747.2 …).

---

## Navigation

← Previous: [Day 746 — OPSEC for Security Researchers](DAY-0746-OPSEC-for-Researchers.md)
→ Next: [Day 748 — Methodology Crystallisation](DAY-0748-Methodology-Crystallisation.md)
