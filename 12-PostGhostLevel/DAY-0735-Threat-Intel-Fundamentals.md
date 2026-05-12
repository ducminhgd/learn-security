---
title: "Threat Intelligence Fundamentals — Intel Cycle, IOC vs TTP, STIX/TAXII"
tags: [threat-intelligence, intel-cycle, ioc, ttp, stix, taxii, misp, module-12-postghost]
module: 12-PostGhostLevel
day: 735
prerequisites:
  - Day 619 — Malware Report Writing
  - Day 639 — APT Tooling Patterns
related_topics:
  - Day 736 — Threat Intel Lab: MISP Setup
  - Day 737 — Advanced Detection Engineering
---

# Day 735 — Threat Intelligence Fundamentals

> "Data is what attackers leave behind. Intelligence is what defenders do with
> it. Logs, IOCs, and PCAP captures are data. Knowing which threat actor left
> them, what they were trying to accomplish, and what they will try next — that
> is intelligence. The gap between data and intelligence is analysis, and
> analysis is a skill."
>
> — Ghost

---

## Goals

Understand the threat intelligence lifecycle and the three types of intelligence.
Learn the difference between IOC-based and TTP-based intelligence and why it
matters for detection longevity. Understand STIX/TAXII as the sharing protocol.
Be able to classify a finding as a specific intelligence type.

**Prerequisites:** Days 619, 639.
**Estimated study time:** 2.5 hours.

---

## 1 — The Intelligence Cycle

```
THE INTELLIGENCE CYCLE

1. PLANNING (What question are we trying to answer?)
   "Which threat actors target financial institutions in Southeast Asia?"
   "Is APT10 active in our sector?"
   "What TTPs will this ransomware group use in their next campaign?"

2. COLLECTION (What data sources do we use?)
   Malware samples (MalwareBazaar, VirusTotal, internal sandbox)
   Network traffic logs
   OSINT (threat actor blogs, dark web forums, Pastebin)
   Commercial feeds (Intel 471, Recorded Future, Mandiant Advantage)
   Vendor incident reports

3. PROCESSING (Turn raw data into structured data)
   Normalise IOCs → STIX format
   Tag malware with ATT&CK techniques
   Pivot on infrastructure (IP → domain → org → actor)

4. ANALYSIS (Turn structured data into intelligence)
   Attribution: "This campaign infrastructure overlaps with APT41"
   Prediction: "Based on past campaigns, lateral movement follows within 72h"
   Recommendation: "Block these 14 domains; add detection for T1059.001"

5. DISSEMINATION (Who needs to know, in what format?)
   SOC: IOC list, Sigma/YARA rules (operational)
   CISO: threat briefing, business impact (strategic)
   IR team: TTPs, C2 patterns, persistence mechanisms (tactical)

6. FEEDBACK (Was the intelligence useful? What questions remain?)
   Update detection rules
   Refine collection sources
   Close the intelligence gaps
```

---

## 2 — Three Intelligence Types

### 2.1 Strategic Intelligence

```
STRATEGIC INTELLIGENCE

Audience: CISO, board, business leadership
Question: "What threats should our organisation plan for over 12–24 months?"
Format:   Written report, 2–5 pages, no IOCs
Example:
  "Ransomware groups targeting manufacturing sector have shifted from
   bulk encryption to double-extortion (data theft + encryption) in
   85% of 2024 campaigns. Organisations without offline backups face
   a 4–7x higher ransom demand."

Characteristics:
  Long shelf life (months to years)
  No technical IOCs
  Guides budget decisions and programme priorities
```

### 2.2 Operational Intelligence

```
OPERATIONAL INTELLIGENCE

Audience: Red team, IR team, senior SOC analysts
Question: "What will this specific threat actor do next campaign?"
Format:   TTP mapping, campaign analysis, tooling profile
Example:
  "APT41 is known to use T1566.001 (spearphishing attachment) for
   initial access in this sector. After compromise, they deploy a
   custom backdoor consistent with DUSTPAN loader, then establish
   persistence via T1547.001 (Registry Run Keys). Expected dwell time
   before data exfiltration: 3–5 days."

Characteristics:
  Medium shelf life (weeks to months)
  TTPs and tooling, minimal IOCs
  Guides defensive architecture decisions
  Source: detailed malware analysis, campaign reports
```

### 2.3 Tactical Intelligence

```
TACTICAL INTELLIGENCE

Audience: SOC analysts, SIEM engineers, endpoint teams
Question: "What do I add to my blocking/detection list right now?"
Format:   IOC lists, YARA rules, Sigma rules, firewall blocks
Example:
  "Block these 14 C2 IPs (from latest Cobalt Strike campaign):
   45.77.X.X, 188.241.X.X ...
   YARA rule detecting the beacon config: [rule attached]
   Sigma rule for T1059.001 PS download cradle: [rule attached]"

Characteristics:
  Short shelf life (days to weeks for network IOCs)
  High volume, machine-readable
  Directly fed into SIEM, EDR, firewall, proxy
  IOCs expire: IP addresses reuse; domains are sinkholed; file hashes
  change on recompile
```

---

## 3 — IOC vs TTP — The Fundamental Tension

This is the most important concept in threat intelligence:

```
IOC PYRAMID OF PAIN (David Bianco, 2013)

                      △ HARDEST FOR ATTACKER TO CHANGE
                      │
                [TTPs]     Behaviour patterns, tradecraft
                      │    "They always use certutil for download cradles"
              [Tools]       Specific malware / tooling
                      │    "Cobalt Strike beacon with specific config"
            [Network/Host]  Mutex names, registry keys
                      │    "Creates mutex: {GUID}"
           [Domain Names]   C2 domain
                      │    "c2.evil-domain[.]com"
        [IP Addresses]      C2 IP
                      │    "185.220.101.X"
    [Hash Values]           MD5/SHA256 of binary
                      │
                      ▽ EASIEST FOR ATTACKER TO CHANGE

IMPLICATION:
  Blocking a hash: attacker recompiles, new hash, bypassed in 1 hour.
  Detecting a TTP: attacker must change their tradecraft, which takes months.

TACTICAL INTEL = fast but fragile (IOC-based)
OPERATIONAL INTEL = slower to build but durable (TTP-based)

The best detection programmes use BOTH.
TTP detections catch novel and IOC-evading variants.
IOC detections catch known-bad immediately.
```

---

## 4 — STIX/TAXII: The Language of Intel Sharing

### 4.1 STIX 2.1 (Structured Threat Information eXpression)

```
STIX is a JSON-based format for describing threat intelligence.

Core STIX objects (Domain Objects):
  attack-pattern     A TTP (maps to ATT&CK)
  campaign           A named operation by a threat actor
  course-of-action   Mitigation recommendation
  identity           Organisation, individual, group
  indicator          IOC with pattern (e.g., IP matches X)
  intrusion-set      Cluster of activity attributed to one actor (APT group)
  malware            Malware family description
  report             Collection of objects in a single intelligence report
  threat-actor       Specific named threat actor
  tool               Legitimate tool used maliciously
  vulnerability      CVE reference
  observed-data      Raw observation (IP seen, file hash, domain)

Example indicator in STIX 2.1:
  {
    "type": "indicator",
    "id": "indicator--[UUID]",
    "name": "Cobalt Strike C2",
    "pattern": "[ipv4-addr:value = '45.77.64.32']",
    "pattern_type": "stix",
    "valid_from": "2025-01-15T00:00:00Z",
    "labels": ["malicious-activity"],
    "created_by_ref": "identity--[YOUR-ORG-UUID]"
  }
```

### 4.2 TAXII (Trusted Automated eXchange of Intelligence Information)

```
TAXII is the transport protocol for STIX objects.

TAXII 2.1 concepts:
  API Root:         Endpoint URL of a TAXII server
  Collection:       A named bucket of STIX objects
  Discovery:        /taxii/ endpoint lists available API roots
  Get Objects:      GET /api/v21/collections/{id}/objects/
  Add Objects:      POST /api/v21/collections/{id}/objects/

Common TAXII servers:
  MISP (self-hosted)              → Has built-in TAXII server
  OpenCTI (self-hosted/cloud)     → Native TAXII 2.1 support
  VirusTotal Intelligence         → Paid tier
  ISAC feeds (FS-ISAC, H-ISAC)   → Sector-specific sharing
  CISA AIS                        → Free US government feed
```

---

## 5 — Pivoting on Infrastructure

A core TI analyst skill: given one IOC, find more by pivoting through shared
infrastructure.

```
PIVOT CHAIN EXAMPLE

Start: malware SHA256 hash
  ↓
  VirusTotal: DNS resolutions during dynamic analysis
  → C2 domain: update-check.site[.]biz
  ↓
  PassiveDNS (SecurityTrails / RiskIQ): other IPs this domain resolved to
  → IP: 185.220.101.47
  ↓
  Shodan/Censys: what else is on that IP?
  → Self-signed TLS cert with Subject: CN=*.cdn-cloudflare[.]net
  ↓
  TLS cert search (crt.sh / Censys): who else uses this cert?
  → 7 more IPs with the same cert → 7 more C2 nodes
  ↓
  WHOIS: who registered update-check.site[.]biz?
  → Registrar email used for 4 other domains
  → All 4 domains follow same naming pattern
  ↓
  Attribution hypothesis: "This infrastructure cluster is consistent
  with known APT10 beacon deployment patterns based on cert reuse."

TOOLS FOR PIVOTING:
  VirusTotal         Full pivot graph on PE submissions
  Shodan             Infrastructure fingerprinting by banner / cert
  Censys             TLS cert search, internet-wide scans
  SecurityTrails     PassiveDNS, WHOIS history
  Spiderfoot         Automated OSINT pivot chaining
  MISP               Store + correlate all pivoted data
```

---

## Key Takeaways

1. **Strategic → Operational → Tactical: know which type your output is** and
   tailor it to the right audience and format.
2. **TTPs are the highest-value intelligence** — they survive attacker
   infrastructure rotation, tool recompilation, and C2 domain changes.
3. **Infrastructure pivoting multiplies the value of a single IOC.** One C2 IP
   can expand to a cluster of 30+ attacker-controlled nodes through cert and
   registrar pivots.
4. **STIX/TAXII is the standard.** MISP and OpenCTI both speak it natively.
   Anything you produce should be expressible as STIX.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q735.1, Q735.2 …).

---

## Navigation

← Previous: [Day 734 — Certification Strategy](DAY-0734-Certification-Strategy.md)
→ Next: [Day 736 — Threat Intel Lab: MISP Setup](DAY-0736-Threat-Intel-Lab-MISP.md)
