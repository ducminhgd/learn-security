---
title: "Day 738 — Building a Threat Intelligence Programme"
tags: [threat-intelligence, ti-programme, misp, attack-attribution,
  ioc-enrichment, threat-hunting, apt, module-12-post-gate]
module: 12-PostGate
day: 738
prerequisites:
  - Day 737 — Advanced Supply Chain Security
  - Day 640 — APT Tooling Patterns (Module 10)
  - Day 639 — APT RAT Analysis
related_topics:
  - Day 739 — Research Automation at Scale
---

# Day 738 — Building a Threat Intelligence Programme

> "Threat intelligence is not a feed subscription. It is a production
> system. It takes raw data — malware samples, IP addresses, domain names,
> TTP observations — and turns them into answers to three questions: Who is
> attacking us? What are they doing? What do we do about it? A TI programme
> that cannot answer those questions in the middle of an incident is noise,
> not intelligence."
>
> — Ghost

---

## Goals

1. Understand the threat intelligence cycle and the difference between
   strategic, operational, and tactical intelligence.
2. Build a local MISP (Malware Information Sharing Platform) instance and
   import real threat data.
3. Enrich IOCs (Indicators of Compromise) automatically using open-source
   tools and APIs.
4. Map a real threat actor's TTPs to MITRE ATT&CK and write a threat profile.
5. Understand how threat intelligence feeds detection engineering.

---

## Prerequisites

- Days 639–640 (APT tooling patterns), Day 737 (supply chain security context).
- Docker for MISP deployment.
- Understanding of MITRE ATT&CK (used throughout this programme).

---

## 1 — The Threat Intelligence Cycle

```
THREAT INTELLIGENCE CYCLE

Planning → Collection → Processing → Analysis → Dissemination → Feedback

PLANNING (What do we need to know?):
  Priority Intelligence Requirements (PIRs):
    "Which threat actors are likely to target our sector?"
    "Are our suppliers targeted by supply chain actors?"
    "Are any of our IPs or domains appearing in threat actor campaigns?"

COLLECTION (Where does the data come from?):
  Technical: malware samples, network captures, SIEM events, honeypot logs
  OSINT: VirusTotal, Shodan, Censys, social media, dark web monitoring
  Shared: ISACs, MISP communities, vendor threat reports
  Human: conferences, vendor advisories, internal incident data

PROCESSING (Converting raw data to usable format):
  Normalise: deduplicate IOCs, standardise formats (STIX 2.1, MISP JSON)
  Enrich: add geolocation, ASN, threat actor association, CVE mapping
  Correlate: link IOCs to TTPs, link TTPs to threat actors

ANALYSIS (Producing intelligence from data):
  Strategic: nation-state motivation, sector targeting trends (for executives)
  Operational: campaign-level TTP analysis (for security teams)
  Tactical: specific IOCs to block, YARA rules to deploy (for SOC)

DISSEMINATION (Delivering intelligence to consumers):
  SIEM: push IOC blocklist updates automatically
  Email: weekly sector threat report to CISO
  Ticketing: auto-create incidents when IOC matches production traffic

FEEDBACK:
  Did the intelligence stop an attack? Did it generate false positives?
  What PIRs are still unanswered? Adjust collection priorities.
```

---

## 2 — MISP: Malware Information Sharing Platform

MISP is the de-facto open source TI platform. Run it locally:

```bash
# Deploy MISP with Docker (official quick setup)
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env
# Edit .env: set MISP_BASEURL, MISP_ADMIN_EMAIL, MISP_ADMIN_PASSPHRASE
docker-compose up -d

# Access: https://localhost (accept self-signed cert)
# Default admin: admin@admin.test / admin (change immediately)

# Import a threat feed (CIRCL OSINT feed):
# Administration → Server Settings → Feeds
# Add feed: https://www.circl.lu/doc/misp/feed-osint/
# Enable and fetch

# Pull threat data from the MISP community:
# Sync with CIRCL's public MISP instance (requires account):
# https://www.circl.lu/doc/misp/sharing/
```

### 2.1 MISP Event Structure

```
MISP EVENT HIERARCHY

Event (incident or campaign):
  ├── Attributes (individual IOCs):
  │     ip-dst: 185.220.101.23
  │     domain: malicious-domain.ru
  │     sha256: a1b2c3d4...
  │     url: https://malicious-domain.ru/payload.exe
  │
  ├── Objects (structured collections of attributes):
  │     network-connection object: {src-ip, dst-ip, dst-port, protocol}
  │     file object: {sha256, filename, size, mime-type}
  │     whois object: {registrar, creation-date, registrant-email}
  │
  ├── Galaxy (ATT&CK TTPs, threat actors, malware families):
  │     Threat Actor: APT29 (Cozy Bear)
  │     Attack Pattern: T1566.001 — Spearphishing Attachment
  │     Malware: SUNBURST
  │
  └── Tags (classification):
        tlp:amber — traffic light protocol
        misp-galaxy:threat-actor="APT29"
        ATT&CK Tactic:TA0001 — Initial Access
```

---

## 3 — IOC Enrichment Pipeline

```python
#!/usr/bin/env python3
# ioc_enricher.py — Enrich a list of IP addresses and domains with OSINT

import requests
import json
import time

VT_API_KEY = "your_virustotal_key"     # 500 lookups/day on free tier
SHODAN_API_KEY = "your_shodan_key"
ABUSEIPDB_KEY = "your_abuseipdb_key"

def enrich_ip(ip):
    result = {"ip": ip, "sources": {}}

    # VirusTotal
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        result["sources"]["virustotal"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country": data["data"]["attributes"].get("country"),
            "as_owner": data["data"]["attributes"].get("as_owner"),
        }
    except Exception as e:
        result["sources"]["virustotal"] = {"error": str(e)}

    # AbuseIPDB
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        data = r.json()["data"]
        result["sources"]["abuseipdb"] = {
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
        }
    except Exception as e:
        result["sources"]["abuseipdb"] = {"error": str(e)}

    # Shodan (host info)
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=10
        )
        data = r.json()
        result["sources"]["shodan"] = {
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
        }
    except Exception as e:
        result["sources"]["shodan"] = {"error": str(e)}

    return result

def calculate_score(enriched):
    """Calculate a composite threat score 0-100."""
    score = 0
    vt = enriched["sources"].get("virustotal", {})
    aip = enriched["sources"].get("abuseipdb", {})
    shodan = enriched["sources"].get("shodan", {})

    score += min(vt.get("malicious", 0) * 10, 40)         # up to 40 points
    score += min(aip.get("abuse_confidence", 0) * 0.4, 40) # up to 40 points
    score += min(len(shodan.get("vulns", [])) * 5, 20)    # up to 20 points

    return score

if __name__ == "__main__":
    iocs = ["185.220.101.23", "198.51.100.42"]   # replace with real IOCs
    for ip in iocs:
        data = enrich_ip(ip)
        score = calculate_score(data)
        print(f"\n=== {ip} (Score: {score}/100) ===")
        print(json.dumps(data["sources"], indent=2))
        time.sleep(1)   # rate limiting
```

---

## 4 — Writing a Threat Actor Profile

```
THREAT ACTOR PROFILE TEMPLATE

Actor Name: _____________________ (ATT&CK designation if available)
Alternative Names: ______________________________________________
Suspected Sponsoring Nation: ____________________________________
Active Since: ___________________________________________________
Primary Targets: ________________________________________________
Primary Motivation: Espionage / Financial / Disruption / Hacktivism

KNOWN CAMPAIGNS:
  1. ____________________________________________________________
     Dates: ___________  Victims: ________________________________
  2. ____________________________________________________________

INITIAL ACCESS TTPs (MITRE ATT&CK):
  Primary: T_______ — _________________________________________
  Secondary: T_______ — ________________________________________

PREFERRED MALWARE / TOOLING:
  Custom: _______________________________________________________
  COTS/Open source: ____________________________________________

PERSISTENCE MECHANISMS:
  T______ — ____________________________________________________

LATERAL MOVEMENT:
  T______ — ____________________________________________________

EXFILTRATION:
  T______ — ____________________________________________________

C2 INFRASTRUCTURE CHARACTERISTICS:
  Protocol: ____________________________________________________
  Domain/IP patterns: __________________________________________
  JA3/JA3S fingerprint (if known): _____________________________

DEFENSIVE RECOMMENDATIONS:
  1. ___________________________________________________________
  2. ___________________________________________________________
  3. ___________________________________________________________

REFERENCES:
  1. ___________________________________________________________
  2. ___________________________________________________________
```

**Exercise:** Complete this template for APT29 (Cozy Bear) using public
reporting from Mandiant, CrowdStrike, and MITRE ATT&CK.

---

## 5 — Feeding Intelligence to Detection

The output of a TI programme is only useful if it improves detection:

```python
# misp_to_siem.py — Export MISP IOCs to Elastic/Splunk format

from pymisp import PyMISP
import json

MISP_URL = "https://localhost"
MISP_KEY = "your_auth_key"

misp = PyMISP(MISP_URL, MISP_KEY, False)  # False = no SSL verify (lab only)

# Fetch all malicious IP indicators from last 30 days
results = misp.search(
    controller="attributes",
    type_attribute=["ip-dst", "ip-src"],
    tags=["misp-galaxy:threat-actor"],   # filter to attributed indicators
    timestamp="30d",
    to_ids=True                           # only IOCs meant for detection
)

# Format for Elastic watchlist
elastic_iocs = []
for attribute in results:
    if hasattr(attribute, "value"):
        elastic_iocs.append({
            "indicator": attribute.value,
            "type": attribute.type,
            "threat_level": attribute.to_ids,
            "source": "MISP",
            "tags": [t.name for t in attribute.tags] if attribute.tags else []
        })

print(json.dumps(elastic_iocs, indent=2))
# Push this to Elasticsearch:
# POST /threat-indicators/_bulk  (with appropriate mapping)
# Elastic Security uses these as reference lists for detection rules
```

---

## Key Takeaways

1. **TI is a programme, not a product.** A threat feed subscription delivers
   data. A TI programme turns data into decisions. The collection, processing,
   analysis, and dissemination steps all require human expertise — feeds are
   an input, not the output.
2. **IOC enrichment is the minimum viable TI workflow.** An IP address alone
   tells you nothing. An IP address + ASN + abuse history + VT detection count
   + open ports + known CVEs tells you whether this is a Tor exit node, a known
   C2, or a legitimate cloud provider. Automate enrichment for scale.
3. **Attribution is hard; TTP-level intelligence is durable.** Threat actor
   attributions change as new data emerges. The TTPs they use — spearphishing,
   ADCS abuse, DLL sideloading — persist across attribution changes and across
   years. Build detection on TTPs, not actor names.
4. **The gap between a TI programme and a detection engineering programme
   is one API call.** If your MISP exports to your SIEM, every new threat
   actor IOC automatically improves your detection coverage. The integration
   is the intelligence value multiplier.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q738.1, Q738.2 …).

---

## Navigation

← Previous: [Day 737 — Advanced Supply Chain Security](DAY-0737-Supply-Chain-Security-Advanced.md)
→ Next: [Day 739 — Research Automation at Scale](DAY-0739-Research-Automation-at-Scale.md)
