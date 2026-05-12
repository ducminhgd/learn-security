---
title: "Threat Intel Lab — MISP Setup, Event Creation, ATT&CK Galaxy, IOC Exchange"
tags: [threat-intelligence, misp, lab, ioc, stix, taxii, att&ck-galaxy, module-12-postghost]
module: 12-PostGhostLevel
day: 736
prerequisites:
  - Day 735 — Threat Intel Fundamentals
related_topics:
  - Day 737 — Advanced Detection Engineering
---

# Day 736 — Threat Intel Lab: MISP Platform Setup

> "MISP is the working environment of a threat intelligence analyst. Every IOC
> you collect, every campaign you track, every pivot chain you build — it all
> lives here. Learn to use it at the analyst level, not the admin level."
>
> — Ghost

---

## Goals

Deploy a local MISP instance using Docker. Create a complete threat intelligence
event from a real malware campaign. Map the campaign's techniques to the MITRE
ATT&CK galaxy. Export as STIX 2.1. Configure a TAXII feed connection.

**Prerequisites:** Day 735.
**Estimated study time:** 4 hours (lab-heavy).

---

## Lab Setup

### Required

```
Host requirements:
  4 CPU cores, 8 GB RAM minimum
  Docker + Docker Compose installed

Network:
  Isolated Docker network (no inbound from internet required)
  Outbound DNS and HTTPS for MISP module updates

MISP Docker image used:
  ghcr.io/misp/misp-docker
```

### MISP Docker Compose

```yaml
# docker-compose.yml
version: '3'
services:
  misp:
    image: ghcr.io/misp/misp-docker:latest
    ports:
      - "443:443"
      - "80:80"
    environment:
      MISP_ADMIN_EMAIL: "admin@lab.local"
      MISP_ADMIN_PASSPHRASE: "LabPassphrase2025!"
      MISP_BASEURL: "https://localhost"
      MYSQL_HOST: misp-db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "mispdbpass"
    depends_on:
      - misp-db
    volumes:
      - misp-data:/var/www/MISP/app/Config
      - misp-logs:/var/www/MISP/app/tmp/logs

  misp-db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: "rootpass"
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "mispdbpass"
    volumes:
      - mysql-data:/var/lib/mysql

volumes:
  misp-data:
  misp-logs:
  mysql-data:
```

```bash
# Start MISP
docker compose up -d

# Wait ~3 minutes for initialization
docker compose logs -f misp | grep "MISP is ready"

# Access at: https://localhost (accept self-signed cert)
# Default login: admin@admin.test / admin
# Change password immediately
```

---

## Lab Exercises

### Exercise 1 — Create a Threat Intelligence Event

Build an event for a fictional AsyncRAT campaign (based on the Day 637
analysis format).

```
MISP EVENT CREATION

1. Log in → Events → Add Event

Event fields:
  Distribution:   This Community Only (lab)
  Threat Level:   High
  Analysis:       Complete
  Event Info:     AsyncRAT Campaign - SEA Financial Sector - 2025-Q2

2. Add Attributes

Category: Payload delivery
  Type: sha256
  Value: [hash from your Day 637 analysis or generate a fake for lab]
  Comment: AsyncRAT dropper PE

Category: Network activity
  Type: ip-dst
  Value: 185.220.101.47
  Comment: AsyncRAT C2 server, TCP/6606

Category: Network activity
  Type: domain
  Value: update-check.site[.]biz
  Comment: AsyncRAT C2 domain (defang in MISP using [.] notation)

Category: Persistence mechanism
  Type: regkey|value
  Value: HKCU\Software\Microsoft\Windows\CurrentVersion\Run|WindowsUpdate
  Comment: AsyncRAT persistence registry key

Category: Payload type
  Type: filename
  Value: %APPDATA%\WindowsUpdate\WindowsUpdate.exe
  Comment: Dropped payload path

3. Add Tags
  tlp:amber          (Traffic Light Protocol — restricted sharing)
  misp-galaxy:threat-actor="APT Unknown - SEA"
  misp-galaxy:mitre-attack-pattern="Scheduled Task/Job - T1053"
  misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter: PowerShell - T1059.001"
  misp-galaxy:mitre-attack-pattern="Boot or Logon Autostart Execution: Registry Run Keys - T1547.001"
```

### Exercise 2 — MITRE ATT&CK Galaxy Mapping

```
GALAXY USAGE

Galaxies are MISP's structured knowledge bases.
ATT&CK Galaxy maps every cluster to a MITRE technique ID.

Navigate: Event → Add Tag → Search "mitre-attack-pattern"
Search for: "Ingress Tool Transfer"
Select: ATT&CK Enterprise T1105

Add all relevant ATT&CK tags to your event:
  T1566.001  Spearphishing Attachment (initial access)
  T1059.003  Windows Command Shell (execution)
  T1105      Ingress Tool Transfer (download cradle)
  T1547.001  Registry Run Keys (persistence)
  T1071.001  Web Protocols - C2 (C&C)
  T1041      Exfiltration Over C2 Channel

EXPORT ATT&CK layer:
  Event Actions → Download → MITRE ATT&CK
  This produces a Navigator JSON layer showing which techniques
  were used in this event.
  Import at: https://mitre-attack.github.io/attack-navigator/
```

### Exercise 3 — Correlations and Pivoting in MISP

```
AUTOMATIC CORRELATION

MISP auto-correlates attributes across events.
If IP 185.220.101.47 appears in two events, MISP links them.

Manual correlation:
  Add a second event: "Cobalt Strike Beacon - SEA 2024-Q4"
  Add same IP: 185.220.101.47

Navigate to Event 1 → Attributes
Click the correlation icon on the IP attribute
→ MISP shows Event 2 as a correlated event
→ This is the platform equivalent of your manual pivot chain from Day 735

PIVOT exercise:
  Create 3 events with overlapping infrastructure
  Use the event graph view (Event Actions → View Event Graph)
  → Visual map of correlated attributes across campaigns
```

### Exercise 4 — STIX 2.1 Export and TAXII

```
STIX EXPORT

From any event:
  Event Actions → Download as STIX 2.1
  Inspect the JSON output:
  {
    "type": "bundle",
    "id": "bundle--[UUID]",
    "objects": [
      { "type": "malware", "name": "AsyncRAT", ... },
      { "type": "indicator", "pattern": "[ipv4-addr:value = '185.220.101.47']", ... },
      { "type": "attack-pattern", "name": "Registry Run Keys", "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1547.001" }
      ]},
      ...
    ]
  }

TAXII SERVER

MISP includes a built-in TAXII server.
Administration → Server Settings → TAXII Server → Enable

TAXII Discovery endpoint: https://localhost/taxii/
Collections: one per MISP event tag/distribution level

Test with PyTAXII:
  pip install taxii2-client

  from taxii2client.v21 import Server
  server = Server(
      "https://localhost/taxii/",
      user="admin@admin.test",
      password="[your_password]",
      verify=False
  )
  api_root = server.api_roots[0]
  for collection in api_root.collections:
      print(collection.title, collection.id)
```

### Exercise 5 — Write a One-Page Threat Brief

Using your MISP event, write a one-page tactical intel brief:

```
THREAT BRIEF TEMPLATE

TITLE:  AsyncRAT Campaign Targeting Financial Sector — SEA Region
DATE:   [Today]
TLP:    AMBER

EXECUTIVE SUMMARY (3 sentences):
  [What happened, who is affected, what defenders should do]

TECHNICAL FINDINGS:
  Malware family:   AsyncRAT (open-source C# RAT)
  Delivery method:  Spearphishing attachment (T1566.001)
  Initial access:   Office document macro drops loader
  Persistence:      Registry Run Key (T1547.001)
  C2:               TCP/6606 to 185.220.101.47 (update-check.site[.])

IOC TABLE:
  Type          Indicator                          First Seen
  SHA256        [hash]                             [date]
  IP            185.220.101.47                     [date]
  Domain        update-check.site[.]biz            [date]
  Registry      HKCU\...\Run|WindowsUpdate         [date]

DETECTION RULES:
  YARA:  [rule name from Day 637]
  Sigma: [rule name from Day 689 format]

RECOMMENDED ACTIONS:
  1. Block C2 IP and domain at perimeter
  2. Hunt for registry key across all endpoints
  3. Add Sigma rule to SIEM — trigger SOC ticket on match
```

---

## Key Takeaways

1. **MISP's correlation engine turns individual IOCs into a connected
   intelligence graph.** A single shared infrastructure element can link
   otherwise disconnected campaigns and reveal actor patterns.
2. **The ATT&CK Galaxy tags transform raw indicators into structured TTPs.**
   This is what separates a data dump from actual intelligence.
3. **STIX export makes your intelligence machine-readable.** Other MISP
   instances, Splunk, OpenCTI, and EDR platforms can consume it directly.
4. **The one-page threat brief is the deliverable that reaches the right
   people.** The MISP database is for analysts; the brief is for everyone else.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q736.1, Q736.2 …).

---

## Navigation

← Previous: [Day 735 — Threat Intel Fundamentals](DAY-0735-Threat-Intel-Fundamentals.md)
→ Next: [Day 737 — Advanced Detection Engineering](DAY-0737-Advanced-Detection-Engineering.md)
