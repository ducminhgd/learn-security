---
title: "Ghost Level Lab Briefing — Project SABLE: Target Network and Rules of Engagement"
tags: [ghost-level, engagement, lab, recon, attack-surface, module-11-ghost-level]
module: 11-GhostLevel
day: 707
prerequisites:
  - Day 706 — Ghost Level Preparation
related_topics:
  - Day 708 — Phase 1: Initial Recon
  - Day 729 — Ghost Level Debrief
---

# Day 707 — Ghost Level Lab Briefing: Project SABLE

> "The clock starts now. Read the briefing. Study the network. Build your
> attack plan. Then execute it."
>
> — Ghost

---

> **48-HOUR CLOCK STARTS: ___:___ on ___/___/______**
> **REPORT DUE: ___:___ on ___/___/______**

---

## Engagement Briefing

```
╔══════════════════════════════════════════════════════════════════════╗
║          GHOST LEVEL ENGAGEMENT — PROJECT SABLE                      ║
║          RULES OF ENGAGEMENT AND TARGET BRIEFING                     ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ENGAGEMENT TYPE:  Full-scope penetration test (lab environment)     ║
║  SCOPE:            The SABLE lab network — 10.0.1.0/24               ║
║  OUT OF SCOPE:     Any IP outside 10.0.1.0/24                        ║
║  ATTACKER POSITION: External (you start from 10.0.2.x/attacker box)  ║
║                                                                      ║
║  OBJECTIVE:                                                          ║
║    1. Identify all vulnerabilities across all in-scope targets       ║
║    2. Exploit at least one vulnerability per service tier            ║
║    3. Document all findings at advisory quality                      ║
║    4. Produce a professional penetration test report                 ║
║                                                                      ║
║  RULES:                                                              ║
║    ✓ All techniques permitted within scope                           ║
║    ✓ Destructive testing (rm -rf, wipe, etc.) PROHIBITED             ║
║    ✓ Restart any crashed service if able; note the crash             ║
║    ✓ Document every action with timestamps                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Target Network Architecture

```
SABLE LAB NETWORK — 10.0.1.0/24

                         ┌──────────────────────┐
                         │   Attacker Machine   │
                         │   10.0.2.10          │
                         │   (Kali / ParrotOS)  │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Lab Gateway / FW   │
                         │   10.0.1.1           │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
   ┌──────────▼──────┐   ┌──────────▼──────┐   ┌──────────▼──────┐
   │  sable-web      │   │  sable-svc      │   │  sable-dc       │
   │  10.0.1.10      │   │  10.0.1.20      │   │  10.0.1.30      │
   │  Web Application│   │  Network Service│   │  Windows DC     │
   │  Ports: 80, 443 │   │  Port: 9000     │   │  Ports: 53,88,  │
   │  8080, 8443     │   │  Custom binary  │   │  135,389,445,   │
   └─────────────────┘   └─────────────────┘   │  636,3268       │
                                                └─────────────────┘
              ┌─────────────────────┬─────────────────────┐
              │                     │
   ┌──────────▼──────┐   ┌──────────▼──────┐
   │  sable-iot      │   │  sable-store    │
   │  10.0.1.40      │   │  10.0.1.50      │
   │  IoT Device     │   │  File Server    │
   │  Port: 80       │   │  Ports: 21,     │
   │  UART on device │   │  445, 2049      │
   └─────────────────┘   └─────────────────┘
```

---

## Target Service Inventory (Pre-Briefed)

### `sable-web` — 10.0.1.10

```
SERVICE: Web Application — "SABLE Analytics Portal"
Technology stack: Node.js + Express + PostgreSQL
Exposed ports: 80 (HTTP redirect), 443 (HTTPS), 8080 (dev)

Description:
  An internal analytics dashboard used by SABLE Corp employees.
  Features: user login, report generation, API endpoints for
  dashboard data, an admin console at /admin.

Known to the team (from pre-engagement OSINT):
  - Runs a custom JWT implementation (not a standard library)
  - The /api/v1/ endpoints are used by a mobile app
  - An older version of the app had an SSRF in the report generator
  - No WAF present
```

### `sable-svc` — 10.0.1.20

```
SERVICE: Custom Network Daemon — "SABLE Data Broker"
Language: C (binary only — no source provided)
Exposed port: 9000/TCP

Description:
  A proprietary data broker service that accepts binary protocol
  requests and returns structured data. Used by internal tools.

Known to the team:
  - The binary is 32-bit x86 ELF
  - It was written 5 years ago and has not been audited
  - The protocol uses a simple TLV (Type-Length-Value) framing
  - There are 4 operation codes: 0x01 (ping), 0x02 (get), 0x03 (put), 0x04 (admin)
```

### `sable-dc` — 10.0.1.30

```
SERVICE: Windows Server 2019 — Active Directory Domain Controller
Domain: SABLE.LOCAL
Exposed ports: Standard AD ports (53, 88, 135, 389, 445, 636, 3268, 3269)

Description:
  The primary domain controller for the SABLE Corp internal domain.
  Contains all user accounts and service accounts.

Known to the team:
  - Domain: SABLE.LOCAL
  - Known user: sarah.jones@sable.local (from OSINT — LinkedIn)
  - Service accounts exist (IT told us there are 3 SPNs configured)
  - The domain functional level is Windows Server 2016
```

### `sable-iot` — 10.0.1.40

```
SERVICE: IoT Network Monitoring Device
Hardware: ARM-based embedded Linux device
Exposed port: 80 (HTTP admin panel)

Description:
  A network monitoring sensor used by the SABLE Corp SOC team.
  The device has a web admin panel and also exposes a UART
  console (physically accessible in the lab).

Known to the team:
  - Admin panel at http://10.0.1.40/
  - Firmware version is 2.1.4 (last updated 2021)
  - UART accessible on GPIO header (baud 115200)
```

### `sable-store` — 10.0.1.50

```
SERVICE: File Server
Exposed ports: 21 (FTP), 445 (SMB), 2049 (NFS)

Description:
  Internal file storage used by the SABLE Corp team.
  Contains project files, backups, and config archives.
  Only accessible from within the SABLE network (not directly
  from 10.0.2.x — requires pivoting through a compromised host).

Note: This target is NOT directly reachable from your attacker box.
  You must obtain a foothold on the SABLE network first.
```

---

## Engagement Planning Sheet

Complete this before running the first scan.

```
ATTACK PLAN — fill in before hour 1

Priority order for Phase 2 (justify each):
  1st: _________________________ because: _____________________
  2nd: _________________________ because: _____________________
  3rd: _________________________ because: _____________________
  4th: _________________________ because: _____________________

Hypotheses to test in first 6 hours:
  H1: ___________________________________________________________
  H2: ___________________________________________________________
  H3: ___________________________________________________________

Highest-value target (initial assessment): _____________________
  Reason: _______________________________________________________

Phase time allocation (adjust to your assessment):
  Phase 1 (recon):          ____ hours (rec: 3)
  Phase 2 (exploitation):   ____ hours (rec: 15)
  Phase 3 (deep exploit):   ____ hours (rec: 12)
  Phase 4 (post-exploit):   ____ hours (rec: 10)
  Phase 5 (reporting):      ____ hours (rec: 8)
  Total:                    48 hours

Note file started: Y / N   Location: ____________________________
Screenshot tool ready: Y / N
Credential log (creds.txt) created: Y / N
```

---

## Engagement Tracking Board

Keep this updated throughout the engagement:

```
ENGAGEMENT STATUS BOARD (update every 4 hours)

TARGET          STATUS           FINDINGS
────────────────────────────────────────────────────────────
sable-web       [ ] Not started
                [ ] Enumeration
                [ ] Exploitation
                [ ] Completed     Finding(s): _______________

sable-svc       [ ] Not started
                [ ] Enumeration
                [ ] Exploitation
                [ ] Completed     Finding(s): _______________

sable-dc        [ ] Not started
                [ ] Enumeration
                [ ] Exploitation
                [ ] Completed     Finding(s): _______________

sable-iot       [ ] Not started
                [ ] Enumeration
                [ ] Exploitation
                [ ] Completed     Finding(s): _______________

sable-store     [ ] Not started    (requires pivot)
                [ ] Accessible
                [ ] Exploitation
                [ ] Completed     Finding(s): _______________

────────────────────────────────────────────────────────────
OVERALL PROGRESS
  Targets with at least 1 finding: ____/5
  Confirmed PoC exploits: ____
  Time elapsed: ____ hours / 48
  Time remaining: ____ hours
```

---

## Navigation

← Previous: [Day 706 — Ghost Level Preparation](DAY-0706-Ghost-Level-Preparation.md)
→ Next: [Day 708 — Phase 1: Initial Recon and Attack Surface Mapping](DAY-0708-Phase1-Initial-Recon.md)
