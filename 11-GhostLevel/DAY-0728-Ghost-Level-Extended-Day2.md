---
title: "Ghost Level Extended — Day 2: Purple Team Exercise"
tags: [ghost-level, purple-team, detection-engineering, sigma-rules,
  threat-hunting, module-11-ghost-level]
module: 11-GhostLevel
day: 728
prerequisites:
  - Day 727 — Ghost Level Extended Day 1
  - Day 508 — Purple Team Concepts
  - Day 509 — Atomic Red Team Lab
related_topics:
  - Day 729 — Ghost Level Extended Day 3: Report Polish and Oral Prep
  - Day 730 — Ghost Level Competency Gate
---

# Day 728 — Ghost Level Extended Day 2: Purple Team Exercise

> "The red team's job is to find what the blue team cannot see. The purple
> team's job is to fix that. Today you switch hats — not to stop thinking
> like an attacker, but to use your attacker knowledge to make the
> defence better. That is the highest-value skill a security professional
> can have."
>
> — Ghost

---

## Goals

1. For each Project SABLE finding, write a detection rule that would have
   caught the attack in a monitored environment.
2. Build a Sigma rule library for the Project SABLE kill chain.
3. Identify which findings would have been detected by a standard SOC
   versus which require custom detection logic.
4. Write a detection gap analysis section for the final report.

---

## Prerequisites

- Ghost Level engagement complete (Days 707–727).
- Days 508–509 (Purple Team concepts and Atomic Red Team).
- Elastic Stack or Graylog lab accessible (from Day B-01 coverage).

---

## 1 — The Detection Engineering Mindset

For every technique you executed during the SABLE engagement, ask:

```
DETECTION QUESTION FRAMEWORK

1. What logs does this technique produce?
   → Which log source? (Windows Event Log, Sysmon, auditd, Zeek, proxy)
   → Which specific Event ID / log field / network signature?

2. Does the log exist in a default environment?
   → Many logging sources (Sysmon, PowerShell script block) require
     explicit configuration to enable.

3. Is the log query uniquely associated with malicious behaviour?
   → If the query produces 1000 alerts per day in a normal enterprise,
     it is not a useful detection.
   → Good detections are high-precision (few false positives) and
     reasonable recall (catch the attack reliably).

4. What is the earliest detection point?
   → Can the attack be detected on the first malicious action (ideal)?
   → Or only after lateral movement is complete (too late)?
```

---

## 2 — Detection Coverage Matrix

Fill in the matrix for each Project SABLE finding:

```
SABLE DETECTION COVERAGE MATRIX

Finding | ATT&CK | Log Source Needed | Default Available | Sigma Rule Possible
--------+--------+-------------------+-------------------+--------------------
F-01    | T1078  | HTTP proxy logs,  | Y (if proxy       | Y — detect JWT
JWT     | .003   | Auth event logs   |  is in place)     |   alg=none
        |        |                   |                   |
F-02    | T1190  | Network IDS,      | Partial (Suricata)| Y — detect TLV
Stack   |        | Process creation  | N (Sysmon req.)   |   oversize payload
Overflow|        |                   |                   |
        |        |                   |                   |
F-03    | T1558  | Domain controller | Y — Event 4769    | Y — detect SPN
Kerberoast|.003  | Security log      |                   |   requests from
        |        |                   |                   |   non-service accts
        |        |                   |                   |
F-04    | T1649  | DC Security log,  | Partial (Event    | Y — detect Certipy
ADCS    |        | ADCS audit log    | 4886 req'd)       |   template abuse
        |        |                   |                   |
F-05    | T1059  | Web server logs   | Y                 | Y — detect OS
CGI     | .004   |                   |                   |   command chars in
Injection|       |                   |                   |   CGI parameters
        |        |                   |                   |
F-06    | T1039  | SMB audit log,    | Y (Event 5140)    | Y — detect null
SMB null|        | File access log   |                   |   session auth
```

---

## 3 — Sigma Rules for Project SABLE

Write a Sigma rule for each finding. At minimum, write rules for F-01
and F-03 (the two with the clearest log sources).

### Rule 1 — JWT Algorithm Confusion (F-01)

```yaml
title: Sable Finding F-01 — JWT Algorithm None Attack
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects an HTTP request containing a JWT token with algorithm set to
  'none', indicating an algorithm confusion attack attempt. A JWT with
  alg:none is always malicious in a properly configured system.
date: 2026-05-09
author: Ghost Student
references:
  - https://portswigger.net/web-security/jwt
logsource:
  category: proxy
  product: squid
detection:
  selection:
    # Base64-decoded JWT header containing "alg":"none"
    # In proxy logs, this appears as a base64 string in Authorization header
    c-uri-query|contains: 'eyJhbGciOiJub25lIn0'   # base64("{"alg":"none"}")
  condition: selection
falsepositives:
  - None — a JWT with alg=none is never legitimate
level: critical
tags:
  - attack.credential_access
  - attack.t1078.003
```

### Rule 2 — Kerberoasting Detection (F-03)

```yaml
title: Sable Finding F-03 — Kerberoasting via SPN Request
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: >
  Detects Kerberoasting — an attacker requesting Kerberos service tickets
  (TGS) for accounts with SPNs. Identifies requests for RC4-encrypted
  tickets (etype 23) from non-service accounts, which indicate offline
  cracking attempts.
date: 2026-05-09
author: Ghost Student
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769                   # Kerberos Service Ticket Operations
    TicketOptions: '0x40810000'     # Forwardable, renewable, canonicalize
    TicketEncryptionType: '0x17'    # RC4-HMAC — attackers request this for cracking
  filter_service_accounts:
    # Legitimate service-to-service Kerberos will use AES (0x12 or 0x11)
    TicketEncryptionType|in:
      - '0x11'   # AES128
      - '0x12'   # AES256
  condition: selection and not filter_service_accounts
falsepositives:
  - Older systems configured for RC4 only (inventory and exclude by host)
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

### Rule 3 — ADCS Certificate Request Anomaly (F-04)

```yaml
title: Sable Finding F-04 — Suspicious ADCS Certificate Request
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
  Detects a certificate request to an ADCS template that includes a
  Subject Alternative Name (SAN) field specifying a different identity
  than the requesting account — characteristic of ESC1 exploitation.
date: 2026-05-09
author: Ghost Student
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4886             # Certificate Services received a certificate request
    CertificateTemplateName: 'SableUser'
  san_injection:
    RequestAttributes|contains: 'SAN:'   # SAN in request attributes
  condition: selection and san_injection
falsepositives:
  - Intentional SAN-enabled certificate issuance by PKI administrators
level: critical
tags:
  - attack.credential_access
  - attack.t1649
```

---

## 4 — Threat Hunt Queries

Write three threat hunting queries that would allow a SOC analyst to
retroactively detect the Project SABLE attack in log data:

### Hunt Query 1 — Golden Ticket Anomaly (KQL / Elastic)

```kql
# Hunt for logon events from service accounts using Kerberos tickets
# with abnormally long ticket lifetimes (Golden Ticket = 10 years default)

event.code: "4624"
AND winlog.event_data.AuthenticationPackageName: "Kerberos"
AND winlog.event_data.TargetUserName: "Administrator"
AND winlog.event_data.LogonType: "3"
AND NOT source.ip: "10.10.10.0/24"   # exclude known admin subnets
```

### Hunt Query 2 — SMB Null Session (Sigma → ElastAlert)

```yaml
# Detect SMB null session authentication attempts
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625           # Logon Failure
    AuthPackage: 'NTLM'
    SubStatus: '0xc000006d' # Unknown username or bad password
    TargetUserName: 'ANONYMOUS LOGON'
  condition: selection
```

### Hunt Query 3 — CGI Command Injection Pattern (Zeek / Suricata)

```bash
# Suricata rule for CGI parameter containing shell metacharacters
alert http any any -> $HOME_NET any (
    msg:"Sable F-05 — CGI command injection attempt";
    flow:to_server,established;
    http.uri;
    content:"/cgi-bin/";
    pcre:"/[;&|`\$\(\)\{\}]/";
    classtype:web-application-attack;
    sid:9000001;
    rev:1;
)
```

---

## 5 — Detection Gap Analysis (Report Addendum)

Write the detection gap analysis section to add to your Phase 6 report:

```
DETECTION GAP ANALYSIS — PROJECT SABLE

This section documents which of the identified findings would be detected
by a standard enterprise SOC versus which require additional tooling,
configuration, or custom detection logic.

CURRENTLY DETECTABLE (with standard Windows audit logging):
  F-03 (Kerberoasting): Event ID 4769 is logged by default. An analyst
  who filtered for RC4 ticket requests from non-service-account principals
  would have identified the attack within minutes of execution.

DETECTABLE WITH CONFIGURATION CHANGES (no additional tooling):
  F-04 (ADCS ESC1): Event ID 4886 requires enabling ADCS auditing
  (not enabled by default). Once enabled, SAN injection requests produce
  a logged event that is immediately detectable with the rule above.
  Estimated configuration time: 15 minutes.

REQUIRES ADDITIONAL TOOLING:
  F-01 (JWT algorithm confusion): No Windows event covers HTTP traffic.
  A web application firewall (WAF) or HTTP proxy with deep header
  inspection is required. Estimated deployment cost: moderate.

  F-02 (Stack overflow): Requires a network IDS (Suricata) with a rule
  covering TLV message sizes, or an EDR with memory protection. A
  standard SIEM without network metadata would not detect this attack.

BLIND SPOTS IN CURRENT ENVIRONMENT:
  F-05 (CGI injection on sable-iot): IoT devices are not domain-joined
  and generate no Windows Event Log data. No Sysmon. No EDR. Detection
  requires network-level monitoring (Zeek/Suricata) on the IoT network
  segment, which was absent during the engagement.

REMEDIATION PRIORITY:
  1. Enable ADCS audit logging immediately (F-04 — 15-minute fix)
  2. Deploy Suricata on internal network segments (F-02, F-05)
  3. Add proxy/WAF with JWT inspection (F-01)
  4. Review SIEM rules for Kerberoasting (F-03 — rule provided above)
```

---

## Key Takeaways

1. **Every attack leaves a detectable trace — the question is whether anyone
   is watching the right log.** The Project SABLE engagement shows that F-03
   (Kerberoasting) was fully detectable with built-in logging. The attacker
   succeeded not because detection is impossible, but because no one was
   watching Event ID 4769.
2. **Purple team exercises create asymmetric value.** For every hour you spend
   writing a detection rule, you potentially prevent a multi-week breach. The
   ROI on detection engineering is an order of magnitude higher than the ROI
   on most offensive techniques.
3. **Detection gaps at the tool level are worse than detection gaps at the
   rule level.** A missing Sigma rule can be written in 30 minutes. A missing
   logging infrastructure (no ADCS audit, no proxy, no EDR on IoT) takes
   months to deploy. Identifying tooling gaps is the highest-impact output
   of a purple team exercise.
4. **The debrief → purple team → report cycle is the deliverable.** A
   penetration test report that contains detection rules and a gap analysis
   is worth five times more to a client than one that contains only findings.
   The client already knows they were compromised. What they need is a
   roadmap to not be compromised next time.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q728.1, Q728.2 …).

---

## Navigation

← Previous: [Day 727 — Ghost Level Extended Day 1](DAY-0727-Ghost-Level-Extended-Day1.md)
→ Next: [Day 729 — Ghost Level Extended Day 3: Report Polish and Oral Prep](DAY-0729-Ghost-Level-Extended-Day3.md)
