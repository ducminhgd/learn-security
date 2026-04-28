---
title: "Auth Attack Detection — Failed Login Patterns, Token Anomalies, Sigma Rules"
tags: [detection, auth-attacks, Sigma-rules, failed-login, token-anomaly, SIEM,
       Kerberoasting-detection, JWT-anomaly, OAuth-detection, ATT&CK, threat-hunting]
module: 04-BroadSurface-01
day: 176
related_topics:
  - Credential Stuffing and Spraying (Day 166)
  - JWT Advanced Attacks (Day 169)
  - OAuth Abuse Deep Dive (Day 171)
  - SAML Attacks (Day 173)
  - Kerberoasting and PtH Intro (Day 175)
  - Auth Hardening (Day 177)
---

# Day 176 — Auth Attack Detection

> "The attacker sprayed 5,000 accounts at one attempt per account over 45
> minutes. Your rate limiter never fired because each account saw less than
> the threshold. The detection would have caught it — if you had written
> the rule. The rule looks for low-and-slow broad coverage. That is a
> different signature from brute force. Know the difference. Write both."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Identify the log sources required to detect each authentication attack
   class covered in Days 166–175.
2. Write Sigma rules for: credential stuffing, password spray, JWT anomalies,
   OAuth misuse, and Kerberoasting.
3. Describe what a baseline looks like for normal authentication behaviour
   and how to spot deviations.
4. Map each detection to a MITRE ATT&CK technique.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All auth attack classes | Days 166–175 |
| Sigma rule format | Day 142 (Advanced Web Detection) |
| SIEM/log aggregation concepts | Day 157 (API Detection) |

---

## Detection Architecture

**Required log sources for auth attack detection:**

| Log source | Data points | Attack classes detected |
|---|---|---|
| Web server access logs | Source IP, timestamp, URL, status code | Stuffing, spray, BOLA, mass assignment |
| Application auth logs | Username, source IP, success/fail, timestamp | Stuffing, spray, account lockout patterns |
| JWT decode logs | `sub`, `role`, `kid`, `alg`, IP, timestamp | JWT forgery, alg confusion, kid traversal |
| OAuth audit logs | `client_id`, `redirect_uri`, `grant_type`, IP | Code theft, PKCE bypass, implicit flow |
| SAML assertion logs | `NameID`, `AssertionID`, IdP, timestamp, SP | XSW, replay, comment injection |
| Windows Event Logs | Event ID 4769 (TGS request) | Kerberoasting |
| Windows Event Logs | Event ID 4776 (NTLM auth) | Pass-the-Hash |
| Windows Event Logs | Event ID 4624 (Logon success) | Lateral movement, PtH |

---

## Part 1 — Credential Stuffing Detection

### 1.1 — High-Volume Per-IP Detection

```yaml
title: Credential Stuffing — High-Volume Failed Logins from Single IP
id: cs-001
status: experimental
description: High number of failed authentication attempts from a single
  IP address targeting multiple different usernames, indicating credential
  stuffing.
logsource:
  category: webserver
detection:
  selection:
    http_status_code:
      - 401
      - 403
    request_uri|endswith:
      - /login
      - /auth/login
      - /api/v1/auth/login
  timeframe: 1m
  condition: selection | count(distinct cs-username) by src_ip > 20
falsepositives:
  - Corporate NAT IP with many users behind it
level: high
tags:
  - attack.t1110.004
```

### 1.2 — Distributed Stuffing Detection

Standard stuffing detection misses distributed campaigns. This rule looks for
a spike in 401s across the whole endpoint regardless of source IP:

```yaml
title: Credential Stuffing — Distributed Campaign (Volume Spike)
id: cs-002
status: experimental
description: Overall spike in authentication failures across many source
  IPs, with failure rate significantly above baseline, indicating distributed
  credential stuffing.
logsource:
  category: webserver
detection:
  selection:
    http_status_code: 401
    request_uri|endswith: /login
  timeframe: 5m
  condition: selection | count() > 500
    and selection | count(distinct src_ip) > 50
falsepositives:
  - Legitimate high-traffic periods (flash sales, announcements)
level: high
tags:
  - attack.t1110.004
```

---

## Part 2 — Password Spray Detection

Password spray has a different signature: low failures per account, broad
coverage. Standard brute-force rules miss it.

```yaml
title: Password Spray — Low-Frequency Multi-Account Failure Pattern
id: spray-001
status: experimental
description: Detects password spray: many different accounts each seeing
  a small number of failed logins. Pattern is distinct from stuffing
  (which targets fewer accounts with more attempts each) and brute force
  (which targets one account heavily).
logsource:
  category: application
  service: auth
detection:
  failed_login:
    eventType: login_failed
  condition:
    - count(distinct username) by src_ip in 30m > 50
    - max(count(username)) by src_ip in 30m < 5
  # More than 50 different accounts, but fewer than 5 attempts per account
falsepositives:
  - Automated integration tests spanning many accounts
level: high
tags:
  - attack.t1110.003
```

### 2.1 — Active Directory Spray Detection

For AD environments, Windows Security Event Log ID 4625:

```yaml
title: AD Password Spray — Event ID 4625 Multi-Account Pattern
id: spray-ad-001
logsource:
  product: windows
  service: security
  definition: Requires Windows Security auditing enabled
detection:
  selection:
    EventID: 4625
    LogonType: 3        # Network logon
    SubStatus: "0xC000006A"   # Wrong password
  timeframe: 30m
  condition: selection | count(distinct TargetUserName) by IpAddress > 50
    and selection | count() by TargetUserName < 5
falsepositives:
  - Password migration tools
level: high
tags:
  - attack.t1110.003
```

---

## Part 3 — JWT Attack Detection

### 3.1 — Algorithm:none in JWT Header

```yaml
title: JWT Algorithm None — Unsigned Token Accepted or Attempted
id: jwt-001
logsource:
  category: application
  service: auth
detection:
  selection:
    eventType: jwt_validation
    jwt_algorithm: none
  condition: selection
falsepositives:
  - Internal service tokens in development (should not appear in production)
level: critical
tags:
  - attack.t1550
```

### 3.2 — kid Path Traversal Attempt

```yaml
title: JWT kid Parameter — Path Traversal Attempt
id: jwt-002
logsource:
  category: application
  service: auth
detection:
  selection:
    eventType:
      - jwt_validation
      - jwt_error
    jwt_kid|contains:
      - ".."
      - "/"
      - "etc"
      - "dev/null"
      - "proc"
  condition: selection
falsepositives:
  - None expected in production
level: critical
tags:
  - attack.t1550
```

### 3.3 — Algorithm Confusion (RS256 → HS256)

```yaml
title: JWT Algorithm Confusion — RS256 to HS256 Switch
id: jwt-003
logsource:
  category: application
  service: auth
detection:
  selection:
    eventType: jwt_validation_failed
    jwt_algorithm: HS256
    expected_algorithm: RS256
  condition: selection
falsepositives:
  - Misconfigured client libraries during migration
level: high
tags:
  - attack.t1550
```

---

## Part 4 — OAuth Attack Detection

### 4.1 — Unusual redirect_uri

```yaml
title: OAuth — Suspicious redirect_uri in Authorization Request
id: oauth-001
logsource:
  category: application
  service: oauth
detection:
  selection:
    eventType: oauth_authorize
  filter_registered:
    redirect_uri|startswith:
      - "https://app.target.com"
      - "https://mobile.target.com"
  condition: selection and not filter_registered
falsepositives:
  - New client registrations during development
level: high
tags:
  - attack.t1550
```

### 4.2 — Missing PKCE in Public Client Flow

```yaml
title: OAuth — Authorization Code Flow Without PKCE (Public Client)
id: oauth-002
logsource:
  category: application
  service: oauth
detection:
  selection:
    eventType: oauth_authorize
    response_type: code
    client_type: public
  filter_pkce:
    code_challenge|exists: true
  condition: selection and not filter_pkce
falsepositives:
  - Legacy mobile app versions before PKCE was added
level: medium
tags:
  - attack.t1550
```

---

## Part 5 — SAML Attack Detection

### 5.1 — SAML Replay (Duplicate AssertionID)

```yaml
title: SAML Replay — Duplicate Assertion ID
id: saml-001
logsource:
  category: application
  service: saml
detection:
  selection:
    eventType: saml_sso_success
  condition: selection | count() by assertion_id > 1 in 60m
falsepositives:
  - None expected — assertion IDs must be unique
level: critical
tags:
  - attack.t1550
```

### 5.2 — SAML XSW — Multiple Assertion Elements

```yaml
title: SAML XSW — Multiple Assertion Elements in Response
id: saml-002
logsource:
  category: application
  service: saml
detection:
  selection:
    eventType: saml_parse
    assertion_count|gte: 2
  condition: selection
falsepositives:
  - Chained SSO flows with multiple embedded assertions (rare)
level: critical
tags:
  - attack.t1550
```

---

## Part 6 — Kerberoasting Detection

Kerberoasting is detectable via Windows Security Event Log. The attack
generates a large number of TGS-REQ requests for RC4-encrypted service tickets.

```yaml
title: Kerberoasting — High Volume TGS Requests for RC4 Service Tickets
id: kerb-001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: "0x17"   # RC4-HMAC — older, more crackable
    TicketOptions: "0x40810000"    # Standard service ticket options
  filter_computer:
    AccountName|endswith: "$"   # Filter out computer account requests
  timeframe: 5m
  condition: selection and not filter_computer | count() by AccountName > 5
falsepositives:
  - Legacy applications that request many RC4 tickets
level: high
tags:
  - attack.t1558.003
```

### 6.1 — Improved: Single Account Requesting Multiple Service Tickets

The more targeted signature — one account requesting TGS tickets for many
different SPNs in a short window:

```yaml
title: Kerberoasting — Single Account Requests TGS for Many SPNs
id: kerb-002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: "0x17"
  timeframe: 10m
  condition: selection | count(distinct ServiceName) by AccountName > 10
falsepositives:
  - Service desk accounts that manage many services
level: high
tags:
  - attack.t1558.003
```

---

## Part 7 — Pass-the-Hash Detection

PtH is harder to detect because the NTLM authentication looks identical to a
legitimate NTLM login. Look for the combination of:
- Successful network logon (Event 4624, LogonType 3)
- With no corresponding interactive logon (Event 4624, LogonType 2)
- From an unexpected source machine

```yaml
title: Pass-the-Hash Indicator — Network Logon Without Interactive Logon
id: pth-001
logsource:
  product: windows
  service: security
detection:
  network_logon:
    EventID: 4624
    LogonType: 3       # Network logon
    AuthenticationPackageName: NTLM
  no_interactive:
    # No Event ID 4624 LogonType 2 from same source in the last 24h
  condition: network_logon
    and not (count by WorkstationName in 24h where LogonType=2 > 0)
  filter_service_accounts:
    AccountName|endswith: "$"
falsepositives:
  - Legitimate remote admin tools, backup agents
level: medium
tags:
  - attack.t1550.002
```

---

## Part 8 — Baselines and Anomaly Detection

Rule-based detection catches known patterns. Anomaly detection catches unknown
patterns by establishing a baseline of normal behaviour.

**Key baselines to establish for auth:**

| Metric | Normal range | Alert when |
|---|---|---|
| Failed logins per user per hour | 0–3 | > 10 |
| Logins per user per day | 1–5 | > 20 (unusual) |
| Unique source IPs per user per day | 1–2 | > 5 (geo jump) |
| Successful logins outside business hours | Low | Spike (investigate) |
| Time between last session and new login | Hours to days | <5 minutes from different continent |
| Service ticket requests (Kerberos) | 10–50/day for service accounts | >200/10 min |

**Impossible travel detection:**

```python
from geopy.distance import geodesic
from datetime import datetime

def check_impossible_travel(user: str, prev_login: dict, new_login: dict) -> bool:
    """Return True if the travel speed between logins is physically impossible."""
    lat1, lon1 = prev_login["lat"], prev_login["lon"]
    lat2, lon2 = new_login["lat"], new_login["lon"]
    distance_km = geodesic((lat1, lon1), (lat2, lon2)).km

    elapsed_hours = (
        new_login["timestamp"] - prev_login["timestamp"]
    ).total_seconds() / 3600

    if elapsed_hours < 0.1:
        elapsed_hours = 0.1   # Avoid division by zero

    speed_kmh = distance_km / elapsed_hours
    MAX_REALISTIC_SPEED = 900   # Commercial jet speed

    if speed_kmh > MAX_REALISTIC_SPEED and distance_km > 200:
        print(f"[ALERT] Impossible travel for {user}: {distance_km:.0f} km "
              f"in {elapsed_hours:.1f}h → {speed_kmh:.0f} km/h")
        return True
    return False
```

---

## Key Takeaways

1. **Credential stuffing and password spray have different signatures.** Write
   two separate rules. Stuffing = high volume per IP. Spray = low volume per
   account across many accounts.
2. **JWT attacks leave traces in validation logs** — only if you log JWT header
   fields (`alg`, `kid`, `jku`). Add those fields to your auth logs.
3. **Kerberoasting is detectable via Event ID 4769 + RC4.** Enforcing AES-only
   Kerberos tickets eliminates both the attack and the need for this specific
   detection.
4. **SAML replay is a zero-false-positive alert** — duplicate assertion IDs
   should never appear in legitimate flows. Alert with high confidence.
5. **Detection without baselines produces alert fatigue.** Tune your rules
   against 30 days of historical data before deploying to production alerting.

---

## Exercises

1. Write a Sigma rule for host header injection on a password reset endpoint.
   What field would you log? What value would trigger the alert?
2. In an ELK or Splunk lab, ingest simulated auth logs from the Day 168
   credential lab. Run the spray detection query. Does it fire? Tune the
   threshold.
3. Research: Windows Event ID 4771 (Kerberos pre-authentication failure).
   Write a Sigma rule for AS-REP Roasting detection using this event ID.
4. Design a detection strategy for OAuth PKCE downgrade. What logs does the
   authorisation server need to emit? Write a Sigma rule or SPL query.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q176.1, Q176.2 …).
> Follow-up questions use hierarchical numbering (Q176.1.1, Q176.1.2 …).

---

## Navigation

← Previous: [Day 175 — Kerberoasting and Pass-the-Hash Intro](DAY-0175-Kerberoasting-and-Pass-the-Hash-Intro.md)
→ Next: [Day 177 — Auth Hardening](DAY-0177-Auth-Hardening.md)
