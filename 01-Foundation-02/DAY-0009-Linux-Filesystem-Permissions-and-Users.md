---
title: "Linux Filesystem Hierarchy, Permissions and Users"
tags: [foundation, linux, filesystem, permissions, users, groups, setuid, setgid,
       passwd, shadow, attacker-mindset, privilege-escalation]
module: 01-Foundation-02
day: 9
related_topics:
  - Linux Privilege Escalation (Day 234)
  - SUID/SGID exploitation (Day 235)
  - Linux forensic artefacts (Day 016)
  - Initial enumeration after landing on a host
---

# Day 009 — Linux Filesystem Hierarchy, Permissions and Users

## Goals

By the end of this lesson you will be able to:

1. Navigate the Linux Filesystem Hierarchy Standard (FHS) and know where secrets live.
2. Read and interpret any `ls -la` output — permissions, ownership, special bits.
3. Explain setuid, setgid, and sticky bit — what each does and why each matters to attackers.
4. Locate all user and group information: `/etc/passwd`, `/etc/shadow`, `/etc/group`.
5. Explain how Linux password hashing works and what format `shadow` hashes are in.
6. Find files by permission type using `find` — a core enumeration skill.
7. Explain when a user's effective UID differs from their real UID and why that matters.

---

## Prerequisites

- [Day 008 — ARP, Routing, NAT and Network Check](../01-Foundation-01/DAY-0008-ARP-Routing-NAT-and-Network-Check.md)
  (or equivalent: basic TCP/IP knowledge)
- You should be comfortable with a command line: `cd`, `ls`, `cat`, `grep`, pipes.

---

## Main Content — Part 1: Linux Filesystem Hierarchy Standard

### 1. The FHS — Where Everything Lives

The Filesystem Hierarchy Standard defines the directory layout of a Linux system.
As an attacker, this is your treasure map — you need to know where credentials, configs,
keys, and interesting files live before you can find them.

```
/                       Root directory — everything hangs from here
├── /bin  → /usr/bin    Essential user binaries (ls, cat, grep, bash)
├── /sbin → /usr/sbin   System administration binaries (iptables, mount, fdisk)
├── /lib  → /usr/lib    Shared libraries for binaries
├── /etc                System-wide configuration files ← HIGH PRIORITY for attackers
├── /home               User home directories (/home/alice, /home/bob)
├── /root               Root user's home directory
├── /var                Variable data (logs, spools, caches)
│   ├── /var/log        Log files (auth.log, syslog, apache2/, nginx/) ← READ THIS
│   ├── /var/mail       Mailboxes
│   ├── /var/www        Web server document root (apache/nginx default)
│   └── /var/tmp        Persistent temporary files (unlike /tmp, survives reboot)
├── /tmp                Temporary files (world-writable, does not survive reboot)
├── /proc               Virtual filesystem — information about running processes
│   ├── /proc/[pid]/    Per-process directory
│   │   ├── cmdline     The command line that started this process
│   │   ├── environ     Environment variables (may contain secrets!)
│   │   ├── maps        Memory map
│   │   └── fd/         Open file descriptors
│   ├── /proc/net/      Network state (TCP connections, ARP table)
│   └── /proc/self/     Symlink to the current process's directory
├── /sys                Virtual filesystem — kernel and hardware info
├── /dev                Device files (disk, tty, random, null, etc.)
├── /mnt                Manual mount points (external drives)
├── /media              Automounted removable media
├── /opt                Optional third-party software
├── /srv                Data for services (FTP, HTTP)
└── /usr                Secondary hierarchy (most binaries, libraries, docs)
    ├── /usr/bin        User binaries
    ├── /usr/share      Architecture-independent data
    └── /usr/local      Locally installed software (not managed by package manager)
```

**High-priority targets for attackers (memorise these):**

| Path | What to look for |
|---|---|
| `/etc/passwd` | User list, shells, UIDs |
| `/etc/shadow` | Hashed passwords (need root to read) |
| `/etc/sudoers` | Who can run what as root |
| `/etc/crontab`, `/etc/cron.*` | Scheduled tasks — potential for injection |
| `/home/*/.ssh/` | SSH private keys (`id_rsa`, `id_ed25519`) |
| `/home/*/.bash_history` | Command history — may contain credentials |
| `/root/.bash_history` | Root's command history |
| `/var/log/auth.log` | Authentication events (SSH, sudo) |
| `/tmp/` and `/var/tmp/` | World-writable — drop tools here |
| `/proc/[pid]/environ` | Environment variables of running processes |
| `/etc/hosts` | Internal hostname mappings |
| `/etc/resolv.conf` | DNS servers — reveals internal resolver |

---

### 2. The /proc Filesystem

`/proc` is a virtual filesystem created by the kernel. It does not exist on disk — it is
generated on-the-fly. It is an attacker's goldmine for host enumeration.

```bash
# Running processes
ls /proc/ | grep -E '^[0-9]+$'   # All PIDs

# What started a specific process
cat /proc/1234/cmdline | tr '\0' ' '

# Environment variables of a process (might contain passwords, API keys)
cat /proc/1234/environ | tr '\0' '\n'

# All environment variables of all processes you can read
for pid in /proc/[0-9]*/environ; do
  echo "=== PID $(basename $(dirname $pid)) ==="
  strings "$pid" 2>/dev/null | grep -iE "pass|key|secret|token|api"
done

# Current active TCP connections (equivalent to netstat -antp)
cat /proc/net/tcp
# Format: local_address remote_address state ... (hex encoded)

# ARP table
cat /proc/net/arp
```

---

## Main Content — Part 2: File Permissions

### 3. Permission Bits

Every Linux file has an owner (user), group, and a set of permission bits:

```
-rwxr-xr--  1  alice  developers  4096  Jan 1 10:00  script.sh
▲▲▲▲▲▲▲▲▲     ▲      ▲
│││││││││     │      └── Group name
│││││││││     └── Owner name
││└────────  Group permissions (r-x = read + execute, no write)
│└─────────  Owner permissions (rwx = read + write + execute)
└──────────  File type and other bits (- = regular file, d = dir, l = symlink)
│
└─ (first character is file type, next 9 are permission bits)
```

**Permission bits in detail:**

| Symbol | Octal | Meaning (for files) | Meaning (for directories) |
|---|---|---|---|
| `r` | 4 | Read file contents | List directory contents (`ls`) |
| `w` | 2 | Write/modify file | Create, delete, rename files in directory |
| `x` | 1 | Execute file | Traverse directory (`cd` into it) |
| `-` | 0 | Permission denied | Permission denied |

**Octal notation:** Permission groups are Owner/Group/Other, each a 3-bit value:
- `rwxrwxrwx` = `777` (all permissions for all)
- `rwxr-xr-x` = `755` (owner all; group/other read+execute)
- `rw-r--r--` = `644` (owner read+write; group/other read only)
- `rwx------` = `700` (owner all; no one else)
- `rw-------` = `600` (owner read+write only; private key format)

**Attacker insight:** A file with world-readable permissions (`rw-r--r--`, `644`) containing
a private key or password is an immediate finding. A directory with world-writable permissions
(`rwxrwxrwx`, `777`) in a service path is a privilege escalation opportunity.

---

### 4. Special Permission Bits — setuid, setgid, sticky

These are extra permission bits that modify standard behaviour. They are where privilege
escalation lives.

#### Setuid (SUID) — `s` in user execute position

```
-rwsr-xr-x  root  root  /usr/bin/passwd
    ▲
    s = setuid bit set (4 in octal prefix)
```

When a setuid binary runs, it executes with the **file owner's UID**, not the caller's UID.
So `/usr/bin/passwd` runs as root even when invoked by a regular user — necessary because
it needs to write `/etc/shadow` (root-only).

**Attacker target:** Any SUID binary owned by root that can be exploited to execute
arbitrary commands executes those commands as root.

```bash
# Find all SUID files on the system
find / -perm -4000 -type f 2>/dev/null

# Common SUID binaries (check against GTFOBins if unexpected)
find / -perm -4000 -type f -ls 2>/dev/null
```

**GTFOBins:** A curated list of Unix binaries that can be abused if set-uid or accessible
via sudo. `https://gtfobins.github.io` — bookmark this, you will use it constantly.

Example: If `find` has SUID set:
```bash
find . -exec /bin/sh -p \; -quit
# -p = privileged mode (do not drop SUID)
# Result: root shell
```

#### Setgid (SGID) — `s` in group execute position

For **files:** Execute with the file's group GID instead of caller's GID.
For **directories:** Files created inside inherit the directory's group (useful for shared directories).

```bash
# Find all SGID files
find / -perm -2000 -type f 2>/dev/null
```

#### Sticky Bit — `t` in other execute position

Applied to directories (most commonly `/tmp`):

```
drwxrwxrwt  root  root  /tmp
         ▲
         t = sticky bit
```

With sticky bit: only the file's owner can delete or rename the file, even if the directory
is world-writable. This prevents users from deleting each other's files in `/tmp`.

**Attacker note:** If `/tmp` lacks the sticky bit, any user can delete other users' files —
potentially enabling race conditions or denial of service.

---

## Main Content — Part 3: Users, Groups and Authentication

### 5. /etc/passwd — The User Database

`/etc/passwd` is world-readable — by design, many tools need to look up usernames.

**Format (colon-separated, 7 fields):**
```
root:x:0:0:root:/root:/bin/bash
alice:x:1001:1001:Alice Jones:/home/alice:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
```

| Field | Content | Attacker relevance |
|---|---|---|
| Username | Login name | Enumerate valid users |
| Password | `x` (hash in /etc/shadow) or actual hash | If `x` not present, hash is here |
| UID | User ID | UID 0 = root; look for other UID 0 accounts |
| GID | Primary group ID | Map to /etc/group |
| GECOS | Full name (optional) | User info |
| Home dir | Home directory path | Where to look for SSH keys, .bash_history |
| Shell | Login shell | `nologin`/`false` = no interactive login |

**Attacker targets in /etc/passwd:**
- Any account with UID 0 that isn't `root` = backdoor account.
- Accounts with writable home directories + SSH keys.
- Service accounts with readable home directories.
- Accounts with `/bin/bash` as shell (can get an interactive session).

---

### 6. /etc/shadow — Password Hashes

`/etc/shadow` stores hashed passwords. Only root (and the shadow group) can read it.

**Format:**
```
alice:$6$rounds=656000$salt$hashed_password:19000:0:99999:7:::
```

| Field | Content |
|---|---|
| Username | Must match /etc/passwd |
| Hash | `$ID$salt$hash` format |
| Last changed | Days since epoch of last password change |
| Min days | Minimum days before password can be changed |
| Max days | Maximum password age |
| Warn | Days before expiry to warn user |
| Inactive | Days after expiry account is disabled |
| Expire | Account expiry date |

**Hash identifier prefixes:**

| Prefix | Algorithm | Status |
|---|---|---|
| `$1$` | MD5 | Broken — crack in seconds with GPU |
| `$2a$` / `$2y$` | bcrypt | Strong — intentionally slow |
| `$5$` | SHA-256 | Moderate |
| `$6$` | SHA-512 | Moderate — 5,000 rounds default |
| `$y$` | yescrypt | Strong — modern Linux default |

**If you gain read access to /etc/shadow:**
```bash
# Crack with hashcat
hashcat -m 1800 shadow_hash.txt rockyou.txt   # SHA-512 ($6$)
hashcat -m 500  shadow_hash.txt rockyou.txt   # MD5 ($1$)
hashcat -m 3200 shadow_hash.txt rockyou.txt   # bcrypt ($2a$)

# Or john the ripper
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
```

**No access to shadow?** Look for credential reuse — if `/etc/passwd` shows a hash directly
(no `x`), that hash can be cracked offline immediately.

---

### 7. /etc/group — Group Membership

```
sudo:x:27:alice,bob
docker:x:998:alice
shadow:x:42:
```

**High-value groups for attackers:**

| Group | Privilege |
|---|---|
| `sudo` | Members can run commands as root via sudo |
| `docker` | Members can mount the host filesystem in a container → root |
| `lxd` | Similar to docker — container escape to root |
| `disk` | Direct read/write to block devices → bypass filesystem permissions |
| `shadow` | Can read `/etc/shadow` |
| `adm` | Can read system log files |

```bash
# See which groups the current user belongs to
id
groups

# List all group memberships
cat /etc/group | grep -v "^#"

# Check if current user is in any interesting group
id | grep -E "sudo|docker|lxd|disk|adm"
```

---

### 8. Finding Files by Permission — Core Enumeration Commands

```bash
# SUID files (run as file owner — typically root)
find / -perm -4000 -type f 2>/dev/null

# SGID files (run as file group)
find / -perm -2000 -type f 2>/dev/null

# World-writable files (anyone can modify)
find / -perm -o+w -type f 2>/dev/null | grep -v /proc | grep -v /sys

# World-writable directories (anyone can create/delete files here)
find / -perm -o+w -type d 2>/dev/null | grep -v /proc | grep -v /sys

# Files owned by the current user
find / -user "$(whoami)" -type f 2>/dev/null

# Files writable by current user (excluding own files)
find / -writable -type f 2>/dev/null | grep -v /proc | grep -v /home/$(whoami)

# Configuration files that might contain credentials
find /etc /var /opt /srv -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null

# SSH private keys anywhere on the filesystem
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
```

---

## Key Takeaways

1. **Know the FHS cold.** `/etc` = configs, `/home` = user data, `/var/log` = logs,
   `/tmp` = writable staging area, `/proc` = live kernel data. These are your first stops
   after landing on a machine.
2. **SUID root binaries are privilege escalation candidates.** Any SUID binary that can
   execute arbitrary commands gives you root. Check GTFOBins for every SUID binary you find.
3. **`/etc/passwd` is your user enumeration source.** Readable by all. `/etc/shadow` needs
   root — but if you ever get it, you have offline crack access to all hashes.
4. **The `docker` and `lxd` groups are root equivalents.** Being in either group = trivial
   privilege escalation. Always check group membership with `id`.
5. **Octal permissions 777 on a directory in a service path** = instant write access to
   plant malicious files that run as the service's user.
6. **World-readable private keys** are an immediate critical finding. Permissions should
   be `600` (`rw-------`) — only owner can read or write.

---

## Exercises

### Exercise 1 — Filesystem Navigation

On your Linux machine (or any Linux VM):

1. List the contents of `/etc` sorted by modification time. What are the 10 most recently
   modified configuration files? What do they contain?
2. Check `/etc/passwd` — how many accounts have `/bin/bash` as their shell? Which have
   `/bin/false` or `/usr/sbin/nologin`?
3. Run `id` and `groups`. Which groups are you in? Are any of them high-privilege?
4. Find all SUID binaries: `find / -perm -4000 -type f 2>/dev/null`. List them. For each
   unexpected one, check GTFOBins. Does any provide a path to root?

---

### Exercise 2 — Permission Interpretation

Read each `ls -la` output and answer the questions:

```
-rwsr-xr-x 1 root root    43352 Mar 10 10:00 /usr/bin/passwd
drwxrwxrwt 9 root root     4096 Apr  5 08:15 /tmp
-rw------- 1 root shadow   1432 Jan 15 09:00 /etc/shadow
-rw-r--r-- 1 root root     2808 Jan 15 09:00 /etc/passwd
drwxr-x--- 2 alice alice   4096 Feb 20 14:00 /home/alice/.ssh
-rw-r--r-- 1 alice alice   1679 Feb 20 14:00 /home/alice/.ssh/id_rsa
-rwxrwxrwx 1 root root      512 Apr  4 23:59 /usr/local/bin/backup.sh
```

For each:
1. Who can read/write/execute it?
2. Is there anything suspicious about the permissions?
3. What is the attacker relevance?

---

### Exercise 3 — User Enumeration

1. Parse `/etc/passwd` to extract only accounts with UID 0 or GID 0:
   ```bash
   awk -F: '$3==0 || $4==0 {print}' /etc/passwd
   ```
2. Find all home directories and check which ones are accessible to you.
3. Check your sudo configuration: `sudo -l`. What can you run as root?
4. If you have access to `/etc/shadow` (on your own machine with `sudo cat /etc/shadow`),
   identify the hash algorithm used for the root and first user account.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 008 — ARP, Routing, NAT and Network Check](../01-Foundation-01/DAY-0008-ARP-Routing-NAT-and-Network-Check.md)*
*Next: [Day 010 — Linux Processes, Networking CLI and Bash for Hackers](DAY-0010-Linux-Processes-Networking-and-Bash.md)*
