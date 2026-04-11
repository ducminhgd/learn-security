---
title: "Linux Hardening and Forensic Artefacts"
tags: [foundation, linux, hardening, forensics, bash-history, ssh-artefacts,
       auditd, sysctl, umask, log-analysis, attacker-traces, blue-team]
module: 01-Foundation-02
day: 16
related_topics:
  - Linux Filesystem and Users (Day 009)
  - Logs, Named Pipes and Sockets (Day 013)
  - Linux Lab Privilege Escalation (Day 015)
  - Digital Forensics — Timeline Reconstruction (Day 198)
  - Secure Architecture Review (Day 253)
---

# Day 016 — Linux Hardening and Forensic Artefacts

## Goals

You broke it on Days 014–015. Now you fix it — and you learn to read the
traces the attacker left behind.

By the end of this lesson you will be able to:

1. Harden the six escalation paths from Day 015 with specific, targeted
   controls.
2. Identify the forensic artefacts each escalation path generates.
3. Configure `auditd` to detect future privilege escalation attempts.
4. Harden SSH configuration against common attack patterns.
5. Apply `sysctl` hardening for kernel-level protection.
6. Read `/proc/[pid]/environ`, `.bash_history`, `.ssh/` forensically — and
   understand what each artefact tells a defender.

> "Every attack leaves a shadow. The better you are at attacking, the better
> you understand the shadow. The better defender knows exactly what to look
> for because they know exactly what they would have done."
> — Ghost

---

## Prerequisites

- [Day 013 — Logs, Named Pipes and Sockets](DAY-0013-Logs-Named-Pipes-and-Sockets.md)
- [Day 015 — Linux Lab: Privilege Escalation](DAY-0015-Linux-Lab-Privilege-Escalation.md)

---

## Main Content — Part 1: Hardening the Escalation Paths

### 1. Harden Cron Scripts (Path A Fix)

**Root cause:** World-writable scripts executed by root cron.

```bash
# Audit all cron-related scripts for world-writable permissions
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
           /etc/cron.weekly /etc/cron.monthly; do
    find "$dir" -type f -perm /o+w 2>/dev/null && \
        echo "World-writable cron script in $dir"
done

# Also check scripts referenced in /etc/crontab
awk 'NF>=6 && $0 !~ /^#/ {print $NF}' /etc/crontab | while read script; do
    [ -w "$script" ] && echo "WRITABLE: $script"
done

# Fix: owner root, mode 700 or 750
chmod 700 /opt/cron-scripts/collect_stats.sh
chown root:root /opt/cron-scripts/collect_stats.sh
```

**Hardening rule:** All scripts executed by root cron MUST be owned by root
and not writable by any other user or group.

---

### 2. Harden Sudo Rules (Path B Fix)

**Root cause:** Sudo allowed unrestricted command with GTFOBins shell escape.

**Principle:** sudo should be used to allow a user to do one specific thing
— not a general-purpose command.

```bash
# Audit current sudo rules
sudo -l                  # As yourself
sudo cat /etc/sudoers    # Or: sudo visudo -c -f /etc/sudoers

# Remove the unsafe rule:
# BAD: lowpriv ALL=(root) NOPASSWD: /usr/bin/find
# If the admin's intent was "search files," consider a wrapper script:
```

**Safe wrapper approach:**

```bash
# /usr/local/bin/safe_find (owned root, not writable by others)
cat > /usr/local/bin/safe_find << 'EOF'
#!/bin/bash
# Allows searching /var/log only, no -exec flag
exec /usr/bin/find /var/log -name "$1" 2>/dev/null
EOF
chmod 755 /usr/local/bin/safe_find
chown root:root /usr/local/bin/safe_find

# In sudoers:
# lowpriv ALL=(root) NOPASSWD: /usr/local/bin/safe_find
```

**Key hardening rules for sudoers:**

1. Never allow generic interpreters (`python`, `perl`, `ruby`, `node`).
2. Never allow editors (`vim`, `nano`, `emacs`) — they have shell escapes.
3. Never allow pager commands (`less`, `more`, `man`).
4. Never allow file managers or archiving tools without strict arguments.
5. Always use absolute paths in sudoers rules.
6. Prefer `PASSWD:` over `NOPASSWD:` — require authentication.
7. Audit with: `sudo -l -U <username>` for every user.

---

### 3. Remove Dangerous Capabilities (Path C Fix)

**Root cause:** `cap_dac_read_search+ep` on Python3.

```bash
# View all file capabilities
getcap -r / 2>/dev/null

# Remove specific capability
setcap -r /usr/bin/python3

# Verify removal
getcap /usr/bin/python3
# (no output = no capabilities set)

# Review what capabilities are actually needed:
# /usr/bin/ping       = cap_net_raw+p    (needed — ping uses raw socket)
# /usr/bin/tcpdump    = cap_net_raw+ep   (consider removing if not used)
# /usr/bin/python3    = (nothing)        ← correct

# Audit script to find dangerous capabilities:
getcap -r / 2>/dev/null | grep -E \
    "cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|\
cap_sys_admin|cap_sys_ptrace|cap_net_raw|cap_fowner"
```

---

### 4. Fix SUID Binaries (Path D Fix)

**Root cause:** Non-standard SUID binary calling system() with relative paths.

```bash
# Remove the unnecessary SUID bit
chmod -s /opt/lab_backup
# Verify:
ls -la /opt/lab_backup
# -rwxr-xr-x (no 's' in owner execute position)

# If the SUID bit is genuinely needed, fix the binary:
# Replace: system("id");
# With:    system("/usr/bin/id");
# Recompile. And ask: does this binary actually need to run as root?

# Audit all non-standard SUID binaries:
find / -perm -4000 -type f 2>/dev/null | \
    grep -vE "^/(bin|sbin|usr/bin|usr/sbin|usr/lib|usr/libexec)" | \
    while read f; do
        echo "NON-STANDARD SUID: $f (owner: $(stat -c '%U' "$f"))"
    done
```

---

### 5. Protect Process Environment Variables (Path E Fix)

**Root cause:** Service credentials injected via environment variables;
`/proc/[pid]/environ` readable by owner.

```bash
# Better: use a credentials file with tight permissions
cat > /etc/service-credentials << 'EOF'
DATABASE_URL=postgresql://admin:labpassword@localhost:5432/production
API_KEY=sk-live-FakeAPIKeyForLabPurposes
EOF
chmod 600 /etc/service-credentials
chown root:root /etc/service-credentials

# Service reads credentials at startup (not via env):
# source /etc/service-credentials  inside the service script

# Kernel-level protection: restrict /proc/[pid]/environ to root only
# (cannot fully prevent root from reading it, but limits user-level access)
echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/99-hardening.conf
sysctl -p /etc/sysctl.d/99-hardening.conf
```

**Modern approach:** Use a secrets manager (HashiCorp Vault, AWS Secrets
Manager, systemd credentials) to inject secrets at runtime without
environment variables.

---

### 6. Protect SSH Keys (Path F Fix)

**Root cause:** SSH private key stored in a world-accessible backup location.

```bash
# Fix permissions on the backup directory
chmod 700 /var/backups/.ssh_backup
chmod 600 /var/backups/.ssh_backup/id_rsa
chown root:root /var/backups/.ssh_backup -R

# Audit for exposed SSH keys:
find / \( -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" \) \
    2>/dev/null | while read f; do
    perms=$(stat -c "%a" "$f")
    owner=$(stat -c "%U:%G" "$f")
    if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
        echo "EXPOSED KEY ($perms, $owner): $f"
    fi
done
```

---

## Main Content — Part 2: Forensic Artefacts

### 7. Bash History — What It Tells a Defender

Bash history is forensically rich but also trivially cleared by attackers.
Understand both sides.

**What bash_history contains:**

```bash
cat ~/.bash_history
# One command per line (simplified)
# May include timestamps if HISTTIMEFORMAT is set
```

**Setting up timestamped history (harder to forge):**

```bash
# Add to /etc/profile or /etc/bash.bashrc (system-wide):
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
HISTSIZE=10000
HISTFILESIZE=20000
# Append to history file on every command (not just on exit):
PROMPT_COMMAND='history -a'
# Don't allow overwriting history file:
readonly HISTFILE
```

**Forensic reading of history:**

```bash
# Read with timestamps if available
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  " history

# Look for attacker TTPs:
grep -E "wget|curl|nc |ncat|socat|python3 -c|perl -e|ruby -e|\
chmod \+s|chown.*root|useradd|adduser|crontab|authorized_keys|\
/proc/.*environ|base64|xxd|dd if=" ~/.bash_history
```

**Attacker anti-forensics — what to look for:**

| Indicator | Meaning |
|---|---|
| Empty `~/.bash_history` | Cleared or `HISTFILE=/dev/null` |
| `~/.bash_history` is a symlink to `/dev/null` | Deliberate suppression |
| Timestamped history with a gap | Commands during the gap weren't logged |
| `history -c` in history | Self-aware attacker; they tried to clear it |
| `unset HISTFILE` in history | The command ran before they disabled history |

---

### 8. SSH Artefacts

The `.ssh/` directory is a forensic goldmine.

```bash
# Defender: check for unexpected entries in authorized_keys
cat /root/.ssh/authorized_keys 2>/dev/null
cat /home/*/.ssh/authorized_keys 2>/dev/null

# Attacker persistence indicator: new key added
# Compare timestamps: when was the key added vs the last legitimate login?
stat ~/.ssh/authorized_keys
ls -la --full-time ~/.ssh/authorized_keys

# Check known_hosts: what hosts has this user connected to?
cat ~/.ssh/known_hosts
# Format: hostname/IP hashedHostname publicKey
# Or hashed format: |1|base64salt|base64hash algorithm key

# Decrypt hashed known_hosts entry (if you know the hostname):
ssh-keygen -H -F hostname 2>/dev/null

# Check recent outbound SSH connections:
grep "Accepted publickey\|Accepted password" /var/log/auth.log | \
    tail -20
```

**Hardening SSH (`/etc/ssh/sshd_config`):**

```bash
# Recommended hardening settings:
PermitRootLogin no                  # Never allow direct root SSH
PasswordAuthentication no           # Keys only
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict to specific users or groups:
AllowUsers alice bob
# or:
AllowGroups ssh-users

# After editing, test before reloading:
sshd -t                             # Test configuration syntax
systemctl reload sshd
```

---

### 9. /tmp and /dev/shm — Attacker Staging Areas

Attackers use `/tmp`, `/var/tmp`, and `/dev/shm` as staging grounds because
they are typically world-writable.

```bash
# Forensic check of staging areas:
find /tmp /var/tmp /dev/shm -type f 2>/dev/null -exec ls -la {} \;

# Look for:
# - Binary files (tools dropped by attacker)
# - Shell scripts with suspicious names (.xxx, random strings)
# - SUID files planted here (cp /bin/bash /tmp/.xxx; chmod +s /tmp/.xxx)
# - Named pipes (type 'p' in ls -la)

# Check file type of suspicious files:
file /tmp/.suspicious_file

# Calculate hash for threat intel lookups:
sha256sum /tmp/.suspicious_file

# Forensic indicator: file timestamps
stat /tmp/.suspicious_file
# Created: atime, mtime, ctime
# ctime = cannot be user-modified with touch; reliable timestamp
```

**Hardening `/tmp` (prevent execution from world-writable areas):**

```bash
# In /etc/fstab (if /tmp is a separate mount):
# tmpfs /tmp tmpfs defaults,nosuid,noexec,nodev 0 0

# Verify mount options:
mount | grep /tmp
# tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,...)
# noexec: prevents executing binaries from /tmp
# nosuid: SUID/SGID bits ignored on /tmp
```

---

## Main Content — Part 3: auditd

### 10. Linux Audit Daemon

`auditd` is the kernel-level audit subsystem for Linux. It can record every
system call, file access, and network event — with user attribution.

```bash
# Install
apt install auditd audispd-plugins

# Status
systemctl status auditd

# View audit rules
auditctl -l

# Audit log location
/var/log/audit/audit.log
```

**Essential audit rules for detecting the Day 015 attacks:**

```bash
# Detect SUID/SGID changes (Path A, D):
auditctl -a always,exit -F arch=b64 -S chmod -F a1=0x4000 -k suid_change
auditctl -a always,exit -F arch=b64 -S fchmod -F a1=0x4000 -k suid_change

# Detect writes to cron directories (Path A):
auditctl -w /etc/crontab -p wa -k cron_tamper
auditctl -w /etc/cron.d -p wa -k cron_tamper
auditctl -w /opt/cron-scripts -p wa -k cron_tamper

# Detect reads of /etc/shadow (Path C and general):
auditctl -w /etc/shadow -p r -k shadow_read

# Detect writes to /etc/passwd, /etc/shadow (account creation/modification):
auditctl -w /etc/passwd -p wa -k passwd_change
auditctl -w /etc/shadow -p wa -k shadow_change

# Detect new user creation:
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/sbin/useradd \
    -k user_add
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/sbin/adduser \
    -k user_add

# Detect setuid syscalls (Path C — Python setuid):
auditctl -a always,exit -F arch=b64 -S setuid -S setreuid -S setresuid \
    -k setuid_calls

# Detect writes to authorized_keys (Path F persistence):
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_key_add
auditctl -w /home -p wa -k home_dir_write

# Persist rules:
# Add all of the above to /etc/audit/rules.d/hardening.rules
```

**Searching audit logs:**

```bash
# Search by key
ausearch -k suid_change
ausearch -k shadow_read

# Search by time range
ausearch --start today

# Search by user
ausearch -ua 1001          # UID 1001

# Search by syscall
ausearch -sc setuid

# Decode an audit event
ausearch -k setuid_calls | aureport -au
```

---

## Main Content — Part 4: Kernel Hardening (sysctl)

### 11. Key sysctl Hardening Parameters

```bash
# Write these to /etc/sysctl.d/99-security.conf
# Apply with: sysctl -p /etc/sysctl.d/99-security.conf

# Prevent unprivileged users from reading dmesg (kernel messages)
kernel.dmesg_restrict = 1

# Restrict ptrace to parent process only (mitigates memory-reading attacks)
# 0 = unrestricted, 1 = restricted to parent, 2 = admin only, 3 = disabled
kernel.yama.ptrace_scope = 1

# Disable core dumps for SUID programs (prevents memory disclosure)
fs.suid_dumpable = 0

# Hide kernel pointers from unprivileged users (/proc/kallsyms, etc.)
# Mitigates KASLR bypass via info leak
kernel.kptr_restrict = 2

# Protect hardlinks and symlinks from abuse in world-writable directories
# (prevents race conditions in /tmp that lead to privesc)
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Disable IPv4 source routing (prevent IP spoofing for routing attacks)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Disable ICMP redirects (prevent routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Enable SYN cookies (prevent SYN flood DoS)
net.ipv4.tcp_syncookies = 1

# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
```

---

## Key Takeaways

1. **Every escalation path has a specific root cause.** Fix the root cause —
   not symptoms. Cron script writable? Fix the permissions. Sudo allows find?
   Remove it or replace with a safe wrapper. Capability on interpreter?
   Remove it.
2. **`auditd` at the kernel level catches what application-level logging
   misses.** Setuid syscalls, file attribute changes, and shadow file reads
   are only visible at the syscall layer. Application logs can be tampered
   with; kernel audit events cannot be easily forged.
3. **Bash history is unreliable but still valuable.** Attackers know to clear
   it, but they often don't do it in time, or they miss a terminal. Timestamp
   your history server-side; forward it to a SIEM immediately.
4. **SSH `authorized_keys` is the most common persistence mechanism on Linux.**
   Monitor it with `auditd`. Diff it against a known-good state weekly.
5. **`sysctl` hardening is a layer, not a solution.** `fs.protected_symlinks`
   and `kernel.yama.ptrace_scope = 1` close entire classes of kernel-level
   attack. Apply them by default on every Linux system you control.

---

## Exercises

### Exercise 1 — Hardening Audit

Reset the lab from Day 014 to its vulnerable state. Then:

1. Apply all six fixes from this lesson.
2. Verify each fix works by attempting the corresponding escalation path from
   Day 015. Each attempt should fail.
3. Write one sentence per path: "This path is now blocked because [root
   cause] was fixed by [specific change]."

---

### Exercise 2 — auditd Detection

1. On the lab machine, install and configure auditd with the rules from
   this lesson.
2. Run Path A (cron exploitation) from Day 015.
3. Use `ausearch -k cron_tamper` to find the audit event.
4. What information is in the audit record? (timestamp, UID, process, file)
5. Write a sentence: "A SOC analyst watching for this key would have been
   alerted within [X seconds] of the attack."

---

### Exercise 3 — Forensic Artefact Hunt

After running all six escalation paths from Day 015 on a fresh lab instance:

1. Check `~/.bash_history` for all users — what commands are recorded?
2. Check `/var/log/auth.log` — which paths generated entries?
3. Check `/tmp` and `/dev/shm` for planted files.
4. Run `ausearch --start today` — how many audit events were generated?
5. Order the six paths from most to least forensic evidence generated.

---

### Exercise 4 — sysctl Hardening

1. Check your current sysctl settings: `sysctl -a 2>/dev/null | grep -E
   "ptrace|dmesg|kptr|protected|syncookies|ip_forward"`
2. Note which parameters are at insecure defaults.
3. Apply the hardening settings from this lesson.
4. Test: can an unprivileged user now read `/proc/kallsyms`? What changed?

---

## Module Completion — 01-Foundation-02

You have completed **Linux for Hackers** (Days 009–016).

**Competency check — can you do all of these from memory?**

- [ ] Explain the Linux permission model: owner, group, other; setuid, setgid,
  sticky
- [ ] Find SUID binaries and assess them with GTFOBins
- [ ] Read `sudo -l` output and identify exploitable rules
- [ ] Enumerate capabilities with `getcap` and exploit `cap_setuid`
- [ ] Find credentials in environment variables, bash history, config files
- [ ] Exploit a writable cron script to get a root shell
- [ ] Read `/var/log/auth.log` for forensic events
- [ ] Write an `auditd` rule that detects a privilege escalation attempt
- [ ] Apply the six escalation fixes and verify each blocks the attack

**If you cannot do all of the above → redo the labs, not the reading.**

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 015 — Linux Lab: Privilege Escalation](DAY-0015-Linux-Lab-Privilege-Escalation.md)*
*Next: Day 017 — Web Architecture Full Stack (01-Foundation-03)*
