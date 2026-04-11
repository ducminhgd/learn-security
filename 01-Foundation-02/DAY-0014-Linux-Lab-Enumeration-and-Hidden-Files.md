---
title: "Linux Lab — Enumeration and Hidden Files"
tags: [foundation, linux, lab, enumeration, hidden-files, post-exploitation,
       CTF, attacker-mindset, shadow-file, reconnaissance]
module: 01-Foundation-02
day: 14
related_topics:
  - Linux Filesystem and Users (Day 009)
  - Linux Processes, Networking CLI and Bash (Day 010)
  - Cron, Env Variables and Capabilities (Day 011)
  - SUID, Sudo and Package Trust (Day 012)
  - Logs, Named Pipes and Sockets (Day 013)
---

# Day 014 — Linux Lab: Enumeration and Hidden Files

## Goals

This is a **pure lab day**. No new theory. You apply everything from Days 009
to 013 against a deliberately vulnerable Linux environment.

By the end of this lab you will have demonstrated ability to:

1. Systematically enumerate a Linux system after gaining initial access.
2. Find hidden files and directories using multiple techniques.
3. Identify credential files and read sensitive data (passwd, shadow,
   configuration files).
4. Document findings in a structured format as a penetration tester would.
5. Build a mental checklist you can execute under time pressure.

> "Enumeration is not a phase — it is a mindset. The attacker who finds
> the most wins, not the one who exploits the first thing they see."
> — Ghost

---

## Prerequisites

- [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)
- [Day 010 — Linux Processes, Networking CLI and Bash](DAY-0010-Linux-Processes-Networking-and-Bash.md)
- [Day 011 — Cron, Env Variables and Capabilities](DAY-0011-Cron-Env-Variables-and-Capabilities.md)
- [Day 012 — SUID, Sudo and Package Trust](DAY-0012-SUID-Sudo-and-Package-Trust.md)
- [Day 013 — Logs, Named Pipes and Sockets](DAY-0013-Logs-Named-Pipes-and-Sockets.md)

---

## Lab Setup

### Option A — Docker Lab (Recommended)

Pull and run the lab container:

```bash
docker pull ghcr.io/nicowillis/dvlp-lab:enumeration-v1 2>/dev/null || \
    echo "Use Option B — build your own"
```

If the image is unavailable, build your own (Option B).

### Option B — Build Your Own Lab VM

The following script sets up a vulnerable Ubuntu 22.04 box. Run it as root
**inside a VM only — never on your host machine.**

```bash
#!/bin/bash
# Ghost Lab Setup — Enumeration Target
# Run as root on a fresh Ubuntu 22.04 VM

set -e

# 1. Create lab users
useradd -m -s /bin/bash lowpriv
echo "lowpriv:letmein123" | chpasswd
useradd -m -s /bin/bash operator
echo "operator:op3rator!" | chpasswd

# 2. Place hidden files in various locations
mkdir -p /opt/.hidden_config
echo "DB_PASSWORD=Sup3rS3cr3t_DB!" > /opt/.hidden_config/db.conf
chmod 644 /opt/.hidden_config/db.conf
chown root:root /opt/.hidden_config/db.conf

# Hidden SSH key
mkdir -p /var/backups/.ssh_backup
ssh-keygen -t rsa -b 2048 -N "" -f /var/backups/.ssh_backup/id_rsa -C "backup@lab" \
    2>/dev/null
chmod 600 /var/backups/.ssh_backup/id_rsa
chmod 644 /var/backups/.ssh_backup/id_rsa.pub

# Credentials in bash history
echo "mysql -u root -pR00tPassw0rd!" >> /home/operator/.bash_history
echo "curl -u admin:s3cr3tAdm1n http://internal-api:8080/v1/data" \
    >> /home/operator/.bash_history
chown operator:operator /home/operator/.bash_history

# Hidden file with backup credentials
echo "BACKUP_KEY=ghp_faketoken1234567890ABCDEFGHIJ" > /home/lowpriv/.backup_token
chmod 600 /home/lowpriv/.backup_token

# Credentials in environment of a running process
cat > /opt/run_service.sh << 'EOF'
#!/bin/bash
export API_KEY="sk-live-FakeAPIKeyForLabPurposes"
export DATABASE_URL="postgresql://admin:labpassword@localhost:5432/production"
while true; do sleep 60; done
EOF
chmod +x /opt/run_service.sh
nohup /opt/run_service.sh &

# 3. Interesting SUID binary (custom, non-standard)
cat > /opt/lab_backup.c << 'EOF'
#include <stdlib.h>
#include <stdio.h>
int main() {
    printf("Performing backup...\n");
    system("id");
    return 0;
}
EOF
gcc -o /opt/lab_backup /opt/lab_backup.c 2>/dev/null
chown root:root /opt/lab_backup
chmod 4755 /opt/lab_backup

# 4. Interesting sudo rule
echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/find" >> /etc/sudoers

# 5. Interesting capability
setcap cap_dac_read_search+ep /usr/bin/python3 2>/dev/null || true

# 6. Cron job with writable script
mkdir -p /opt/cron-scripts
echo '#!/bin/bash' > /opt/cron-scripts/collect_stats.sh
echo 'uptime >> /var/log/stats.log' >> /opt/cron-scripts/collect_stats.sh
chown root:root /opt/cron-scripts/collect_stats.sh
chmod 777 /opt/cron-scripts/collect_stats.sh  # intentionally world-writable
echo "* * * * * root /opt/cron-scripts/collect_stats.sh" >> /etc/crontab

echo "[+] Lab setup complete. SSH or su to 'lowpriv' to begin."
```

---

## Lab Objectives

You are `lowpriv`. You have logged in with the password `letmein123`.
Your mission: **enumerate everything you can find without escalating
privileges yet.** The privilege escalation lab is Day 015.

Document every finding. Use the template at the end of this file.

---

## Enumeration Checklist

Work through this list methodically. Every item has a command. Every command
should produce output you understand — not just scroll past.

### Phase 1 — Who Am I?

```bash
id                          # UID, GID, supplementary groups
whoami                      # Username
uname -a                    # Kernel version + architecture
cat /etc/os-release         # OS name and version
hostname                    # Machine hostname
uptime                      # How long has it been running?
```

**Record:**
- Your UID and GID
- The kernel version (search for known exploits later)
- OS version
- Interesting supplementary groups?

---

### Phase 2 — Users and Groups

```bash
cat /etc/passwd             # All users + shells + home dirs
cat /etc/group              # All groups + members
cat /etc/shadow             # Can you read it? (usually no)
ls -la /home/               # Other user home directories
ls -la /root/               # Can you list root's home?
lastlog                     # Last login for every user
last                        # Recent login history
w                           # Who is currently logged in?
```

**Record:**
- List of users with valid login shells
- Any groups that suggest special access (docker, sudo, adm, disk, shadow)?
- Which home directories are readable?

---

### Phase 3 — System-Wide Configuration

```bash
cat /etc/crontab            # System crontab
ls -la /etc/cron.d/         # Drop-in crontabs
ls -la /etc/cron.{daily,hourly,weekly,monthly}/

# Sudoers
sudo -l 2>/dev/null         # What can you run?
cat /etc/sudoers 2>/dev/null  # If readable
ls /etc/sudoers.d/

# Capabilities
getcap -r / 2>/dev/null     # All file capabilities

# Installed packages (look for unusual software)
dpkg -l 2>/dev/null | head -50     # Debian/Ubuntu
rpm -qa 2>/dev/null | head -50     # RHEL/CentOS
```

**Record:**
- Any cron jobs running as root with suspicious scripts?
- Any sudo rules you can exploit?
- Any unusual capabilities on interpreters or tools?

---

### Phase 4 — Interesting Files

#### 4a — SUID/SGID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null | sort
find / -perm -2000 -type f 2>/dev/null | sort

# Triage: separate expected from unexpected
# Expected locations: /bin, /sbin, /usr/bin, /usr/sbin, /usr/lib
# Unexpected: /opt, /home, /var, /tmp, custom paths
```

#### 4b — Hidden Files and Directories

```bash
# Hidden files in home directories
ls -la /home/*/
ls -la /root/ 2>/dev/null

# Hidden files system-wide (expensive — be patient)
find / -name ".*" -not -path "*/proc/*" -not -path "*/sys/*" \
    -not -path "*/.git/*" 2>/dev/null | \
    grep -v "^/home/lowpriv/\." | \
    grep -v "^/etc/\." | \
    head -50

# Hidden directories specifically
find / -type d -name ".*" 2>/dev/null | \
    grep -v proc | grep -v sys | head -30
```

#### 4c — World-Readable Sensitive Files

```bash
# Config files containing passwords
grep -ri "password\|passwd\|secret\|api_key\|token\|key=" \
    /etc/ /opt/ /var/www/ 2>/dev/null | \
    grep -v ".pyc" | grep -v "^Binary"

# SSH private keys (readable by you)
find / \( -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" \
    -o -name "id_ecdsa" \) 2>/dev/null | while read f; do
    [ -r "$f" ] && echo "READABLE KEY: $f"
done

# Backup files (often contain credentials)
find / \( -name "*.bak" -o -name "*.backup" -o -name "*.old" \
    -o -name "*.orig" \) 2>/dev/null | \
    grep -v proc | head -30
```

#### 4d — Recently Modified Files

```bash
# Files modified in the last 24 hours (attacker activity indicator)
find / -newer /etc/passwd -type f 2>/dev/null | \
    grep -v proc | grep -v sys | head -30

# Files modified in /tmp (staging ground for attackers)
find /tmp /var/tmp /dev/shm -type f 2>/dev/null
```

---

### Phase 5 — Processes and Network

```bash
# Running processes
ps aux
ps axjf             # Process tree

# Environment variables of running processes
# (look for API keys, passwords, connection strings)
for pid in /proc/[0-9]*/environ; do
    content=$(strings "$pid" 2>/dev/null)
    if echo "$content" | grep -qiE "password|secret|key|token|api"; then
        echo "PID $(echo $pid | grep -oP '\d+'):"
        echo "$content" | grep -iE "password|secret|key|token|api"
    fi
done

# Network connections
ss -tlnp            # Listening ports
ss -tnp             # Established connections
ip addr             # Network interfaces + IPs
ip route            # Routing table
cat /etc/hosts      # Internal hostname mappings
```

**Record:**
- Any internal services not exposed externally (listening on 127.0.0.1)?
- Any processes leaking credentials in environment variables?
- Any other network interfaces (internal network ranges for pivoting)?

---

### Phase 6 — Bash History and Logs

```bash
# Bash history files
cat /home/*/.bash_history 2>/dev/null
cat ~/.bash_history

# Log files (may need elevated access for some)
tail -50 /var/log/auth.log 2>/dev/null
tail -50 /var/log/syslog 2>/dev/null
tail -50 /var/log/cron 2>/dev/null

# Failed logins
lastb 2>/dev/null | head -20
```

---

## Findings Template

Fill this in as you enumerate. A real pentest report uses exactly this
structure.

```markdown
## Lab Enumeration Findings — Day 014

**Target:** lab-machine (127.0.0.1)
**Date:** [your date]
**Tester:** [your name]
**Starting access:** lowpriv (UID 1001)

---

### Finding 1 — [Short title]

**Severity:** [Critical / High / Medium / Low / Informational]
**Location:** [Path or command that revealed this]
**Description:** [What you found and why it matters]
**Evidence:**
\```
[Paste the actual command output here]
\```
**Potential Impact:** [What could an attacker do with this?]

---

### Finding 2 — [Short title]
...
```

---

## Validation Checklist

Before you declare enumeration complete, verify you have found:

- [ ] The hidden config file in `/opt/`
- [ ] The backup SSH key in `/var/backups/`
- [ ] Credentials in operator's bash history
- [ ] The hidden token in lowpriv's home directory
- [ ] The process leaking API credentials in its environment
- [ ] The non-standard SUID binary in `/opt/`
- [ ] The sudo rule granting lowpriv access to `find`
- [ ] The capability set on python3
- [ ] The world-writable cron script

**If you found all 9 — you are ready for Day 015 (privilege escalation).**

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 013 — Logs, Named Pipes and Sockets](DAY-0013-Logs-Named-Pipes-and-Sockets.md)*
*Next: [Day 015 — Linux Lab: Privilege Escalation](DAY-0015-Linux-Lab-Privilege-Escalation.md)*
