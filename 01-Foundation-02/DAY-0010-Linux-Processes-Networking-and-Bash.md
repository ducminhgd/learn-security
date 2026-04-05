---
title: "Linux Processes, Networking CLI and Bash for Hackers"
tags: [foundation, linux, processes, networking, bash, one-liners, piping,
       enumeration, attacker-mindset, post-exploitation]
module: 01-Foundation-02
day: 10
related_topics:
  - Linux Filesystem and Users (Day 009)
  - Linux PrivEsc enumeration (Day 234)
  - Post-exploitation enumeration (Day 241)
  - Bash automation for recon (Day 070)
---

# Day 010 — Linux Processes, Networking CLI and Bash for Hackers

## Goals

By the end of this lesson you will be able to:

1. List and inspect running processes using `ps`, `top`, `/proc`, and `pstree`.
2. Read the process tree and understand parent-child relationships — and why they matter
   for both forensics and privilege escalation.
3. Send signals to processes: `kill`, `killall`, `pkill`.
4. Use `ip`, `ss`, `netstat`, `lsof` to enumerate network connections, listening services,
   and open sockets from the command line.
5. Read and manipulate environment variables — and find credentials hiding in them.
6. Write Bash one-liners using pipes, redirection, substitution, and loops for hacker tasks.
7. Schedule, read, and exploit crontab entries.
8. Explain how `LD_PRELOAD` and `PATH` hijacking work at the shell level.

---

## Prerequisites

- [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)

---

## Main Content — Part 1: Linux Processes

### 1. What is a Process?

A process is a running instance of a program. Each process has:
- **PID** (Process ID): unique identifier.
- **PPID** (Parent Process ID): who spawned it.
- **UID/GID**: the user and group it runs as.
- **File descriptors**: references to open files, sockets, pipes.
- **Memory maps**: stack, heap, loaded libraries.
- **Environment variables**: key=value pairs inherited from parent.

Every process in Linux except PID 1 (init/systemd) was spawned by another process. This
parent-child chain is the **process tree** — and it is forensically important. A shell
spawned from an Apache worker is anomalous. A bash process parented by `sshd` is normal.

---

### 2. Process Inspection Commands

```bash
# Snapshot of all processes (BSD syntax)
ps aux
# a = all users, u = user-oriented format, x = include processes without terminal

# Process tree (visual hierarchy)
ps axjf
pstree -p           # show PIDs
pstree -u           # show users

# Interactive process monitor
top
htop                # better version (install: apt install htop)

# Specific process by name
ps aux | grep nginx
pgrep nginx         # returns PIDs
pgrep -a nginx      # returns PIDs with command

# Detailed info about a specific PID
cat /proc/1234/status    # UID, GID, memory, state
cat /proc/1234/cmdline | tr '\0' ' '   # full command line
cat /proc/1234/exe       # symlink to executable binary (readlink -f)
ls -la /proc/1234/fd/    # open file descriptors
cat /proc/1234/maps      # memory map (loaded libraries)
```

**Attacker use of process listing:**

```bash
# Find processes running as root
ps aux | awk '$1=="root" {print}'

# Find processes running with specific environment variables
# (look for processes that might have credentials)
for pid in /proc/[0-9]*/environ; do
    pid_num=$(echo $pid | grep -oP '\d+')
    content=$(strings $pid 2>/dev/null)
    if echo "$content" | grep -qiE "password|passwd|secret|token|key|api"; then
        echo "PID $pid_num:"
        echo "$content" | grep -iE "password|passwd|secret|token|key|api"
    fi
done

# Find processes running from writable directories (potential hijacking)
ps aux | awk '{print $11}' | while read exe; do
    if [ -f "$exe" ] && [ -w "$exe" ]; then
        echo "WRITABLE: $exe"
    fi
done
```

---

### 3. Signals

Signals are software interrupts sent to processes. Key signals for attackers:

| Signal | Number | Effect | Common use |
|---|---|---|---|
| SIGTERM | 15 | Graceful termination | `kill PID` (default signal) |
| SIGKILL | 9 | Forceful termination | `kill -9 PID` (cannot be caught) |
| SIGSTOP | 19 | Pause process | `kill -19 PID` or Ctrl+Z |
| SIGCONT | 18 | Resume paused process | `kill -18 PID` or `fg` |
| SIGHUP | 1 | Hangup / reload config | `kill -1 PID` (many daemons reload on HUP) |
| SIGUSR1/2 | 10/12 | User-defined | Service-specific actions |

```bash
kill -15 PID      # SIGTERM (graceful)
kill -9  PID      # SIGKILL (forceful)
killall nginx     # send SIGTERM to all nginx processes
pkill -9 -u alice # kill all processes owned by alice
```

**Post-exploitation use:** Killing a monitoring or detection process before doing something
noisy. Sending SIGHUP to reload a service config after modifying it.

---

## Main Content — Part 2: Network Enumeration from CLI

### 4. ip — Network Interface and Routing

```bash
# Show all interfaces and their addresses
ip addr show
ip a                  # shorthand

# Show routing table
ip route show
ip r                  # shorthand

# Show ARP/neighbour table
ip neigh show
ip n                  # shorthand

# Add a temporary route (useful for pivoting)
sudo ip route add 10.10.10.0/24 via 192.168.1.1

# Check interface statistics (packet drops, errors)
ip -s link show eth0
```

---

### 5. ss — Socket Statistics (Replaces netstat)

`ss` is faster and more feature-rich than the deprecated `netstat`:

```bash
# All listening TCP sockets
ss -tlnp
# t = TCP, l = listening, n = numeric (no DNS), p = show process

# All established TCP connections
ss -tnp

# All sockets (TCP + UDP + Unix)
ss -anp

# Connections to a specific port
ss -tnp dst :443

# What process is listening on port 8080?
ss -tlnp | grep :8080

# UDP listening sockets
ss -ulnp
```

**Output example:**
```
State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN   0       128     0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
LISTEN   0       511     127.0.0.1:3306      0.0.0.0:*          users:(("mysqld",pid=5678,fd=21))
ESTAB    0       0       192.168.1.100:22    192.168.1.50:48732 users:(("sshd",pid=9012,fd=5))
```

**Attacker enumeration after landing:**
```bash
# What is listening internally that might not be exposed externally?
ss -tlnp | grep "127.0.0.1\|::1"
# Internal services: databases (3306, 5432), Redis (6379), internal APIs

# What external connections are established? (could be C2, exfil, or legitimate)
ss -tnp | grep ESTAB
```

---

### 6. netstat — Legacy (Still Common)

`netstat` may still be installed on older systems:

```bash
netstat -tlnp    # Listening TCP (same as ss -tlnp)
netstat -anp     # All connections + PIDs
netstat -rn      # Routing table
netstat -i       # Interface statistics
```

---

### 7. lsof — List Open Files

`lsof` shows every open file for every process — and in Linux, everything is a file
(regular files, directories, sockets, devices, pipes):

```bash
# All open files (huge output — use with filters)
sudo lsof

# All network connections
sudo lsof -i

# Connections to a specific port
sudo lsof -i :80
sudo lsof -i TCP:8443

# All files opened by a specific process
sudo lsof -p 1234

# All files opened by a specific user
sudo lsof -u alice

# What process has this file open?
sudo lsof /var/log/auth.log

# All open files in a directory
sudo lsof +D /var/www/html
```

**Attacker enumeration:**
```bash
# Find processes with open network connections + their binary paths
sudo lsof -i -n -P | grep ESTABLISHED

# Find web server processes and what files they have open (config files, data files)
sudo lsof -p $(pgrep apache2 | head -1)

# Find processes that have opened the database socket
sudo lsof /var/run/mysql/mysql.sock 2>/dev/null
```

---

## Main Content — Part 3: Bash for Hackers

### 8. Essential Bash Constructs

You will write dozens of Bash one-liners in your hacking work. These are the building
blocks — not nice-to-haves, essential tools.

#### Pipes and Redirection

```bash
command1 | command2       # Pipe stdout of command1 to stdin of command2
command > file            # Redirect stdout to file (overwrite)
command >> file           # Redirect stdout to file (append)
command 2> file           # Redirect stderr to file
command 2>/dev/null       # Discard stderr (suppress error messages)
command &> file           # Redirect both stdout and stderr to file
command 2>&1 | command2   # Merge stderr into stdout, pipe to command2
```

#### Command Substitution

```bash
whoami                    # Output: alice
echo "I am $(whoami)"     # I am alice
echo "My PID is $$"       # My PID is 1234
files=$(ls /etc/*.conf)   # Store output in variable
echo $files
```

#### Variables

```bash
NAME="Ghost"
echo "Hello, $NAME"
echo "Hello, ${NAME}"       # Curly braces — use for clarity/adjacent chars

# Read-only variable
readonly SECRET="dont_change_me"

# Array
HOSTS=("10.0.0.1" "10.0.0.2" "10.0.0.3")
echo ${HOSTS[0]}            # 10.0.0.1
echo ${HOSTS[@]}            # all elements
echo ${#HOSTS[@]}           # count: 3
```

#### Loops

```bash
# For loop over a list
for ip in 192.168.1.{1..254}; do
    ping -c 1 -W 1 "$ip" &>/dev/null && echo "$ip is up"
done

# For loop over command output
for user in $(cat /etc/passwd | cut -d: -f1); do
    echo "User: $user"
done

# While loop
while IFS= read -r line; do
    echo "Processing: $line"
done < /etc/hosts

# While loop with condition
count=0
while [ $count -lt 10 ]; do
    echo "Count: $count"
    ((count++))
done
```

#### Conditionals

```bash
# File tests
[ -f /etc/shadow ] && echo "Shadow exists"    # -f = is regular file
[ -d /home/alice ] && echo "Alice home exists" # -d = is directory
[ -r /etc/shadow ] && echo "Shadow is readable" # -r = is readable
[ -w /tmp/test ]   && echo "Test is writable"  # -w = is writable
[ -x /bin/bash ]   && echo "Bash is executable" # -x = is executable
[ -s /tmp/data ]   && echo "Data is non-empty"  # -s = non-empty

# String comparison
[ "$USER" = "root" ] && echo "Running as root"
[ -z "$VAR" ] && echo "VAR is empty"    # -z = zero length
[ -n "$VAR" ] && echo "VAR is set"      # -n = non-zero length

# Numeric comparison
[ $UID -eq 0 ] && echo "UID is 0 (root)"
[ $PORT -lt 1024 ] && echo "Privileged port"
```

---

### 9. Hacker One-Liners

These are patterns you will use repeatedly. Study them until you can write them from memory.

```bash
# ── HOST ENUMERATION ──────────────────────────────────────────────
# Quick network sweep (ping all hosts in subnet)
for i in {1..254}; do
    ping -c 1 -W 1 "192.168.1.$i" &>/dev/null && echo "192.168.1.$i UP" &
done; wait

# Or with fping (faster)
fping -a -g 192.168.1.0/24 2>/dev/null

# Check which common ports are open on a host (without nmap)
for port in 21 22 23 25 80 443 3306 5432 8080 8443; do
    (echo >/dev/tcp/192.168.1.1/$port) &>/dev/null && \
    echo "Port $port OPEN"
done

# ── CREDENTIAL HUNTING ────────────────────────────────────────────
# Find passwords in config files
grep -ri "password\|passwd\|secret\|api_key\|token" /etc/ 2>/dev/null | \
    grep -v "^Binary" | grep -v ".pyc"

# Find credentials in bash history files
cat /home/*/.bash_history /root/.bash_history 2>/dev/null | \
    grep -iE "password|passwd|curl.*-u|mysql.*-p|psql.*-W"

# Find credentials in environment variables of running processes
strings /proc/*/environ 2>/dev/null | \
    grep -iE "pass|secret|key|token|api" | sort -u

# ── FILE HUNTING ──────────────────────────────────────────────────
# Find all SSH private keys
find / -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" \
    -o -name "id_ecdsa" 2>/dev/null | while read f; do
    [ -r "$f" ] && echo "READABLE: $f"
done

# Find recently modified files (last 10 minutes)
find / -newer /tmp/ref_file -type f 2>/dev/null
# First create reference: touch -t $(date -d '10 minutes ago' +%Y%m%d%H%M) /tmp/ref_file

# Find world-writable files in service directories
find /var /etc /opt /usr/local -writable -type f 2>/dev/null

# ── SUID/SUDO ENUMERATION ─────────────────────────────────────────
# SUID binaries (not in standard paths)
find / -perm -4000 -type f 2>/dev/null | \
    grep -v -E "^/(bin|sbin|usr/bin|usr/sbin|usr/lib)/"

# What can current user run with sudo?
sudo -l 2>/dev/null

# ── NETWORK RECON FROM INSIDE ─────────────────────────────────────
# Internal network ranges accessible from this host
ip route | awk '{print $1}' | grep -v default | grep -v "^169\|^127"

# All listening services + their process names
ss -tlnp | awk 'NR>1 {print $4, $6}' | \
    sed 's/.*:\([0-9]*\) .*pid=\([0-9]*\).*/port \1 → pid \2/'

# Establish what's in the hosts file (internal DNS)
grep -v "^#\|^$\|^127\|^::1" /etc/hosts | awk '{print $2, $1}'
```

---

### 10. Environment Variables — Credential Goldmine

```bash
# Print all environment variables of current process
env
printenv

# Set a variable (current session only)
export MY_VAR="value"

# Check for credentials in current env
env | grep -iE "pass|secret|key|token|aws|db|sql"

# Unset a variable
unset MY_VAR

# Persistent env vars per user
cat ~/.bashrc | grep export
cat ~/.profile | grep export
cat ~/.bash_profile | grep export

# System-wide env
cat /etc/environment
cat /etc/profile
ls /etc/profile.d/
```

**Common places credentials appear in environment variables:**
- Docker containers: secrets injected via `-e` or `--env-file`.
- CI/CD runners: pipeline variables in `CI_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.
- Application servers: database passwords in `DATABASE_URL`, `DB_PASSWORD`.
- Web servers: API keys in `STRIPE_SECRET_KEY`, `SENDGRID_API_KEY`, etc.

**Reading another process's environment (post-exploitation):**
```bash
# Read env vars of process with PID 1337 (if you have permission)
cat /proc/1337/environ | tr '\0' '\n'

# Read env vars of a running web server process
pid=$(pgrep -f "python3 app.py" | head -1)
cat /proc/$pid/environ | tr '\0' '\n' | grep -i key
```

---

### 11. Cron Jobs — Scheduled Task Exploitation

Cron is the Linux task scheduler. It runs commands at specified intervals.

```bash
# Current user's crontab
crontab -l

# Root's crontab (if readable)
crontab -u root -l 2>/dev/null

# System-wide crontab
cat /etc/crontab

# System-wide cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
```

**Crontab format:**
```
# ┌───────────── minute (0-59)
# │ ┌───────────── hour (0-23)
# │ │ ┌───────────── day of month (1-31)
# │ │ │ ┌───────────── month (1-12)
# │ │ │ │ ┌───────────── day of week (0-7, both 0 and 7 = Sunday)
# │ │ │ │ │
# * * * * * command_to_execute
  * * * * * /opt/scripts/backup.sh         # Every minute
  0 2 * * * /usr/local/bin/cleanup.sh      # 2 AM daily
  */5 * * * * /home/alice/check_status.sh  # Every 5 minutes
```

**Privilege escalation via cron:**
- A cron job running as root that executes a script you can write to → inject commands.
- A cron job that uses a relative command (e.g. `backup.sh` without full path) → PATH injection.
- A cron job that uses wildcard expansion in dangerous ways (`tar -czf /tmp/backup.tar.gz /data/*`
  → if you can write to `/data`, create a file named `--checkpoint-action=exec=sh rce.sh`).

```bash
# Detect writable scripts called by cron
cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v "^#" | awk '{print $6}' | \
    while read script; do
        [ -w "$script" ] && echo "WRITABLE CRON SCRIPT: $script"
    done
```

---

## Key Takeaways

1. **`ps aux` and `pstree`** are your first process enumeration tools. Anomalous parent-child
   relationships are forensic indicators. A web shell spawning `/bin/bash` is obvious in
   a process tree.
2. **`ss -tlnp`** replaces `netstat`. Shows exactly what is listening internally — databases,
   Redis, internal APIs that are not exposed externally but might be reachable after compromise.
3. **`lsof -i`** shows all network connections with PIDs. Combine with `lsof -p` to see
   everything a suspicious process has open.
4. **Environment variables contain credentials.** Check `/proc/*/environ` after landing on
   a host. Web servers, containers, and CI systems routinely inject secrets via env vars.
5. **Bash one-liners are weapons.** You need to write them from scratch, not copy-paste.
   Practice: write a subnet sweep, a credential grep, and a SUID finder without looking
   at notes. You will do this under time pressure in real engagements.
6. **Writable cron scripts running as root** are among the most common privilege escalation
   vectors. Always audit cron entries and check if any scripts are writable.

---

## Exercises

### Exercise 1 — Process Enumeration

On your Linux machine:

1. Run `ps axjf`. Find the PID of your current shell. What is its PPID? Trace the parent
   chain all the way to PID 1.
2. Find all processes running as root: `ps aux | awk '$1=="root"'`. List the top 5 by
   CPU usage.
3. Pick one of those root processes. Read its `cmdline` from `/proc/`. What command started it?
4. For that same process, check `/proc/[pid]/environ`. Are there any interesting environment
   variables? (Use `cat /proc/[pid]/environ | tr '\0' '\n'`.)

---

### Exercise 2 — Network Enumeration

1. Run `ss -tlnp`. What services are listening on your machine? For each service, identify
   whether it is listening on all interfaces (`0.0.0.0`) or only localhost (`127.0.0.1`).
2. For any service listening on localhost only, ask: why is it restricted to localhost? Is
   that a security control or just a default?
3. Run `sudo lsof -i`. How many open network connections do you have? Which processes have
   the most?

---

### Exercise 3 — Bash One-Liners

Write the following from scratch (no looking at notes):

1. A one-liner that checks if ports 22, 80, 443, and 8080 are open on `192.168.1.1`.
2. A one-liner that finds all files in `/etc` containing the word "password".
3. A loop that iterates through all PIDs in `/proc` and prints the UID of each process.
4. A one-liner that lists all SUID binaries not in `/bin`, `/sbin`, `/usr/bin`, or `/usr/sbin`.
5. A script that reads each entry from `/etc/crontab` and checks if the script it calls
   is writable by the current user.

---

### Exercise 4 — Cron Analysis

1. Check all cron directories: `ls -la /etc/cron.*` and `cat /etc/crontab`.
2. For each script called by cron, check: (a) Who owns it? (b) What are its permissions?
   (c) Can you write to it?
3. Install the `pspy` tool (no-privilege process spy) and watch for cron jobs running:
   ```bash
   wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
   chmod +x pspy64 && ./pspy64
   ```
   What cron jobs do you observe running? Are any running as root?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 009 — Linux Filesystem, Permissions and Users](DAY-0009-Linux-Filesystem-Permissions-and-Users.md)*
*Next: [Day 011 — Cron, Environment Variables and Linux Capabilities](DAY-0011-Cron-Env-Variables-and-Capabilities.md)*
