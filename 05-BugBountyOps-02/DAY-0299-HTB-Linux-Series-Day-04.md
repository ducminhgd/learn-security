---
title: "HTB Linux Series Day 4 — Container Escape and Post-Exploitation"
tags: [HTB, HackTheBox, CTF, Linux, container-escape, Docker, post-exploitation,
       practice, methodology]
module: 05-BugBountyOps-02
day: 299
related_topics:
  - HTB Linux Series Day 3 (Day 298)
  - Container Escape (Day 240)
  - Post-Exploitation Basics (Day 241)
---

# Day 299 — HTB Linux Series Day 4: Container Escape and Post-Exploitation

> "Cloud-hosted targets in bug bounty often land you in a container — not
> the host. Knowing how to identify that you are in a container, and how
> to escape it, is the difference between a P2 RCE and a P1 full host
> compromise."
>
> — Ghost

---

## Goals

Complete an HTB machine involving container escape or advanced post-exploitation.

**Time budget:** 4–5 hours.

---

## Container Awareness Checks

Run these on foothold:

```bash
# Am I in a container?
cat /proc/1/cgroup | grep -i docker
ls -la /.dockerenv          # Docker
ls -la /run/.containerenv   # Podman
cat /proc/self/status | grep CapEff
# Full caps (0000003fffffffff) = privileged container

# Can I reach the Docker socket?
ls -la /var/run/docker.sock

# Host filesystem mounted?
cat /proc/mounts | grep -v tmpfs | grep -v proc
```

---

## Engagement Log

### Container Status

```
In container: Y/N
Container type: Docker / Podman / LXC / other
Privileged: Y/N
Evidence: ___
```

### Escape Path

```
Method chosen:
  [ ] Docker socket abuse
  [ ] cgroup release_agent
  [ ] Privileged container host mount
  [ ] Other: ___

Steps:
  1. ___
  2. ___
  3. ___

Host access obtained: Y/N
```

### Post-Exploitation

```
Landing on host as: ___
Further escalation: ___
```

### Flags

```
user.txt: ___
root.txt: ___
Total time: ___ min
```

---

## Debrief

```
Escape technique used:
___

How would a defender detect this escape?
___

How would Falco rule catch it?
___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q299.1, Q299.2 …).

---

## Navigation

← Previous: [Day 298 — HTB Linux Series Day 3](DAY-0298-HTB-Linux-Series-Day-03.md)
→ Next: [Day 300 — Milestone 300 Days](DAY-0300-Milestone-300-Days.md)
