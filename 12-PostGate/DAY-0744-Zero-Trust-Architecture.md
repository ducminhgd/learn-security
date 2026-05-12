---
title: "Day 744 — Zero Trust Architecture: Never Trust, Always Verify"
tags: [zero-trust, beyondcorp, spiffe, spire, ztna, microsegmentation,
  identity-aware-proxy, conditional-access, module-12-post-gate]
module: 12-PostGate
day: 744
prerequisites:
  - Day 743 — Cloud-Native Security (Kubernetes, Istio mTLS)
  - Day 527 — Kubernetes Security (Module 08)
  - Day 401 — OAuth 2.0 and OIDC (Module 06)
related_topics:
  - Day 745 — Final Synthesis
---

# Day 744 — Zero Trust Architecture: Never Trust, Always Verify

> "The perimeter is dead. Not 'weakened'. Not 'reduced'. Dead. The moment you
> put a corporate device on a coffee shop WiFi, or let an employee VPN in from
> a compromised home network, or deploy a workload in a cloud provider you do
> not control, you shattered the castle-and-moat model. Zero Trust is not a
> product you buy. It is the acceptance that your network is already hostile —
> and building as if that is true from day one."
>
> — Ghost

---

## Goals

1. Understand Zero Trust as a security model, not a product: the three core
   principles and where they break traditional architecture assumptions.
2. Analyse the BeyondCorp model — the first large-scale Zero Trust deployment —
   and map its components to your own environment.
3. Understand SPIFFE/SPIRE for workload identity and how it provides the
   cryptographic identity layer Zero Trust requires.
4. Implement a practical conditional access policy framework.
5. Map Zero Trust principles to the MITRE ATT&CK techniques they mitigate.

---

## Prerequisites

- Day 743 (Kubernetes mTLS with Istio — a Zero Trust implementation at the
  pod layer).
- Day 401 (OAuth/OIDC — the identity protocols Zero Trust builds on).

---

## 1 — Zero Trust: The Three Principles

```
ZERO TRUST — CORE PRINCIPLES

PRINCIPLE 1: NEVER TRUST, ALWAYS VERIFY
  Traditional model: "Inside the network? Trusted."
  Zero Trust model: "On the network means nothing. Prove identity every time."

  Implication: Every request — from a user, a device, a service — must
  authenticate and authorise before accessing any resource, regardless of
  network location.

  What this kills:
    - Implicit trust for anything inside the corporate network
    - VPN as a trust boundary ("connected to VPN = trusted")
    - IP address as an identity signal

PRINCIPLE 2: ASSUME BREACH
  Traditional model: Build strong walls; if nothing breaches them, we are safe.
  Zero Trust model: Act as if a breach has already occurred — or will occur.

  Implication: Design systems so a breached endpoint or credential causes
  minimal damage. Limit blast radius by design.

  What this enables:
    - Micro-segmentation (a compromised pod cannot reach the database)
    - Just-In-Time access (credentials expire; no persistent privileged sessions)
    - Continuous monitoring (detect lateral movement after the initial breach)

PRINCIPLE 3: VERIFY EXPLICITLY
  Traditional model: Verify once (at login), then trust for the session.
  Zero Trust model: Verify continuously — identity, device health, context,
  behaviour — on every access decision.

  Signals used in continuous verification:
    - Identity: Who are you? (User identity via IdP, workload identity via SPIFFE)
    - Device: Is your device healthy? (MDM compliance, patch level, disk encryption)
    - Context: Where are you? What time is it? Is this a normal pattern?
    - Behaviour: Does this request match historical access patterns?
```

---

## 2 — BeyondCorp: The First Zero Trust at Scale

Google's BeyondCorp programme (2014–2017) replaced the traditional VPN model
for all Google employees. It is the most documented Zero Trust deployment
in the industry.

```
BEYONDCORP ARCHITECTURE

TRADITIONAL VPN MODEL:
  [Employee Device] → [VPN Gateway] → [Corporate Network] → [Application]
  Trust boundary: the VPN. Inside VPN = trusted. Outside = untrusted.
  Problem: VPN credential compromise = full internal network access.

BEYONDCORP MODEL:
  [Employee Device] → [Identity-Aware Proxy] → [Application]
  No VPN. No corporate network. Applications are exposed to the internet.
  Trust boundary: identity + device health. No network position trust.

BEYONDCORP COMPONENTS:

  1. DEVICE INVENTORY DATABASE
     - Every device that can access corporate resources is enrolled
     - Device certificate issued; tracks: OS version, patch level, disk
       encryption status, MDM compliance
     - Non-enrolled device = no access, regardless of credentials

  2. USER/GROUP DATABASE
     - Identity source of truth (usually via LDAP/Active Directory or IdP)
     - Maps users to access groups and roles
     - Integrated with HR system: offboarded employees lose access automatically

  3. ACCESS CONTROL ENGINE
     - Policy evaluation engine: takes (user, device, resource, context)
     - Returns: allow / deny / step-up authentication required
     - Policies expressed as: "SRE group + managed device + low-risk context
       → allow access to prod-read API"

  4. IDENTITY-AWARE PROXY (IAP)
     - Sits in front of every application
     - Validates: identity token (OIDC), device certificate, access policy
     - Application never receives unauthenticated requests
     - Applications do NOT need to implement their own authentication

  5. SSO + MFA
     - Single Sign-On via SAML/OIDC to the central IdP
     - MFA required: FIDO2 hardware keys preferred (phishing-resistant)
     - Short-lived tokens; re-authentication triggered by policy changes

ACCESS FLOW:
  1. Employee opens browser → navigates to internal app URL
  2. IAP intercepts → checks: is there a valid session token? No →
  3. IAP redirects to SSO login → employee authenticates (MFA)
  4. IAP checks device certificate → is device enrolled and compliant? No →
     deny with "enrol your device" message
  5. IAP evaluates access policy → does this user + device + context
     match the policy for this resource? No → deny 403
  6. IAP forwards request to backend application with user identity header:
     X-Goog-Authenticated-User-Email: user@company.com
  7. Application trusts that header; renders response

GOOGLE OPEN SOURCE IMPLEMENTATIONS:
  - Cloud IAP (GCP): fully managed IAP service
  - Pomerium (pomerium.com): open-source IAP, self-hosted
  - Teleport: access plane for SSH, Kubernetes, databases with Zero Trust model
```

---

## 3 — SPIFFE/SPIRE: Workload Identity

Zero Trust for users relies on IAP + OIDC. Zero Trust for *workloads* (services,
pods, functions) requires a different identity layer: **SPIFFE**.

```
SPIFFE — SECURE PRODUCTION IDENTITY FRAMEWORK FOR EVERYONE

PROBLEM:
  Service A calls Service B. How does Service B know the request is really
  from Service A? Options:
    - Shared API key → secret management nightmare; if leaked, all trust broken
    - IP allowlist → IP addresses are not identity; pods change IPs constantly
    - mTLS with manually managed certificates → does not scale; cert rotation
      is a persistent operational failure mode
  SPIFFE solves this with cryptographic workload identity that is:
    - Automatically issued at workload startup
    - Short-lived (rotated continuously)
    - Not tied to network location

SPIFFE ID:
  Format: spiffe://<trust-domain>/<path>
  Example: spiffe://prod.example.com/ns/payments/sa/payment-service
  This is a URI that uniquely identifies a workload (not a machine, not an IP).

SVID — SPIFFE VERIFIABLE IDENTITY DOCUMENT:
  The credential a workload presents. Two formats:
  - X.509-SVID: a TLS certificate with the SPIFFE ID in the Subject Alt Name
    Used for: mTLS between services (mutual authentication)
  - JWT-SVID: a JWT with the SPIFFE ID as the subject
    Used for: HTTP header-based identity (e.g. REST APIs)

SPIRE — THE REFERENCE SPIFFE IMPLEMENTATION:

  Architecture:
  ┌────────────────────────────────────────────────────────┐
  │  SPIRE Server                                          │
  │  - Root CA and intermediate CA management              │
  │  - Registration API: define which workloads get which  │
  │    SPIFFE IDs                                          │
  │  - Node attestation: verify the node is legitimate     │
  │    (AWS IMDSv2, GCP metadata, TPM attestation, etc.)   │
  └────────────────────────────────────────────────────────┘
           ↕ node attestation, SVID issuance
  ┌────────────────────────────────────────────────────────┐
  │  SPIRE Agent (runs on each node)                       │
  │  - Attests to SPIRE Server: "I am a legitimate node"   │
  │  - Workload API: listens on a Unix socket              │
  │  - Workload attestation: verifies the workload's       │
  │    identity (Kubernetes SA, Docker label, process UID) │
  │  - Issues SVIDs to attested workloads                  │
  └────────────────────────────────────────────────────────┘
           ↕ Workload API (Unix socket)
  ┌────────────────────────────────────────────────────────┐
  │  Your Workload (pod/service)                           │
  │  - Calls Workload API: "Give me my SVID"               │
  │  - Receives: X.509 certificate with SPIFFE ID          │
  │  - Uses certificate for mTLS to other services         │
  │  - Certificate auto-rotated every 1 hour (default)     │
  └────────────────────────────────────────────────────────┘
```

```bash
# SPIRE quick-start on Kubernetes
# Install SPIRE server and agent:
kubectl apply -f https://spiffe.io/downloads/latest/spire-k8s.yaml

# Register a workload:
kubectl exec -n spire spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://example.org/ns/default/sa/payment-service \
    -parentID spiffe://example.org/spire/agent/k8s_sat/default \
    -selector k8s:ns:default \
    -selector k8s:sa:payment-service

# The workload fetches its SVID:
kubectl exec payment-service-pod -- \
    /opt/spire/bin/spire-agent api fetch x509 \
    -socketPath /run/spire/sockets/agent.sock
# Returns: X.509 SVID with spiffe://example.org/ns/default/sa/payment-service
# in the Subject Alt Name field — ready for mTLS
```

---

## 4 — Conditional Access Policy Framework

Conditional access is the operational implementation of "Verify Explicitly."
Every access request is evaluated against a policy that considers multiple
signals — not just "is the user authenticated?"

```
CONDITIONAL ACCESS POLICY STRUCTURE

Policy: <ALLOW | DENY | STEP-UP> access to <resource>
        when <conditions>

CONDITIONS (signals evaluated at access time):

1. IDENTITY CONDITIONS:
   - User.group IN [engineering, sre]
   - User.mfa_method == "FIDO2"    # phishing-resistant only
   - User.last_password_change < 90 days
   - ServiceAccount.spiffe_id == "spiffe://prod/payments"

2. DEVICE CONDITIONS:
   - Device.enrolled == true
   - Device.os_patch_level >= "2025-01-01"
   - Device.disk_encrypted == true
   - Device.edr_installed == true
   - Device.jailbroken == false

3. NETWORK/CONTEXT CONDITIONS:
   - Request.ip_risk_score < 30          # threat intel enrichment
   - Request.country IN [VN, SG, US]
   - Request.time BETWEEN 07:00 AND 22:00 (local)
   - Request.anomaly_score < 50          # ML-based anomaly detection

4. RESOURCE CONDITIONS:
   - Resource.sensitivity IN [low, medium]    # allow
   - Resource.sensitivity == high             # require step-up MFA
   - Resource.sensitivity == critical         # deny from non-corporate device

POLICY EXAMPLES:

Policy: prod-api-read
  ALLOW access to api.prod/v1/read
  when:
    User.group == "engineers"
    AND Device.enrolled == true
    AND Device.compliant == true

Policy: prod-api-write
  ALLOW access to api.prod/v1/write
  when:
    User.group == "engineers"
    AND Device.enrolled == true
    AND User.mfa_method == "FIDO2"      # hardware key required for writes

Policy: admin-console
  STEP-UP → re-authenticate with FIDO2
  THEN ALLOW access to admin.prod
  when:
    User.group == "sre"
    AND Device.enrolled == true
    AND session_step_up_completed == true
    ELSE DENY

Policy: any-resource
  DENY if:
    Device.enrolled == false
    OR Device.jailbroken == true
    OR User.account_suspended == true
    OR Request.ip_risk_score > 80       # high-risk IP (TOR, known bad)
```

```python
#!/usr/bin/env python3
# conditional_access_evaluator.py — simplified policy engine

from dataclasses import dataclass
from enum import Enum
from typing import List

class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"

@dataclass
class AccessContext:
    user_id: str
    user_groups: List[str]
    mfa_method: str           # "totp" | "fido2" | "sms" | "none"
    device_enrolled: bool
    device_compliant: bool
    device_jailbroken: bool
    ip_risk_score: int        # 0–100
    resource_sensitivity: str  # "low" | "medium" | "high" | "critical"

def evaluate_access(ctx: AccessContext) -> tuple[Decision, str]:
    """Evaluate access request against Zero Trust policies."""

    # Hard denies — check first
    if ctx.device_jailbroken:
        return Decision.DENY, "Jailbroken/rooted device not permitted"

    if not ctx.device_enrolled:
        return Decision.DENY, "Device not enrolled in MDM"

    if ctx.ip_risk_score > 80:
        return Decision.DENY, f"IP risk score too high: {ctx.ip_risk_score}"

    # Resource sensitivity gates
    if ctx.resource_sensitivity == "critical":
        if not ctx.device_compliant:
            return Decision.DENY, "Critical resources require fully compliant device"
        if ctx.mfa_method != "fido2":
            return Decision.DENY, "Critical resources require FIDO2 hardware key"

    elif ctx.resource_sensitivity == "high":
        if ctx.mfa_method not in ("fido2", "totp"):
            return Decision.DENY, "High-sensitivity resources require MFA"
        if not ctx.device_compliant:
            return Decision.STEP_UP, "Step-up: complete device compliance check"

    elif ctx.resource_sensitivity in ("low", "medium"):
        if not ctx.device_compliant:
            return Decision.STEP_UP, "Step-up: device compliance required"

    return Decision.ALLOW, "Access granted"

# Test the evaluator:
ctx = AccessContext(
    user_id="alice@company.com",
    user_groups=["engineering"],
    mfa_method="fido2",
    device_enrolled=True,
    device_compliant=True,
    device_jailbroken=False,
    ip_risk_score=10,
    resource_sensitivity="high",
)
decision, reason = evaluate_access(ctx)
print(f"Decision: {decision.value} — {reason}")
# Decision: allow — Access granted
```

---

## 5 — Zero Trust vs. Traditional Architecture: Attack Path Comparison

```
ATTACK PATH: CREDENTIAL THEFT → LATERAL MOVEMENT

TRADITIONAL NETWORK (VPN-based):
  Attacker steals VPN credentials via phishing.
  → Attacker connects to VPN.
  → Attacker is now "inside the network" — all internal services visible.
  → Attacker scans 10.0.0.0/8, finds 5000 internal hosts.
  → Attacker pivots: SMB relay, Kerberoasting, LDAP queries.
  → 4 hours later: Domain Admin.
  Control that could have stopped this: nothing (credential was valid).

ZERO TRUST ARCHITECTURE:
  Attacker steals user credentials (no VPN to steal — ZTNA model).
  → Attacker attempts login → MFA challenge (FIDO2).
  → Attacker cannot pass FIDO2 (phishing-resistant) → blocked.
  IF attacker also has the FIDO2 key (physical theft):
  → Login succeeds → Conditional Access checks device certificate.
  → Attacker's device is not enrolled → DENY.
  IF attacker uses victim's device:
  → Login succeeds + device enrolled → Access limited to victim's permissions.
  → No network scan possible: no network access granted, only application access.
  → Attacker can only access what alice@company.com can access via the IAP.
  → Blast radius = alice's data. Not 5000 hosts.

MITRE ATT&CK TECHNIQUES MITIGATED BY ZERO TRUST:

  T1133 External Remote Services (VPN abuse)
    Mitigation: ZTNA eliminates VPN; no network access without per-request auth.

  T1078 Valid Accounts (credential theft)
    Mitigation: FIDO2 MFA (phishing-resistant) + device compliance gate.

  T1021 Remote Services (lateral movement via SMB/RDP/SSH)
    Mitigation: No implicit network access; services require SPIFFE mTLS identity.

  T1049 System Network Connections Discovery
    Mitigation: No network to scan; IAP does not expose internal network topology.

  T1558 Steal or Forge Kerberos Tickets (Kerberoasting/Golden Ticket)
    Mitigation: Reduced blast radius; SPIFFE workload identity replaces Kerberos
    for service-to-service — fewer SPNs to target.

  T1071 Application Layer Protocol (C2 via HTTP)
    Mitigation: All outbound traffic inspected via forward proxy with TLS
    interception; anomaly detection on outbound patterns.
```

---

## 6 — Practical Zero Trust Implementation Roadmap

```
ZERO TRUST MATURITY MODEL — 5 STAGES

STAGE 1 — IDENTITY FOUNDATION (Month 1–3)
  - Deploy a centralised IdP (Okta, Azure AD, Google Workspace)
  - Enforce MFA for ALL users — TOTP minimum, FIDO2 for privileged accounts
  - Audit service-to-service authentication: find all API keys, shared secrets
  - Enable SSO for all applications that support SAML/OIDC
  Observable outcome: Zero shared passwords between services.

STAGE 2 — DEVICE TRUST (Month 3–6)
  - Deploy MDM (Intune, Jamf, Google Endpoint Management)
  - Enrol all corporate devices; define compliance policy
  - Issue device certificates from internal PKI
  - Block access from non-enrolled devices (Conditional Access policy)
  Observable outcome: A stolen password from an un-enrolled device = no access.

STAGE 3 — APPLICATION MICROSEGMENTATION (Month 6–12)
  - Deploy an IAP in front of all internal applications
  - Remove VPN as the trust boundary (keep for legacy only, with strict policy)
  - Implement NetworkPolicy in Kubernetes clusters
  - Define RBAC for every application; remove wildcard permissions
  Observable outcome: A compromised service can only reach what it is authorised
  to reach. Lateral movement requires escalating one service at a time.

STAGE 4 — WORKLOAD IDENTITY (Month 12–18)
  - Deploy SPIFFE/SPIRE or a service mesh (Istio, Linkerd) for mTLS
  - Replace all API keys / shared secrets with SVID-based mTLS
  - All service-to-service traffic requires valid workload certificate
  - Rotate certificates automatically (≤1 hour lifetime)
  Observable outcome: A compromised container cannot authenticate as any other
  service — it only has its own SVID.

STAGE 5 — CONTINUOUS MONITORING + ADAPTIVE ACCESS (Month 18–24)
  - Deploy UEBA (User and Entity Behaviour Analytics)
  - Feed access logs into SIEM; build anomaly detection rules
  - Implement risk-based adaptive access: anomalous request → step-up MFA
  - Quarterly access reviews: remove unused permissions automatically
  Observable outcome: A valid credential used anomalously triggers re-auth
  or blocks before lateral movement completes.
```

---

## Key Takeaways

1. **Zero Trust is a model, not a product.** Vendors sell "Zero Trust solutions"
   but Zero Trust is the architectural principle that no network location confers
   trust. The principle must be applied across identity, device, network, and
   workload layers. A single product cannot implement it — it requires a
   systematic redesign of access controls.
2. **FIDO2 hardware keys are the single highest-ROI security control in a Zero
   Trust deployment.** Phishing is the primary credential theft vector. FIDO2
   is cryptographically bound to the origin — a phishing site cannot intercept
   a FIDO2 authentication. Every privileged account should use FIDO2. This is
   the control that breaks the most common attack chain.
3. **SPIFFE/SPIRE solves the workload identity problem that Kubernetes RBAC
   alone cannot.** A pod with the right ServiceAccount can call the API server
   — but that does not give it a cryptographic identity that another service can
   verify. SPIFFE provides the workload equivalent of a user certificate: a
   short-lived, automatically rotated, cryptographically verifiable identity
   that any service can validate without calling a central authority.
4. **Blast radius reduction is the Zero Trust outcome that matters most for
   incident response.** The goal is not to prevent all breaches — it is to
   ensure that a single compromised credential or workload cannot cascade into
   a full environment compromise. When IR comes in after a breach, the question
   is "how far did they get?" Zero Trust architecture is designed to make the
   answer to that question much smaller.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q744.1, Q744.2 …).

---

## Navigation

← Previous: [Day 743 — Cloud-Native Security](DAY-0743-Cloud-Native-Security.md)
→ Next: [Day 745 — Final Synthesis](DAY-0745-Final-Synthesis.md)
