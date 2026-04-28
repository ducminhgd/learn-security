---
title: "Cloud Threat Model — Shared Responsibility, Cloud-Specific Attack Surface"
tags: [cloud-security, threat-model, AWS, Azure, GCP, shared-responsibility,
       attack-surface, IAM, metadata-service, SSRF, ATT&CK-T1552, MITRE]
module: 04-BroadSurface-02
day: 181
related_topics:
  - SSRF Fundamentals (Day 113)
  - IAM Misconfiguration Attacks (Day 183)
  - Cloud Hardening (Day 195)
---

# Day 181 — Cloud Threat Model

> "The cloud is not a magic security layer. It is someone else's computer,
> where you are responsible for everything above the hypervisor — and most
> teams do not know exactly where that line is. The shared responsibility
> model is not a contract that protects you. It is a map that tells an attacker
> exactly which problems the cloud provider does not fix for you."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain the shared responsibility model for AWS, Azure, and GCP and
   identify the security boundary between provider and customer responsibility.
2. Map the cloud-specific attack surface: metadata service, IAM, storage,
   compute, serverless, and network.
3. Describe how traditional web attacks pivot into cloud attacks (SSRF →
   metadata → credential theft).
4. Build a threat model for a simple three-tier cloud application using
   STRIDE.
5. Map cloud attack techniques to MITRE ATT&CK for Cloud.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| SSRF fundamentals | Day 113 |
| Auth attacks (IAM is auth) | Days 166–177 |
| HTTP and web architecture | Day 21 |
| Basic Linux | Days 9–10 |

---

## Part 1 — Shared Responsibility Model

Every major cloud provider publishes a shared responsibility model.
The details differ; the principle is identical:

```
Cloud Provider Responsible For:
  ├── Physical security (datacentre, hardware)
  ├── Hypervisor and host OS
  ├── Network infrastructure
  └── Managed service availability (RDS, Lambda runtime, S3 durability)

Customer Responsible For:
  ├── IAM (who can access what)
  ├── Data classification and encryption
  ├── Network configuration (security groups, VPC, NACLs)
  ├── OS patching (EC2, self-managed VMs)
  ├── Application code and configuration
  └── Logging and monitoring configuration
```

**The attacker's read of this model:**

The provider will not be breached at the hypervisor level (practically).
Every cloud breach in the public record was in the customer-managed layer:
- IAM misconfiguration (Capital One 2019: SSRF → IMDS → overly permissive role)
- Public S3 bucket (Twitch 2021: 125 GB of internal data from misconfigured bucket)
- Exposed secrets in Lambda env vars, Git repos, Docker images
- Over-privileged CI/CD pipelines with cross-account access

---

## Part 2 — Cloud-Specific Attack Surface

### 2.1 — Instance Metadata Service (IMDS)

Every cloud provider runs a metadata endpoint reachable only from within the
instance or container. It provides:

- Instance identity and tags
- **Temporary credentials for the attached IAM role / service account**
- User data (bootstrap scripts — often contain secrets)
- Network configuration

| Provider | Metadata endpoint | Key credential path |
|---|---|---|
| AWS | `http://169.254.169.254/` | `/latest/meta-data/iam/security-credentials/{role-name}` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `/metadata/identity/oauth2/token` |
| GCP | `http://metadata.google.internal/` | `/computeMetadata/v1/instance/service-accounts/default/token` |

**Why this matters for attackers:** SSRF (Server-Side Request Forgery) to the
metadata endpoint extracts temporary cloud credentials that are valid for
1–12 hours. This is the single most common cloud initial access technique.

### 2.2 — IAM (Identity and Access Management)

Cloud IAM is fundamentally different from traditional RBAC:

```
Traditional RBAC:
  User → Role → Permission

Cloud IAM:
  Principal (user/role/service account)
    → Policy (JSON document)
      → Resource (S3 bucket/EC2/Lambda/RDS)
        → Condition (IP, time, MFA status)
```

**Attack surface in IAM:**
- Overly permissive policies (wildcards: `"Action": "*"`, `"Resource": "*"`)
- Misconfigured trust relationships (who can assume a role)
- Inline policies vs managed policies (inline = harder to audit)
- Role chaining (assume role A → use role A to assume role B with more access)
- Permission boundary misconfigurations
- Long-lived access keys vs short-lived role credentials

### 2.3 — Object Storage

| Provider | Service | Attack patterns |
|---|---|---|
| AWS | S3 | Public read ACL; public bucket policy; pre-signed URL abuse; bucket name guessing |
| Azure | Blob Storage | Public container; SAS token leakage; anonymous read |
| GCP | Cloud Storage | allUsers / allAuthenticatedUsers ACLs; uniform vs fine-grained access |

Object storage is the most frequently misconfigured cloud resource. The attack
is simple: enumerate publicly accessible buckets and retrieve sensitive data.

### 2.4 — Serverless

Lambda (AWS), Functions (Azure/GCP) attack surface:

- **Environment variables** — secrets passed as env vars are visible in the
  function configuration to anyone with `lambda:GetFunctionConfiguration`
- **Event injection** — function input is user-controlled; SQLi, SSTI, command
  injection inside the function are all possible
- **Over-privileged execution role** — a Lambda with `iam:*` can create
  admin users; one with `s3:*` can read every bucket

### 2.5 — Container and Orchestration

| Component | Attack |
|---|---|
| Container runtime | Privileged escape via host mount, Docker socket, `--privileged` flag |
| Kubernetes | SSRF to API server; misconfigured RBAC; exposed dashboard |
| ECS (AWS) | SSRF to task metadata endpoint → task role credentials |
| ECR (AWS) | Public image repository; weak image scanning |

---

## Part 3 — How Web Attacks Pivot to Cloud

This is the kill chain pattern that appears in the majority of cloud breaches:

```
Step 1 — Web vulnerability (SSRF, XXE, open redirect)
          ↓
Step 2 — Request to metadata endpoint (http://169.254.169.254/)
          ↓
Step 3 — Extract temporary credentials (AccessKeyId, SecretAccessKey, SessionToken)
          ↓
Step 4 — Use credentials from attacker machine (aws configure + token)
          ↓
Step 5 — Enumerate permissions (what can this role do?)
          ↓
Step 6 — Exploit permissions (read S3, create admin user, invoke Lambda, etc.)
          ↓
Step 7 — Escalate privileges (assume a more powerful role, create persistent access)
          ↓
Step 8 — Persist (backdoor IAM user, create cross-account role, plant Lambda)
```

**Capital One 2019 — Real Kill Chain:**

```
SSRF vulnerability in WAF configuration
  → metadata endpoint on EC2 running WAF
  → temporary credentials for attached IAM role
  → role had overly permissive S3 access
  → attacker listed and downloaded 100+ S3 buckets
  → 106 million customer records exfiltrated
Impact: $190M fine + remediation costs
```

---

## Part 4 — Threat Modelling a Cloud Application

### STRIDE Applied to a Three-Tier Cloud App

**Target architecture:**

```
Internet → ALB (Load Balancer)
                ↓
         EC2 web tier (IAM role: ec2-web-role)
                ↓
         RDS PostgreSQL (private subnet)
         S3 bucket (customer uploads)
         Lambda (async processing)
```

**STRIDE threat model:**

| STRIDE | Asset | Threat | Mitigation |
|---|---|---|---|
| **S**poofing | ALB | Forge requests bypassing ALB to EC2 directly | Security group: EC2 only accepts from ALB |
| **T**ampering | S3 | Attacker modifies uploaded files | Object integrity checks; versioning |
| **R**epudiation | CloudTrail | Attacker disables logging to cover tracks | CloudTrail integrity validation; GuardDuty |
| **I**nformation Disclosure | IMDS | SSRF to 169.254.169.254 exposes role creds | IMDSv2 required (token-based); block at app level |
| **D**enial of Service | Lambda | Invoke Lambda in loop; concurrency exhaustion | Reserved concurrency limits; WAF rate limiting |
| **E**levation of Privilege | ec2-web-role | SSRF → creds → role has `iam:CreateUser` → admin | Least-privilege policy; no IAM write from web tier |

---

## Part 5 — MITRE ATT&CK for Cloud

ATT&CK has a dedicated Cloud matrix. Key techniques this module covers:

| Technique | ID | What we do |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Web exploit → SSRF → metadata |
| Cloud Instance Metadata API | T1552.005 | SSRF to 169.254.169.254 → steal creds |
| Unsecured Credentials in Environment | T1552.001 | Lambda env vars, EC2 user-data |
| Valid Accounts — Cloud Accounts | T1078.004 | Use stolen IAM creds from attacker machine |
| Permission Groups Discovery | T1069.003 | Enumerate IAM groups, roles, policies |
| Cloud Infrastructure Discovery | T1580 | Enumerate EC2, S3, Lambda, RDS |
| Create Cloud Account | T1136.003 | Create backdoor IAM user |
| Account Manipulation | T1098 | Attach policy to attacker-controlled principal |
| Transfer Data to Cloud Account | T1537 | Exfiltrate to attacker-controlled S3 |
| Modify Cloud Compute Infrastructure | T1578 | Snapshot EC2 → mount → read data |

---

## Key Takeaways

1. **The shared responsibility model defines the attack surface.** The cloud
   provider secures the infrastructure; everything the customer configures is
   customer-managed and therefore the attacker's target.
2. **SSRF + IMDS is the most impactful single-step cloud attack.** A single
   SSRF vulnerability in a web application running on EC2 can extract IAM
   credentials valid for hours. One vulnerability = potential account
   compromise.
3. **IAM is the most important cloud security domain.** Every other cloud
   control (storage ACLs, network security groups, encryption) can be bypassed
   by a sufficiently privileged IAM principal. Least privilege is not optional.
4. **Cloud attacks look different from traditional attacks.** There is no
   exploit code, no memory corruption. The "exploit" is often a valid API call
   with stolen credentials. The log noise is identical to legitimate traffic.
5. **The kill chain from web to cloud is well-documented and commonly found.**
   Capital One, Uber, Twitch — the pattern repeats. SSRF + overpermissive role =
   catastrophic data breach.

---

## Exercises

1. Draw the complete kill chain for the Capital One 2019 breach from first
   principles. Identify every step where a security control could have stopped
   the attack. Which single control would have had the highest impact?
2. For the three-tier architecture in Part 4: write an IAM policy document
   for `ec2-web-role` that follows least privilege. The web tier only needs to:
   read/write objects to a specific S3 bucket prefix, and invoke one specific
   Lambda function. Write the policy JSON.
3. Research: what is IMDSv2 and how does it prevent SSRF exploitation of the
   metadata endpoint? What HTTP header is required? How does the token
   acquisition flow work?
4. Using the STRIDE template from Part 4, build a threat model for a
   serverless application: API Gateway → Lambda → DynamoDB + S3. List at least
   one threat per STRIDE category and one mitigation per threat.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q181.1, Q181.2 …).
> Follow-up questions use hierarchical numbering (Q181.1.1, Q181.1.2 …).

---

## Navigation

← Previous: [Day 180 — Auth Attacks Competency Check](../04-BroadSurface-01/DAY-0180-Auth-Attacks-Competency-Check.md)
→ Next: [Day 182 — AWS IAM Fundamentals](DAY-0182-AWS-IAM-Fundamentals.md)
