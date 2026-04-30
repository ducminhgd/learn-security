---
title: "Practice Checkpoint — Cloud and Container (Days 521–529)"
tags: [red-team, checkpoint, cloud, AWS, Azure, Kubernetes, container, hybrid-identity,
  consolidation, ATT&CK]
module: 08-RedTeam-03
day: 530
related_topics:
  - Cross-Environment Attack Paths (Day 529)
  - Practice Checkpoint Days 511–519 (Day 520)
  - AWS Red Teaming (Days 523–524)
  - Azure Red Teaming (Days 525–526)
  - Kubernetes and Container (Days 527–528)
---

# Day 530 — Practice Checkpoint: Cloud and Container

> "Cloud security is the same game, different board. The attacker's objective
> is unchanged: find a credential, escalate, achieve the objective, persist.
> But the credentials are tokens that expire in an hour, the escalation paths
> are IAM policies instead of ACLs, and the persistence is a service principal
> secret instead of a registry key. If you do not know the differences cold,
> you will be slow in the field. Today measures that."
>
> — Ghost

---

## Goals

Measure retention and execution ability for Days 521–529 techniques.
Identify gaps between conceptual understanding and hands-on execution.
Produce a prioritised re-lab plan for cloud and container techniques.

**Prerequisites:** Days 521–529 completed. AWS lab account + Azure trial tenant
+ local Kubernetes lab (kind/minikube) configured.
**Time budget:** 6 hours.

---

## Part 1 — Self-Assessment Before the Lab

Rate each technique **before** you open the lab.

```
Rating scale:
  1 — Cannot execute without step-by-step reference
  2 — Can execute with notes open; would miss steps independently
  3 — Can execute without notes; might miss edge cases
  4 — Can execute, explain the mechanism, detect it, and remediate it

TECHNIQUE                                       | RATING | LAST EXECUTED
------------------------------------------      | ------ | ----------------
C2 multi-tier: redirector + teamserver          |        |
Nginx redirector: only C2 path forwarded        |        |
Cloudflare Worker as C2 relay                   |        |
Malleable profile: Office 365 header mimicry    |        |
VPS OPSEC: disable logging, restrict firewall   |        |
Domain registration OPSEC (cert + WHOIS)        |        |
AWS: sts get-caller-identity fingerprint        |        |
AWS IMDS: curl 169.254.169.254 credential chain |        |
AWS IAM: CreatePolicyVersion priv esc           |        |
AWS: CloudTrail event for CreatePolicyVersion   |        |
Azure: roadrecon gather + SQLite query          |        |
Azure: service principal credential add         |        |
Azure: PRT theft concept (ROADtoken)            |        |
Azure: legacy auth IMAP spray                   |        |
Azure: Managed Identity IMDS token              |        |
K8s: read SA token from /var/run/secrets/...    |        |
K8s: kubectl via SA token from inside a pod     |        |
K8s: escape via privileged pod + hostPath       |        |
K8s: escape via Docker socket mount             |        |
K8s: OPA/Kyverno policy to block priv pods      |        |
Golden SAML: export ADFS signing cert           |        |
Golden SAML: forge token for any user           |        |
AAD Connect: MSOL$ account DCSync rights        |        |
Seamless SSO: AZUREADSSOACC$ Silver Ticket path |        |
```

---

## Part 2 — Timed Challenges (3 Hours 30 Min)

---

### Challenge 1 — AWS Credential Chain (45 min)

**Target state:** Full account access obtained from a simulated SSRF → IMDS
credential theft → privilege escalation.

```
Lab setup:
  → AWS lab account with an EC2 instance (IMDSv1 enabled)
  → EC2 IAM role: EC2AppRole with s3:ListBuckets, iam:ListRoles, iam:CreatePolicyVersion
  → A DevPolicy ARN in the account
  → An S3 bucket with a "credentials.txt" file

Your mission (time yourself):
  1. Simulate IMDS access: curl 169.254.169.254 for credentials (from inside the EC2)
  2. Export the credentials; verify with sts get-caller-identity
  3. List all S3 buckets; read credentials.txt
  4. Identify iam:CreatePolicyVersion is permitted on DevPolicy
  5. Escalate via CreatePolicyVersion → AdministratorAccess
  6. Create a backdoor IAM user with admin access
  7. List all events in CloudTrail that you generated (last 30 minutes)

Time: 45 minutes.
Stop at 45 min regardless of completion. Record your stopping point.

Sticking points:
  → Exact curl command for IMDS credential path:
    ____________________________________________
  → CreatePolicyVersion policy JSON (write from memory):
    ____________________________________________
  → CloudTrail query to list your own actions:
    ____________________________________________
```

---

### Challenge 2 — Azure Token and SP Abuse (45 min)

**Target state:** Authenticated to Azure AD as a high-privilege Service Principal;
backdoor credential added; role assigned.

```
Lab setup:
  → Azure trial tenant with user jsmith (User Administrator role)
  → A Service Principal "HighPrivApp" with Application.ReadWrite.All
  → A target user "targetadmin" (Global Administrator)

Your mission:
  Part A — Enumeration:
    1. Run roadrecon gather as jsmith
    2. Query the SQLite DB to find all SPs with Directory.* permissions
    3. Query for all users with Global Administrator role

  Part B — SP credential backdoor:
    1. Find the HighPrivApp Service Principal object ID
    2. Add a new client secret (--append) with a 2-year expiry
    3. Authenticate as HighPrivApp with the new secret
    4. Verify: call Graph API to list all users

  Part C — Persistence:
    1. Add jsmith to the Global Administrator role using Graph API
    2. Verify the role assignment appears in the Azure AD audit log
    3. Identify which Azure AD audit log event fired (write the event name)
       Your answer: _________________________

Time: 45 minutes.

Sticking points:
  → roadrecon SQLite query for SPs with Directory permissions:
    ____________________________________________
  → az CLI command to add SP credential (exact flags):
    ____________________________________________
```

---

### Challenge 3 — Kubernetes Escape (45 min)

**Target state:** Root shell on the underlying kind/minikube host from inside a pod.

```
Lab setup:
  → kind or minikube cluster
  → A namespace "testns" with SA "test-sa"
  → test-sa has pods:create and pods:exec in testns

Your mission (no notes for the pod spec):
  1. Start a pod in testns running as test-sa with automountServiceAccountToken: true
  2. From inside the pod: read the SA token and verify kubectl access to the API server
  3. Run kubectl auth can-i --list — identify what actions are permitted
  4. Create the privileged escape pod YAML (write it from memory)
  5. Apply the escape pod; exec into it
  6. From inside the escape pod: read /host/etc/shadow

Score: 1 point per step completed. Goal = 6/6
Score: ___/6

Sticking points:
  → Escape pod YAML (write it from memory — do not look it up):

apiVersion: v1
kind: Pod
metadata:
  name: ________________
spec:
  ________________________
  ________________________
  containers:
  - name: shell
    image: ________________
    securityContext:
      ________________________
    volumeMounts:
    - name: host-root
      mountPath: ________________
  volumes:
  - name: host-root
    hostPath:
      path: ________________
```

---

### Challenge 4 — Hybrid Identity Concept Exam (30 min)

Answer without reference material. Check answers after.

```
1. What is the name of the on-prem AD account created by AAD Connect that has
   DCSync-equivalent rights?
   Your answer: _________________________
   (Answer: MSOL_xxxxxxxxxxxxxxxx — the sync account)

2. What NTLM hash do you need to forge a Seamless SSO Silver Ticket that
   authenticates to Azure AD?
   Your answer: _________________________
   (Answer: AZUREADSSOACC$ computer account NTLM hash)

3. What Azure AD audit log event fires when you add a credential to a Service
   Principal?
   Your answer: _________________________
   (Answer: "Add service principal credentials")

4. In a Golden SAML attack, what artifact is stolen from the ADFS server?
   Your answer: _________________________
   (Answer: the token-signing certificate private key — .pfx / private key material)

5. What is the Azure equivalent of 169.254.169.254/meta-data/iam/security-credentials/?
   Your answer: _________________________
   (Answer: 169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/)

6. Which Conditional Access policy control makes PRT theft less useful?
   Your answer: _________________________
   (Answer: Token Protection / device-bound tokens — binds the token to a specific device;
   PRT replay from a different device is then rejected)

7. What is the difference between IMDSv1 and IMDSv2 in AWS?
   Your answer: _________________________
   (Answer: IMDSv2 requires a PUT pre-request to obtain a session token, then GET requests
   with that token in a header. IMDSv1 allows direct GET requests with no pre-authentication.
   Most SSRF attacks cannot perform the PUT + GET sequence, making IMDSv2 resistant to SSRF.)

8. What Falco rule category detects the Docker socket escape technique?
   Your answer: _________________________
   (Answer: Any rule monitoring fd.name = /var/run/docker.sock inside a container;
   Falco's default rule "Contact Docker Socket" covers this.)
```

---

### Challenge 5 — Detection Writing (45 min)

Write detection logic for the following scenarios. Use Sigma YAML, KQL (Sentinel),
or CloudTrail Athena SQL as appropriate. Write them from memory first.

```
Detection 1: AWS IAM privilege escalation via CreatePolicyVersion
  Target query (CloudTrail Athena SQL):
  ___________________________________________________
  ___________________________________________________
  ___________________________________________________

Detection 2: Azure AD Service Principal with new credentials added by a
  non-admin account (KQL for Sentinel):
  ___________________________________________________
  ___________________________________________________
  ___________________________________________________

Detection 3: Kubernetes privileged pod created (Sigma YAML):
  Detection field: requestObject.spec.containers[].securityContext.privileged = true
  ___________________________________________________
  ___________________________________________________
  ___________________________________________________

Detection 4: Container process reading Docker socket (Falco rule condition):
  ___________________________________________________
  ___________________________________________________

Reference answers:
  Detection 1 (CloudTrail Athena SQL):
    SELECT eventTime, userIdentity.arn, requestParameters.policyArn,
           sourceIPAddress
    FROM cloudtrail_logs
    WHERE eventName = 'CreatePolicyVersion'
      AND requestParameters LIKE '%setAsDefault%true%'
    ORDER BY eventTime DESC;

  Detection 2 (KQL / Sentinel):
    AuditLogs
    | where OperationName == "Add service principal credentials"
    | where InitiatedBy.user.userPrincipalName !in (known_admin_accounts)
    | project TimeGenerated, OperationName, InitiatedBy, TargetResources

  Detection 3 (Sigma):
    logsource:
      product: kubernetes
      service: audit
    detection:
      selection:
        verb: create
        objectRef.resource: pods
        requestObject.spec.containers[].securityContext.privileged: true
      condition: selection

  Detection 4 (Falco):
    condition: container and open_write and fd.name = /var/run/docker.sock
```

---

## Part 3 — Gap Analysis

```
After completing Parts 1–2, fill in the table for each technique rated 1 or 2,
or for any challenge step where you failed.

TECHNIQUE               | Rating | Gap type | Next action
----------------------- | ------ | -------- | ---------------------
                        |        | A/B/C/D  |
                        |        |          |
                        |        |          |

Gap types (same as Day 520):
  A — Never ran it (only read it)
  B — Command syntax gaps (know the concept, miss the flags)
  C — Conceptual gap (do not understand why)
  D — Prerequisite gap (need to revisit an earlier lesson)

Priority order for re-lab:
  1. Any AWS/Azure technique rated 1: these are immediately applicable to
     real engagements; the gap costs money in a commercial red team context
  2. Kubernetes escape techniques: consistently underestimated by candidates
  3. Detection writing: if you cannot write the detection, you cannot convince
     a blue team to deploy it; that is a professional gap, not just a lab gap
```

---

## Part 4 — Free-Form Reflection (15 min)

Write three sentences only (no more, no less) for each prompt:

```
1. The cloud red teaming concept I understand most solidly:


2. The cloud red teaming concept where I still feel like a reader, not an operator:


3. The detection I would deploy TODAY if I were the defender of the lab environment
   we just attacked:


4. The one technique from Days 521–529 that I would add to my engagement toolkit
   immediately — and why:
```

---

## Key Takeaways

1. Cloud red teaming is IAM-first. In AWS and Azure, every attack path flows through
   IAM — credential to permission to action. If you cannot enumerate permissions
   quickly from a stolen token, you will miss the escalation path. Practice
   `enumerate-iam` and `roadrecon` until they are reflexes.
2. The IMDS endpoint is present in AWS, Azure, and GCP. Every cloud provider
   implements a variant. The attack pattern is identical: SSRF or code execution
   → `169.254.169.254` → temporary credentials → cloud API access. Know it cold
   for each provider.
3. Container escapes are a prerequisite for cloud red teaming. When you compromise
   a Kubernetes pod, the most powerful next step is not lateral movement to other
   pods — it is escaping to the underlying node and using the node's Managed
   Identity for full cloud account access. The escape enables the cloud pivot.
4. Hybrid identity is the highest-value target in a mature enterprise. ADFS
   token-signing certs and AAD Connect MSOL accounts are in almost every enterprise
   that has an on-prem AD. They are rarely rotated and rarely monitored. If you
   find them, you own both planes.
5. Detection across cloud and container requires log correlation that most
   organisations do not have. CloudTrail, Azure Audit Logs, K8s audit, and Falco
   are four separate streams. Exercises 5 identified specific detection gaps;
   the goal is to ensure your purple team deliverables address exactly those gaps
   with deployable detection content.

---

## Exercises

1. For any technique rated 1 after this checkpoint: execute it in the lab without
   any notes. If you cannot, identify the exact step where you fail and return to
   that day's lesson.
2. Build an ATT&CK Navigator layer covering all techniques from Days 521–529.
   Colour by confidence (same as Day 520). Compare to your Day 520 layer — has
   the pattern of gaps changed? Are they in different technique families?
3. Write a one-page "Cloud Red Team Engagement Preparation Checklist" covering:
   infrastructure setup, credential handling, enumeration order (AWS vs Azure),
   OPSEC controls, and post-engagement cleanup. Use it as your standard pre-
   engagement reference.
4. For one cloud or container technique you rated 4: write the full detection
   playbook for a blue team analyst. What log source? What query? What fields
   to collect for IR? What false positive conditions exist? This is the output
   format expected from a purple team engagement.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q530.1, Q530.2 …).

---

## Navigation

← Previous: [Day 529 — Cross-Environment Attack Paths](DAY-0529-Cross-Environment-Attack-Paths.md)
→ Next: [Day 531 — Advanced Persistence Techniques](DAY-0531-Advanced-Persistence.md)
