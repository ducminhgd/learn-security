---
title: "Cloud Security Review — Complete Map of Days 181–195"
tags: [review, cloud-security, AWS, Azure, GCP, IAM, S3, SSRF, IMDS, Lambda,
       containers, persistence, detection, hardening, ATT&CK, CWE-mapping]
module: 04-BroadSurface-02
day: 196
related_topics:
  - All lessons in Days 181–195
  - Cloud Security Competency Check (Day 210)
---

# Day 196 — Cloud Security Review

> "Cloud security compresses five different disciplines: IAM, networking,
> storage, compute, and detection — all in a single environment where the
> attacker runs the same API calls as the administrator. The review is not
> about memorising services. It is about understanding the pattern: credential
> extraction → enumeration → escalation → persistence → exfiltration. That
> pattern is the same in every cloud environment. The tools change. The
> thinking does not."
>
> — Ghost

---

## Goals

By the end of today's review session you will be able to:

1. Trace the complete cloud attack kill chain from initial access to persistence.
2. Name the detection indicator and single most effective fix for every attack
   class covered in Days 181–195.
3. Map every attack to a MITRE ATT&CK for Cloud technique and a CWE.
4. Identify the five highest-impact cloud hardening controls.
5. Answer the review questions without notes in under 90 seconds each.

---

## Complete Attack Class Reference

| Day | Attack | Mechanism | ATT&CK | CWE | Detect | Fix |
|---|---|---|---|---|---|---|
| 184 | SSRF → IMDS (IMDSv1) | SSRF to `169.254.169.254` → role creds | T1552.005 | CWE-918 | CloudTrail: API calls from non-EC2 IP with ASIA* key | IMDSv2 required |
| 183 | IAM CreatePolicyVersion escalation | `iam:CreatePolicyVersion` → new `Action:*` version | T1098 | CWE-269 | CloudTrail: CreatePolicyVersion + SetDefaultPolicyVersion in sequence | Remove CreatePolicyVersion; use permission boundaries |
| 183 | PassRole + Lambda escalation | `iam:PassRole` + `lambda:CreateFunction` → admin code | T1098 | CWE-269 | CloudTrail: CreateFunction with high-priv role + Invoke | Restrict PassRole to specific role ARNs |
| 183 | Role chaining | `sts:AssumeRole` from low-priv → high-priv role | T1078.004 | CWE-269 | CloudTrail: AssumeRole chain; session name anomaly | Restrict sts:AssumeRole to specific roles |
| 185 | Public S3 bucket | `allUsers` ACL / bucket policy with `Principal:*` | T1530 | CWE-732 | S3 server access logs: GetObject from 0.0.0.0 | S3 Block Public Access (account level) |
| 185 | Terraform state exposure | tfstate in public S3 → plaintext secrets | T1552.001 | CWE-312 | tfstate keyword in S3 object key accessed publicly | Move tfstate to S3 with Block Public Access + encryption |
| 187 | Lambda env var theft | `lambda:GetFunctionConfiguration` → plaintext secrets | T1552.001 | CWE-312 | CloudTrail: GetFunctionConfiguration by non-CI/CD principal | Secrets Manager + remove secret env vars |
| 187 | Lambda event injection | User-controlled event field in `shell=True` | T1190 | CWE-78 | Lambda error logs: unexpected command output | Parameterised command; `shell=False` |
| 188 | Privileged container escape | `--privileged` → host filesystem mount | T1611 | CWE-250 | Falco: container making mount syscall | Never run `--privileged`; use seccomp profiles |
| 188 | Docker socket escape | `/var/run/docker.sock` mounted inside container | T1611 | CWE-250 | Falco: new container created via container process | Never mount Docker socket in containers |
| 188 | ECS task role theft | SSRF to `169.254.170.2` inside container | T1552.005 | CWE-918 | Unusual API calls with ECS task role in CloudTrail | Network policy blocking 169.254.170.2 from containers |
| 189 | Azure managed identity theft | SSRF to `169.254.169.254` with `Metadata: true` | T1552.005 | CWE-918 | Azure Monitor: token request from unusual IP | Conditional Access: require Azure resource source |
| 189 | Azure Blob public container | `allUsers` → anonymous read | T1530 | CWE-732 | Storage access logs: anonymous requests | Storage account: Disable Blob Public Access |
| 190 | GCP service account token theft | SSRF to `metadata.google.internal` | T1552.005 | CWE-918 | Cloud Audit Logs: token request from unusual IP | VPC Service Controls; workload identity |
| 190 | GCP bucket allUsers/allAuthenticatedUsers | IAM binding to allUsers | T1530 | CWE-732 | GCS access logs: anonymous requests | Remove allUsers binding; uniform bucket-level access |
| 191 | Backdoor IAM user | `iam:CreateUser` + `iam:AttachUserPolicy` + `iam:CreateAccessKey` | T1136.003 | CWE-269 | CloudTrail: CreateUser at unusual hour; admin policy attached | SCP denying CreateUser in production; CloudTrail alert |
| 191 | Cross-account backdoor role | Create role with external account trust | T1098 | CWE-269 | CloudTrail: CreateRole with external Principal + admin policy | CloudTrail alert on cross-account role creation |
| 191 | Lambda backdoor with schedule | EventBridge-triggered Lambda that recreates access | T1053.005 | CWE-269 | CloudTrail: CreateRule + PutTargets outside business hours | Audit all scheduled Lambdas; require IaC for changes |
| 191 | Shadow access key | Second `iam:CreateAccessKey` for existing user | T1098.001 | CWE-269 | CloudTrail: CreateAccessKey for a user who already has 1 key | IR must list ALL keys for ALL users |

---

## Cloud Attack Kill Chain Summary

```
Phase 1 — Initial Access
  Web vulnerability (SSRF, command injection, file upload)
  OR exposed cloud console credentials (GitHub leak, phishing)
  OR publicly accessible resource (S3, blob container)
  ↓

Phase 2 — Credential Extraction
  SSRF → IMDS → temporary IAM credentials
  OR Lambda GetFunctionConfiguration → env var secrets
  OR public S3 tfstate → plaintext secrets
  ↓

Phase 3 — Enumeration
  sts:GetCallerIdentity → identify role/user
  iam:ListPolicies + GetPolicyVersion → map permissions
  s3:ListAllMyBuckets, lambda:ListFunctions, ec2:DescribeInstances
  Pacu / enumerate-iam → automated permission discovery
  ↓

Phase 4 — Privilege Escalation
  sts:AssumeRole → higher-privilege role
  OR iam:CreatePolicyVersion → escalate own policy
  OR PassRole + Lambda → execute as admin role
  ↓

Phase 5 — Data Exfiltration
  s3:GetObject → download sensitive buckets
  secretsmanager:GetSecretValue → all secrets
  lambda:GetFunction → function code + embedded secrets
  ↓

Phase 6 — Persistence
  iam:CreateUser + iam:CreateAccessKey → backdoor user
  iam:CreateRole + trust external account → cross-account backdoor
  lambda:CreateFunction + events:PutRule → scheduled beacon
  iam:CreateAccessKey on existing user → shadow key
```

---

## Detection Summary Table

| Attack phase | Log source | Key indicator |
|---|---|---|
| IMDS credential theft | CloudTrail | ASIA* key used from non-EC2 source IP |
| IAM enumeration burst | CloudTrail | >30 distinct IAM read events per minute per ARN |
| Privilege escalation via CreatePolicyVersion | CloudTrail | CreatePolicyVersion + SetDefaultPolicyVersion in same session |
| Admin Lambda deployed | CloudTrail | CreateFunction with high-priv role ARN |
| S3 exfiltration | CloudTrail | GetObject count > 500 in 10 minutes per ARN |
| Backdoor user created | CloudTrail | CreateUser outside business hours; admin policy attached within 5 min |
| Cross-account role re-entry | CloudTrail | AssumeRole with callerAccountId not in org |
| Lambda beacon | CloudTrail | CreateFunction + PutRule + PutTargets in same session |
| Privileged container | Falco | Container with `privileged: true` or mount syscall |

---

## Key Hardening Controls (Priority Order)

```
1. IMDSv2 required (blocks SSRF-to-IMDS — the most common cloud initial access)
2. S3 Block Public Access at account level (eliminates accidental public buckets)
3. CloudTrail all-regions with integrity validation (enables all detection)
4. SCPs protecting CloudTrail/GuardDuty/Config from modification
5. Secrets Manager instead of environment variables
6. IAM least privilege: no wildcards, no iam:* in non-admin roles
7. Permission boundaries on all IAM roles created by automation
8. GuardDuty enabled in all regions
9. VPC endpoints for S3 and Secrets Manager (prevents exfiltration via internet)
10. Region restrictions via SCP (reduces blast radius)
```

---

## Self-Assessment Questions

Answer without notes. Target: 60 seconds per question.

1. An EC2 instance has `ec2-app-role` attached. The instance runs a Flask
   app with a `/fetch?url=` endpoint. IMDSv1 is enabled. Walk through the
   exact steps an attacker uses to extract the role credentials and what
   AWS API calls they make next.

2. A Lambda function has these environment variables: `DB_URL`,
   `STRIPE_KEY`, `JWT_SECRET`. What IAM permission does an attacker need
   to read them? What is the fix?

3. A Docker container runs with `--privileged` flag. The attacker has
   achieved RCE inside the container. List two distinct techniques to
   escape to the host OS. What process does the escape involve?

4. Describe the Lambda privilege escalation via `iam:PassRole`. What
   three IAM permissions are required? Write the AWS CLI command chain
   that executes the escalation.

5. What is a cross-account backdoor role? Write the trust policy JSON
   for a role that allows account `999999999999` to assume it with an
   ExternalId. Why is ExternalId used?

6. A CloudTrail alert fires for `CreateUser` at 3 AM. What are the first
   three IR steps you take? What other events would you search for in the
   same CloudTrail time window?

7. What is the difference between `allUsers` and `allAuthenticatedUsers`
   in a GCS bucket IAM binding? Which is more dangerous and why?

8. An SCP has `"Effect": "Deny", "Action": "cloudtrail:DeleteTrail"`.
   An account administrator with `AdministratorAccess` tries to delete
   a CloudTrail trail. Does the deletion succeed? Why?

9. Name the five cloud hardening controls in priority order. For each:
   which single attack class does it directly block?

10. In the Azure IMDS attack, what header is required that makes SSRF
    harder to exploit compared to AWS IMDSv1? What are two ways an
    attacker can still bypass this?

---

## Key Takeaways

1. **The cloud attack pattern is always: credential → enumerate → escalate →
   exfiltrate → persist.** The tools and service names differ by provider;
   the logic is identical across AWS, Azure, and GCP.
2. **IMDSv2 is the single highest-impact AWS security control.** It stops
   the most common cloud initial access technique (SSRF to IMDS). If you
   can only do one thing today, do this.
3. **IAM misconfiguration is not the cloud provider's failure — it is the
   customer's.** The shared responsibility model is clear: IAM is fully
   customer-managed. Over-permissioned roles are a design choice, not a bug.
4. **Cross-account backdoor roles are the hardest persistence artefact to
   detect and remove.** They survive credential rotation, incident response,
   and password resets. Audit trust policies as part of every IR.
5. **CloudTrail is the ground truth.** Every API call is logged. Without
   CloudTrail analysis, cloud IR is guesswork. With CloudTrail analysis
   and pre-written detection queries, IR is a matter of running the right
   queries on the right time window.

---

## Exercises

1. Without notes: write the Python script that extracts IMDS credentials
   via SSRF, assumes a higher-privilege role, lists all S3 buckets, and
   downloads the most sensitive file. Time yourself. Target: under 10 minutes.
2. Draw the full cloud kill chain from Day 192 from memory. Label each step
   with: (a) the AWS API call, (b) the CloudTrail event name, (c) the
   detection rule that would catch it.
3. Review the SYLLABUS for the cloud module. List every topic covered.
   Identify two topics you are least confident on. Spend 30 minutes
   re-reading those lessons before the practice days.
4. Write the SCP from Part 3 of Day 195 (deny CloudTrail modification)
   from memory. Apply it to a test OU in LocalStack or a test AWS account.
   Confirm that even an admin user cannot stop CloudTrail.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q196.1, Q196.2 …).
> Follow-up questions use hierarchical numbering (Q196.1.1, Q196.1.2 …).

---

## Navigation

← Previous: [Day 195 — Cloud Hardening](DAY-0195-Cloud-Hardening.md)
→ Next: [Day 197 — Cloud Practice: IAM Privilege Escalation](DAY-0197-Cloud-Practice-IAM-PrivEsc.md)
