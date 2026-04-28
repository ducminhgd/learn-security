---
title: "Cloud Hardening — IMDSv2, SCPs, Resource-Based Policies, Least Privilege"
tags: [cloud-hardening, AWS, IMDSv2, SCP, service-control-policies, least-privilege,
       S3-block-public-access, CloudTrail, GuardDuty, AWS-Config, IAM,
       zero-trust, CIS-benchmark, cloud-security]
module: 04-BroadSurface-02
day: 195
related_topics:
  - Cloud Threat Model (Day 181)
  - IAM Misconfiguration Attacks (Day 183)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Persistence Techniques (Day 191)
  - Detecting Cloud Attacks (Day 194)
---

# Day 195 — Cloud Hardening

> "Cloud security is not a checklist. But if you do not have the checklist,
> you will miss the controls that stop 90% of attacks. IMDSv2 stops SSRF-to-
> metadata. Block Public Access stops S3 exposure. SCPs stop the entire
> class of account-level escalation via child accounts. These three controls
> would have prevented the Capital One breach, the Uber AWS breach, and the
> Twitch leak. Apply them. Then go build the detective layer on top."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Enforce IMDSv2 on all EC2 instances using AWS Config and instance launch
   templates.
2. Apply S3 Block Public Access at the account level and per-bucket.
3. Write and apply an SCP that prevents child accounts from disabling security
   controls.
4. Implement a least-privilege IAM policy audit process.
5. Map each hardening control to the attack class it mitigates.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All cloud attack classes | Days 181–194 |
| AWS IAM fundamentals | Day 182 |
| CloudTrail and detection | Day 194 |

---

## Hardening Controls → Attack Mitigation Map

| Control | Mitigates | ATT&CK technique blocked |
|---|---|---|
| IMDSv2 required | SSRF to IMDS credential theft | T1552.005 |
| S3 Block Public Access (account) | Public S3 data exposure | T1530 |
| CloudTrail all-regions + integrity | Covering tracks by disabling logging | T1562.008 |
| GuardDuty enabled | Known attack pattern detection | Multiple |
| SCP: deny iam:CreateUser in prod | Backdoor IAM user creation | T1136.003 |
| IAM permission boundaries | Privilege escalation via IAM APIs | T1098 |
| VPC Endpoint for S3 | Data exfiltration to external S3 | T1537 |
| Credential Guard (AD) | Pass-the-Hash (applies to hybrid) | T1550.002 |
| AWS Config continuous compliance | Prevents drift from secure baseline | Multiple |
| Secrets Manager (not env vars) | Lambda env var secret exposure | T1552.001 |

---

## Part 1 — IMDSv2 Enforcement

### 1.1 — Enforce on New Instances via Launch Template

```json
// launch-template-imdsv2.json
{
  "LaunchTemplateName": "secure-baseline",
  "LaunchTemplateData": {
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpPutResponseHopLimit": 1,
      "HttpEndpoint": "enabled"
    }
  }
}
```

```bash
aws ec2 create-launch-template \
  --cli-input-json file://launch-template-imdsv2.json
```

### 1.2 — Enforce on Existing Instances

```bash
# Fix all existing instances in one region
for instance_id in $(aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text); do
  aws ec2 modify-instance-metadata-options \
    --instance-id $instance_id \
    --http-tokens required \
    --http-put-response-hop-limit 1
  echo "Fixed: $instance_id"
done
```

### 1.3 — AWS Config Rule + Auto-Remediation

```bash
# Enable the managed Config rule
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "ec2-imdsv2-check",
    "Source": {"Owner": "AWS", "SourceIdentifier": "EC2_IMDSV2_REQUIRED"}
  }'

# Create auto-remediation using Systems Manager Automation
aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "ec2-imdsv2-check",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "AWSConfigRemediation-EnforceEC2InstanceIMDSv2",
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]'
```

### 1.4 — SCP: Prevent IMDSv1 in Entire Organisation

```json
// scp-require-imdsv2.json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireIMDSv2",
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringNotEquals": {
        "ec2:MetadataHttpTokens": "required"
      }
    }
  }]
}
```

---

## Part 2 — S3 Block Public Access

### 2.1 — Account-Level Block (Highest Priority)

```bash
# Enable Block Public Access for all S3 buckets in the account
# This overrides any bucket-level settings that allow public access
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

# Verify
aws s3control get-public-access-block --account-id 123456789012
```

### 2.2 — Per-Bucket Enforcement

```bash
# Apply to all existing buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3api put-public-access-block \
    --bucket $bucket \
    --public-access-block-configuration \
      'BlockPublicAcls=true,IgnorePublicAcls=true,
       BlockPublicPolicy=true,RestrictPublicBuckets=true'
  echo "Hardened: $bucket"
done
```

### 2.3 — S3 Bucket Policy: Deny Non-HTTPS Access

```json
{
  "Statement": [{
    "Sid": "DenyHTTP",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"
    ],
    "Condition": {
      "Bool": {"aws:SecureTransport": "false"}
    }
  }]
}
```

---

## Part 3 — Service Control Policies (SCPs)

SCPs restrict what actions any principal in a child account can perform —
even if that principal has AdministratorAccess.

### 3.1 — Deny Disabling Security Services

```json
// scp-protect-security-services.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailModification",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyGuardDutyDisable",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:UpdateDetector"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyConfigModification",
      "Effect": "Deny",
      "Action": [
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*"
    }
  ]
}
```

### 3.2 — Deny IAM Root Usage

```json
{
  "Statement": [{
    "Sid": "DenyRootAccount",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:root"
      }
    }
  }]
}
```

### 3.3 — Region Restriction (Attack Surface Reduction)

```json
{
  "Statement": [{
    "Sid": "RestrictToApprovedRegions",
    "Effect": "Deny",
    "NotAction": [
      "iam:*",
      "sts:*",
      "support:*",
      "s3:GetBucketLocation",
      "s3:ListAllMyBuckets"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": [
          "us-east-1",
          "eu-west-1"
        ]
      }
    }
  }]
}
```

---

## Part 4 — IAM Least Privilege Audit

### 4.1 — Find Wildcard Policies

```python
# find_wildcard_policies.py
import boto3, json

iam = boto3.client("iam")

def check_policy_document(doc: dict, policy_name: str) -> None:
    for stmt in doc.get("Statement", []):
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions or any(a.endswith(":*") for a in actions):
            if "*" in resources:
                print(f"[CRITICAL] {policy_name}: Action=* Resource=*")
            else:
                print(f"[HIGH]     {policy_name}: Action=* Resource={resources[:2]}")

# Check all managed policies in the account
paginator = iam.get_paginator("list_policies")
for page in paginator.paginate(Scope="Local"):
    for policy in page["Policies"]:
        version_id = policy["DefaultVersionId"]
        doc = iam.get_policy_version(
            PolicyArn=policy["Arn"],
            VersionId=version_id,
        )["PolicyVersion"]["Document"]
        check_policy_document(doc, policy["PolicyName"])

# Also check inline policies for all roles
for role in iam.list_roles()["Roles"]:
    for policy_name in iam.list_role_policies(RoleName=role["RoleName"])["PolicyNames"]:
        doc = iam.get_role_policy(
            RoleName=role["RoleName"],
            PolicyName=policy_name,
        )["PolicyDocument"]
        check_policy_document(doc, f"{role['RoleName']}/{policy_name}")
```

### 4.2 — IAM Access Analyzer

```bash
# Enable IAM Access Analyzer (finds overly permissive policies + unused access)
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT

# List findings (external access that may be unintended)
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account-analyzer \
  | jq '.findings[] | {Resource: .resource, Type: .findingType, Status: .status}'

# Generate a least-privilege policy from actual usage (using IAM role last used data)
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::123456789012:role/ec2-webapp-role

# Get the results (takes a few seconds)
aws iam get-service-last-accessed-details \
  --job-id JOB_ID_FROM_ABOVE \
  | jq '.ServicesLastAccessed[] | select(.TotalAuthenticatedEntities > 0) | .ServiceName'
```

---

## Part 5 — Secrets Management Hardening

Replace Lambda environment variables and EC2 user-data secrets with
Secrets Manager:

```python
# secrets_manager_pattern.py — correct way to load secrets in Lambda
import boto3, json, os
from functools import lru_cache

secretsmanager = boto3.client("secretsmanager")

@lru_cache(maxsize=None)
def get_secret(secret_name: str) -> dict:
    """Retrieve and cache a secret. Cache survives Lambda container reuse."""
    response = secretsmanager.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

def handler(event, context):
    # Correct: secrets fetched from Secrets Manager at runtime
    db_creds = get_secret("prod/rds/webapp")
    conn = connect_to_db(
        host=db_creds["host"],
        user=db_creds["username"],
        password=db_creds["password"],
    )
    # ...
```

```python
# Wrong: secret in environment variable
# DB_PASSWORD = os.environ["DB_PASSWORD"]   # ← Never do this for production secrets
```

---

## Cloud Hardening Checklist

```
Identity and Access:
[ ] IMDSv2 required on all EC2 instances (Config rule + auto-remediation)
[ ] S3 Block Public Access enabled at account level
[ ] No IAM users in production (use roles + SSO)
[ ] All IAM roles have permission boundaries
[ ] SCPs prevent disabling CloudTrail, GuardDuty, Config
[ ] SCP restricts to approved regions only
[ ] Root account: MFA enabled, access keys deleted, not used operationally
[ ] IAM Access Analyzer enabled; all findings resolved or accepted

Detection:
[ ] CloudTrail enabled in all regions with log integrity validation
[ ] CloudTrail logs centralised to a security-dedicated S3 bucket
[ ] GuardDuty enabled in all regions and all accounts (delegated admin)
[ ] AWS Config recording enabled for all resource types
[ ] Config rules: ec2-imdsv2-check, s3-bucket-public-read-prohibited,
    root-access-key-check, mfa-enabled-for-iam-console-access

Data Protection:
[ ] S3 buckets: encryption enabled (SSE-S3 minimum; SSE-KMS for sensitive data)
[ ] RDS encryption enabled at rest and in transit (ssl=true in connection string)
[ ] Secrets in Secrets Manager or SSM Parameter Store (not env vars)
[ ] CloudWatch Logs encrypted with KMS
[ ] EBS volumes encrypted by default (account-level setting)

Network:
[ ] VPC endpoints for S3, Secrets Manager, SSM (prevent traffic over internet)
[ ] Security groups: principle of least access (no 0.0.0.0/0 except for web tier)
[ ] NACLs: deny inbound from known-bad CIDR ranges (use GuardDuty threat intel)
[ ] Flow logs enabled on all VPCs
```

---

## Key Takeaways

1. **Four controls stop 80% of known cloud attacks:** IMDSv2 required,
   S3 Block Public Access, CloudTrail all-regions, GuardDuty enabled. These
   should be the non-negotiable baseline for every AWS account.
2. **SCPs are the organisational-level security layer.** Even if a child
   account's administrator makes a mistake (or is compromised), the SCP
   prevents disabling logging or creating backdoors in production.
3. **Permission boundaries limit the blast radius of IAM privilege escalation.**
   A role with `iam:CreateUser` inside a permission boundary that caps
   permissions at ReadOnly cannot create an admin user — the boundary applies
   to anything the role creates.
4. **Secrets Manager costs money. Breaches cost more.** Lambda environment
   variables with production database passwords are a finding in every cloud
   security assessment. The fix is simple; the resistance is usually cost.
5. **The CIS AWS Foundations Benchmark is the canonical hardening checklist.**
   It maps directly to AWS Config managed rules. Enable it. Track drift from
   it weekly.

---

## Exercises

1. Enable IMDSv2 on a test EC2 instance using `modify-instance-metadata-options`.
   Verify that `curl http://169.254.169.254/latest/meta-data/` without the
   PUT token returns a 401. Verify that the PUT flow works.
2. Write an SCP that prevents any principal in the organisation from: (a)
   creating IAM users (use roles + SSO instead), (b) disabling GuardDuty,
   (c) creating public S3 ACLs. Apply it to a test OU in AWS Organizations.
3. Run `find_wildcard_policies.py` from Part 4 on a test account. Identify
   the three most permissive policies. Rewrite each one as a least-privilege
   policy for its actual use case.
4. Research: what is the difference between an IAM permission boundary and an
   SCP? Give an example where each one stops a privilege escalation that the
   other does not.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q195.1, Q195.2 …).
> Follow-up questions use hierarchical numbering (Q195.1.1, Q195.1.2 …).

---

## Navigation

← Previous: [Day 194 — Detecting Cloud Attacks](DAY-0194-Detecting-Cloud-Attacks.md)
→ Next: [Day 196 — Cloud Security Review](DAY-0196-Cloud-Security-Review.md)
