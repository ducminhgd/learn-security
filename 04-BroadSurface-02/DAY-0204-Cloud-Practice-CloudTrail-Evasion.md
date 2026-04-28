---
title: "Cloud Practice — CloudTrail Evasion and Hunting"
tags: [cloud-practice, CloudTrail, evasion, threat-hunting, Sigma, jq,
       Athena, detection-engineering, log-analysis, ATT&CK-T1562, blue-team]
module: 04-BroadSurface-02
day: 204
related_topics:
  - Detecting Cloud Attacks (Day 194)
  - Cloud Persistence Detection (Day 203)
  - Cloud Hardening (Day 195)
  - Cloud Security Review (Day 196)
---

# Day 204 — Cloud Practice: CloudTrail Evasion and Hunting

> "Every attacker tries to stay quiet. In the cloud, quiet means using the
> same API calls as normal operations but with slightly wrong timing, wrong
> source IP, wrong session name, or wrong volume. The hunter's job is to know
> what 'wrong' looks like. Today you build detection rules by first understanding
> exactly what an attacker would do to avoid them — then you close each gap."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Identify common CloudTrail evasion techniques and the detection gaps they
   create.
2. Write `jq` queries that surface anomalous CloudTrail events.
3. Write Sigma rules for at least three distinct cloud attack patterns.
4. Identify attacker behaviour that GuardDuty misses and build custom rules for it.
5. Simulate a slow, low-volume attack and tune detection thresholds to catch it.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Detecting Cloud Attacks | Day 194 |
| CloudTrail log structure | Day 194 Part 1 |
| Sigma rule format | Day 142 |
| `jq` installed | `apt install jq` |

---

## Part 1 — CloudTrail Evasion Techniques

Understanding evasion makes better detection.

### 1.1 — Technique: Using Services That Have Less Logging

```bash
# Not all AWS services log to CloudTrail equally
# Data plane events (S3 GetObject, Lambda invoke) are not logged by default
# Only management plane events (CreateUser, PutBucketPolicy) are logged by default

# Attacker preference:
# - Use GetObject (data plane) instead of CreateBucket (management plane)
# - Use already-existing infrastructure instead of creating new resources
# - Prefer ListBuckets → GetObject over CreateUser → AttachUserPolicy

# Detection gap:
# If CloudTrail data events are not enabled, S3 reads are INVISIBLE

# Check if data events are enabled
aws cloudtrail get-event-selectors --trail-name main-trail | jq '.'

# Correct configuration (enables S3 data event logging):
aws cloudtrail put-event-selectors \
  --trail-name main-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::"]
    }]
  }]'
```

### 1.2 — Technique: Low-and-Slow Enumeration

```python
# Attacker tool (slow.py) — evade burst-based detection
import boto3, time, random

iam = boto3.client("iam")
calls = [
    lambda: iam.get_account_authorization_details(Filter=["User"]),
    lambda: iam.list_policies(Scope="Local"),
    lambda: iam.list_roles(),
    lambda: iam.get_account_summary(),
    lambda: iam.list_groups(),
    lambda: iam.list_users(),
]

for call in calls:
    try:
        call()
    except Exception as e:
        print(f"Error: {e}")
    # Sleep 5–30 seconds between calls (evades "30 calls per minute" detection)
    sleep_time = random.uniform(5, 30)
    print(f"Sleeping {sleep_time:.1f}s...")
    time.sleep(sleep_time)
```

```yaml
# Detection that catches low-and-slow (uses longer time window)
title: AWS IAM Enumeration — Extended Window
id: cloud-low-slow-001
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName|startswith:
      - "Get"
      - "List"
      - "Describe"
  # Extend time window to 60 minutes (not 60 seconds)
  timeframe: 60m
  # Lower threshold — catch even patient attackers
  condition: selection | count(distinct eventName) by userIdentity.arn > 15
level: medium
```

### 1.3 — Technique: Staging Through Legitimate-Looking Sessions

```bash
# Attacker uses a session name that looks like a legitimate CI/CD pipeline
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/escalation-target-role \
  --role-session-name "github-actions-deploy-prod"   # mimics CI/CD

# Legitimate CI/CD session would have:
# - Consistent naming pattern: "github-actions-*"
# - Source IP from GitHub Actions IP ranges
# - Called during business hours / deployment windows

# Detection: session name matches CI/CD pattern but source IP is not GitHub
```

```yaml
title: AWS AssumeRole With CI/CD Session Name From Non-CI/CD IP
id: cloud-session-spoof-001
detection:
  selection:
    eventName: AssumeRole
    requestParameters.roleSessionName|startswith:
      - "github-actions"
      - "terraform-"
      - "jenkins-"
      - "circleci-"
  filter_cicd_ip:
    # GitHub Actions IP ranges — download from https://api.github.com/meta
    sourceIPAddress|startswith:
      - "192.30."
      - "185.199."
      - "140.82."
  condition: selection and not filter_cicd_ip
level: high
```

### 1.4 — Technique: Disabling CloudTrail (Last Resort)

```bash
# An attacker with admin access might try to disable logging
# This is noisy and is caught by GuardDuty and SCPs

aws cloudtrail stop-logging --name main-trail   # This IS logged before it takes effect
aws cloudtrail delete-trail --name main-trail   # If no SCP blocks this

# Detection: StopLogging and DeleteTrail events
# Mitigation: SCP denying cloudtrail:StopLogging and cloudtrail:DeleteTrail (Day 195)
```

---

## Part 2 — Advanced `jq` CloudTrail Hunting (45 min)

```bash
# Download a simulated CloudTrail log file
# (In a real environment: pull from S3 or query with Athena)
LOGFILE="cloudtrail-sim.json"

# The log is a JSON array of events
# Query 1: Find all events by a specific ARN
jq '[.[] | select(.userIdentity.arn | contains("escalation-target-role"))]' $LOGFILE

# Query 2: Timeline of all events by one identity
jq 'sort_by(.eventTime) |
  .[] |
  select(.userIdentity.arn | contains("escalation-target-role")) |
  {Time: .eventTime, Action: .eventName, Resource: .requestParameters}' $LOGFILE

# Query 3: Find all CreateUser events and their context
jq '.[] |
  select(.eventName == "CreateUser") |
  {
    Time: .eventTime,
    By: .userIdentity.arn,
    ByAccount: .userIdentity.accountId,
    NewUser: .requestParameters.userName,
    SourceIP: .sourceIPAddress,
    UserAgent: .userAgent
  }' $LOGFILE

# Query 4: Find rapid IAM calls (>10 distinct actions from same ARN)
jq 'group_by(.userIdentity.arn) |
  map({
    ARN: .[0].userIdentity.arn,
    DistinctActions: ([.[].eventName] | unique | length),
    Actions: ([.[].eventName] | unique)
  }) |
  sort_by(.DistinctActions) | reverse |
  .[:5]' $LOGFILE

# Query 5: Find cross-account AssumeRole
jq '.[] |
  select(.eventName == "AssumeRole") |
  select(.userIdentity.accountId != .recipientAccountId) |
  {
    Time: .eventTime,
    CallerAccount: .userIdentity.accountId,
    CallerARN: .userIdentity.arn,
    TargetRole: .requestParameters.roleArn,
    SourceIP: .sourceIPAddress
  }' $LOGFILE

# Query 6: Find events with errorCode (failed attempts = attacker mapping perms)
jq '.[] |
  select(.errorCode == "AccessDenied") |
  {Time: .eventTime, By: .userIdentity.arn, Action: .eventName, Error: .errorCode}' \
  $LOGFILE | head -50

# Query 7: Find unusual user agents (CLI tools, known attacker frameworks)
jq '.[] |
  select(.userAgent | test("pacu|boto|aws-sdk"; "i") | not) |
  select(.userAgent | test("python|curl|go-aws"; "i")) |
  {Time: .eventTime, Agent: .userAgent, Action: .eventName, By: .userIdentity.arn}' \
  $LOGFILE | head -20
```

---

## Part 3 — Writing Detection Rules for Attack Patterns (30 min)

Write Sigma rules for the following scenarios. Write them without looking at
Day 194 — these should be from memory.

### Exercise 3.1 — Detect PassRole + Lambda Privilege Escalation

```yaml
title: AWS Lambda Created With High-Privilege IAM Role
id: cloud-passrole-lambda-001
status: experimental
description: >
  A Lambda function was created with a high-privilege IAM execution role.
  Combined with iam:PassRole, this is the PassRole + Lambda escalation path.
logsource:
  product: aws
  service: cloudtrail
detection:
  function_created:
    eventName: CreateFunction
  # The role ARN in the request contains a high-priv role name
  # In practice, you would maintain a list of high-priv role ARNs
  high_priv_role:
    requestParameters.role|contains:
      - "AdminRole"
      - "escalation-target"
      - "FullAccess"
  filter_known_deployers:
    userIdentity.arn|contains:
      - "ci-cd-role"
      - "terraform-role"
      - "deployment-role"
  condition: function_created and high_priv_role and not filter_known_deployers
falsepositives:
  - Legitimate Lambda deployments by DevOps teams (add to filter_known_deployers)
level: high
tags:
  - attack.t1098
  - attack.t1059.009
```

### Exercise 3.2 — Detect CreatePolicyVersion Escalation

```yaml
title: AWS IAM Policy Version Escalation — Create Then Set Default
id: cloud-createpolicyversion-001
status: experimental
description: >
  CreatePolicyVersion immediately followed by SetDefaultPolicyVersion on the
  same policy ARN. This is the iam:CreatePolicyVersion privilege escalation
  technique where the attacker adds an Action:* to their own policy.
logsource:
  product: aws
  service: cloudtrail
detection:
  create_version:
    eventName: CreatePolicyVersion
  set_default:
    eventName: SetDefaultPolicyVersion
  timeframe: 5m
  condition: >
    create_version | correlate with set_default
    by requestParameters.policyArn and userIdentity.arn
falsepositives:
  - IaC pipelines updating managed policies (they also call CreatePolicyVersion)
  - Add filter for known IaC deployer role ARNs
level: critical
tags:
  - attack.t1098
```

### Exercise 3.3 — Detect Backdoor User Creation Pattern

```yaml
title: AWS IAM Backdoor User — Create, Attach Admin, Create Key in Sequence
id: cloud-backdoor-user-001
status: experimental
description: >
  Three events in tight sequence: CreateUser, then AttachUserPolicy
  with AdministratorAccess, then CreateAccessKey — all on the same
  username within 10 minutes. This is the classic cloud backdoor pattern.
logsource:
  product: aws
  service: cloudtrail
detection:
  create_user:
    eventName: CreateUser
  attach_admin:
    eventName: AttachUserPolicy
    requestParameters.policyArn|endswith: "AdministratorAccess"
  create_key:
    eventName: CreateAccessKey
  timeframe: 10m
  condition: >
    create_user | correlate with attach_admin by requestParameters.userName
    | correlate with create_key by requestParameters.userName
falsepositives:
  - Automated IAM provisioning (should never attach AdministratorAccess)
  - Emergency break-glass user creation (document and alert on this too)
level: critical
tags:
  - attack.t1136.003
  - attack.t1098
```

---

## Part 4 — GuardDuty Gap Analysis (20 min)

GuardDuty has detection blind spots. Identify them:

```
GuardDuty detects → Custom rule needed for:

GuardDuty finding: CredentialAccess:EC2/UnusualCredentials
  ↓ Detects: EC2 creds from non-EC2 IP
  ✗ Misses: Credentials from a VPN/jump host (still non-EC2 but GuardDuty may
            not flag if the IP is not on its threat intel list)
  → Custom rule: ASIA* key used from source IP not in the account's known EC2 ranges

GuardDuty finding: Persistence:IAMUser/UserCreated
  ↓ Detects: Any IAM user created
  ✗ Misses: Cross-account backdoor roles (these are Roles, not Users)
  → Custom rule: CreateRole with external Principal not in org account list

GuardDuty finding: PrivilegeEscalation:IAMUser/AdminPolicyAdded
  ↓ Detects: Admin policy attached to existing user
  ✗ Misses: CreatePolicyVersion on an existing policy to inject Action:*
  → Custom rule: CreatePolicyVersion + SetDefaultPolicyVersion in same session

GuardDuty finding: Exfiltration:S3/MaliciousIPCaller
  ↓ Detects: S3 access from known malicious IPs
  ✗ Misses: High-volume GetObject from a new IP not yet on threat intel lists
  → Custom rule: GetObject count > 500 in 10 minutes per ARN

Not in GuardDuty:
  Lambda beacon with EventBridge schedule
  Shadow access key on existing user
  Slow-and-low IAM enumeration over 60+ minutes
  Role chaining through multiple intermediate roles
```

Build one custom Sigma rule for each item in the "✗ Misses" column above.

---

## Key Takeaways

1. **CloudTrail data events are disabled by default.** S3 `GetObject` (exfiltration)
   and Lambda `Invoke` (beacon execution) are invisible without explicit data event
   configuration. Enable them — they add cost but close a critical detection gap.
2. **Low-and-slow enumeration evades rate-based rules.** A burst detector at
   30 events/minute misses an attacker making 15 calls over 60 minutes. Set
   separate thresholds for short windows (burst) and long windows (sustained).
3. **Session name spoofing is trivial and impersonates CI/CD.** The session name
   in `AssumeRole` is chosen by the caller. Correlate with source IP to distinguish
   real CI/CD pipelines from session name spoofing.
4. **GuardDuty covers known-bad patterns; custom Sigma rules cover logic-based
   patterns.** The two complement each other. GuardDuty finds Tor exit node access;
   custom rules find the three-event backdoor user sequence.
5. **`jq` is the analyst's scalpel for CloudTrail.** `group_by`, `select`, `sort_by`,
   `unique` — these four operations cover 80% of CloudTrail hunting queries.
   Know them cold.

---

## Exercises

1. Take the CloudTrail simulation log. Write `jq` queries that find: (a) the
   attacker's initial access event, (b) the escalation event, (c) the backdoor
   creation event, (d) the first use of the backdoor credentials. Write each
   query from scratch, then verify against the expected timeline.
2. Write a Python script that reads a CloudTrail log (JSON array), groups events
   by `userIdentity.arn` and 1-hour windows, and outputs ARNs with more than
   20 distinct `eventName` values in any 60-minute window.
3. Research: AWS Athena for CloudTrail — how do you query CloudTrail logs at
   scale without `jq`? Write the SQL equivalent of query 4 (rapid IAM calls)
   from Part 2 using Athena syntax.
4. Write a complete detection runbook: "Procedure for responding to a CloudTrail
   alert on CreateUser + AttachUserPolicy + CreateAccessKey." Include: initial
   triage steps, containment actions (exact AWS CLI commands), evidence collection,
   and escalation criteria.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q204.1, Q204.2 …).
> Follow-up questions use hierarchical numbering (Q204.1.1, Q204.1.2 …).

---

## Navigation

← Previous: [Day 203 — Cloud Practice: Persistence Detection](DAY-0203-Cloud-Practice-Persistence-Detection.md)
→ Next: [Day 205 — Cloud Practice: Bug Bounty Recon](DAY-0205-Cloud-Practice-Bug-Bounty-Recon.md)
