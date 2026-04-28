---
title: "Detecting Cloud Attacks — CloudTrail, GuardDuty, Alerting on Metadata Queries"
tags: [cloud-detection, CloudTrail, GuardDuty, AWS-Config, Sigma, SIEM, alerting,
       metadata-query, IAM-anomaly, S3-data-exfiltration, ATT&CK-T1552.005,
       ATT&CK-T1530, threat-hunting, blue-team]
module: 04-BroadSurface-02
day: 194
related_topics:
  - Auth Attack Detection (Day 176)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Persistence Techniques (Day 191)
  - Cloud Hardening (Day 195)
---

# Day 194 — Detecting Cloud Attacks

> "CloudTrail is the equivalent of web server access logs — except it captures
> every API call made to every AWS service. If you know how to read CloudTrail,
> you can reconstruct any cloud attack. If you have written the detection rules
> in advance, you catch it in real time. The detective work is the same as web
> detection: understand the attack, find the log field that differs from normal
> behaviour, write the rule. The log source is different. The logic is identical."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain what CloudTrail logs capture and how to query them.
2. Write detection rules for SSRF-to-IMDS, IAM privilege escalation, and
   S3 data exfiltration.
3. Interpret a GuardDuty finding and map it to an ATT&CK technique.
4. Build an AWS Config rule to detect IMDSv1-enabled instances.
5. Write Sigma rules for cloud attack patterns.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud attack classes | Days 181–193 |
| Sigma rule format | Day 142 |
| Detection architecture | Day 176 |

---

## Part 1 — CloudTrail: The Cloud Detection Foundation

### 1.1 — What CloudTrail Captures

CloudTrail records every AWS API call as a JSON event:

```json
{
  "eventVersion": "1.08",
  "eventTime": "2024-01-01T03:14:23Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "185.212.1.1",
  "userAgent": "aws-cli/2.0.0",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAIOSFODNN7EXAMPLE:escalated-session",
    "arn": "arn:aws:sts::123456789012:assumed-role/escalation-target-role/escalated-session",
    "accountId": "123456789012",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::123456789012:role/escalation-target-role"
      }
    }
  },
  "requestParameters": {
    "userName": "monitoring-health-svc"
  },
  "responseElements": {
    "user": {
      "userName": "monitoring-health-svc",
      "userId": "AIDAIOSFODNN7EXAMPLE",
      "createDate": "2024-01-01T03:14:23Z"
    }
  }
}
```

**Key fields for detection:**

| Field | Use |
|---|---|
| `eventName` | The API call — `CreateUser`, `AssumeRole`, `GetObject` |
| `eventSource` | Service — `iam.amazonaws.com`, `s3.amazonaws.com` |
| `userIdentity.type` | `AssumedRole` = temporary creds; `IAMUser` = long-lived |
| `userIdentity.arn` | Full identity ARN including role and session name |
| `sourceIPAddress` | Source IP; `AWS Internal` = from another AWS service |
| `requestParameters` | The call's input — what was requested |
| `responseElements` | The call's output — what was returned |
| `errorCode` | Populated on failed calls — `AccessDenied`, `NoSuchEntity` |

### 1.2 — Querying CloudTrail with AWS CLI

```bash
# Find all IAM user creation events in the last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  | jq '.Events[] | {
      Time: .EventTime,
      By: (.CloudTrailEvent | fromjson | .userIdentity.arn),
      NewUser: (.CloudTrailEvent | fromjson | .requestParameters.userName),
      SourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)
    }'

# Find cross-account AssumeRole events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  | jq '.Events[] | .CloudTrailEvent | fromjson |
    select(.userIdentity.accountId != .recipientAccountId) |
    {Caller: .userIdentity.arn, CallerAccount: .userIdentity.accountId,
     Time: .eventTime}'
```

---

## Part 2 — Detection Rules for Cloud Attacks

### 2.1 — SSRF to IMDS Detection

The key indicator: an EC2 instance role makes API calls from an IP address
outside the AWS EC2 IP ranges (meaning the credential was used off-instance).

```yaml
title: AWS EC2 Instance Role Credentials Used From Non-EC2 IP
id: cloud-001
status: experimental
description: Temporary credentials from an EC2 instance role (ASIA* prefix)
  are being used from a source IP that is not in AWS EC2 IP ranges. This
  indicates possible IMDS credential theft via SSRF.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: AssumedRole
    userIdentity.sessionContext.sessionIssuer.type: Role
  filter_aws_internal:
    sourceIPAddress|startswith:
      - "AWS Internal"
      - "10."
      - "172."
      - "192.168."
  filter_ec2_ip_ranges:
    # AWS EC2 IP ranges vary — use the ip-ranges.json published by AWS
    # In practice: alert when sourceIPAddress is not in the account's EC2 IPs
    sourceIPAddress|startswith:
      - "3."    # AWS IP space — approximate; use full ranges in production
      - "52."
      - "54."
      - "18."
  condition: selection and not filter_aws_internal and not filter_ec2_ip_ranges
falsepositives:
  - Developers running awscli from their laptops with role credentials (unlikely
    for production roles; use separate dev roles with source IP conditions)
level: high
tags:
  - attack.t1552.005
  - attack.t1078.004
```

### 2.2 — IAM Privilege Escalation Detection

```yaml
title: AWS IAM User Created Outside Business Hours by Non-Admin Principal
id: cloud-002
status: experimental
description: A new IAM user was created at an unusual hour by a principal
  that is not in the IAM admin group. This indicates potential backdoor user
  creation following compromise.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateUser
  filter_admin:
    userIdentity.arn|contains:
      - "iam-admin"
      - "ops-team"
      - "platform-team"
  # Flag creation outside 08:00–18:00 UTC on weekdays
  # This requires log enrichment with time-of-day field
  condition: selection and not filter_admin
falsepositives:
  - Legitimate user provisioning by DevOps teams
  - Automated infrastructure-as-code (flag if session is not CI/CD role)
level: high
tags:
  - attack.t1136.003
  - attack.t1098
```

```yaml
title: AWS IAM Admin Policy Attached to Newly Created User
id: cloud-003
status: experimental
description: AdministratorAccess or equivalent admin policy attached to a
  user within 5 minutes of that user's creation. Classic backdoor user pattern.
logsource:
  product: aws
  service: cloudtrail
detection:
  user_created:
    eventName: CreateUser
  admin_policy_attached:
    eventName: AttachUserPolicy
    requestParameters.policyArn|contains:
      - "AdministratorAccess"
      - "PowerUserAccess"
      - "iam:*"
  timeframe: 5m
  condition: user_created | correlate with admin_policy_attached by requestParameters.userName
falsepositives:
  - Automated IAM provisioning pipelines (should not attach AdministratorAccess)
level: critical
tags:
  - attack.t1136.003
  - attack.t1098
```

### 2.3 — S3 Data Exfiltration Detection

```yaml
title: High-Volume S3 GetObject — Potential Data Exfiltration
id: cloud-004
status: experimental
description: A single IAM principal performs a high volume of S3 GetObject
  calls within a short time window, indicating potential data exfiltration.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetObject
  timeframe: 10m
  condition: selection | count() by userIdentity.arn > 500
falsepositives:
  - Backup jobs; ETL pipelines; analytics workflows
  - Add filter for known service accounts that legitimately do bulk reads
level: high
tags:
  - attack.t1530
```

### 2.4 — Kerberoasting-Equivalent: IAM Key Enumeration

```yaml
title: Rapid IAM Read API Calls — Credential Enumeration
id: cloud-005
status: experimental
description: A principal makes more than 30 different IAM read API calls
  within 60 seconds. This indicates automated IAM permission enumeration
  (equivalent of running enumerate-iam or Pacu iam__enum_permissions).
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName|startswith:
      - "Get"
      - "List"
      - "Describe"
  timeframe: 60s
  condition: selection | count(distinct eventName) by userIdentity.arn > 30
falsepositives:
  - Security tooling that reads IAM configuration for compliance
  - Infrastructure-as-code tools (Terraform, Pulumi) during initial setup
level: medium
tags:
  - attack.t1069.003
  - attack.t1580
```

### 2.5 — Cross-Account Role Assumption Anomaly

```yaml
title: AssumeRole From External AWS Account
id: cloud-006
status: experimental
description: An AssumeRole call was made from a principal in an account
  that is not in the organisation's known account list. Indicates use of
  a cross-account backdoor role.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRole
  filter_internal:
    userIdentity.accountId:
      - "123456789012"   # Production account
      - "234567890123"   # Staging account
      - "345678901234"   # Dev account
  condition: selection and not filter_internal
falsepositives:
  - Legitimate third-party integrations (add their account IDs to filter_internal)
  - AWS service-linked role assumptions (accountId = "AWS Internal")
level: critical
tags:
  - attack.t1098
  - attack.t1078.004
```

---

## Part 3 — AWS GuardDuty

GuardDuty is AWS's managed threat detection service. It analyses CloudTrail,
VPC Flow Logs, and DNS logs for known attack patterns.

### 3.1 — Key GuardDuty Finding Types

| Finding | ATT&CK | What it detects |
|---|---|---|
| `UnauthorizedAccess:IAMUser/TorIPCaller` | T1078.004 | API calls from Tor exit node |
| `CredentialAccess:EC2/UnusualCredentials` | T1552.005 | EC2 credentials used from unusual location |
| `Discovery:S3/MaliciousIPCaller` | T1580 | S3 enumeration from known malicious IP |
| `Exfiltration:S3/MaliciousIPCaller` | T1530 | S3 GetObject from known malicious IP |
| `Persistence:IAMUser/UserCreated` | T1136.003 | New IAM user created |
| `PrivilegeEscalation:IAMUser/AdminPolicyAdded` | T1098 | Admin policy attached |
| `CryptoCurrency:EC2/BitcoinTool.B` | T1496 | EC2 making cryptocurrency mining connections |

### 3.2 — Reading a GuardDuty Finding

```json
{
  "Type": "CredentialAccess:EC2/UnusualCredentials",
  "Severity": 8.0,
  "Description": "EC2 instance credentials were used from an IP address
    not associated with EC2 infrastructure, indicating that the credentials
    may have been extracted and used elsewhere.",
  "Resource": {
    "InstanceDetails": {
      "InstanceId": "i-0abcdef1234567890",
      "IamInstanceProfile": {
        "Arn": "arn:aws:iam::123456789012:instance-profile/ec2-webapp-profile"
      }
    }
  },
  "Service": {
    "Action": {
      "AwsApiCallAction": {
        "Api": "GetObject",
        "ServiceName": "s3.amazonaws.com",
        "RemoteIpDetails": {
          "IpAddressV4": "185.212.1.1",
          "Country": {"CountryName": "Netherlands"},
          "Organization": {"Asn": "AS29695", "AsnOrg": "Hosting company"}
        }
      }
    }
  }
}
```

**IR response to this finding:**

```bash
# 1. Identify which EC2 instance's credentials were stolen
INSTANCE_ID="i-0abcdef1234567890"

# 2. Revoke the instance profile's credentials (force rotation)
aws ec2 replace-iam-instance-profile-association \
  --iam-instance-profile Name=temp-readonly-profile \
  --association-id iip-assoc-0abcdef1234567890

# 3. Audit what the stolen credentials did (CloudTrail lookup)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=i-0abcdef1234567890 \
  --start-time 2024-01-01T00:00:00Z

# 4. Check for persistence artefacts
aws iam list-users  # New users?
aws iam list-roles  # New cross-account roles?
```

---

## Part 4 — AWS Config Rules for Preventive Detection

```bash
# Create a Config rule that flags any EC2 instance with IMDSv1 enabled
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "ec2-imdsv2-check",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "EC2_IMDSV2_REQUIRED"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::EC2::Instance"]
    }
  }'

# Create a Config rule for public S3 buckets
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
  }'
```

---

## Key Takeaways

1. **CloudTrail is the single most important cloud security tool.** Every API
   call is logged. A detective with CloudTrail access and the right queries
   can reconstruct any cloud attack — but only if CloudTrail is enabled in
   all regions with log integrity validation.
2. **Detection rules for cloud attacks mirror web attack detection.** Find
   the field that differs between attacker and legitimate user behaviour.
   The log source is different; the logic is the same.
3. **GuardDuty handles known-bad patterns; custom rules handle unknown-bad.**
   GuardDuty detects EC2 credentials used from Tor. Your custom CloudTrail
   rule detects credentials used from a specific attacker IP that GuardDuty
   does not flag. Both are required.
4. **Cross-account role assumption from an external account is a near-zero
   false-positive alert.** It should always trigger immediate investigation —
   either a misconfigured integration or an active compromise.
5. **AWS Config rules are preventive detections.** They continuously evaluate
   whether resources are compliant with defined standards. An `ec2-imdsv2-check`
   rule flags any new IMDSv1-enabled instance before an attacker finds it.

---

## Exercises

1. Enable CloudTrail in a test AWS account (free tier). Run the full attack
   chain from Day 192 against LocalStack. Export the simulated CloudTrail
   logs. Write a jq query that identifies the exact moment of credential
   theft (the GetObject call from the metadata endpoint), the escalation
   (AssumeRole), and the backdoor (CreateUser + AttachUserPolicy).
2. Write a complete Sigma rule for Lambda function creation outside of
   business hours by a non-CI/CD principal. What fields distinguish a CI/CD
   role from a manual attacker session?
3. Research: GuardDuty finding `Persistence:IAMUser/UserCreated` fires only
   for IAM users, not for roles. Write a CloudTrail-based detection rule
   that covers both: a new IAM role created with a cross-account trust policy
   pointing to an account not in the organisation.
4. Write an EventBridge rule that automatically triggers a Lambda when a
   GuardDuty finding of severity ≥ 7 is generated. The Lambda should: (a)
   log the finding to S3, (b) send an SNS notification, (c) output the
   affected IAM ARN and source IP.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q194.1, Q194.2 …).
> Follow-up questions use hierarchical numbering (Q194.1.1, Q194.1.2 …).

---

## Navigation

← Previous: [Day 193 — Cloud Bug Bounty Strategy](DAY-0193-Cloud-Bug-Bounty-Strategy.md)
→ Next: [Day 195 — Cloud Hardening](DAY-0195-Cloud-Hardening.md)
