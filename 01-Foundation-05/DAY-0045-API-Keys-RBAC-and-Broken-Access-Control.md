---
title: "API Keys, RBAC and Broken Access Control"
tags: [foundation, auth, API-keys, RBAC, ABAC, IDOR, forced-browsing,
       access-control, privilege-escalation, OWASP-A01]
module: 01-Foundation-05
day: 45
related_topics:
  - OpenID Connect, SAML and SSO Attacks (Day 044)
  - Password Reset Flaws and Account Takeover (Day 046)
  - Auth Detection and Hardening (Day 047)
  - Broken Access Control (OWASP A01)
---

# Day 045 — API Keys, RBAC and Broken Access Control

## Goals

By the end of this lesson you will be able to:

1. Describe correct API key hygiene — storage, rotation, scope, revocation.
2. Distinguish RBAC from ABAC and identify where each breaks down.
3. Exploit an IDOR in a lab environment and write a finding.
4. Enumerate endpoints via forced browsing and explain why obscurity fails.
5. Explain horizontal vs vertical privilege escalation with real examples.

---

## Prerequisites

- [Day 044 — OpenID Connect, SAML and SSO Attacks](DAY-0044-OpenID-Connect-SAML-and-SSO-Attacks.md)

---

## Main Content — Part 1: API Keys

### 1. What API Keys Are and How They Fail

An API key is a shared secret that identifies and authenticates a caller.
Unlike JWTs, they carry no claims — the server looks up permissions.

**How they are commonly mishandled:**

| Mistake | Consequence | Frequency |
|---|---|---|
| Committed to version control | Key exposed to anyone with repo access | Extremely common |
| Stored in client-side JS | Key visible to any user of the site | Very common |
| Sent in URL query parameter | Appears in server logs, browser history | Common |
| No scope restriction | Compromise = full account access | Very common |
| Never rotated | Old keys from ex-employees stay valid | Near-universal |
| No revocation mechanism | Can't invalidate a compromised key | Common |

**Real-world case:**
GitGuardian scans public GitHub commits and reports millions of exposed secrets
per year. Stripe keys, AWS keys, Twilio keys — they are found within seconds of
a commit to a public repo. Bots scrape GitHub in real time.

**Correct API key handling:**

```python
# Storage: environment variable, never in code
import os
api_key = os.environ["STRIPE_API_KEY"]

# Storage: use a secrets manager in production
from google.cloud import secretmanager
client = secretmanager.SecretManagerServiceClient()
secret = client.access_secret_version(name="projects/123/secrets/stripe-key/versions/latest")
api_key = secret.payload.data.decode("utf-8")

# Transmission: Authorization header, never query parameter
import requests
resp = requests.get(
    "https://api.example.com/v1/charges",
    headers={"Authorization": f"Bearer {api_key}"}
    # NOT: ?api_key=... — this leaks to server logs
)
```

**API key server-side requirements:**
- Hash the key before storing (like a password): `sha256(key)` in the DB.
- The full key is shown once at generation and never again.
- Per-key scope (read-only vs read-write vs admin).
- Per-key IP allowlist for high-privilege operations.
- Expiry date or mandatory rotation policy.
- Audit log: every API call logs which key used it.

---

## Main Content — Part 2: Access Control Models

### 2. RBAC — Role-Based Access Control

Each user has one or more roles. Permissions are assigned to roles.

```
User alice → Roles: [editor, viewer]
Role editor → Permissions: [post:create, post:update, post:delete:own]
Role viewer → Permissions: [post:read]
```

**Where RBAC breaks:**

```python
# The classic RBAC mistake — checking role, not ownership:
@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if current_user.role != 'editor':
        return jsonify({'error': 'forbidden'}), 403

    post = db.get_post(post_id)
    db.delete(post)   # ← Deletes ANY post, including other users' posts!
    return '', 204

# Fix — check ownership too:
    post = db.get_post(post_id)
    if post.author_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'forbidden'}), 403
```

**RBAC is vertical access control (role gates), not horizontal
(per-resource ownership).** You need both.

---

### 3. ABAC — Attribute-Based Access Control

Instead of roles, ABAC evaluates attributes of the user, resource,
and environment at decision time:

```
allow if:
  user.department == resource.department
  AND user.clearance_level >= resource.classification
  AND time.hour between 9 and 17
  AND request.ip in corporate_network
```

ABAC is more flexible but harder to audit. Use RBAC for coarse-grained
access, ABAC for fine-grained policies on sensitive resources.

---

## Main Content — Part 3: IDOR Lab

### 4. Insecure Direct Object Reference — CWE-639

**What it is:**
The application exposes an internal implementation object (database ID,
filename, etc.) and does not check that the requesting user is authorised to
access that specific object.

**Why it works:**
The application checks "is the user authenticated?" but not "does this user
own object 42?"

**Vulnerable code:**

```python
# Vulnerable — checks auth but not ownership:
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = db.query("SELECT * FROM orders WHERE id = %s", (order_id,))
    return jsonify(order)   # Any authenticated user can read any order!

# Fix — enforce ownership in the query:
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = db.query(
        "SELECT * FROM orders WHERE id = %s AND user_id = %s",
        (order_id, current_user.id)   # ← Ownership enforced in DB layer
    )
    if not order:
        return jsonify({'error': 'not found'}), 404  # Same response as "not yours"
    return jsonify(order)
```

**Lab — exploiting IDOR with Burp:**

```bash
# Step 1: Login and capture a normal request
GET /api/orders/1042
Authorization: Bearer <alice_token>
→ 200: {"id":1042,"user_id":5,"total":99.99,"items":[...]}

# Step 2: Increment the ID — do you get other users' orders?
GET /api/orders/1041
GET /api/orders/1043
GET /api/orders/1000
→ If yes → IDOR confirmed

# Step 3: Use Burp Intruder to enumerate a range automatically:
# Payload type: Numbers, 1000 to 1100, step 1
# Grep for: "user_id" with value != current user's ID
```

**Horizontal IDOR** → access resources belonging to a peer (different user,
same privilege level). Order 1042 belongs to Alice; attacker reads Bob's 1043.

**Vertical IDOR** → access resources requiring a higher privilege level.
Regular user accessing `/api/admin/users/5`.

---

## Main Content — Part 4: Forced Browsing

### 5. Forced Browsing — CWE-425

**What it is:**
Accessing URLs that are not linked from the interface but exist and are not
access-controlled. Security through obscurity is not access control.

**Common targets:**

```bash
# Admin panels:
/admin
/admin/users
/administrator
/manage
/console

# Debug/dev endpoints:
/debug
/test
/dev
/swagger
/api/docs
/graphql  (introspection)
/_debug_toolbar  (Flask Debug Toolbar)

# Backup files:
/backup.sql
/db.sqlite3
/config.php.bak
/.env
/.env.production
/web.config
/docker-compose.yml

# Version control artifacts:
/.git/config
/.git/HEAD
/.svn/entries
```

**Lab — directory enumeration with ffuf:**

```bash
# Standard wordlist scan:
ffuf -u http://target.lab/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,301,302,403 \
  -o ffuf_results.json

# With authentication (if endpoints require login):
ffuf -u http://target.lab/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer <token>" \
  -mc 200,201,204

# Targeted admin panel scan:
ffuf -u http://target.lab/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt \
  -mc 200,301,302
```

**Fix:**
Every route must have an explicit access control check. Default-deny: if no
rule explicitly permits access, deny it. Obscurity is not a control.

---

## Key Takeaways

1. **OWASP A01 (Broken Access Control) is the most common web vulnerability.**
   It is almost always a logic failure, not a cryptographic one. The fix is
   consistently checking "can THIS user access THIS specific resource?"
2. **RBAC handles vertical access (role gates). Ownership checks handle
   horizontal access.** Both are required. RBAC alone does not prevent IDOR.
3. **API keys must be hashed at rest, scoped, and revocable.** An unscoped,
   non-expiring key stored in plaintext is equivalent to a permanent password
   you cannot change after compromise.
4. **Security through obscurity fails under enumeration.** Unlisted admin
   panels, debug routes, and backup files will be found. Every route needs an
   access check.
5. **Default-deny access control is the only safe posture.** If you have to
   explicitly add permission for each action, you cannot accidentally forget
   to add a restriction.

---

## Exercises

### Exercise 1 — IDOR Lab

Using DVWA or Juice Shop:
1. Find an endpoint that takes a user-controlled ID parameter.
2. Confirm you can access other users' data by changing the ID.
3. Identify the exact line of code where the ownership check is missing.
4. Write a one-paragraph finding in pentest report format:
   - Vulnerability name
   - Evidence (request/response)
   - Impact
   - Remediation

### Exercise 2 — Forced Browsing

Run ffuf against DVWA or a local target with at least 3 different wordlists.
Find at least 2 endpoints that:
- Are not linked from the main navigation
- Return 200 or a redirect
- Reveal something interesting (version info, admin panel, config)

Document each finding.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 044 — OpenID Connect, SAML and SSO Attacks](DAY-0044-OpenID-Connect-SAML-and-SSO-Attacks.md)*
*Next: [Day 046 — Password Reset Flaws and Account Takeover](DAY-0046-Password-Reset-Flaws-and-Account-Takeover.md)*
