---
title: "OpenID Connect, SAML and SSO Attacks"
tags: [foundation, auth, OIDC, SAML, SSO, id-token, assertion, XML-signature,
       wrapping-attack, nonce, audience-validation]
module: 01-Foundation-05
day: 44
related_topics:
  - OAuth 2 Flow and OAuth Attacks (Day 043)
  - API Keys, RBAC and Broken Access Control (Day 045)
  - Auth Detection and Hardening (Day 047)
---

# Day 044 — OpenID Connect, SAML and SSO Attacks

## Goals

By the end of this lesson you will be able to:

1. Explain what OpenID Connect adds to OAuth 2.0 and what the ID Token is.
2. Validate an OIDC ID Token correctly — all five required checks.
3. Explain the SAML assertion structure and how SP-initiated SSO works.
4. Execute an XML Signature Wrapping (XSW) attack conceptually.
5. Identify four validation failures common in SSO implementations.

---

## Prerequisites

- [Day 043 — OAuth 2 Flow and OAuth Attacks](DAY-0043-OAuth-2-Flow-and-OAuth-Attacks.md)

---

## Main Content — Part 1: OpenID Connect

### 1. What OIDC Adds to OAuth

OAuth 2.0 answers: "Does this user authorise this app to do X?"
It does **not** answer: "Who is this user?"

OpenID Connect (OIDC) is an identity layer on top of OAuth 2.0.
It adds an **ID Token** — a JWT that identifies the user.

```
OAuth 2.0 response:
  access_token  ← authorise API calls
  refresh_token ← get new access token

OIDC response adds:
  id_token      ← who the user is (JWT, signed by the auth server)
```

---

### 2. The ID Token

An OIDC ID Token is a JWT with these required claims:

| Claim | Required | Meaning |
|---|---|---|
| `iss` | Yes | Issuer URL — e.g. `https://accounts.google.com` |
| `sub` | Yes | Subject — unique user ID at this issuer |
| `aud` | Yes | Audience — must equal your `client_id` |
| `exp` | Yes | Expiry — must be in the future |
| `iat` | Yes | Issued at |
| `nonce` | If sent in request | Anti-replay — must match the value you sent |

**Example decoded payload:**
```json
{
  "iss": "https://accounts.google.com",
  "sub": "10769150350006150715113082367",
  "aud": "1234567890.apps.googleusercontent.com",
  "exp": 1735689600,
  "iat": 1735603200,
  "nonce": "abc123xyz",
  "email": "alice@example.com",
  "email_verified": true
}
```

---

### 3. Correct ID Token Validation

**All five checks are mandatory. Skipping any one is a vulnerability.**

```python
import jwt, requests, time

def validate_id_token(id_token: str, client_id: str, nonce: str) -> dict:
    # Step 1: Fetch the JWKS (public keys) from the issuer
    # (Cache this — it should not be fetched on every request)
    jwks = requests.get("https://accounts.google.com/.well-known/openid-configuration")
    jwks_uri = jwks.json()["jwks_uri"]
    keys = requests.get(jwks_uri).json()

    # Step 2: Decode and verify signature + claims
    payload = jwt.decode(
        id_token,
        options={"verify_signature": True},
        algorithms=["RS256"],        # ← Never accept HS256 from a third-party
        audience=client_id,          # ← Check 1: aud == client_id
        issuer="https://accounts.google.com",  # ← Check 2: iss matches
        # PyJWT also checks exp automatically ← Check 3: not expired
        jwks_client=jwt.PyJWKClient(jwks_uri)
    )

    # Check 4: nonce must match what we sent in the request
    if payload.get("nonce") != nonce:
        raise ValueError("Nonce mismatch — possible replay attack")

    # Check 5: iat should be recent (not a token from days ago)
    if time.time() - payload["iat"] > 600:
        raise ValueError("Token too old")

    return payload
```

**What goes wrong when checks are skipped:**

| Skipped check | Attack enabled |
|---|---|
| `iss` not validated | Attacker creates their own OIDC server with valid tokens |
| `aud` not validated | Token for app A used at app B (token substitution) |
| `exp` not validated | Expired tokens accepted indefinitely |
| `nonce` not validated | Replay attack — same token reused |
| Signature not validated | Forged ID token (same as `alg:none`) |

---

## Main Content — Part 2: SAML

### 4. SAML Basics

SAML (Security Assertion Markup Language) is an older XML-based SSO standard.
Enterprises use it heavily — Okta, ADFS, Shibboleth all speak SAML.

**SP-initiated SSO flow:**

```
1. User visits Service Provider (SP): https://app.corp.com/login
2. SP generates a SAML AuthnRequest and redirects user to IdP
3. User authenticates at Identity Provider (IdP): https://idp.corp.com/sso
4. IdP generates a signed SAML Response (XML) with Assertion
5. IdP POST-binds the Response to the SP's ACS URL:
   POST https://app.corp.com/sso/acs
   SAMLResponse=BASE64(GZIP(XML_RESPONSE))
6. SP validates the signature and assertion → user is logged in
```

**SAML Assertion structure (simplified):**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                Destination="https://app.corp.com/sso/acs"
                InResponseTo="_request_id">
  <Issuer>https://idp.corp.com</Issuer>
  <Signature>...</Signature>           <!-- Signs the entire Response -->
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion>
    <Issuer>https://idp.corp.com</Issuer>
    <Signature>...</Signature>         <!-- Signs the Assertion only -->
    <Subject>
      <NameID>alice@corp.com</NameID>
    </Subject>
    <Conditions NotBefore="..." NotOnOrAfter="...">
      <AudienceRestriction>
        <Audience>https://app.corp.com</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="Role">
        <AttributeValue>user</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</samlp:Response>
```

---

### 5. XML Signature Wrapping (XSW) Attack

**What it is:**
An attacker modifies the SAML XML while keeping the valid signature intact —
by wrapping a new malicious assertion around the signed element and exploiting
how the XML parser resolves references.

**Why it works:**
XML Digital Signatures sign a specific element (identified by its `ID` attribute).
The parser that validates the signature uses `getElementById()` to find the
signed element. But the parser that extracts claims for authorisation might
traverse the XML tree differently — finding a different node with the same ID
or traversing to the first matching element.

The attacker:
1. Copies the valid signed `<Assertion>` into an `<Extensions>` element.
2. Creates a new unsigned `<Assertion>` with forged claims (e.g. `Role: admin`).
3. The signature validator finds the original signed assertion (valid signature).
4. The claim extractor finds the new forged assertion first.

**Conceptual payload:**

```xml
<Response>
  <Extensions>
    <!-- Original signed assertion — valid signature -->
    <Assertion ID="original_id">
      <Signature>VALID_SIG</Signature>
      <NameID>alice@corp.com</NameID>
      <AttributeValue>user</AttributeValue>
    </Assertion>
  </Extensions>

  <!-- New forged assertion — no signature, but processed first -->
  <Assertion ID="original_id">
    <NameID>alice@corp.com</NameID>
    <AttributeValue>admin</AttributeValue>
  </Assertion>
</Response>
```

**Tool:** `saml-raider` (Burp extension) automates XSW attack generation.
It generates 8 standard XSW permutations (XSW1 through XSW8).

**Real-world case:**
CVE-2012-5664 — Ruby on Rails SAML implementation was vulnerable to XSW.
Multiple enterprise SSO implementations have had XSW vulnerabilities
discovered in the 2010s. GitHub's Enterprise SAML was found vulnerable in 2017.

**Fix:**
Use a battle-tested SAML library that correctly resolves the signed element
before parsing claims. The claim parser must use the same element that the
signature validator verified — not a traversal of the document tree.

---

### 6. Four Other SAML/SSO Failures

**Failure 1 — No `NotBefore` / `NotOnOrAfter` validation:**
The assertion has a time window. Skipping this check means expired or
future-dated assertions are accepted.

**Failure 2 — `AudienceRestriction` not checked:**
An assertion from `app1.corp.com` can be replayed at `app2.corp.com` if
neither checks the `<Audience>` element.

**Failure 3 — `InResponseTo` not validated:**
The Response should reference the specific `AuthnRequest` ID. If not
validated, an attacker can replay a legitimate response out of context.

**Failure 4 — Accepting assertions over GET (redirect binding) with
tampered XML:**
The redirect binding uses URL encoding + deflation. An attacker who can
modify the URL before the signature is verified can inject attributes.
Always verify the signature before processing any claims.

---

## Key Takeaways

1. **OIDC is OAuth + identity.** The ID Token is a signed JWT that proves who
   the user is. You must validate all five claims: `iss`, `aud`, `exp`,
   `nonce`, and signature.
2. **Audience validation is the most commonly skipped check.** Tokens are
   scoped to a specific client. Cross-application token substitution is the
   result of not checking `aud`.
3. **SAML is XML-based and XML is complex.** That complexity is the attack
   surface. XSW exploits the gap between what the signature covers and what
   the parser reads. Use established SAML libraries — do not roll your own.
4. **SSO centralises authentication.** A flaw in the IdP or in one SP's
   validation logic can compromise every integrated application. Scope,
   validate, and monitor SSO flows carefully.
5. **Test your SP's validation logic, not just the IdP.** The IdP can be
   perfectly secure while the SP's SAML assertion parser is vulnerable to XSW.

---

## Exercises

### Exercise 1 — OIDC Validation

Write a Python function that validates a Google ID token. Check all five
required properties. Write a test that deliberately passes a token with:
- Wrong `aud` — confirm rejection.
- Wrong `iss` — confirm rejection.
- Expired `exp` — confirm rejection.
- Tampered signature — confirm rejection.

### Exercise 2 — SAML Assertion Decode

Use `base64 -d` to decode a real SAML Response from a test IdP (SimpleSAMLphp
Docker container). Parse the XML. Find:
- The `NameID`
- The `NotOnOrAfter` time
- The `Audience`
- The attribute assertions

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 043 — OAuth 2 Flow and OAuth Attacks](DAY-0043-OAuth-2-Flow-and-OAuth-Attacks.md)*
*Next: [Day 045 — API Keys, RBAC and Broken Access Control](DAY-0045-API-Keys-RBAC-and-Broken-Access-Control.md)*
