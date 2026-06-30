---
tags: [email-security]
---
# Interpreting Authentication Headers

## TCM Exam Objectives
- Differentiate authentication header schemes: Basic (base64), Bearer (JWT/opaque token), Digest (challenge-response MD5), API Key, AWS SigV4, and Cookie
- Decode a JWT by handling base64url padding, and explain why decoding is NOT verifying
- Identify key cookie security flags: `HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, `Max-Age`
- Distinguish HTTP 401 Unauthorized (missing/invalid credentials) from 403 Forbidden (authenticated but lacks permission)
- Explain the Bearer token security model: possession = authorization, short expiry, HTTPS-only transmission
- Analyze `WWW-Authenticate` challenge headers: `realm`, `error`, `error_description` for Bearer (RFC 6750)
- Recognize common anti-patterns: ID tokens sent to APIs, API keys in query params, tokens in localStorage, missing CSRF protection for cookies
- Trace the Cookie/Set-Cookie header pair for session-based authentication and why CSRF tokens are required
Authentication headers are the standardized HTTP carriers of identity credentials — most commonly the `Authorization` request header (using schemes like `Basic`, `Bearer`, `Digest`, or `ApiKey`) and the `Set-Cookie`/`Cookie` header pair for session-based flows, with `WWW-Authenticate` serving as the server's challenge when credentials are missing or invalid.?turn0search0??turn0search11??turn0search15? Interpreting these headers correctly means recognizing the scheme, decoding the token format (especially base64url-encoded JWTs), validating the security flags on cookies, and understanding how `401 Unauthorized` differs from `403 Forbidden` — a skill set that sits at the intersection of web development, API integration, and security analysis.?turn0search18?

## The Authentication Header Flow

The request/response dance of HTTP authentication follows a predictable pattern: the client presents credentials, the server validates them, and either grants access or challenges with a `WWW-Authenticate` header explaining what it needs.?turn0search15??turn0search17?

```mermaid
flowchart LR
    C[Client] -->|Request without credentials| S[Server / Resource]
    S -->|401 Unauthorized<br/>+ WWW-Authenticate challenge| C
    C -->|Resends with Authorization header<br/>or Cookie| S
    S -->|200 OK + Set-Cookie<br/>optional| C
    C -->|Subsequent requests<br/>auto-attach Cookie / token| S
    S -->|403 Forbidden<br/>authenticated, not authorized| C
    S -->|200 OK Resource| C
```

The dotted nuance: `401` means "I don't know who you are — authenticate and try again," while `403` means "I know who you are, but you can't have this resource."?turn0search18? Only `401` is required to carry a `WWW-Authenticate` challenge header.

## Master Comparison of Authentication Header Schemes

| Scheme | Header Format | Encoding | Use Case | Security Notes |
|---|---|---|---|---|
| **Basic** | `Authorization: Basic <base64(user:pass)>` | Base64 (not encryption) | Legacy APIs, internal dev servers, simple scripts | Sends credentials in cleartext encoding — must be over HTTPS only; no expiry, no revocation |
| **Bearer** | `Authorization: Bearer <token>` | Token is opaque or JWT | OAuth 2.0 / OIDC access tokens, modern REST APIs, SPAs | "Bearer" = whoever holds the token gets access; vulnerable to token theft; short-lived tokens mitigate |
| **Digest** | `Authorization: Digest username="...", realm="...", nonce="...", response="..."` | MD5 hash of challenge + password | HTTP Digest Auth (challenge-response) | Prevents password replay but uses MD5 — largely superseded by Bearer + TLS |
| **API Key** | `X-API-Key: <key>` or `Authorization: ApiKey <key>` or `?api_key=` query param | Raw string | Service-to-service, developer APIs, rate-limited public APIs | Long-lived secret; rotate carefully; avoid query param (logged in URLs/referrers) |
| **AWS SigV4** | `Authorization: AWS4-HMAC-SHA256 Credential=.../... SignedHeaders=... Signature=...` | HMAC-SHA256 signature | AWS API requests (S3, Lambda, etc.) | Per-request signature over canonical request; prevents replay; requires `X-Amz-Date` |
| **Cookie / Session** | `Cookie: sessionid=...; csrf=...` (response: `Set-Cookie: ...`) | Opaque session ID | Traditional web apps, server-rendered sessions | Auto-attached by browser; requires `Secure`, `HttpOnly`, `SameSite` flags |
| **JWT in Header** | `Authorization: Bearer eyJhbGci...` | Base64url-encoded JSON | Stateless APIs, OIDC ID tokens, service tokens | Stateless but unrevocable; verify signature + `exp` + `iss` + `aud` |

Sources: ?turn0search0??turn0search3??turn0search4??turn2search0?

---

## Module 1 — The `Authorization` Header

The HTTP `Authorization` request header provides credentials that authenticate a user agent with a server, allowing access to protected resources.?turn0search0? Its syntax is always `<scheme> <credentials>` — the scheme determines how to interpret everything after the space.

### Basic Authentication

`Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=`

The credential is `base64(username:password)`. Decoding `dXNlcm5hbWU6cGFzc3dvcmQ=` yields `username:password`. Base64 is **encoding, not encryption** — it provides zero confidentiality and is trivially reversible in any browser console or terminal.?turn0search4? Basic auth is acceptable only over TLS and is commonly seen on legacy APIs, dev/staging servers protected by HTTP basic, and simple scripts. Its weaknesses: credentials are sent on every request, there's no expiry, and revocation requires changing the password.

### Bearer Authentication

`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

The Bearer scheme means "whoever holds this token can access the resource" — like a concert ticket, possession equals authorization.?turn0search22? The token can be an opaque string (a database lookup key) or a self-contained JWT. Bearer tokens are the dominant pattern for OAuth 2.0 and modern REST APIs because they decouple authentication (done once at the auth server) from resource access (done repeatedly with the token). The security trade-off: if the token is stolen, the attacker gains full access until it expires — which is why Bearer tokens should be short-lived (minutes to an hour) and transmitted only over HTTPS.

### Digest Authentication

`Authorization: Digest username="admin", realm="example.com", nonce="abc123...", uri="/protected", response="e5917c..."`

Digest auth uses a challenge-response mechanism: the server sends a `nonce` in `WWW-Authenticate`, the client computes an MD5 hash of `username:password:nonce` and sends back the `response`. This prevents password replay but relies on MD5, which is cryptographically broken. Digest is largely historical — modern systems use Bearer + TLS instead.?turn0search3?

### API Keys

`X-API-Key: 12345-abcde-67890` or `Authorization: ApiKey 12345-abcde-67890`

API keys are long-lived opaque strings identifying a client/application rather than a user. They're common in developer-facing APIs (Stripe, GitHub, Twilio). The header name is non-standard (`X-API-Key` is a convention, not an RFC).?turn2search2? Critical pitfalls: avoid passing API keys as URL query parameters (`?api_key=...`) because they get logged in server access logs, browser history, and `Referer` headers — always use a header instead.

### AWS Signature Version 4

`Authorization: AWS4-HMAC-SHA256 Credential=AKIA... /20260629/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=fe5f80f7...`

SigV4 is the most complex common scheme — it signs the entire canonical request (method, path, query, headers, body hash) with HMAC-SHA256 derived from the secret key, date, region, and service.?turn2search0??turn2search3? The signature is request-specific, so it can't be replayed. Interpreting a SigV4 header means recognizing the `AWS4-HMAC-SHA256` prefix, parsing the `Credential` (access key + date + region + service + request type), the `SignedHeaders` list, and the `Signature` itself. This is the pattern for all AWS API calls and increasingly for AWS-style S3-compatible APIs (MinIO, Backblaze B2).

---

?? **Exam Tip:** The #1 JWT exam trap is `alg: none`. An attacker sets the algorithm to `none` and removes the signature — if the JWT library doesn't enforce a whitelist of allowed algorithms, the token is accepted without verification. Always check: does the server verify the signature? Does it reject `alg: none`? Also remember that decoding reads the claims, but ONLY signature verification proves authenticity.

```mermaid
flowchart LR
    TOKEN[JWT String] --> SPLIT[Split by '.']
    SPLIT --> HDR[Header<br/>eyJhbGciOiJI...]
    SPLIT --> PAY[Payload<br/>eyJzdWIiOiIx...]
    SPLIT --> SIG[Signature<br/>SflKxwRJSMeK...]
    
    HDR --> DECODE_HDR[Base64url Decode<br/>Add padding = fix]
    PAY --> DECODE_PAY[Base64url Decode]
    SIG --> VERIFY{Verify Signature}
    
    DECODE_HDR --> ALG{Check alg}
    ALG -->|none| REJECT[REJECT<br/>unsigned token]
    ALG -->|HS256/RS256/ES256| VERIFY
    
    VERIFY -->|valid sig + exp + aud + iss| ACCEPT[Accept Claims]
    VERIFY -->|invalid| REJECT_SIG[Reject<br/>tampered token]
    
    DECODE_PAY --> CLAIMS[Extract Claims<br/>sub, exp, iss, aud, scope]
```

## Module 2 — Decoding a JWT (Base64url Deep Dive)

JSON Web Tokens (RFC 7519) are the most common payload carried in Bearer headers. A JWT has three base64url-encoded segments separated by dots: `header.payload.signature`.?turn0search5??turn0search6?

### The Standard Example

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Base64url vs Base64

JWTs use **base64url** encoding (RFC 7515): standard base64 with `+` replaced by `-`, `/` replaced by `_`, and trailing `=` padding characters **removed**.?turn1search16? This is the most common decoding pitfall — standard base64 decoders reject JWT segments with `Incorrect padding` errors.?turn1search15??turn1search18?

The fix is to add padding back before decoding:

```python
import base64
import json

def decode_jwt_segment(segment):
    # Add padding to make length a multiple of 4
    padded = segment + '=' * (4 - len(segment) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    return json.loads(decoded)

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
header, payload, signature = token.split('.')

print(decode_jwt_segment(header))
# {"alg": "HS256", "typ": "JWT"}

print(decode_jwt_segment(payload))
# {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
```

The signature segment (`SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`) is **not decoded for content** — it's a cryptographic signature, not encoded data. You verify it against the header + payload + secret/key, you don't read it.?turn0search8?

### Decoding ? Verifying

This distinction is critical and frequently misunderstood. **Decoding** means reading the claims without checking the signature — useful for debugging, inspecting token contents, or understanding what a server received. **Verifying** means cryptographically confirming the signature matches the payload using the issuer's public key (for RS256/ES256) or shared secret (for HS256).?turn0search7? A decoded-but-unverified JWT tells you what the token *claims* to be, not what it *is*. An attacker can trivially craft a JWT with any payload they want — only signature verification proves authenticity.

### Common JWT Claims to Interpret

When you decode a JWT payload, look for these standard claims:
- `iss` — issuer (who created the token)
- `sub` — subject (who the token is about, usually the user ID)
- `aud` — audience (intended recipient; the resource server must match)
- `exp` — expiration time (Unix timestamp; reject if past)
- `iat` — issued at
- `nbf` — not before (valid from this time)
- `scope` / `scp` — OAuth scopes granted
- `azp` — authorized party (the client the token was issued to)

### The `alg: none` Attack

A classic JWT vulnerability: an attacker sets the header to `{"alg": "none"}` and removes the signature, expecting the library to skip verification. Well-maintained libraries reject `alg: none` by default, but legacy configurations have been vulnerable. When interpreting a JWT, always check the `alg` field — if it says `none`, the token is unsigned and should be rejected unless you have a specific reason to accept unsigned tokens.

---

```mermaid
flowchart LR
    E[Suspicious Email] --> H[Parse Email Headers]
    H --> AUTH{Authentication Check}
    AUTH -->|SPF/DKIM/DMARC Fail| SPOOF[Likely Spoofed]
    AUTH -->|Pass| CONT[Analyze Content]
    SPOOF --> URL[Analyze URLs]
    CONT --> URL
    URL --> REP{URL Reputation}
    REP -->|Malicious| BLOCK[Block / Alert]
    REP -->|Clean| ATTACH[Analyze Attachments]
    ATTACH --> HASH[Compute File Hash]
    HASH --> VT[VirusTotal Check]
    VT -->|Malicious| BLOCK
    VT -->|Unknown| SANDBOX[Sandbox Detonation]
    SANDBOX --> IOC{Extract IOCs}
    IOC --> BLOCK
    BLOCK --> RESPOND[Incident Response]
```


## Module 3 — Cookie-Based Authentication

For traditional web applications (server-rendered, browser-based), authentication typically uses the `Set-Cookie` / `Cookie` header pair rather than (or alongside) the `Authorization` header.?turn0search11?

### The Header Pair

Server response:
```
Set-Cookie: sessionid=abc123def456; Path=/; Domain=example.com; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
```

Client subsequent request:
```
Cookie: sessionid=abc123def456
```

The browser automatically attaches cookies to subsequent requests matching the `Domain` and `Path` — the application code never touches the cookie value directly. This differs fundamentally from Bearer tokens, which the application must explicitly attach to each request's `Authorization` header.

### Cookie Security Attributes (What to Look For When Interpreting)

Each attribute controls a specific attack surface:?turn0search12??turn0search14?

**`HttpOnly`** — blocks JavaScript (`document.cookie`) from accessing the cookie, mitigating XSS-based session theft. When you inspect a `Set-Cookie` header and see no `HttpOnly`, the session is vulnerable to any XSS in the application.?turn0search12??turn0search13?

**`Secure`** — the cookie is only sent over HTTPS, never over plaintext HTTP. Without `Secure`, a man-in-the-middle on HTTP can harvest session cookies.?turn0search14?

**`SameSite`** — controls cross-site cookie sending, the primary CSRF mitigation:
- `Strict` — cookie never sent on cross-site requests (most secure, can break SSO flows)
- `Lax` — cookie sent on top-level navigation GETs but not cross-site POSTs (default in modern browsers, balances security and usability)
- `None` — cookie sent on all cross-site requests (requires `Secure`; previously default, now requires explicit opt-in)

**`Path` and `Domain`** — scope the cookie to specific URLs. Overly broad `Domain` (e.g., `Domain=example.com` set by `app.example.com`) makes the cookie visible to every subdomain, increasing exposure if a sibling subdomain is compromised.?turn0search12?

**`Max-Age` / `Expires`** — controls cookie lifetime. Long-lived session cookies increase the window for theft; short-lived with refresh is safer.

**`Partitioned`** — the newer cross-site cookie isolation attribute (part of Privacy Sandbox), restricting third-party cookies to the top-level site that set them.

### CSRF and Cookie Authentication

CSRF (Cross-Site Request Forgery) is a vulnerability specific to cookie-based auth: because the browser auto-attaches cookies, a malicious site can trick the user's browser into making authenticated requests. **CSRF tokens are required whenever authentication relies on cookies** (session-based or token-in-cookie) and are **not required** when auth uses Bearer tokens in headers, because the browser doesn't auto-attach `Authorization` headers.?turn2search5? This is the core security trade-off between cookie and Bearer approaches: cookies get auto-attachment convenience but need CSRF protection; Bearer tokens need explicit attachment but are CSRF-immune.?turn2search6??turn2search8?

---

## Module 4 — The `WWW-Authenticate` Challenge Header

When a server returns `401 Unauthorized`, it must include at least one `WWW-Authenticate` header advertising the authentication schemes it accepts.?turn0search15??turn0search18? This is the server's way of telling the client "here's how you can authenticate."

### Header Format

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Access to staging", charset="UTF-8"
```

Or multiple challenges:
```
WWW-Authenticate: Newauth realm="apps", type=1, title="Login to apps", Basic realm="simple"
```

Each challenge specifies a scheme (e.g., `Basic`, `Digest`, `Bearer`) and scheme-specific parameters.?turn0search17? The `realm` parameter is a string identifying a protected space on the server — it's displayed to the user in the browser's native auth prompt and lets the client know which credentials to reuse for that protection space.?turn0search16?

### Bearer-Specific Challenges

For OAuth 2.0 / Bearer auth, the `WWW-Authenticate` header carries specific error codes:

```
WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
```

The `error` values are standardized in RFC 6750:
- `invalid_request` — malformed request
- `invalid_token` — expired, revoked, or malformed token
- `insufficient_scope` — token valid but lacks required scopes

When debugging a `401` from a Bearer-protected API, the `error` and `error_description` in `WWW-Authenticate` are the most diagnostic fields — they tell you whether to refresh the token, request different scopes, or fix the request format.?turn0search18?

?? **Exam Tip:** 401 vs. 403 is a classic test point. 401 = "I don't know who you are" — missing or invalid credentials. 403 = "I know who you are, but you can't do this" — insufficient permissions. Only 401 requires a `WWW-Authenticate` header. A 403 with valid credentials means no amount of re-authentication will fix it — it's an authorization problem, not an authentication problem.

### Digest-Specific Challenges

```
WWW-Authenticate: Digest realm="example.com", nonce="abc123...", qop="auth", opaque="...", stale="FALSE"
```

The `nonce` is a server-issued value the client must incorporate into its hash; `qop` (quality of protection) is `auth` or `auth-int`; `stale=TRUE` means the nonce expired but the credentials were otherwise valid (retry with new nonce, don't re-prompt user).?turn0search19?

---

## Module 5 — ID Tokens vs Access Tokens vs Refresh Tokens

When interpreting headers from an OIDC/OAuth 2.0 flow, recognizing which token type you're looking at is essential — they have different purposes, audiences, and validation rules.?turn0search21??turn0search24?

| Token Type | Defined By | Audience | Format | Where Sent | Purpose |
|---|---|---|---|---|---|
| **Access Token** | OAuth 2.0 | Resource Server (API) | Opaque or JWT | `Authorization: Bearer <token>` to API | Authorize API access |
| **ID Token** | OpenID Connect | Client Application | Always JWT | Consumed by client, not sent to APIs | Prove user authentication to client |
| **Refresh Token** | OAuth 2.0 | Authorization Server | Opaque (usually) | Sent only to auth server's token endpoint | Obtain new access tokens without re-prompting user |

**Access tokens are meant to be read and validated by the resource server.** They're what the client sends in the `Authorization: Bearer` header to access protected APIs. They can be opaque (a random string the API looks up in a database) or JWTs (self-contained, validated by checking signature + claims).?turn0search24??turn1search7?

**ID tokens are meant to be read by the OAuth client (the application), not the resource server.** They contain user profile claims (name, email, sub) and authentication event metadata (auth_time, nonce). Sending an ID token to an API in the `Authorization` header is a common anti-pattern — the API should receive access tokens, not ID tokens.?turn0search24??turn1search8?

**Refresh tokens are long-lived credentials sent only to the authorization server's token endpoint** to obtain new access tokens when the current one expires.?turn1search13? They should never appear in `Authorization` headers sent to resource servers — they're exchanged at a dedicated `/token` endpoint, typically as a POST body parameter. Refresh tokens stored in the browser face CORS complications when the auth server is on a different domain than the app.?turn1search9??turn1search11?

---

## Module 6 — Debugging Workflow

When an API call fails with `401 Unauthorized` or behaves unexpectedly, a systematic inspection workflow isolates the problem faster than guessing.

### Step 1: Inspect the Request Headers

**Browser DevTools (Network tab)** — Click the failing request ? Headers ? Request Headers. Look for:
- Is `Authorization` present at all?
- Is the scheme correct (`Bearer` vs `Basic` vs custom)?
- Is the token value complete (no truncation in logging)?
- Is `Cookie` present with the expected session ID?

**curl with verbose** — `curl -v https://api.example.com/protected` shows the exact request headers being sent and the response headers received. Use `-H "Authorization: Bearer $TOKEN"` to attach a header explicitly.

**Burp Suite Proxy** — Burp intercepts HTTP traffic between the browser and server, letting you inspect and modify headers in flight.?turn1search4? For token-based auth, Burp's Cookie Jar and the "Add Custom Header" extension can capture and replay tokens across requests.?turn1search0?

### Step 2: Decode the Token

If the `Authorization` header uses a Bearer JWT, decode the header and payload segments (see Module 2) and check:
- `exp` — has the token expired? (`iat` + lifetime vs current time)
- `iss` — does the issuer match what the API expects?
- `aud` — does the audience include this API?
- `scope` — does the token have the scopes required for this endpoint?

For opaque tokens, you can't decode locally — you need the API's introspection endpoint (RFC 7662) or the auth server's logs.

### Step 3: Inspect the Response

Look at the `WWW-Authenticate` header on the `401` response — the `error` field tells you the failure reason.?turn0search18? Common patterns:
- `error="invalid_token"` + `error_description="expired"` ? refresh the token
- `error="invalid_token"` + `error_description="signature invalid"` ? wrong signing key, clock skew, or tampered token
- `error="insufficient_scope"` ? request additional scopes at the auth server
- No `WWW-Authenticate` at all ? the server may not be treating this as an auth failure (could be a routing or middleware issue)

### Step 4: Distinguish 401 from 403

- **401 Unauthorized** — authentication missing or invalid. Fix: provide/refresh credentials.?turn0search18?
- **403 Forbidden** — authentication succeeded but the user lacks permission for this resource. Fix: grant the user the required role/scope (or accept that they shouldn't have access).

A `403` with valid credentials is an authorization problem, not an authentication problem — no amount of token refreshing will fix it.

### Step 5: Check Cookie Attributes

For cookie-based auth failures:
- Missing `Secure` on an HTTPS-only deployment can cause the cookie to not be set over HTTP redirects
- `SameSite=Lax` blocks cookies on cross-site POSTs (a common SPA + API issue)
- `Domain` mismatch means the cookie isn't sent to the API subdomain
- Expired `Max-Age` means the session is gone

### Step 6: CORS Considerations

If the `Authorization` header works in curl/Postman but fails from a browser SPA, check CORS. Bearer tokens in the `Authorization` header avoid many CORS complications because they don't rely on cookies — but the server must still send `Access-Control-Allow-Headers: Authorization` in its CORS preflight response.?turn1search11? Refresh token flows that rely on cookies face the most CORS friction because they require `Access-Control-Allow-Credentials: true` plus specific `Access-Control-Allow-Origin` (not `*`).?turn1search9??turn1search10?

---

## Module 7 — Common Pitfalls

**Treating base64 as encryption.** Basic auth credentials and JWT payloads are base64-encoded, not encrypted. Anyone with the header can decode them in seconds. Never log `Authorization` headers, never put tokens in URLs, and always use TLS.?turn0search4?

**Decoding without verifying.** A decoded JWT tells you what the token claims, not what it is. Always verify the signature before trusting claims — otherwise an attacker can forge any payload. This is the #1 JWT implementation mistake.?turn0search7?

**Sending ID tokens to APIs.** ID tokens are for the client application, not the resource server. Sending them in `Authorization: Bearer` to an API either fails validation (wrong audience) or, worse, succeeds if the API naively accepts any JWT — leaking user profile data to the wrong consumer.?turn0search24?

**Ignoring token expiration.** Access tokens expire (typically 1 hour). A common failure: token works for an hour, then every request fails with `401` until the client implements refresh token rotation. Build refresh logic into the client from day one.?turn1search13?

**Missing cookie security flags.** A `Set-Cookie: sessionid=abc123` with no attributes is vulnerable to XSS theft (no `HttpOnly`), plaintext interception (no `Secure`), and CSRF (no `SameSite`). Every session cookie should have all three.?turn0search12??turn0search13?

**Confusing 401 with 403.** A `403` is not a credential problem — refreshing the token won't help. Distinguish "who are you?" (401) from "you can't do this" (403) before debugging.?turn0search18?

**Storing tokens in localStorage.** Bearer tokens in `localStorage` are accessible to any JavaScript running on the page, including injected XSS. `HttpOnly` cookies are safer for storage but introduce CSRF. The trade-off has no universally correct answer — pick the model that fits the threat model and mitigate the corresponding risk (XSS for localStorage, CSRF for cookies).?turn2search6??turn2search8?

**API keys in query parameters.** `?api_key=abc123` gets logged in server access logs, browser history, `Referer` headers, and CDN logs. Always use a header (`X-API-Key` or `Authorization`).?turn2search2?

**Clock skew on JWT validation.** JWT `exp` and `nbf` checks depend on the server's clock. A few seconds of skew between client and server can cause valid tokens to be rejected. Most JWT libraries accept a `leeway` parameter to tolerate small skew.

---

## Recap

Interpreting authentication headers means recognizing the scheme (`Basic`, `Bearer`, `Digest`, `ApiKey`, `AWS4-HMAC-SHA256`, cookie), decoding the credential format (base64 for Basic, base64url for JWT segments, opaque strings for session IDs and API keys), validating the security posture (cookie flags like `HttpOnly`/`Secure`/`SameSite`, JWT signature + claims, token expiration), and reading the server's challenge in `WWW-Authenticate` when authentication fails.?turn0search0??turn0search5??turn0search11??turn0search15? The practical workflow: inspect the `Authorization` or `Cookie` header with DevTools/curl/Burp, decode JWT payloads (with base64url padding fix) to check `exp`/`iss`/`aud`/`scope`, inspect the `401` response's `WWW-Authenticate` for the error code, and distinguish authentication failure (401 — fix credentials) from authorization failure (403 — fix permissions).?turn0search7??turn0search18? The deeper lesson: every header has a security trade-off — Basic sends credentials in cleartext encoding, Bearer tokens are valuable to thieves, cookies need CSRF protection, JWTs are stateless but unrevocable, and the choice between them depends on the application's threat model, not on which is "more secure" in the abstract.