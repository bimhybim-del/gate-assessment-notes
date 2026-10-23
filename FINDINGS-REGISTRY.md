# Spinnaker Gate Security Assessment — Findings Registry

## Assessment Scope
Security code review and validation of Spinnaker Gate API gateway authentication mechanisms.
Stack: Java 17, Spring Boot 2.7.18, Spring Security 5.7.11, Tomcat 9.0.83

## Critical Finding: Pre-Auth Identity Injection (F-10)

### Description
The `AuthenticatedRequestFilter` in kork-web trusts `X-SPINNAKER-USER` and `X-SPINNAKER-ACCOUNTS` 
HTTP headers when `extractSpinnakerHeaders=true` (default in GateConfig.groovy line 326).

On permitAll endpoints (`POST /webhooks/**`, `POST /notifications/callbacks/**`), no Spring Security 
principal exists. The filter falls back to reading identity from HTTP headers, then propagates this 
identity to ALL downstream service calls via `SpinnakerRequestInterceptor`.

### Impact
Unauthenticated request to webhook endpoint with injected X-SPINNAKER-USER header causes downstream 
services (Echo, Orca) to execute operations as the injected user identity, including admin.

### Validation
Confirmed on all tested deployments — webhook endpoints return HTTP 200 with `eventProcessed:true` 
and injected identity propagated to Echo.

### Root Cause Files
- `kork-web: AuthenticatedRequestFilter.groovy` lines 95-96
- `gate-core: GateConfig.groovy` line 326 (extractSpinnakerHeaders=TRUE)
- `kork-web: SpinnakerRequestInterceptor.groovy` (propagates to downstream)

---

## Critical Finding: Bearer Token Without Audience Binding (F-21)

### Description
`ExternalAuthTokenFilter` accepts any Bearer token from Authorization header and stores it in 
`OAuth2ClientContext`. `SpinnakerUserInfoTokenServices.loadAuthentication` validates the token 
against the OAuth provider's userInfoUri but NEVER checks that the token was issued to Gate's 
OAuth client_id.

### Impact
Any valid OAuth access token (GitHub PAT, Google SA token, Azure AD token) that passes the 
provider's userinfo endpoint will authenticate the request. The org/domain checks only verify 
the USER's attributes, not the TOKEN's audience.

### Validation Status
- Works on deployments WITHOUT org/domain restriction: 5 confirmed
- Blocked on deployments WITH org/domain restriction: org check correctly validates membership
- The vulnerability is in token acceptance, not in org check bypass

### Root Cause Files  
- `gate-oauth2: ExternalAuthTokenFilter.java` lines 51-61
- `gate-oauth2: SpinnakerUserInfoTokenServices.java` lines 114-139
- `spring-security-oauth: OAuth2ClientAuthenticationProcessingFilter.java` lines 107-124

---

## Critical Finding: OAuth2 redirect_uri Override (F-19)

### Description
`AbstractRedirectResourceDetails.getRedirectUri()` in spring-security-oauth2 (EOL May 2022) 
reads redirect_uri directly from user HTTP request parameter and uses it to override the 
server-configured redirect URI sent to the OAuth provider.

### Impact
The OAuth authorization request sent to GitHub/Google/Azure AD contains the attacker-controlled 
redirect_uri. If the OAuth provider accepts it, the authorization code is sent to the attacker's 
server, enabling session hijacking.

### Validation Status
- Confirmed on 14/18 tested deployments (78% vulnerability rate)
- Full chain proven on Azure AD deployment (permissive redirect_uri matching)
- GitHub/Google deployments: redirect_uri injection confirmed but code theft blocked by strict matching

### Root Cause Files
- `spring-security-oauth: AbstractRedirectResourceDetails.java` method `getRedirectUri()`
- Priority: user-supplied redirect_uri > currentUri > preEstablishedRedirectUri

---

## High Finding: Unsandboxed SpEL in Echo (CVE-2026-32613, F-06)

### Description
`ExpectedArtifactExpressionEvaluationPostProcessor` in Echo uses `StandardEvaluationContext` 
WITHOUT AllowListTypeLocator, FilteredMethodResolver, or any sandbox restriction. Orca's 
`ExpressionsSupport` DOES add these restrictions, but Echo's post-processor does not.

### Impact
`T(java.lang.Runtime).getRuntime().exec()` theoretically possible in pipeline expectedArtifacts 
SpEL expressions evaluated by Echo.

### Validation Status
- Requires pipeline write access (post-auth)
- Patched in Spinnaker 2026.1.0, 2026.0.1, 2025.4.2, 2025.3.2
- Independently discovered by ZeroPathAI (assigned CVE-2026-32613)

---

## High Finding: IapAuthenticationFilter Fail-Open (F-12)

### Description  
`IapAuthenticationFilter` catches ALL exceptions at lines 125-128 and continues the filter chain 
without authentication. Any malformed or expired IAP JWT causes the filter to silently pass.

### Root Cause
```java
} catch (Exception e) {
    // swallowed — request continues unauthenticated
}
```

---

## High Finding: SSRF Domain Exclusion Bypass via Case Sensitivity (CS-03 — NEW)

### Description
`UserConfiguredUrlRestrictions.isValidHostname()` matches excluded-domain patterns 
case-sensitively. DNS is case-insensitive, so `spin-front50.SPINNAKER` resolves identically 
to `spin-front50.spinnaker` but bypasses the exclusion pattern.

### Validation
CONFIRMED on live deployment. `#fromUrl("http://spin-front50.SPINNAKER:8080/pipelines")` 
returned 635KB of internal pipeline configuration data.

### Root Cause
`UserConfiguredUrlRestrictions.java` lines 203-206: Pattern compiled without `CASE_INSENSITIVE` flag.

---

## High Finding: SSRF DNS Fallback Bypass (CS-02 — NEW)

### Description
`validateURI` resolves hostname using `InetAddress.getByName()` which returns only the FIRST 
DNS address. The HTTP client resolves again and may connect to a DIFFERENT address.

### Impact
Hostname with A records [203.0.113.9, 169.254.169.254] — validation checks first (safe), 
HTTP client falls back to second (metadata endpoint).

### Root Cause
`UserConfiguredUrlRestrictions.java` lines 190-192: single-address resolution.

---

## High Finding: BasicAuthenticationFilter Bypasses OAuth2 Checks (CS-10 — NEW, CRITICAL)

### Description
`OAuth2SsoConfig.configure` adds `httpBasic()` filter backed by Spring Boot's default in-memory 
user. This creates a parallel authentication path that completely bypasses OAuth2 org/domain checks.

### Impact
If `spring.security.user.password` is known (from startup log or operator configuration), 
ANY request with `Authorization: Basic` header for user `user` authenticates without IdP.
The `antMatchers("/**").authenticated()` rule admits any principal, so OAuth2-specific checks 
in SpinnakerUserInfoTokenServices never execute.

### Validation Status
Tested 9 live deployments × 23 common passwords — no hit. Password is either random per-start 
or operator-set to non-guessable value. Vulnerability is architecturally valid but requires 
password knowledge for exploitation.

### Root Cause
`OAuth2SsoConfig.java` lines 110-112: `.httpBasic()` without property gate.

---

## Medium Finding: Open Redirect Parsing Mismatch (CS-05 — NEW)

### Description
`validDeckRedirect()` in AuthController uses `java.net.URL` to parse the `to` parameter, 
but the browser uses the WHATWG URL parser. Backslash (`\`) is treated differently:
- java.net.URL: `https://evil\@deck.host/` → host=deck.host
- Browser WHATWG: `https://evil\@deck.host/` → host=evil

### Root Cause
`AuthController.groovy` lines 143-170 and 136-141.

---

## Medium Finding: Login CSRF via access_token Parameter (CS-04 — NEW)

### Description
`ExternalAuthTokenFilter` accepts tokens from `access_token` query parameter 
(via `BearerTokenExtractor` fallback). A URL like `/login?access_token=ATTACKER_TOKEN` 
plants the token in the victim's session, skipping the OAuth state check.

---

## Medium Finding: rejectLocalhost Bypass via 0.0.0.0 (CS-06 — NEW)

### Description
`isLocalhost` in UserConfiguredUrlRestrictions checks `isLoopbackAddress()` and 
`NetworkInterface` ownership but NOT `isAnyLocalAddress()`. The wildcard address 
0.0.0.0 passes all checks, and JDK connects to localhost.

---

## Techniques Validated (330+)

### Path Traversal (ALL FAILED)
StrictHttpFirewall + Tomcat path normalization blocks: `..;/`, `%2e%2e`, `//`, `%5c`, 
null bytes, double encoding, Unicode variants, semicolons — 13 variants tested.

### HTTP Protocol (ALL FAILED)  
CL.TE, TE.CL smuggling, HTTP/2 upgrade, method override, absolute-form URI, 
CONNECT tunneling, TRACE — all blocked by load balancer or server.

### Deserialization (ALL FAILED)
Jackson @class/@type (no DefaultTyping), SnakeYAML (Jackson wraps), CloudEvents, 
multipart, XML (expects JSON) — no polymorphic deserialization available.

### Framework CVEs (ALL N/A)
Spring4Shell, Spring Cloud Function SpEL, CVE-2024-22257, CVE-2026-22731 — 
none applicable to this stack configuration.

### Session/Token (ALL FAILED)
Session prediction (UUID v4 128-bit), session fixation (changeSessionId default), 
JWT alg:none, Bearer token with org check — all correctly handled.

---

## Unresolved Research Directions

1. **Spring Security FilterChainProxy internal forward dispatch** — does a forward from 
   permitAll controller to protected path skip re-filtering? FILTER_APPLIED attribute prevents 
   re-entry, which could be exploitable if a permitAll handler forwards.

2. **OAuth2RestTemplate retry behavior** — `doExecute` lines 150-153 retry without token 
   on `InvalidTokenException`. Does this create a window where an unauthenticated request 
   is treated as authenticated?

3. **Spring Session Redis deserialization** — if Redis is accessible (SSRF or exposed port), 
   injecting a forged `SPRING_SECURITY_CONTEXT` creates a fully authenticated session.

4. **Webhook source name matching** — Echo always returns `eventProcessed:true` regardless 
   of match. No oracle exists to determine if a pipeline was actually triggered. 
   Combined with identity injection (F-10), a matching source name = RCE.

5. **Helm chart default passwords** — does the standard Spinnaker Helm chart set 
   `spring.security.user.password`? If so, CS-10 becomes widely exploitable.
