# Claude Security AI Scan Findings (2026-10-23)

## Scan Info
- Model: Claude Opus 5.5 (Claude Security internal)  
- Repo: bimhybim-del/spinnaker-gate-review (58 source files)
- Status: Active (still scanning)
- Total: 10 findings (1 CRITICAL, 5 HIGH, 4 MEDIUM)

## CRITICAL

### CS-10: BasicAuthenticationFilter bypasses ALL OAuth2 org/domain checks
- OAuth2SsoConfig adds httpBasic() backed by Spring Boot default in-memory user
- Basic auth principal admitted by `antMatchers("/**").authenticated()` 
- OAuth2 org/domain checks in SpinnakerUserInfoTokenServices NEVER RUN
- Password: random per-start (in log) or operator-set spring.security.user.password
- **Root**: OAuth2SsoConfig.java:110-112
- **Impact**: FULL auth bypass if password known — skips ALL identity checks

## HIGH

### CS-01: OAuth2 bearer tokens without audience binding (= our F-21)
### CS-02: URL policy DNS fallback bypass → SSRF to cloud metadata
### CS-03: Excluded-domain case-sensitive bypass → SSRF (**PROVEN LIVE**)
### CS-08: fromUrl userinfo-as-host authority confusion → bypass ALL SSRF controls
### CS-09: Verbatim-IP rejection bypass via two/three-part IPv4 literals

## MEDIUM

### CS-04: Login CSRF via access_token query parameter
### CS-05: Open redirect parsing mismatch (backslash java.net.URL vs WHATWG)
### CS-06: rejectLocalhost bypass via 0.0.0.0 wildcard address
### CS-07: Stack trace exposure via ?trace=true on /error

## PROVEN ON LIVE TARGET (ClarityApp)
- CS-03: `spin-front50.SPINNAKER:8080` → 635KB pipelines, 423 webhook sources, 46 K8s namespaces
