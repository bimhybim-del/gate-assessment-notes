# Spinnaker Gate Security Assessment

Security code review findings and validation tools for Spinnaker Gate API gateway.

## Contents

- `FINDINGS-REGISTRY.md` — All findings with root cause analysis, validation status, and source code references
- `claude-security-findings.md` — AI-assisted scan results (10 findings)
- `validation-tools/` — Python scripts for validating each finding

## Stack Under Review

- Spinnaker Gate 6.63.0
- Spring Boot 2.7.18, Spring Security 5.7.11
- Embedded Tomcat 9.0.83
- OAuth2 (GitHub, Google, Azure AD, GitLab), SAML, X.509, Basic Auth
- Spring Session (Redis-backed)

## Key Areas

1. Authentication bypass vectors in OAuth2 SSO flow
2. Identity propagation trust boundaries (X-SPINNAKER-* headers)  
3. SpEL expression sandbox restrictions and escape paths
4. SSRF controls in UserConfiguredUrlRestrictions
5. Spring Security filter chain ordering and dispatch behavior
