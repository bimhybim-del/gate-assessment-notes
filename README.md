# Spinnaker Gate — Security Code Review

Source code from Spinnaker Gate (Netflix/Spinnaker open-source CI/CD platform) for security code review and vulnerability analysis.

## Components

- `gate-auth/` — Gate authentication configuration (Spring Security, OAuth2, SAML, X509, IAP)
- `kork-auth/` — Shared authentication library (request filters, identity propagation, SpEL sandbox)
- `spring-security-oauth-auth/` — Spring Security OAuth2 legacy library (redirect handling, token processing)
- `echo-auth/` — Echo notification service (webhook handling, callback processing, SpEL evaluation)
- `orca-spel/` — Orca pipeline execution (SpEL expression evaluation, URL validation)

## Purpose

Static analysis and code review to identify potential authentication bypass vulnerabilities, injection flaws, and security misconfigurations in the Spinnaker Gate API gateway.

## Stack

- Java 17, Spring Boot 2.7.18, Spring Security 5.7.11
- Embedded Tomcat 9.0.83
- Spring Session (Redis-backed)
- OAuth2 (GitHub, Google, Azure AD, GitLab), SAML, LDAP, X.509, Basic Auth
