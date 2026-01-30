#!/usr/bin/env python3
import os
import sys
import argparse
import requests
import re

# ================= CONFIGURATION =================
PDNS_HOST = "192.119.169.12" 
PDNS_PORT = "8081"
BASE_URL = f"http://{PDNS_HOST}:{PDNS_PORT}/api/v1/servers/localhost"
DEFAULT_TTL = 300

def get_api_key():
    api_key = os.environ.get("PDNS_API_KEY")
    if api_key: return api_key.strip()
    return "MyDNSApiKey2026"

def get_headers(api_key):
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }

def validate_domain(domain):
    if not domain: return None
    domain = domain.strip().rstrip('.')
    if "example" in domain.lower(): return None
    return domain + "."

def ensure_zone(domain, headers):
    zone_url = f"{BASE_URL}/zones/{domain}"
    try:
        if requests.get(zone_url, headers=headers).status_code == 200:
            return
        
        # Create Native Zone
        payload = {
            "name": domain,
            "kind": "Native",
            "nameservers": [f"ns1.{domain}", f"ns2.{domain}"]
        }
        requests.post(f"{BASE_URL}/zones", headers=headers, json=payload)
    except:
        sys.exit(1)

def create_records(domain, ips, hostname, selector, dkim_key, dmarc_email, headers, client_only=False):
    rrsets = []
    
    def make_rrset(name, type_, content_list):
        return {
            "name": name,
            "type": type_,
            "ttl": DEFAULT_TTL,
            "changetype": "REPLACE",
            "records": [{"content": c, "disabled": False} for c in content_list]
        }

    # 1. & 2. A/MX Records (infrastructure) - SKIP IN CLIENT MODE
    if not client_only:
        primary_ip = ips[0]
        
        if hostname:
            # Enforce Hostname A Record
            if not hostname.rstrip('.').endswith(domain.rstrip('.')):
                 print(f"Warning: Hostname {hostname} does not match domain {domain}")
            
            rrsets.append(make_rrset(hostname, "A", [primary_ip]))
            rrsets.append(make_rrset(domain, "MX", [f"10 {hostname}"]))
            
        else:
            # Fallback Legacy
            rrsets.append(make_rrset(f"mail.{domain}", "A", ips))
            rrsets.append(make_rrset(domain, "MX", [f"10 mail.{domain}"]))

        # Root A Record
        rrsets.append(make_rrset(domain, "A", ips))

    # 3. SPF Record -> v=spf1 ip4:IP1 ... -all
    spf_parts = ["v=spf1"]
    for ip in ips:
        spf_parts.append(f"ip4:{ip}")
    spf_parts.append("-all")
    rrsets.append(make_rrset(domain, "TXT", [f"\"{' '.join(spf_parts)}\""]))

    # 4. DKIM
    if dkim_key and dkim_key.lower() != "none":
        dkim_clean = dkim_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "").strip()
        dkim_val = f"\"v=DKIM1; k=rsa; p={dkim_clean}\""
        rrsets.append(make_rrset(f"{selector}._domainkey.{domain}", "TXT", [dkim_val]))

    # 5. DMARC
    dmarc_val = f"\"v=DMARC1; p=none; rua=mailto:{dmarc_email}; ruf=mailto:{dmarc_email}; fo=1\""
    rrsets.append(make_rrset(f"_dmarc.{domain}", "TXT", [dmarc_val]))

    # Batch Update
    zone_url = f"{BASE_URL}/zones/{domain}"
    try:
        requests.patch(zone_url, headers=headers, json={"rrsets": rrsets})
        print(f"DNS Provisioned for {domain} (Client Mode: {client_only})")
    except Exception as e:
        print(f"DNS Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--ip", action='append', required=True)
    parser.add_argument("--hostname", required=False, help="PTR-derived Hostname for A record enforcement")
    parser.add_argument("--selector", required=True)
    parser.add_argument("--dkim-key", required=True)
    parser.add_argument("--dmarc-email", required=True)
    parser.add_argument("--client-only", action="store_true", help="Skip A/MX records, only provision SPF/DKIM/DMARC")
    
    args = parser.parse_args()
    
    api_key = get_api_key()
    headers = get_headers(api_key)
    
    domain = validate_domain(args.domain)
    if not domain:
        print("Invalid Domain")
        sys.exit(1)
        
    ensure_zone(domain, headers) 
    create_records(domain, args.ip, args.hostname, args.selector, args.dkim_key, args.dmarc_email, headers, client_only=args.client_only)
