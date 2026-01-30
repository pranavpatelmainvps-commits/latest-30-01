import socket
import requests
import time
import sys

SERVICES = [
    ("Dovecot IMAP", "localhost", 143),
    ("Dovecot POP3", "localhost", 110),
    ("Roundcube Web", "localhost", 8000),
    ("Backend API", "localhost", 5000),
]

def check_port(name, host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"[OK] {name} is listening on {port}")
            return True
        else:
            print(f"[FAIL] {name} is NOT listening on {port}")
            return False
    except Exception as e:
        print(f"[ERR] {name} check failed: {e}")
        return False

def check_webhook():
    print("\n--- Testing Backend Webhook ---")
    url = "http://localhost:5000/api/inbound/webhook"
    payload = {
        "subject": "Test Verification Email",
        "sender": "verifier@localhost",
        "recipient": "admin@localhost",
        "message_type": "verification"
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code == 200:
            print(f"[OK] Webhook endpoint responded: {resp.json()}")
            return True
        else:
            print(f"[FAIL] Webhook returned status {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
         print(f"[FAIL] Webhook connection failed: {e}")
         return False

def simulate_email_delivery():
    print("\n--- Testing Full Flow (File -> Processor -> Webhook) ---")
    
    # Create a dummy email file content
    email_content = (
        "Return-Path: <sender@example.com>\n"
        "From: sender@example.com\n"
        "To: admin@localhost\n"
        "Subject: E2E Test Email\n"
        "\n"
        "This is a test email dropped directly into the Maildir.\n"
    )
    
    # We need to write this to a file inside the container.
    # Target: /var/mail/vhosts/localhost/admin/new/test_msg_1
    
    cmd = [
        "docker", "exec", "powermta-main-dovecot-1", "bash", "-c", 
        f"mkdir -p /var/mail/vhosts/localhost/admin/new && echo '{email_content}' > /var/mail/vhosts/localhost/admin/new/1000000001.M12345P12345.host"
    ]
    # Note: Container name might vary. We should check 'docker ps' or use labels.
    # Assuming 'powermta-main-dovecot-1' or similar depending on folder name. 
    # Let's try a generic approach or ask user. For now, try default compose naming.
    # Folder name is 'PowerMTA-main', so 'powermta-main_dovecot_1'.
    
    # Let's get the container ID for dovecot
    import subprocess
    try:
        cont_id = subprocess.check_output("docker ps -qf name=dovecot", shell=True).decode().strip()
        if not cont_id:
            print("[SKIP] Could not find dovecot container to inject email.")
            return False
        
        print(f"Injecting email into container {cont_id}...")
        
        # Write to local temp file first
        with open("e2e_test.eml", "w") as f:
            f.write(email_content)
            
        # 1. Copy to container /tmp
        cp_cmd = f"docker cp e2e_test.eml {cont_id}:/tmp/e2e_test.eml"
        subprocess.run(cp_cmd, shell=True, check=True)
        
        # 2. Move to Maildir using direct commands (avoid shell quoting hell)
        
        # Ensure directory exists
        mkdir_cmd = ["docker", "exec", cont_id, "mkdir", "-p", "/var/mail/vhosts/localhost/admin/new"]
        subprocess.run(mkdir_cmd, check=True)
        
        # Move file
        mv_cmd = ["docker", "exec", cont_id, "mv", "/tmp/e2e_test.eml", "/var/mail/vhosts/localhost/admin/new/1000000001.M12345P12345.host"]
        subprocess.run(mv_cmd, check=True)
        
        print("Email file created.")
        
        # Cleanup local file
        import os
        try:
            os.remove("e2e_test.eml")
        except:
            pass
        
        # Wait for processor
        print("Waiting for processor (5s)...")
        time.sleep(5)
        
        # Check backend stats via API
        resp = requests.get("http://localhost:5000/api/inbound/emails")
        if resp.status_code == 200:
            emails = resp.json().get("emails", [])
            for e in emails:
                if e.get("subject") == "E2E Test Email":
                    print("[PASS] E2E Test Passed! Email received by backend.")
                    return True
            print(f"[FAIL] E2E Email not found in backend. Recent emails: {len(emails)}")
        else:
             print(f"[FAIL] Could not fetch emails from backend: {resp.status_code}")
             
    except Exception as e:
        print(f"[ERR] E2E Test Failed: {e}")
        return False

def main():
    print("Verifying Inbound Mail Stack...")
    all_up = True
    for name, host, port in SERVICES:
        if not check_port(name, host, port):
            all_up = False
    
    if all_up:
        print("\nAll ports are open. Testing Application Logic...")
        if check_webhook():
             simulate_email_delivery()
        else:
             print("\n>>> APPLICATION LOGIC FAILED <<<")
    else:
        print("\n>>> VERIFICATION FAILED: Services are not accessible <<<")

if __name__ == "__main__":
    main()
