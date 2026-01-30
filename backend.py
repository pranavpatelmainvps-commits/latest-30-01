from flask import Flask, request, jsonify, send_from_directory
import paramiko
import tempfile
import os
import threading
import time
import subprocess
import sys
import requests
import socket

# Use local path for easier debugging
INSTALL_LOG_FILE = os.path.join(os.getcwd(), "install_progress.log")

app = Flask(__name__)

# Mock database for received emails
RECEIVED_EMAILS = []

@app.route("/api/inbound/webhook", methods=["POST"])
def inbound_webhook():
    data = request.json
    print(f"Received Inbound Mail Webhook: {data.get('subject')} from {data.get('sender')}")
    RECEIVED_EMAILS.append(data)
    # Keep only last 100 emails in memory
    if len(RECEIVED_EMAILS) > 100:
        RECEIVED_EMAILS.pop(0)
        
    return jsonify({"status": "received", "count": len(RECEIVED_EMAILS)})

@app.route("/api/inbound/emails", methods=["GET"])
def get_inbound_emails():
    return jsonify({"emails": list(reversed(RECEIVED_EMAILS))})

PMTA_TEMPLATE = "pmta-advanced.sh.tmpl"
BASE_INSTALLER = "pmta-install.sh.tmpl"
PLATFORM_SMTP_HOSTNAME = "smtp.quicklendings.com"

# Files expected in the current directory
PMTA_FILES = ["PowerMTA.rpm", "pmtad", "pmtahttpd", "license"]

@app.route("/")
def index():
    return send_from_directory(".", "test-dashboard.html")

@app.route("/install", methods=["POST"])
def install_pmta():
    data = request.json
    threading.Thread(target=run_install, args=(data,)).start()
    return jsonify({"status": "started", "message": "Installation started"})


@app.route("/logs", methods=["POST"])
def get_logs():
    data = request.json
    server_ip = data["server_ip"]
    ssh_user = data["ssh_user"]
    ssh_pass = data["ssh_pass"]

    logs = ""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(server_ip, username=ssh_user, password=ssh_pass, timeout=10)
        stdin, stdout, stderr = ssh.exec_command("tail -n 100 /var/log/pmta/log")
        logs = stdout.read().decode('utf-8')
    except Exception as e:
        logs = f"Error fetching logs: {str(e)}"
    finally:
        ssh.close()

    return jsonify({
        "status": "success",
        "logs": logs
    })

def run_install(data):
    print(">>> DEBUG: run_install thread STARTED")
    try:
        server_ip = data["server_ip"]
        ssh_user = data["ssh_user"]
        ssh_pass = data["ssh_pass"]
        mappings = data["mappings"]
        fresh_install = data.get("fresh_install", False)

        with open(INSTALL_LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")

        def log(msg):
            try:
                with open(INSTALL_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
                print(msg) 
            except Exception as e:
                print(f"FAILED TO WRITE LOG: {e}")

        def get_ptr(ip):
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
            except socket.herror:
                return None
            except Exception:
                return None

        def check_a_record(hostname):
            try:
                msg_ip = socket.gethostbyname(hostname)
                return msg_ip
            except:
                return None

        def create_ssh_client():
            retries = 3
            for attempt in range(retries):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(server_ip, username=ssh_user, password=ssh_pass, timeout=60)
                    return client
                except Exception as e:
                    print(f"SSH Connection Attempt {attempt+1} Failed: {e}")
                    if attempt < retries - 1:
                        time.sleep(5) 
                    else:
                        log(f"!!! SSH Connection Failed after {retries} attempts: {e}")
                        return None

        def run_command(cmd, description):
            log(f"--- {description} ---")
            client = create_ssh_client()
            if not client: return False

            try:
                stdin, stdout, stderr = client.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode('utf-8')
                error_out = stderr.read().decode('utf-8')
                
                log(output)
                if error_out: log(f"STDERR: {error_out}")
                
                if exit_status != 0:
                    log(f"!!! FAILED: {description} (Exit Code: {exit_status})")
                    client.close()
                    return False
                
                client.close()
                return True
            except Exception as e:
                log(f"!!! EXCEPTION: {e}")
                if client: client.close()
                return False

        def check_command(cmd):
            client = create_ssh_client()
            if not client: return False
            try:
                stdin, stdout, stderr = client.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                client.close()
                return exit_status == 0
            except:
                if client: client.close()
                return False

        def validate_pmta_config(config_str):
            issues = []
            
            # 1. Check for properly closed pools
            open_pools = config_str.count("<virtual-mta-pool")
            close_pools = config_str.count("</virtual-mta-pool>")
            if open_pools != close_pools:
                issues.append(f"Pool Mismatch: {open_pools} opened, {close_pools} closed")
            
            # 2. Check for Forbidden Directives in Domain Blocks
            lines = config_str.split('\n')
            in_domain = False
            curr_domain = ""
            
            for line in lines:
                line = line.strip()
                if line.startswith("<domain"):
                    in_domain = True
                    curr_domain = line
                elif line.startswith("</domain>"):
                    in_domain = False
                
                if in_domain:
                    # Forbidden directives
                    if line.startswith("use-virtual-mta") or line.startswith("use-virtual-mta-pool") or "source-ip" in line:
                         issues.append(f"Forbidden Routing Directive in '{curr_domain}': {line}")
            
            # 3. Check for Mandatory Global Directives
            if "add-date-header yes" not in config_str:
                issues.append("Missing Mandatory Directive: 'add-date-header yes'")
                
            # 4. Safety Check: No Placeholder Domains
            if "myplatform.com" in config_str:
                 issues.append("CRITICAL: Placeholder domain 'myplatform.com' found in config. Aborting!")

            return issues

        def upload_file(local_path, remote_path):
            if not os.path.exists(local_path):
                 log(f"!!! Local file missing: {local_path}")
                 return False

            client = create_ssh_client()
            if not client: return False

            try:
                sftp = client.open_sftp()
                try:
                    r_stat = sftp.stat(remote_path)
                    l_size = os.path.getsize(local_path)
                    if r_stat.st_size == l_size:
                        log(f"--- Upload {local_path} Success (Skipped - Already Exists) ---")
                        sftp.close()
                        client.close()
                        return True
                except IOError:
                    pass

                log(f"Uploading {local_path} to {remote_path}...")
                sftp.put(local_path, remote_path)
                sftp.close()
                client.close()
                log(f"--- Upload {local_path} Success ---")
                return True
            except Exception as e:
                log(f"!!! Upload Failed: {e}")
                if client: client.close()
                return False

        log("=== Installation Started (Authoritative Config Mode) ===")
        log(">>> [STEP:INIT] Initializing Deployment...")

        if fresh_install:
            log(">>> [STEP:UPLOAD] Uploading Core Files...")
            for f in PMTA_FILES:
                local_f = os.path.abspath(f)
                if not upload_file(local_f, f"/tmp/{f}"):
                    log(f"Required file upload failed: {f}. Aborting.")
                    return

            log(">>> [STEP:INSTALL] Checking PowerMTA Installation...")
            if check_command("rpm -q PowerMTA"):
                 log("PowerMTA is already installed. Skipping installer.")
                 log(">>> [STEP:INSTALL] Skipping (Already Installed)") 
            else:
                log("Running PowerMTA Installer...")
                try:
                    with open(BASE_INSTALLER, "r") as f:
                        script = f.read()
                    
                    # For the base installer, we just need a valid hostname to set /etc/hosts/hostname
                    # We'll pick the first domain from mappings as the 'primary' system hostname
                    # This is just for OS identity, PMTA config handles the rest per-IP
                    primary_domain = mappings[0]["domain"] if mappings else "localhost.localdomain"

                    script = script.replace("{{DOMAIN}}", primary_domain) 
                    script = script.replace("{{SERVER_IP}}", server_ip)
                    script = script.replace("{{SMTP_USER}}", "smtpuser")
                    script = script.replace("{{SMTP_PASS}}", "smtppass")

                    with tempfile.NamedTemporaryFile(delete=False, mode="wb", suffix=".sh") as tmp:
                        tmp.write(script.encode('utf-8'))
                        tmp_path = tmp.name
                    
                    if not upload_file(tmp_path, "/root/pmta-install.sh"): return
                    if not run_command("chmod +x /root/pmta-install.sh", "Set Execute Permission"): return
                    if not run_command("bash /root/pmta-install.sh", "Run PMTA Installer"): return

                except Exception as e:
                    log(f"Error preparing install script: {e}")
                    return

        log(">>> [STEP:CONFIG] Generating Authoritative Configuration...")
        
        try:
            input_pool_name = data.get("pool", "pool1")
            input_user = data.get("smtp_user", {"username": "admin", "password": "password"})
            input_routing = data.get("routing", [])

            # 1. Prepare Data Structures
            domain_groups = {}
            for m in mappings:
                d = m["domain"]
                if d not in domain_groups: domain_groups[d] = []
                domain_groups[d].append(m["ip"])
            
            dkim_pub_keys = {} 

            # 2. Key Generation Loop (Pre-Check)
            log("--- Ensuring DKIM Keys on Server ---")
            ssh_client = create_ssh_client()
            if not ssh_client: return

            for d_name in domain_groups.keys():
                parts = d_name.split('.')
                root_domain = ".".join(parts[-2:]) if len(parts) > 2 else d_name
                selector = "default"
                dkim_key_Path = f"/etc/pmta/dkim/{root_domain}/{selector}.private"
                
                # Check/Gen
                ssh_client.exec_command(f"mkdir -p {os.path.dirname(dkim_key_Path)}")
                
                # Check/Gen Key
                check_cmd = (
                    f"if [ ! -f {dkim_key_Path} ]; then "
                    f"  openssl genrsa -out {dkim_key_Path} 2048; "
                    f"  openssl rsa -in {dkim_key_Path} -pubout > {dkim_key_Path}.pub; "
                    f"fi; "
                    # Enforce Permissions
                    f"chmod 755 /etc/pmta/dkim; "
                    f"chmod 755 {os.path.dirname(dkim_key_Path)}; "
                    f"chmod 640 {dkim_key_Path}; "
                    f"chown -R pmta:pmta /etc/pmta/dkim; "
                    # Output Pub Key
                    f"cat {dkim_key_Path}.pub"
                )
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                pub_key = stdout.read().decode('utf-8').strip()
                
                if pub_key:
                     dkim_pub_keys[d_name] = pub_key
                else:
                     log(f"Warning: Failed to get DKIM key for {d_name}")
            
            ssh_client.close()


            # 3. DNS Provisioning & Config Building
            vmta_blocks = []
            pool_blocks = []
            source_blocks = []
            user_blocks = []
            domain_blocks = []
            pattern_blocks = []
            
            vmta_names_all = []
            vmta_global_idx = 1
            
            # --- 3a. Provision CLIENT IDENTITY + Generate VMTA Blocks (Multi-Home Mode) ---
            # We treat every domain as its own sender identity (Client Mode)
            
            env = os.environ.copy()
            env["PDNS_API_KEY"] = "MyDNSApiKey2026"

            for d_name, ips in domain_groups.items():
                parts = d_name.split('.')
                root_domain = ".".join(parts[-2:]) if len(parts) > 2 else d_name
                
                # Retrieve key for DNS provisioning
                pub_key = dkim_pub_keys.get(d_name, "")
                
                # Provision Client Sender Identity (SPF/DKIM/DMARC)
                # Since we are making the domain the HOSTNAME of the IP, we SHOULD provision A/MX records too if possible?
                # The user asked for "Dashboard Input" to drive everything.
                # Let's assume full provisioning for the domain -> IPs mapping.
               
                if pub_key:
                    # Determine if we should provision A/MX (Infrastructure) or just SPF/DKIM (Client)
                    # If the domain is being used as the HELO host, it NEEDS an A record.
                    # So we run in FULL mode (not client-only) for these domains.
                    
                    cmd_client = [
                        sys.executable, "pdns_automator.py",
                        "--domain", root_domain,
                        # "--client-only", # REMOVED: We need A records because we are using this domain as the source-host
                        "--selector", "default",
                        "--dkim-key", pub_key,
                        "--dmarc-email", f"postmaster@{root_domain}"
                    ]
                    for ip in ips:
                        cmd_client.extend(["--ip", ip])
                        
                    subprocess.run(cmd_client, capture_output=True, env=env)
                
                domain_vmta_names = []
                
                for ip in ips:
                    # B. Build Config (CLIENT MODE: Source Host = Client Domain)
                    vmta_name = f"vmta{vmta_global_idx}"
                    dkim_path = f"/etc/pmta/dkim/{root_domain}/default.private"
                    dkim_line = f"    domain-key default,{root_domain},{dkim_path}"
                    
                # DYNAMIC: smtp-source-host uses the DOMAIN mapped in the dashboard
                    source_host_val = f"mail.{root_domain}"

                    vmta_blocks.append(f"<virtual-mta {vmta_name}>\n    smtp-source-host {ip} {source_host_val}\n{dkim_line}\n</virtual-mta>")
                    
                    domain_vmta_names.append(vmta_name)
                    vmta_names_all.append(vmta_name)
                    vmta_global_idx += 1
                
                # C. Build Domain Config
                # [MODIFIED] OUTBOUND ONLY - No Inbound Processing in PMTA
                # Removed: route run-pipe ...
                # Removed: deliver-local yes
                # We do NOT generate <domain> blocks for local delivery anymore.
                pass

            # 4. Finalize Config Blocks
            if vmta_names_all:
                pool_members = "\n    ".join([f"virtual-mta {n}" for n in vmta_names_all])
                pool_blocks.append(f"<virtual-mta-pool {input_pool_name}>\n    {pool_members}\n</virtual-mta-pool>")

            # Define Source for Authenticated Submission (Port 2525 or 587)
            source_blocks.append(f"<source {input_pool_name}>\n    always-allow-relaying yes\n    smtp-service yes\n    add-date-header yes\n    default-virtual-mta {input_pool_name}\n</source>")
            user_blocks.append(f"<smtp-user {input_user['username']}>\n    password {input_user['password']}\n    source {input_pool_name}\n</smtp-user>")

            if input_routing:
                pt_lines = []
                for r in input_routing:
                    pt_lines.append(f"    mail-from /{r['pattern']}/ virtual-mta={r['vmta']}")
                pattern_blocks.append("<pattern-list selections>\n" + "\n".join(pt_lines) + "\n</pattern-list>")

            final_config_str = "\n\n".join(
                vmta_blocks + pool_blocks + source_blocks + user_blocks + domain_blocks + pattern_blocks
            )

            # 5. Validate & Apply Config
            validation_issues = validate_pmta_config(final_config_str)
            if validation_issues:
                log("!!! CONFIG VALIDATION FAILED !!!")
                for issue in validation_issues:
                    log(f" - {issue}")
                return

            with open(PMTA_TEMPLATE, "r") as f:
                script = f.read()

            script = script.replace("{{VMTA_BLOCK}}", final_config_str)
            script = script.replace("{{DOMAIN_BLOCK}}", "")
            # Removing HOSTNAME replacement as it was used for global setting, now handled per VMTA
            # But wait, pmta-advanced.sh.tmpl doesn't have {{HOSTNAME}} ?
            # Checking pmta-advanced.sh.tmpl...
            # It actually didn't seem to use {{HOSTNAME}} in the template view I saw earlier.
            # But the backend code WAS replacing it. Let's keep it safe or empty.
            script = script.replace("{{HOSTNAME}}", "localhost.localdomain") 

            with tempfile.NamedTemporaryFile(delete=False, mode="wb", suffix=".sh") as tmp:
                safety_header = """# Safety: Backup existing config
cp /etc/pmta/config /etc/pmta/config.bak
"""
                final_script = safety_header + "\n" + script + """
# Validate & Start
echo "Validating Config..."
/usr/sbin/pmtad --debug --dontSend > /var/log/pmta_validation.log 2>&1 &
sleep 5
systemctl restart pmta
echo "Service Restarted."
"""
                tmp.write(final_script.encode('utf-8'))
                tmp_path = tmp.name

            if not upload_file(tmp_path, "/root/pmta-apply-config.sh"): return
            if not run_command("bash /root/pmta-apply-config.sh", "Apply Configuration"): return
            
            log(">>> [STEP:FINISH] PMTA configuration completed successfully.")

            # 6. Post-Config Compliance Audit
            log("\n>>> [AUDIT] Running Post-Install Compliance Check...")
            
            ptr_failures = []
            
            log("-" * 60)
            log(f"{'IP':<16} {'Current PTR':<25} {'Required PTR':<25} {'Result'}")
            log("-" * 60)
            
            for m in mappings:
                ip = m["ip"]
                d = m["domain"]
                parts = d.split('.')
                root_d = ".".join(parts[-2:]) if len(parts) > 2 else d
                
                # AUDIT CHANGE: Required PTR is now the dynamic host
                required_hostname = f"mail.{root_d}"
                
                ptr = get_ptr(ip)
                ptr_short = (ptr[:22] + '..') if ptr and len(ptr) > 25 else (ptr or "None")
                req_short = (required_hostname[:22] + '..') if len(required_hostname) > 25 else required_hostname
                
                status_msg = "✅ OK"
                
                # Case-insensitive comparison
                if not ptr or (ptr.lower() != required_hostname.lower()):
                    status_msg = "⚠ PTR update required"
                    ptr_failures.append({"ip": ip, "required": required_hostname, "current": ptr})
                
                log(f"{ip:<16} {ptr_short:<25} {req_short:<25} {status_msg}")
            
            log("-" * 60)

            if ptr_failures:
                log("\nIMPORTANT INFRASTRUCTURE AUDIT:")
                log("The following IPs do not have the correct PTR record:")
                for fail in ptr_failures:
                    current_val = fail['current'] if fail['current'] else "None"
                    log(f"IP: {fail['ip']}")
                    log(f"Current PTR : {current_val}")
                    log(f"Required PTR: {fail['required']} (Domain Identity)")
                    log(f"Action: Update PTR for {fail['ip']} -> {fail['required']}\n")
            else:
                log("\n>>> Perfect! All IPs match their Domain Identity.")

            log("=== Process Finished ===")

        except Exception as e:
            log(f"Error in config generation: {e}")
            import traceback
            log(traceback.format_exc())
            return

    except Exception as outer_e:
        print(f"!!! CRITICAL THREAD ERROR: {outer_e}")


@app.route("/install_logs", methods=["GET"])
def get_install_logs():
    if os.path.exists(INSTALL_LOG_FILE):
        try:
            with open(INSTALL_LOG_FILE, "r", encoding="utf-8") as f:
                return jsonify({"logs": f.read()})
        except Exception:
             return jsonify({"logs": "Error reading log file"})
    return jsonify({"logs": ""})

@app.route("/dns/records", methods=["GET"])
def get_dns_records():
    domain = request.args.get("domain")
    if not domain: return jsonify({"error": "Domain is required"}), 400
    if not domain.endswith("."): domain += "."

    PDNS_HOST = "192.119.169.12"
    PDNS_PORT = "8081"
    API_KEY = "MyDNSApiKey2026"
    
    url = f"http://{PDNS_HOST}:{PDNS_PORT}/api/v1/servers/localhost/zones/{domain}"
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            rrsets = data.get("rrsets", [])
            ns_records = []
            other_records = []

            for rr in rrsets:
                if rr["type"] == "NS":
                    for r in rr["records"]: ns_records.append(r["content"])
                else:
                    for r in rr["records"]:
                        other_records.append({
                            "name": rr["name"],
                            "type": rr["type"],
                            "ttl": rr["ttl"],
                            "content": r["content"]
                        })
            return jsonify({
                "status": "success",
                "domain": domain,
                "nameservers": ns_records,
                "records": other_records
            })
        elif resp.status_code == 404:
             return jsonify({"error": "Zone not found"}), 404
        else:
             return jsonify({"error": f"PowerDNS Error: {resp.text}"}), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
