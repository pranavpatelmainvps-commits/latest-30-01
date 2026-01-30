#!/usr/bin/env python3
import os
import sys
import time
import email
import email.policy
import json
import requests
import re
import shutil
import logging
from datetime import datetime

# ================= CONFIGURATION =================
MAIL_ROOT = "/var/mail/vhosts"
PROCESSED_DIR = "/var/mail/processed"
ERROR_DIR = "/var/mail/error"
# When running in docker, point to the container name
API_ENDPOINT = "http://pmta-dashboard:5000/api/inbound/webhook"
API_KEY = "SECRET_API_KEY"

# Domains to watch
# Domains are now discovered dynamically from MAIL_ROOT
# DOMAINS = [] 

# Polling Interval (Seconds)
POLL_INTERVAL = 2

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("InboundProcessor")

# ================= CLASSIFICATION LOGIC =================
BOUNCE_LOWER_TERMS = ["undeliverable", "delivery status notification", "failure notice", "mailer-daemon", "postmaster"]
AUTO_REPLY_HEADERS = ["X-Auto-Response-Suppress", "Auto-Submitted"]

def classify_message(msg):
    """
    Classifies email as 'bounce', 'auto', or 'reply'.
    Returns: (message_type, bounce_type, diagnostic_info)
    """
    # 1. Check Auto-Reply Headers
    for h in AUTO_REPLY_HEADERS:
        if msg.get(h):
            return "auto", "null", "Auto-Submitted Header Found"
    
    subject = msg.get("Subject", "").lower()
    sender = msg.get("From", "").lower()
    
    if "automatic reply" in subject or "out of office" in subject:
        return "auto", "null", "Subject Heuristic"

    # 2. Check for Bounce (DSN)
    content_type = msg.get_content_type()
    
    if "multipart/report" in content_type or "delivery-status" in content_type:
        return "bounce", "hard", "Standard DSN"
    
    if any(term in sender for term in BOUNCE_LOWER_TERMS):
        return "bounce", "hard", "Sender Heuristic"
        
    if any(term in subject for term in BOUNCE_LOWER_TERMS):
        return "bounce", "hard", "Subject Heuristic"

    # 3. Default to Reply
    return "reply", "null", "User Reply"

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in cdispo:
                try:
                    body = part.get_content()
                except:
                    pass
                break # Prefer first text/plain
    else:
        try:
            body = msg.get_content()
        except:
             # Fallback
             body = str(msg.get_payload())
    return body

def parse_bounce_diagnostic(msg, body):
    """
    Simulated deep bounce parser.
    In production, this would parse message/delivery-status parts.
    """
    # Regex for common SMTP codes
    match = re.search(r'([45]\.\d\.\d)', body)
    code = match.group(1) if match else "5.0.0"
    
    # Simple Heuristic
    if code.startswith("5"):
        return "hard", code, body[:200]
    elif code.startswith("4"):
        return "soft", code, body[:200]
    
    return "hard", "unknown", "Could not parse code"

# ================= PROCESSING LOOP =================
def process_file(filepath, domain, user):
    try:
        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
            
        # Basic Metadata
        original_to = msg.get("To", "")
        msg_from = msg.get("From", "")
        subject = msg.get("Subject", "")
        
        # Classification
        m_type, b_type, diag = classify_message(msg)
        body = extract_body(msg)
        
        smtp_status = ""
        if m_type == "bounce":
            # Deep scan for diagnostic code if it's a DSN
            b_type_refined, code, detailed_diag = parse_bounce_diagnostic(msg, body)
            b_type = b_type_refined
            smtp_status = code
            diag = detailed_diag
            
        payload = {
            "message_type": m_type,
            "bounce_type": b_type,
            "recipient": user + "@" + domain, # The mailbox it landed in (e.g. bounce@domain)
            "original_recipient": original_to, # Who sent it (or who it was sent to, context dependent)
            "sender": msg_from,
            "smtp_status": smtp_status,
            "smtp_diagnostic": diag,
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "subject": subject,
            "body_track": body[:500] # Truncate for log
        }
        
        # Send to API
        logger.info(f"Processing {filepath}: {m_type} from {msg_from}")
        try:
            resp = requests.post(API_ENDPOINT, json=payload, headers={"X-API-Key": API_KEY}, timeout=5)
            resp.raise_for_status()
            logger.info("API Push Success")
        except Exception as e:
            logger.error(f"API Push Failed: {e}")
            # Depending on policy, maybe move to error or retry. 
            # For now, we move to processed to avoid loop, but log heavily.

        # Move to processed
        dest_dir = os.path.join(PROCESSED_DIR, domain, user)
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(filepath, os.path.join(dest_dir, os.path.basename(filepath)))
        
    except Exception as e:
        logger.error(f"Failed to process {filepath}: {e}")
        dest_dir = os.path.join(ERROR_DIR, domain, user)
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(filepath, os.path.join(dest_dir, os.path.basename(filepath)))

def scan_maildirs():
    if not os.path.exists(MAIL_ROOT):
        return

    # Dynamic Discovery: List all directories in MAIL_ROOT
    # Filter only directories to avoid crashes on files
    candidates = [d for d in os.listdir(MAIL_ROOT) if os.path.isdir(os.path.join(MAIL_ROOT, d))]
    
    for domain in candidates:
        domain_path = os.path.join(MAIL_ROOT, domain)
        
        # Scan users (bounce, support, catchall)
        if not os.path.exists(domain_path): continue
        pass
        
        for user in os.listdir(domain_path):
            user_path = os.path.join(domain_path, user)
            if not os.path.isdir(user_path): continue
            
            # Dovecot configured with maildir:/var/mail/vhosts/%d/%n
            # So 'new' is directly under the user directory
            new_dir = os.path.join(user_path, "new")
            if os.path.exists(new_dir):
                for fname in os.listdir(new_dir):
                    fpath = os.path.join(new_dir, fname)
                    if os.path.isfile(fpath):
                         process_file(fpath, domain, user)

if __name__ == "__main__":
    logger.info("Inbound Processor Started...")
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(ERROR_DIR, exist_ok=True)
    
    while True:
        scan_maildirs()
        time.sleep(POLL_INTERVAL)
