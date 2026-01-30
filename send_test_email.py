import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================= CONFIGURATION =================
# Replace with your server IP
SMTP_SERVER = "192.119.169.5" # Updated from last log
SMTP_PORT = 25
SMTP_USER = "admin"      # Default from backend.py
SMTP_PASS = "password"   # Default from backend.py

SENDER_EMAIL = "test@quicklendings.com"
RECIPIENT_EMAIL = "test-hu1s9nfsa@srv1.mail-tester.com" # Updated from user input
# =================================================

msg = MIMEMultipart()
msg['From'] = SENDER_EMAIL
msg['To'] = RECIPIENT_EMAIL
msg['Subject'] = "PowerMTA Test: Hello World!"

body = "This is a test email from your freshly installed PowerMTA server."
msg.attach(MIMEText(body, 'plain'))

try:
    print(f"Connecting to {SMTP_SERVER}:{SMTP_PORT}...")
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.set_debuglevel(1) # See verbose output
    
    print("Logging in...")
    server.login(SMTP_USER, SMTP_PASS)
    
    print("Sending mail...")
    text = msg.as_string()
    server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, text)
    server.quit()
    
    print("\n>>> SUCCESS! Email sent successfully.")
except Exception as e:
    print(f"\n!!! ERROR: {e}")
