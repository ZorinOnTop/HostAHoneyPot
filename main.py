from flask import Flask, request, render_template_string, make_response
import logging
import sys
import json
import os
from datetime import datetime, timedelta, timezone
import requests

app = Flask(__name__)

# Konfiguracja logowania do pliku i konsoli
logger = logging.getLogger()
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('honeypot.log', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(message)s'))
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.handlers = [file_handler, console_handler]

COOLDOWN_FILE = 'honeypot_cooldown.json'
COOLDOWN_HOURS = 24
ABUSEIPDB_API_KEY = ''  # <-- API key to AbuseIPDB


def load_cooldowns():
    if os.path.exists(COOLDOWN_FILE):
        with open(COOLDOWN_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def save_cooldowns(cooldowns):
    with open(COOLDOWN_FILE, 'w', encoding='utf-8') as f:
        json.dump(cooldowns, f)

def should_log_ip(ip):
    cooldowns = load_cooldowns()
    now = datetime.now(timezone.utc)
    last = cooldowns.get(ip)
    if last:
        last_dt = datetime.fromisoformat(last)
        if now - last_dt < timedelta(hours=COOLDOWN_HOURS):
            return False
    cooldowns[ip] = now.isoformat()
    save_cooldowns(cooldowns)
    return True

def get_abuseipdb_timestamp(dt):
    # AbuseIPDB expects: 2023-04-24T16:20:38Z (no microseconds, always UTC)
    return dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def report_to_abuseipdb(ip, comment, timestamp):
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    data = {
        'ip': ip,
        'categories': '19',
        'comment': comment,
        'timestamp': timestamp
    }
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        logger.info(f"AbuseIPDB response for {ip}: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"AbuseIPDB report failed for {ip}: {e}")

nginx_template = '''
<!DOCTYPE html><html><head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body></html>
'''

nginx_404_template = '''
<html><head>
<meta charset="utf-8"><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body></html>
'''

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def index(path):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    endpoint = request.path
    protocol = request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
    method = request.method
    if should_log_ip(ip):
        now = datetime.now(timezone.utc)
        log_message = f"""
Hitted a Honeypot server!

IP: {ip}
Endpoint: {endpoint}
Protocol: {protocol} ({method})
User-Agent: {user_agent}

Host your own Honeypot server and collect malicious IP's:
https://github.com/ZorinOnTop/HostAHoneyPot
"""
        logger.info(log_message.strip())
        # Wyślij raport do AbuseIPDB
        report_to_abuseipdb(
            ip=ip,
            comment=log_message.strip(),
            timestamp=get_abuseipdb_timestamp(now)
        )

    response = make_response(render_template_string(nginx_template))
    response.headers['Server'] = 'nginx'
    return response

@app.errorhandler(404)
def page_not_found(e):
    response = make_response(nginx_404_template, 404)
    response.headers['Server'] = 'nginx'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False) 
