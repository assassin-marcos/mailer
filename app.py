import smtplib
import json
import csv
import io
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import random
import os
import re
import html
import base64
import hashlib
import uuid
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
import imaplib
import email as email_lib
from email.header import decode_header
import threading
import queue
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta, datetime, timezone
import pyotp
import qrcode
import qrcode.image.svg

# IST timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import requests as http_requests

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

app.config['SESSION_COOKIE_NAME'] = 'securemailer'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------- CSRF Protection ----------
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    if request.method in ('POST', 'PUT', 'DELETE'):
        if request.content_type and 'application/json' in request.content_type:
            return
        if request.endpoint in ('login', 'reset_with_otp', 'request_otp', 'verify_2fa_login'):
            return
        token = session.get('_csrf_token')
        form_token = request.form.get('_csrf_token')
        if not token or token != form_token:
            flash('Session expired. Please try again.')
            return redirect(request.referrer or url_for('dashboard'))

# ---------- Track Last Active ----------
@app.before_request
def track_last_active():
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        try:
            with get_pg_conn() as conn:
                conn.execute(
                    "UPDATE users SET last_active=%s WHERE username=%s",
                    (now_ist().strftime('%Y-%m-%d %I:%M %p IST'), current_user.id)
                )
                conn.commit()
        except Exception:
            pass

# ---------- Security Headers ----------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response

# ---------- Rate Limiting (simple in-memory) ----------
_rate_limits = {}
_rate_lock = threading.Lock()

def check_rate_limit(key, max_requests, window_seconds):
    now = time.time()
    with _rate_lock:
        if key not in _rate_limits:
            _rate_limits[key] = []
        _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window_seconds]
        if len(_rate_limits[key]) >= max_requests:
            return False
        _rate_limits[key].append(now)
        return True

# ---------- OTP Store for Password Reset ----------
_otp_store = {}
_otp_lock = threading.Lock()
OTP_EXPIRY = 600  # 10 minutes

def generate_otp():
    """Generate a 6-digit OTP."""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def store_otp(username, otp):
    """Store OTP with expiry for a username."""
    with _otp_lock:
        _otp_store[username] = {'otp': otp, 'created_at': time.time()}
        # Cleanup expired OTPs
        stale = [k for k, v in _otp_store.items() if time.time() - v['created_at'] > OTP_EXPIRY]
        for k in stale:
            del _otp_store[k]

def verify_otp(username, otp):
    """Verify OTP for a username. Returns True if valid and not expired."""
    with _otp_lock:
        entry = _otp_store.get(username)
        if not entry:
            return False
        if time.time() - entry['created_at'] > OTP_EXPIRY:
            del _otp_store[username]
            return False
        if entry['otp'] != otp:
            return False
        del _otp_store[username]
        return True

# ---------- MX Record Cache ----------
_mx_cache = {}
_mx_cache_lock = threading.Lock()
MX_CACHE_TTL = 3600  # 1 hour

def check_mx_record(domain):
    """Check if domain has valid MX records. Returns (has_mx, details)."""
    now = time.time()
    with _mx_cache_lock:
        if domain in _mx_cache:
            cached_result, cached_time = _mx_cache[domain]
            if now - cached_time < MX_CACHE_TTL:
                return cached_result
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        result = (True, mx_hosts[:3])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result = (False, ['No MX records found'])
    except dns.resolver.NoNameservers:
        result = (False, ['DNS server unreachable'])
    except Exception:
        result = (True, ['DNS lookup timeout — assuming valid'])
    with _mx_cache_lock:
        _mx_cache[domain] = (result, now)
    return result

# ---------- Credential Daily Usage Tracker ----------
_cred_usage = {}
_cred_usage_lock = threading.Lock()
GMAIL_DAILY_LIMIT = 500

def track_cred_usage(email_addr):
    """Increment daily usage counter for a credential email."""
    today = now_ist().strftime('%Y-%m-%d')
    with _cred_usage_lock:
        key = f"{email_addr}:{today}"
        _cred_usage[key] = _cred_usage.get(key, 0) + 1
        # Cleanup old days
        stale = [k for k in _cred_usage if not k.endswith(today)]
        for k in stale:
            del _cred_usage[k]

def get_cred_usage(email_addr):
    """Get number of emails sent today by this credential."""
    today = now_ist().strftime('%Y-%m-%d')
    with _cred_usage_lock:
        return _cred_usage.get(f"{email_addr}:{today}", 0)

def get_cred_remaining(email_addr):
    """Get remaining emails for today."""
    return max(0, GMAIL_DAILY_LIMIT - get_cred_usage(email_addr))

# ---------- Encryption Utilities ----------
def derive_key(password, salt):
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, dklen=32))

def encrypt(value, key):
    return Fernet(key).encrypt(value.encode()).decode()

def decrypt(value, key):
    return Fernet(key).decrypt(value.encode()).decode()

def mask_email(email_str):
    try:
        local, domain = email_str.split('@')
        return local[:3] + '****@' + domain[:3] + '***.com'
    except (ValueError, AttributeError):
        return '***@***.com'

def extract_email_from_header(from_header):
    """Extract email address from a From header like 'Name <email@example.com>'."""
    match = re.search(r'<([^>]+)>', from_header)
    if match:
        return match.group(1).lower().strip()
    if '@' in from_header:
        return from_header.strip().lower()
    return ''

# ---------- Bounce / NDR Detection ----------
BOUNCE_SENDERS = {
    'mailer-daemon', 'postmaster', 'mail-daemon', 'noreply',
    'no-reply', 'donotreply', 'do-not-reply',
    'bounce', 'bounces', 'mail-noreply'
}
BOUNCE_SUBJECT_PATTERNS = re.compile(
    r'(delivery\s*(status|fail|notif)|undeliver|mail\s*delivery\s*(failed|subsystem)|'
    r'returned\s*mail|failure\s*notice|bounce|auto[\-\s]?reply|'
    r'out\s*of\s*(the\s*)?office|automatic\s*reply|'
    r'message\s*not\s*delivered|recipient\s*rejected|'
    r'delayed\s*mail|mail\s*system\s*error)',
    re.IGNORECASE
)

def is_bounce_or_ndr(sender, subject):
    """Detect bounce/NDR/auto-reply emails by sender and subject patterns."""
    sender = sender or ''
    subject = subject or ''
    sender_lower = sender.lower().strip()
    # Check sender address
    sender_email = extract_email_from_header(sender_lower) or sender_lower
    sender_local = sender_email.split('@')[0] if '@' in sender_email else sender_email
    # Also check if local part starts with a known bounce prefix (handles bounce+abc@sendgrid.net)
    if sender_local in BOUNCE_SENDERS:
        return True
    for prefix in ('mailer-daemon', 'postmaster', 'bounce', 'noreply', 'no-reply', 'donotreply', 'do-not-reply'):
        if sender_local.startswith(prefix):
            return True
    # Check subject patterns
    if BOUNCE_SUBJECT_PATTERNS.search(subject):
        return True
    return False

# ---------- PostgreSQL Database ----------
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost/mailer')

# Connection pool — shared across threads, min 2, max 20 connections
_pg_pool = psycopg2.pool.ThreadedConnectionPool(2, 20, DATABASE_URL)

class PgConn:
    """Thin wrapper around psycopg2 connection that mimics sqlite3 interface.
    Creates a fresh RealDictCursor per execute() call to avoid stale-cursor issues.
    Auto-rolls back on errors so the connection stays usable."""
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql, params=None):
        try:
            cursor = self._conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute(sql, params or ())
            self._last_cursor = cursor
            return cursor
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.rollback()
        except Exception:
            pass
        _pg_pool.putconn(self._conn)

    def fetchone(self):
        return self._last_cursor.fetchone()

    def fetchall(self):
        return self._last_cursor.fetchall()

    @property
    def rowcount(self):
        return self._last_cursor.rowcount

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

def get_pg_conn():
    """Get a PostgreSQL connection from the pool, wrapped in PgConn."""
    return PgConn(_pg_pool.getconn())

SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    last_active TEXT DEFAULT '',
    totp_secret TEXT DEFAULT ''
)""",
    """CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    encrypted_email TEXT NOT NULL,
    encrypted_app_password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS sent_logs (
    id SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_domain TEXT NOT NULL,
    encrypted_email TEXT NOT NULL,
    sender_email TEXT NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL,
    name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    discord_webhook_url TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS inbox_cache (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER NOT NULL,
    message_id TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_preview TEXT NOT NULL,
    full_body TEXT DEFAULT '',
    received_at TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS email_templates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    sender_name TEXT NOT NULL DEFAULT 'Whitehat',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    inbox_cache_id INTEGER NOT NULL,
    sent_log_id INTEGER NOT NULL,
    credential_id INTEGER NOT NULL,
    matched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (inbox_cache_id) REFERENCES inbox_cache(id) ON DELETE CASCADE,
    FOREIGN KEY (sent_log_id) REFERENCES sent_logs(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS email_opens (
    id SERIAL PRIMARY KEY,
    tracking_token TEXT UNIQUE NOT NULL,
    sent_log_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    opened_at TEXT,
    open_count INTEGER DEFAULT 0,
    user_agent TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sent_log_id) REFERENCES sent_logs(id) ON DELETE CASCADE
)""",
]

INDEX_STATEMENTS = [
    "CREATE INDEX IF NOT EXISTS idx_sent_logs_username ON sent_logs(username)",
    "CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_inbox_cache_credential_id ON inbox_cache(credential_id)",
    "CREATE INDEX IF NOT EXISTS idx_responses_user_id ON responses(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_email_opens_username ON email_opens(username)",
    "CREATE INDEX IF NOT EXISTS idx_email_opens_sent_log_id ON email_opens(sent_log_id)",
]

def get_db():
    if 'db' not in g:
        g.db = get_pg_conn()
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass

def init_db():
    """Create tables if they don't exist and ensure admin user exists."""
    with get_pg_conn() as conn:
        for stmt in SCHEMA_STATEMENTS:
            conn.execute(stmt)
        for stmt in INDEX_STATEMENTS:
            conn.execute(stmt)
        conn.commit()

        admin = conn.execute("SELECT id FROM users WHERE username=%s", ('aditya',)).fetchone()
        if not admin:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Aditya@819409557')
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
            password_hash = generate_password_hash(admin_password)
            conn.execute(
                "INSERT INTO users (username, password, salt, role) VALUES (%s,%s,%s,%s)",
                ('aditya', password_hash, salt, 'admin')
            )
            conn.commit()
            user_row = conn.execute("SELECT id FROM users WHERE username=%s", ('aditya',)).fetchone()
            user_id = user_row['id']
            key = derive_key('decryption-key' + 'aditya', salt)

            admin_creds = os.environ.get('ADMIN_CREDS', '')
            if admin_creds:
                for pair in admin_creds.split(','):
                    parts = pair.strip().split(':')
                    if len(parts) == 2:
                        conn.execute(
                            "INSERT INTO credentials (user_id, encrypted_email, encrypted_app_password) VALUES (%s,%s,%s)",
                            (user_id, encrypt(parts[0].strip(), key), encrypt(parts[1].strip(), key))
                        )
            else:
                for email_addr, app_pass in [
                    ('itsecresearcher007@gmail.com', 'vqakudjcxhaeomgp'),
                    ('researcher.whitehat@gmail.com', 'yjfwtcehvweadfui'),
                    ('whitehatsaviour007@gmail.com', 'aifserzbcmrpislx'),
                    ('secureit1337@gmail.com', 'ikwetyinnghqsgog')
                ]:
                    conn.execute(
                        "INSERT INTO credentials (user_id, encrypted_email, encrypted_app_password) VALUES (%s,%s,%s)",
                        (user_id, encrypt(email_addr, key), encrypt(app_pass, key))
                    )

        # Seed default "Bug Bounty" template if no default exists
        default_tmpl = conn.execute("SELECT id FROM email_templates WHERE is_default=1").fetchone()
        if not default_tmpl:
            conn.execute(
                "INSERT INTO email_templates (user_id, name, subject, body, sender_name, is_default) VALUES (%s,%s,%s,%s,%s,%s)",
                (None, 'Bug Bounty', 'Security Finding Report for {domain}',
                 'Hello {domain} Security Team,\n\nI am {sender_name}, an independent security researcher. During routine analysis, I identified a potential vulnerability affecting {domain}.\n\nI would like to responsibly disclose my findings. Could you direct me to your preferred reporting channel — whether that is a security@ address, a bug bounty platform, or another disclosure process?\n\nI am happy to provide a detailed technical report at your convenience.\n\nBest regards,\n{sender_name}\nSecurity Researcher\n{email}',
                 'Security Researcher', 1)
            )

        conn.commit()

def migrate_schema():
    """Apply incremental schema changes to existing database."""
    with get_pg_conn() as conn:
        def get_columns(table):
            conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name=%s ORDER BY ordinal_position",
                (table,)
            )
            return [r['column_name'] for r in conn.fetchall()]

        columns = get_columns('inbox_cache')
        if 'is_read' not in columns:
            conn.execute("ALTER TABLE inbox_cache ADD COLUMN is_read INTEGER DEFAULT 0")
        if 'full_body' not in columns:
            conn.execute("ALTER TABLE inbox_cache ADD COLUMN full_body TEXT DEFAULT ''")

        columns = get_columns('profiles')
        if 'discord_webhook_url' not in columns:
            conn.execute("ALTER TABLE profiles ADD COLUMN discord_webhook_url TEXT DEFAULT ''")

        user_columns = get_columns('users')
        if 'last_active' not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_active TEXT DEFAULT ''")
        if 'totp_secret' not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                inbox_cache_id INTEGER NOT NULL,
                sent_log_id INTEGER NOT NULL,
                credential_id INTEGER NOT NULL,
                matched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (inbox_cache_id) REFERENCES inbox_cache(id) ON DELETE CASCADE,
                FOREIGN KEY (sent_log_id) REFERENCES sent_logs(id) ON DELETE CASCADE
            )
        """)

        # Migrate old default template to improved version (anti-spam)
        old_tmpl = conn.execute(
            "SELECT id, subject FROM email_templates WHERE is_default=1 AND subject=%s",
            ('Urgent Security Vulnerability Notification',)
        ).fetchone()
        if old_tmpl:
            conn.execute(
                "UPDATE email_templates SET name=%s, subject=%s, body=%s, sender_name=%s WHERE id=%s",
                ('Bug Bounty',
                 'Security Finding Report for {domain}',
                 'Hello {domain} Security Team,\n\nI am {sender_name}, an independent security researcher. During routine analysis, I identified a potential vulnerability affecting {domain}.\n\nI would like to responsibly disclose my findings. Could you direct me to your preferred reporting channel — whether that is a security@ address, a bug bounty platform, or another disclosure process?\n\nI am happy to provide a detailed technical report at your convenience.\n\nBest regards,\n{sender_name}\nSecurity Researcher\n{email}',
                 'Security Researcher',
                 old_tmpl['id'])
            )

        conn.commit()

# Initialize DB at module load
init_db()
migrate_schema()

# ---------- Database Helper Functions ----------
def get_user(username):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()

def get_user_credentials(username):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (username,)).fetchone()
    if not user:
        return []
    rows = db.execute(
        "SELECT encrypted_email, encrypted_app_password FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()
    return [(r['encrypted_email'], r['encrypted_app_password']) for r in rows]

def get_decrypted_credentials(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()
    if not user:
        return []
    key = derive_key('decryption-key' + username, user['salt'])
    creds = get_user_credentials(username)
    result = []
    for enc_email, enc_pass in creds:
        try:
            result.append((decrypt(enc_email, key), decrypt(enc_pass, key)))
        except Exception:
            result.append(('Corrupted', 'Corrupted'))
    return result

def add_credential(username, email_addr, app_password):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()
    if not user:
        return False
    key = derive_key('decryption-key' + username, user['salt'])
    db.execute(
        "INSERT INTO credentials (user_id, encrypted_email, encrypted_app_password) VALUES (%s,%s,%s)",
        (user['id'], encrypt(email_addr, key), encrypt(app_password, key))
    )
    db.commit()
    return True

def delete_credential_by_email(username, email_to_delete):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()
    if not user:
        return False
    key = derive_key('decryption-key' + username, user['salt'])
    creds = db.execute(
        "SELECT id, encrypted_email FROM credentials WHERE user_id=%s",
        (user['id'],)
    ).fetchall()
    for cred in creds:
        try:
            if decrypt(cred['encrypted_email'], key) == email_to_delete:
                db.execute("DELETE FROM credentials WHERE id=%s", (cred['id'],))
                db.commit()
                return True
        except Exception:
            continue
    return False

def save_user(username, password, role):
    db = get_db()
    existing = db.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()
    if existing:
        if password:
            db.execute("UPDATE users SET password=%s, role=%s WHERE username=%s",
                       (generate_password_hash(password), role, username))
        else:
            db.execute("UPDATE users SET role=%s WHERE username=%s", (role, username))
    else:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
        db.execute("INSERT INTO users (username, password, salt, role) VALUES (%s,%s,%s,%s)",
                   (username, generate_password_hash(password), salt, role))
    db.commit()

# ---------- Flask-Login ----------
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with get_pg_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=%s", (user_id,)).fetchone()
        if user:
            return User(user_id, user['role'])
        return None

# ---------- General Tools ----------
predefined_usernames = ['contact', 'security', 'support', 'info', 'admin', 'help', 'techsupport', 'hello', 'office', 'tech']

def is_valid_email(email_str):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email_str)

def is_valid_domain(domain):
    return re.match(r'^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$', domain)

def now_ist():
    """Return current datetime in IST."""
    return datetime.now(IST)

def sanitize_input(value):
    if not value:
        return ''
    return html.escape(value.strip())

def generate_emails(usernames, domain):
    return [f"{username}@{domain}" for username in usernames]

def expand_template_vars(text, to_email='', domain='', sender_name='Whitehat'):
    """Expand template variables: {sender_name}, {domain}, {email}, {date}, {time}."""
    now = now_ist()
    return (text
        .replace('{sender_name}', sender_name)
        .replace('{domain}', domain)
        .replace('{email}', to_email)
        .replace('{date}', now.strftime('%d %B %Y'))
        .replace('{time}', now.strftime('%I:%M %p IST')))

def send_email(subject, to_email, template, sender_email, app_password, sender_name='Whitehat', max_retries=3, domain_label='', tracking_token=''):
    """Send a plain-text email with clean headers for maximum deliverability."""
    target_domain = to_email.split('@')[1] if '@' in to_email else domain_label

    # Expand template variables in both subject and body
    body = expand_template_vars(template, to_email, target_domain, sender_name)
    expanded_subject = expand_template_vars(subject, to_email, target_domain, sender_name)

    for attempt in range(1, max_retries + 1):
        try:
            sender_domain = sender_email.split('@')[1]
            msg_id = f"<{uuid.uuid4().hex[:12]}.{int(time.time())}@{sender_domain}>"

            if tracking_token:
                # HTML email with tracking pixel (user opted in)
                base_url = os.environ.get('MAILER_BASE_URL', 'https://mailer.adityasec.com').rstrip('/')
                escaped_body = html.escape(body).replace('\n', '<br>')
                tracking_pixel = f'<img src="{base_url}/track/{tracking_token}.gif" width="1" height="1" alt="" style="display:none;" />'
                html_body = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#333;padding:20px;">
{escaped_body}
</td></tr></table>{tracking_pixel}</body></html>'''
                message = MIMEMultipart('alternative')
                message.attach(MIMEText(body, 'plain', 'utf-8'))
                message.attach(MIMEText(html_body, 'html', 'utf-8'))
            else:
                # Plain text only (default — best deliverability)
                message = MIMEText(body, 'plain', 'utf-8')

            message['From'] = f"{sender_name} <{sender_email}>"
            message['To'] = to_email
            message['Subject'] = expanded_subject
            message['Message-ID'] = msg_id

            server = smtplib.SMTP('smtp.gmail.com', 587, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, to_email, message.as_string())
            server.quit()
            track_cred_usage(sender_email)
            return f"Sent to {to_email} using {sender_email}"
        except smtplib.SMTPRecipientsRefused:
            return f"Failed: {to_email} rejected by server (invalid recipient)"
        except smtplib.SMTPDataError as e:
            if '550' in str(e) or '553' in str(e):
                return f"Failed: {to_email} permanently rejected"
            if attempt < max_retries:
                backoff = (2 ** attempt) + random.uniform(0, 1)
                app.logger.warning(f"Retry {attempt}/{max_retries} for {to_email} after {backoff:.1f}s: {e}")
                time.sleep(backoff)
            else:
                return f"Failed to send to {to_email} after {max_retries} retries: {e}"
        except (smtplib.SMTPException, ConnectionError, TimeoutError, OSError) as e:
            if attempt < max_retries:
                backoff = (2 ** attempt) + random.uniform(0, 1)
                app.logger.warning(f"Retry {attempt}/{max_retries} for {to_email} after {backoff:.1f}s: {e}")
                time.sleep(backoff)
            else:
                return f"Failed to send to {to_email} after {max_retries} retries: Connection error"
        except Exception as e:
            app.logger.error(f"Send email error to {to_email}: {e}")
            return f"Failed to send to {to_email}: {e}"
    return f"Failed to send to {to_email}: Unknown error"

def get_template(template_id, user_id=None):
    with get_pg_conn() as conn:
        user_row = conn.execute("SELECT id FROM users WHERE username=%s", (user_id,)).fetchone() if user_id else None
        uid = user_row['id'] if user_row else None
        tmpl = conn.execute("SELECT * FROM email_templates WHERE id=%s", (template_id,)).fetchone()
        if tmpl:
            if tmpl['user_id'] is None or (uid and tmpl['user_id'] == uid):
                return dict(tmpl)
        return None

def log_sent_email(username, domain, emails, sender_email, enable_tracking=False):
    """Log sent emails. If enable_tracking=True, also create tracking tokens. Returns list of (log_id, email, token) tuples."""
    with get_pg_conn() as conn:
        user = conn.execute("SELECT salt FROM users WHERE username=%s", (username,)).fetchone()
        if not user:
            return []
        key = derive_key('decryption-key' + username, user['salt'])
        now = now_ist().strftime("%Y-%m-%d %I:%M %p IST")
        results = []
        for email_addr in emails:
            cur = conn.execute(
                "INSERT INTO sent_logs (timestamp, username, encrypted_domain, encrypted_email, sender_email) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (now, username, encrypt(domain, key), encrypt(email_addr, key), sender_email)
            )
            log_id = cur.fetchone()['id']
            token = ''
            if enable_tracking:
                token = secrets.token_urlsafe(24)
                conn.execute(
                    "INSERT INTO email_opens (tracking_token, sent_log_id, username, recipient_email) VALUES (%s,%s,%s,%s)",
                    (token, log_id, username, encrypt(email_addr, key))
                )
            results.append((log_id, email_addr, token))
        conn.commit()
        return results

def get_logs(user_id=None, page=1, per_page=20, search=None):
    db = get_db()
    target_user = user_id if user_id else current_user.id
    user = db.execute("SELECT * FROM users WHERE username=%s", (target_user,)).fetchone()
    if not user:
        return [], 0
    key = derive_key('decryption-key' + target_user, user['salt'])
    rows = db.execute(
        "SELECT * FROM sent_logs WHERE username=%s ORDER BY id DESC",
        (target_user,)
    ).fetchall()
    logs = []
    for row in rows:
        try:
            decrypted_log = [
                row['timestamp'],
                decrypt(row['encrypted_domain'], key),
                decrypt(row['encrypted_email'], key),
                row['sender_email']
            ]
            if search and search.lower() not in ' '.join(decrypted_log).lower():
                continue
            logs.append(decrypted_log)
        except Exception:
            continue
    total = len(logs)
    start = (page - 1) * per_page
    end = start + per_page
    return logs[start:end], total

def send_discord_notification(webhook_url, sender, subject):
    try:
        payload = {
            "embeds": [{
                "title": "New Email Received",
                "description": f"**From:** {sender}\n**Subject:** {subject}",
                "color": 6366961,
                "timestamp": now_ist().isoformat()
            }]
        }
        http_requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        app.logger.warning(f"Discord webhook error: {e}")

# ---------- SSE Task Store ----------
_send_tasks = {}
_send_tasks_lock = threading.Lock()

# ---------- Routes ----------
@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        if not check_rate_limit(f'login:{ip}', 5, 60):
            flash('Too many login attempts. Try again later.')
            return render_template('login.html')
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            # Check if 2FA is enabled
            if user['totp_secret']:
                # Store username in session for 2FA verification (don't login yet)
                session['_2fa_pending_user'] = username
                session['_2fa_pending_role'] = user['role']
                return redirect(url_for('verify_2fa_login'))
            login_user(User(username, user['role']))
            session.permanent = True
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa_login():
    username = session.get('_2fa_pending_user')
    role = session.get('_2fa_pending_role')
    if not username or not role:
        return redirect(url_for('login'))

    if request.method == 'POST':
        ip = request.remote_addr
        if not check_rate_limit(f'2fa:{ip}', 5, 60):
            flash('Too many attempts. Try again later.')
            return render_template('verify_2fa.html')

        code = request.form.get('totp_code', '').strip()
        user = get_user(username)
        if user and user['totp_secret']:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(code, valid_window=1):
                session.pop('_2fa_pending_user', None)
                session.pop('_2fa_pending_role', None)
                login_user(User(username, role))
                session.permanent = True
                return redirect(url_for('dashboard'))
        flash('Invalid 2FA code. Please try again.')

    return render_template('verify_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    creds_decrypted = get_decrypted_credentials(current_user.id)
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    uid = user['id'] if user else None
    if uid:
        tmpls = db.execute(
            "SELECT id, name, sender_name, is_default FROM email_templates WHERE user_id IS NULL OR user_id=%s ORDER BY is_default DESC, created_at DESC",
            (uid,)
        ).fetchall()
    else:
        tmpls = db.execute(
            "SELECT id, name, sender_name, is_default FROM email_templates WHERE user_id IS NULL ORDER BY is_default DESC, created_at DESC"
        ).fetchall()
    # Credential usage stats for the dashboard
    cred_usage_info = []
    for email_addr, _ in creds_decrypted:
        usage = get_cred_usage(email_addr)
        remaining = get_cred_remaining(email_addr)
        cred_usage_info.append({'email': email_addr, 'used': usage, 'remaining': remaining, 'limit': GMAIL_DAILY_LIMIT})

    return render_template(
        'dashboard.html',
        credentials=creds_decrypted,
        predefined_usernames=predefined_usernames,
        templates=[dict(t) for t in tmpls],
        cred_usage=cred_usage_info
    )

@app.route('/delete-credential', methods=['POST'])
@login_required
def delete_credential():
    email_to_delete = request.json.get('email')
    deleted = delete_credential_by_email(current_user.id, email_to_delete)
    return jsonify({'success': deleted})

@app.route('/add-sender', methods=['GET', 'POST'])
@login_required
def add_sender():
    if request.method == 'POST':
        email_addr = sanitize_input(request.form['email'])
        app_password = sanitize_input(request.form['app_password'])
        if not is_valid_email(email_addr):
            flash('Invalid email format.')
            return redirect(url_for('add_sender'))
        add_credential(current_user.id, email_addr, app_password)
        flash('Sender added successfully.')
        return redirect(url_for('dashboard'))
    return render_template('add_sender.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        user = get_user(current_user.id)
        if user and check_password_hash(user['password'], old):
            db = get_db()
            db.execute("UPDATE users SET password=%s WHERE username=%s",
                       (generate_password_hash(new), current_user.id))
            db.commit()
            flash("Password updated successfully.")
        else:
            flash("Incorrect old password.")
    return render_template('change_password.html')

# ---------- Concurrent Email Sending (legacy JSON endpoint) ----------
def _validate_send_data(data):
    """Shared validation for send_emails and send_emails_start."""
    domains = [sanitize_input(d) for d in data.get('domains', []) if d and d.strip()]
    invalid_domains = [d for d in domains if not is_valid_domain(d)]
    if invalid_domains:
        return None, f"Invalid domains: {', '.join(invalid_domains)}"

    usernames = data.get('selected_usernames', [])
    if data.get('custom_usernames'):
        custom = [u.strip() for u in data['custom_usernames'].split(',') if u.strip()]
        usernames += custom

    direct_emails = [sanitize_input(e) for e in data.get('direct_emails', []) if e and e.strip()]
    invalid_emails = [e for e in direct_emails if not is_valid_email(e)]
    if invalid_emails:
        return None, f"Invalid emails: {', '.join(invalid_emails[:5])}"

    if not domains and not direct_emails:
        return None, "Provide at least one domain or direct email."
    if domains and not usernames:
        return None, "Select at least one username for domain-based sending."

    creds_decrypted = get_decrypted_credentials(current_user.id)
    if not creds_decrypted:
        return None, "No credentials available. Add via 'Add Sender'."

    selected_cred = data.get('selected_cred', 'auto')

    template_id = data.get('template_id', None)
    sender_name_override = sanitize_input(data.get('sender_name', ''))

    if template_id:
        tmpl = get_template(int(template_id), current_user.id)
        if not tmpl:
            return None, "Template not found."
        use_subject = tmpl['subject']
        use_body = tmpl['body']
        use_sender_name = sender_name_override if sender_name_override else tmpl['sender_name']
    else:
        db = get_db()
        tmpl = db.execute("SELECT * FROM email_templates WHERE is_default=%s", (1,)).fetchone()
        if tmpl:
            use_subject = tmpl['subject']
            use_body = tmpl['body']
            use_sender_name = sender_name_override if sender_name_override else tmpl['sender_name']
        else:
            return None, "No default template found."

    # MX verification — skip domains with no MX records
    valid_domains = []
    mx_warnings = []
    mx_ok = []
    for domain in domains:
        has_mx, details = check_mx_record(domain)
        if has_mx:
            valid_domains.append(domain)
            mx_ok.append(f"{domain} → {', '.join(details)}")
        else:
            mx_warnings.append(f"{domain}: {details[0]}")

    if not valid_domains and not direct_emails:
        if mx_warnings:
            return None, f"No valid domains. MX failures: {'; '.join(mx_warnings)}"
        return None, "Provide at least one domain or direct email."

    # Build all target groups: [(domain_label, [email_list]), ...]
    all_targets = []
    for domain in valid_domains:
        email_list = generate_emails(usernames, domain)
        all_targets.append((domain, email_list))
    if direct_emails:
        all_targets.append(("direct-emails", direct_emails))

    if selected_cred != 'auto' and selected_cred.isdigit():
        # Single credential selected — one worker handles everything
        cred_idx = int(selected_cred) - 1
        if cred_idx < 0 or cred_idx >= len(creds_decrypted):
            return None, "Invalid credential index."
        cred = creds_decrypted[cred_idx]
        cred_workers = [(cred, all_targets)]
    else:
        # Smart auto-assign: 1 credential per domain (not per email).
        # All usernames for the same domain go through the same credential.
        # Sort credentials by least-used-today so the freshest one picks up the next domain.
        sorted_creds = sorted(creds_decrypted, key=lambda c: get_cred_usage(c[0]))
        available_creds = [c for c in sorted_creds if get_cred_remaining(c[0]) > 0]
        if not available_creds:
            available_creds = sorted_creds

        # Assign one credential per domain target (round-robin across credentials)
        cred_workers_map = {}  # cred_idx -> [(domain, emails), ...]
        for i, target in enumerate(all_targets):
            cred_idx = i % len(available_creds)
            if cred_idx not in cred_workers_map:
                cred_workers_map[cred_idx] = []
            cred_workers_map[cred_idx].append(target)

        cred_workers = []
        for idx, targets in cred_workers_map.items():
            cred_workers.append((available_creds[idx], targets))

    enable_tracking = bool(data.get('enable_tracking', False))

    return {
        'cred_workers': cred_workers,
        'subject': use_subject,
        'body': use_body,
        'sender_name': use_sender_name,
        'mx_warnings': mx_warnings,
        'mx_ok': mx_ok,
        'enable_tracking': enable_tracking
    }, None

@app.route('/send_emails', methods=['POST'])
@login_required
def send_emails():
    if not check_rate_limit(f'send:{current_user.id}', 3, 60):
        return jsonify({"error": "Rate limited. Try again later."}), 429

    data = request.get_json()
    validated, error = _validate_send_data(data)
    if error:
        return jsonify({"error": error}), 400

    cred_workers = validated['cred_workers']
    use_subject = validated['subject']
    use_body = validated['body']
    use_sender_name = validated['sender_name']
    enable_tracking = validated.get('enable_tracking', False)

    all_results = []
    results_lock = threading.Lock()

    def cred_worker(sender_email, app_password, targets):
        """One thread per credential — sends to all its assigned domains sequentially."""
        thread_results = []
        for domain_label, email_list in targets:
            log_results = log_sent_email(current_user.id, domain_label, email_list, sender_email, enable_tracking=enable_tracking)
            token_map = {email_addr: token for _, email_addr, token in log_results}
            for to_addr in email_list:
                if get_cred_remaining(sender_email) <= 0:
                    thread_results.append(f"Skipped {to_addr}: daily limit reached")
                    continue
                time.sleep(random.uniform(2, 5))
                tracking_token = token_map.get(to_addr, '')
                result = send_email(use_subject, to_addr, use_body, sender_email, app_password, use_sender_name, domain_label=domain_label, tracking_token=tracking_token)
                thread_results.append(result)
        return thread_results

    max_workers = min(len(cred_workers), 10)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for (sender_email, app_password), targets in cred_workers:
            future = executor.submit(cred_worker, sender_email, app_password, targets)
            futures[future] = sender_email

        for future in as_completed(futures):
            try:
                thread_results = future.result()
                with results_lock:
                    all_results.extend(thread_results)
            except Exception:
                with results_lock:
                    all_results.append(f"Error with credential {futures[future]}")

    return jsonify({"results": all_results})

# ---------- SSE Live Terminal Sending ----------
@app.route('/send_emails_start', methods=['POST'])
@login_required
def send_emails_start():
    if not check_rate_limit(f'send:{current_user.id}', 3, 60):
        return jsonify({"error": "Rate limited. Try again later."}), 429

    data = request.get_json()
    validated, error = _validate_send_data(data)
    if error:
        return jsonify({"error": error}), 400

    task_id = str(uuid.uuid4())
    with _send_tasks_lock:
        cutoff = time.time() - 300
        stale = [k for k, v in _send_tasks.items() if v['created_at'] < cutoff]
        for k in stale:
            del _send_tasks[k]
        _send_tasks[task_id] = {
            'username': current_user.id,
            'cred_workers': validated['cred_workers'],
            'subject': validated['subject'],
            'body': validated['body'],
            'sender_name': validated['sender_name'],
            'mx_warnings': validated.get('mx_warnings', []),
            'mx_ok': validated.get('mx_ok', []),
            'enable_tracking': validated.get('enable_tracking', False),
            'created_at': time.time()
        }

    return jsonify({"task_id": task_id})

@app.route('/send_emails_stream')
@login_required
def send_emails_stream():
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({"error": "task_id required"}), 400

    with _send_tasks_lock:
        task = _send_tasks.pop(task_id, None)

    if not task:
        return jsonify({"error": "Task not found or expired"}), 404
    if task['username'] != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    def generate():
        cred_workers = task['cred_workers']
        use_subject = task['subject']
        use_body = task['body']
        use_sender_name = task['sender_name']
        username = task['username']
        enable_tracking = task.get('enable_tracking', False)

        # Count total emails across all credential workers
        total_emails = 0
        for (_, _), targets in cred_workers:
            for _, email_list in targets:
                total_emails += len(email_list)

        num_workers = len(cred_workers)
        event_queue = queue.Queue()

        # Emit MX check results
        mx_ok = task.get('mx_ok', [])
        for ok in mx_ok:
            event_queue.put(json.dumps({'type': 'mx_check', 'success': True, 'message': f'MX OK: {ok}'}))
        mx_warnings = task.get('mx_warnings', [])
        for warn in mx_warnings:
            event_queue.put(json.dumps({'type': 'mx_check', 'success': False, 'message': f'MX FAIL: {warn} — skipped'}))

        event_queue.put(json.dumps({'type': 'start', 'total': total_emails, 'workers': num_workers}))

        def cred_thread(sender_email, app_password, targets):
            """One thread per credential — sends to all its assigned domains with 2-5s gap between each email."""
            local_sent = 0
            local_fail = 0
            for domain_label, email_list in targets:
                # Check rate limit before processing this batch
                remaining = get_cred_remaining(sender_email)
                if remaining <= 0:
                    event_queue.put(json.dumps({
                        'type': 'result', 'success': False, 'to': '', 'via': sender_email,
                        'domain': domain_label, 'message': f'Daily limit reached ({GMAIL_DAILY_LIMIT}/day) — skipping',
                        'time': now_ist().strftime('%I:%M %p')
                    }))
                    local_fail += len(email_list)
                    continue
                elif remaining < len(email_list):
                    event_queue.put(json.dumps({
                        'type': 'result', 'success': False, 'to': '', 'via': sender_email,
                        'domain': domain_label, 'message': f'Warning: only {remaining} sends remaining today (limit: {GMAIL_DAILY_LIMIT})',
                        'time': now_ist().strftime('%I:%M %p')
                    }))

                # Pre-log (with optional tracking tokens)
                try:
                    log_results = log_sent_email(username, domain_label, email_list, sender_email, enable_tracking=enable_tracking)
                    token_map = {email_addr: token for _, email_addr, token in log_results}
                except Exception:
                    token_map = {}

                for to_addr in email_list:
                    # Re-check remaining per email
                    if get_cred_remaining(sender_email) <= 0:
                        event_queue.put(json.dumps({
                            'type': 'result', 'success': False, 'to': to_addr, 'via': sender_email,
                            'domain': domain_label, 'message': 'Skipped — daily limit reached',
                            'time': now_ist().strftime('%I:%M %p')
                        }))
                        local_fail += 1
                        continue

                    timestamp = now_ist().strftime('%I:%M %p')
                    event_queue.put(json.dumps({
                        'type': 'sending', 'to': to_addr, 'via': sender_email,
                        'domain': domain_label, 'time': timestamp
                    }))

                    time.sleep(random.uniform(2, 5))
                    tracking_token = token_map.get(to_addr, '')
                    result = send_email(use_subject, to_addr, use_body, sender_email, app_password, use_sender_name, domain_label=domain_label, tracking_token=tracking_token)
                    success = result.startswith("Sent")
                    if success:
                        local_sent += 1
                    else:
                        local_fail += 1

                    event_queue.put(json.dumps({
                        'type': 'result', 'success': success, 'to': to_addr,
                        'via': sender_email, 'domain': domain_label,
                        'message': result, 'time': timestamp
                    }))

            return local_sent, local_fail

        # Tracking across threads
        threads_done = [0]
        total_sent = [0]
        total_failed = [0]
        lock = threading.Lock()

        def thread_wrapper(sender_email, app_password, targets):
            try:
                s, f = cred_thread(sender_email, app_password, targets)
            except Exception:
                target_count = sum(len(el) for _, el in targets)
                s, f = 0, target_count
            with lock:
                total_sent[0] += s
                total_failed[0] += f
                threads_done[0] += 1
                if threads_done[0] == num_workers:
                    event_queue.put(json.dumps({
                        'type': 'complete', 'sent': total_sent[0],
                        'failed': total_failed[0], 'total': total_emails
                    }))
                    event_queue.put(None)  # Sentinel to stop generator

        # Launch one thread per credential
        executor = ThreadPoolExecutor(max_workers=min(num_workers, 10))
        for (sender_email, app_password), targets in cred_workers:
            executor.submit(thread_wrapper, sender_email, app_password, targets)

        # Yield SSE events from queue until sentinel (None)
        while True:
            try:
                event = event_queue.get(timeout=120)
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'complete', 'sent': total_sent[0], 'failed': total_failed[0], 'total': total_emails})}\n\n"
                break
            if event is None:
                break
            yield f"data: {event}\n\n"

        executor.shutdown(wait=False)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

# ---------- Logs ----------
@app.route('/my-logs')
@login_required
def my_logs():
    return render_template('my_logs.html')

@app.route('/get_my_logs', methods=['GET'])
@login_required
def get_my_logs():
    page = int(request.args.get('page', 1))
    search = request.args.get('search', '')
    logs, total = get_logs(current_user.id, page, 20, search)
    return jsonify({
        'logs': logs,
        'total': total,
        'per_page': 20,
        'current_page': page
    })

@app.route('/clear_my_logs', methods=['POST'])
@login_required
def clear_my_logs():
    db = get_db()
    db.execute("DELETE FROM sent_logs WHERE username=%s", (current_user.id,))
    db.commit()
    return jsonify({'success': True})

# ---------- Profile ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    creds = get_decrypted_credentials(current_user.id)
    email_display = creds[0][0] if creds else 'Not set'

    db = get_db()
    user = get_user(current_user.id)
    profile_row = db.execute("SELECT * FROM profiles WHERE user_id=%s", (user['id'],)).fetchone()

    webhook_url = ''
    if profile_row and profile_row['discord_webhook_url']:
        key = derive_key('decryption-key' + current_user.id, user['salt'])
        try:
            webhook_url = decrypt(profile_row['discord_webhook_url'], key)
        except Exception:
            webhook_url = ''

    if request.method == 'POST':
        new_email = sanitize_input(request.form.get('email', ''))
        if new_email and not is_valid_email(new_email):
            flash('Invalid email format.')
            return redirect(url_for('profile'))

        if new_email and creds:
            key = derive_key('decryption-key' + current_user.id, user['salt'])
            all_creds = db.execute(
                "SELECT id, encrypted_email FROM credentials WHERE user_id=%s ORDER BY id",
                (user['id'],)
            ).fetchall()
            if all_creds:
                db.execute(
                    "UPDATE credentials SET encrypted_email=%s WHERE id=%s",
                    (encrypt(new_email, key), all_creds[0]['id'])
                )

        # Handle Discord webhook
        new_webhook = request.form.get('discord_webhook', '').strip()
        key = derive_key('decryption-key' + current_user.id, user['salt'])

        if profile_row:
            if new_webhook:
                db.execute("UPDATE profiles SET discord_webhook_url=%s WHERE user_id=%s",
                           (encrypt(new_webhook, key), user['id']))
            else:
                db.execute("UPDATE profiles SET discord_webhook_url='' WHERE user_id=%s", (user['id'],))
        else:
            db.execute("INSERT INTO profiles (user_id, discord_webhook_url) VALUES (%s,%s)",
                       (user['id'], encrypt(new_webhook, key) if new_webhook else ''))

        db.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    has_2fa = bool(user['totp_secret']) if user else False
    return render_template('profile.html', username=current_user.id, email=email_display, webhook_url=webhook_url, has_2fa=has_2fa)

# ---------- Two-Factor Authentication (TOTP) ----------
@app.route('/setup-2fa')
@login_required
def setup_2fa():
    db = get_db()
    user = get_user(current_user.id)
    if not user:
        flash('User not found.')
        return redirect(url_for('profile'))

    if user['totp_secret']:
        flash('2FA is already enabled. Disable it first to reconfigure.')
        return redirect(url_for('profile'))

    # Generate a new TOTP secret
    totp_secret = pyotp.random_base32()
    session['_pending_totp_secret'] = totp_secret

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.id,
        issuer_name='Mailer App'
    )

    # Generate QR code as SVG data
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(provisioning_uri, image_factory=factory, box_size=8)
    svg_buffer = io.BytesIO()
    img.save(svg_buffer)
    qr_svg = svg_buffer.getvalue().decode('utf-8')

    return render_template('setup_2fa.html', qr_svg=qr_svg, totp_secret=totp_secret)

@app.route('/confirm-2fa', methods=['POST'])
@login_required
def confirm_2fa():
    db = get_db()
    user = get_user(current_user.id)
    if not user:
        flash('User not found.')
        return redirect(url_for('profile'))

    pending_secret = session.get('_pending_totp_secret')
    if not pending_secret:
        flash('No 2FA setup in progress. Please start again.')
        return redirect(url_for('setup_2fa'))

    code = request.form.get('totp_code', '').strip()
    totp = pyotp.TOTP(pending_secret)
    if totp.verify(code, valid_window=1):
        db.execute("UPDATE users SET totp_secret=%s WHERE username=%s", (pending_secret, current_user.id))
        db.commit()
        session.pop('_pending_totp_secret', None)
        flash('Two-factor authentication enabled successfully!')
        return redirect(url_for('profile'))
    else:
        flash('Invalid code. Please scan the QR code again and enter the current code.')
        return redirect(url_for('setup_2fa'))

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    db = get_db()
    user = get_user(current_user.id)
    if not user:
        flash('User not found.')
        return redirect(url_for('profile'))

    password = request.form.get('password', '')
    if not check_password_hash(user['password'], password):
        flash('Incorrect password. 2FA not disabled.')
        return redirect(url_for('profile'))

    db.execute("UPDATE users SET totp_secret='' WHERE username=%s", (current_user.id,))
    db.commit()
    flash('Two-factor authentication has been disabled.')
    return redirect(url_for('profile'))

# ---------- Email Templates ----------
@app.route('/templates')
@login_required
def templates_page():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    uid = user['id'] if user else None
    if uid:
        tmpls = db.execute(
            "SELECT * FROM email_templates WHERE user_id IS NULL OR user_id=%s ORDER BY is_default DESC, created_at DESC",
            (uid,)
        ).fetchall()
    else:
        tmpls = db.execute(
            "SELECT * FROM email_templates WHERE user_id IS NULL ORDER BY is_default DESC, created_at DESC"
        ).fetchall()
    return render_template('templates.html', templates=tmpls)

@app.route('/add-template', methods=['POST'])
@login_required
def add_template():
    name = sanitize_input(request.form.get('name', ''))
    subject = sanitize_input(request.form.get('subject', ''))
    body = request.form.get('body', '').strip()
    sender_name = sanitize_input(request.form.get('sender_name', 'Whitehat'))
    if not name or not subject or not body:
        flash('All fields are required for template.')
        return redirect(url_for('templates_page'))
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    db.execute(
        "INSERT INTO email_templates (user_id, name, subject, body, sender_name, is_default) VALUES (%s,%s,%s,%s,%s,%s)",
        (user['id'], name, subject, body, sender_name, 0)
    )
    db.commit()
    flash(f'Template "{name}" created successfully.')
    return redirect(url_for('templates_page'))

@app.route('/delete-template/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    db = get_db()
    tmpl = db.execute("SELECT * FROM email_templates WHERE id=%s", (template_id,)).fetchone()
    if not tmpl:
        return jsonify({'error': 'Template not found'}), 404
    if tmpl['is_default']:
        return jsonify({'error': 'Cannot delete the default template'}), 400
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if tmpl['user_id'] != user['id'] and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    db.execute("DELETE FROM email_templates WHERE id=%s", (template_id,))
    db.commit()
    return jsonify({'success': 'Template deleted'})

@app.route('/edit-template/<int:template_id>', methods=['POST'])
@login_required
def edit_template(template_id):
    db = get_db()
    tmpl = db.execute("SELECT * FROM email_templates WHERE id=%s", (template_id,)).fetchone()
    if not tmpl:
        flash('Template not found.')
        return redirect(url_for('templates_page'))
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if tmpl['user_id'] is not None and tmpl['user_id'] != user['id'] and current_user.role != 'admin':
        flash('Unauthorized.')
        return redirect(url_for('templates_page'))
    name = sanitize_input(request.form.get('name', ''))
    subject = sanitize_input(request.form.get('subject', ''))
    body = request.form.get('body', '').strip()
    sender_name = sanitize_input(request.form.get('sender_name', 'Whitehat'))
    if not name or not subject or not body:
        flash('All fields are required.')
        return redirect(url_for('templates_page'))
    db.execute(
        "UPDATE email_templates SET name=%s, subject=%s, body=%s, sender_name=%s WHERE id=%s",
        (name, subject, body, sender_name, template_id)
    )
    db.commit()
    flash(f'Template "{name}" updated successfully.')
    return redirect(url_for('templates_page'))

@app.route('/get-templates', methods=['GET'])
@login_required
def get_templates_json():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    uid = user['id'] if user else None
    if uid:
        tmpls = db.execute(
            "SELECT id, name, subject, sender_name, is_default FROM email_templates WHERE user_id IS NULL OR user_id=%s ORDER BY is_default DESC, created_at DESC",
            (uid,)
        ).fetchall()
    else:
        tmpls = db.execute(
            "SELECT id, name, subject, sender_name, is_default FROM email_templates WHERE user_id IS NULL ORDER BY is_default DESC, created_at DESC"
        ).fetchall()
    return jsonify({'templates': [dict(t) for t in tmpls]})

# ---------- IMAP Inbox Reading ----------
@app.route('/inbox')
@login_required
def inbox():
    creds_decrypted = get_decrypted_credentials(current_user.id)
    return render_template('inbox.html', credentials=creds_decrypted)

@app.route('/fetch_inbox', methods=['POST'])
@login_required
def fetch_inbox():
    data = request.get_json() or {}
    cred_index = int(data.get('cred_index', 0))
    page = int(data.get('page', 1))
    per_page = 20
    hide_bounces = data.get('hide_bounces', True)

    creds = get_decrypted_credentials(current_user.id)
    if cred_index < 0 or cred_index >= len(creds):
        return jsonify({"error": "Invalid credential"}), 400

    email_addr, app_password = creds[cred_index]

    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(email_addr, app_password)
        mail.select('INBOX', readonly=True)

        status, messages = mail.search(None, 'ALL')
        if status != 'OK':
            mail.logout()
            return jsonify({"error": "Failed to search inbox"}), 500

        msg_nums = messages[0].split()
        msg_nums.reverse()

        total = len(msg_nums)
        start = (page - 1) * per_page
        end = min(start + per_page, total)
        page_msgs = msg_nums[start:end]

        emails_list = []
        for num in page_msgs:
            status, msg_data = mail.fetch(num, '(RFC822)')
            if status != 'OK':
                continue

            raw_email = msg_data[0][1]
            msg = email_lib.message_from_bytes(raw_email)

            subject_header = decode_header(msg.get('Subject', ''))
            subject = ''
            for part, encoding in subject_header:
                if isinstance(part, bytes):
                    subject += part.decode(encoding or 'utf-8', errors='replace')
                else:
                    subject += str(part)

            from_header = decode_header(msg.get('From', ''))
            from_addr = ''
            for part, encoding in from_header:
                if isinstance(part, bytes):
                    from_addr += part.decode(encoding or 'utf-8', errors='replace')
                else:
                    from_addr += str(part)

            date_str = msg.get('Date', '')

            body = ''
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode(charset, errors='replace')
                        break
            else:
                charset = msg.get_content_charset() or 'utf-8'
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(charset, errors='replace')

            body_preview = body[:300] if body else ''
            bounce = is_bounce_or_ndr(from_addr, subject)

            # Skip bounce emails if filter is on
            if hide_bounces and bounce:
                continue

            emails_list.append({
                'from': html.escape(from_addr),
                'subject': html.escape(subject),
                'date': html.escape(date_str),
                'preview': html.escape(body_preview),
                'full_body': html.escape(body),
                'msg_num': num.decode() if isinstance(num, bytes) else str(num),
                'is_bounce': bounce
            })

        mail.logout()

        return jsonify({
            'emails': emails_list,
            'total': len(emails_list),
            'per_page': per_page,
            'current_page': page
        })

    except imaplib.IMAP4.error:
        return jsonify({"error": "Failed to connect to email server. Check credentials."}), 500
    except Exception:
        return jsonify({"error": "An unexpected error occurred while fetching emails."}), 500

@app.route('/email_detail/<int:email_id>')
@login_required
def email_detail(email_id):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    row = db.execute("""
        SELECT ic.* FROM inbox_cache ic
        JOIN credentials c ON ic.credential_id = c.id
        WHERE ic.id = %s AND c.user_id = %s
    """, (email_id, user['id'])).fetchone()

    if not row:
        return jsonify({"error": "Email not found"}), 404

    db.execute("UPDATE inbox_cache SET is_read = 1 WHERE id = %s", (email_id,))
    db.commit()

    return jsonify({
        'id': row['id'],
        'from': html.escape(row['sender']),
        'subject': html.escape(row['subject']),
        'body': html.escape(row['full_body'].strip() if row['full_body'] and row['full_body'].strip() else row['body_preview']),
        'date': html.escape(row['received_at']),
        'fetched_at': row['fetched_at']
    })

@app.route('/mark_read/<int:email_id>', methods=['POST'])
@login_required
def mark_read(email_id):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400
    email_row = db.execute("""
        SELECT ic.id FROM inbox_cache ic
        JOIN credentials c ON ic.credential_id = c.id
        WHERE ic.id = %s AND c.user_id = %s
    """, (email_id, user['id'])).fetchone()
    if not email_row:
        return jsonify({"error": "Email not found"}), 404
    db.execute("UPDATE inbox_cache SET is_read = 1 WHERE id = %s", (email_id,))
    db.commit()
    return jsonify({"success": True})

@app.route('/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all cached emails as read for current user (optionally for specific credential)."""
    data = request.get_json() or {}
    cred_index = data.get('cred_index', 'all')

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    creds = db.execute(
        "SELECT id FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()

    if cred_index == 'all':
        cred_ids = [c['id'] for c in creds]
    else:
        cred_index = int(cred_index)
        if cred_index < 0 or cred_index >= len(creds):
            return jsonify({"error": "Invalid credential"}), 400
        cred_ids = [creds[cred_index]['id']]

    if not cred_ids:
        return jsonify({"success": True, "updated": 0})

    result = db.execute(
        "UPDATE inbox_cache SET is_read = 1 WHERE credential_id = ANY(%s) AND is_read = 0",
        (cred_ids,)
    )
    db.commit()
    updated = result.rowcount

    return jsonify({"success": True, "updated": updated})

@app.route('/delete_bounces', methods=['POST'])
@login_required
def delete_bounces():
    """Delete all bounce/NDR emails from the cache for current user."""
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    creds = db.execute(
        "SELECT id FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()
    cred_ids = [c['id'] for c in creds]
    if not cred_ids:
        return jsonify({"success": True, "deleted": 0})

    all_emails = db.execute(
        "SELECT id, sender, subject FROM inbox_cache WHERE credential_id = ANY(%s)",
        (cred_ids,)
    ).fetchall()

    bounce_ids = [e['id'] for e in all_emails if is_bounce_or_ndr(e['sender'], e['subject'])]
    if not bounce_ids:
        return jsonify({"success": True, "deleted": 0})

    # Delete responses referencing these emails first (FK cascade)
    db.execute("DELETE FROM responses WHERE inbox_cache_id = ANY(%s)", (bounce_ids,))
    db.execute("DELETE FROM inbox_cache WHERE id = ANY(%s)", (bounce_ids,))
    db.commit()

    return jsonify({"success": True, "deleted": len(bounce_ids)})

@app.route('/clear_inbox_cache', methods=['POST'])
@login_required
def clear_inbox_cache():
    data = request.get_json() or {}
    cred_index = int(data.get('cred_index', 0))

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    creds = db.execute(
        "SELECT id FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()

    if cred_index < 0 or cred_index >= len(creds):
        return jsonify({"error": "Invalid credential"}), 400

    cred_id = creds[cred_index]['id']

    # Delete responses linked to these cached emails first
    db.execute("""
        DELETE FROM responses WHERE inbox_cache_id IN (
            SELECT id FROM inbox_cache WHERE credential_id=%s
        )
    """, (cred_id,))

    # Count and delete cached emails
    count = db.execute("SELECT COUNT(*) as cnt FROM inbox_cache WHERE credential_id=%s", (cred_id,)).fetchone()['cnt']
    db.execute("DELETE FROM inbox_cache WHERE credential_id=%s", (cred_id,))
    db.commit()

    return jsonify({"success": True, "deleted": count})

@app.route('/unread_count')
@login_required
def unread_count():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"count": 0})
    # Fetch unread emails and exclude bounces from the count
    unread_rows = db.execute("""
        SELECT ic.sender, ic.subject FROM inbox_cache ic
        JOIN credentials c ON ic.credential_id = c.id
        WHERE c.user_id = %s AND ic.is_read = 0
    """, (user['id'],)).fetchall()
    count = sum(1 for r in unread_rows if not is_bounce_or_ndr(r['sender'], r['subject']))
    return jsonify({"count": count})

# ---------- Responses (Match Incoming → Sent) ----------
@app.route('/responses')
@login_required
def responses_page():
    return render_template('responses.html')

@app.route('/get_responses', methods=['GET'])
@login_required
def get_responses():
    page = int(request.args.get('page', 1))
    per_page = 20

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    key = derive_key('decryption-key' + current_user.id, user['salt'])

    total = db.execute(
        "SELECT COUNT(*) as cnt FROM responses WHERE user_id=%s", (user['id'],)
    ).fetchone()['cnt']

    offset = (page - 1) * per_page
    rows = db.execute("""
        SELECT r.id, r.matched_at,
               ic.sender, ic.subject, ic.body_preview, ic.full_body, ic.received_at, ic.id as cache_id,
               sl.encrypted_domain, sl.encrypted_email, sl.sender_email, sl.timestamp as sent_timestamp
        FROM responses r
        JOIN inbox_cache ic ON r.inbox_cache_id = ic.id
        JOIN sent_logs sl ON r.sent_log_id = sl.id
        WHERE r.user_id = %s
        ORDER BY r.matched_at DESC
        LIMIT %s OFFSET %s
    """, (user['id'], per_page, offset)).fetchall()

    results = []
    for row in rows:
        try:
            domain = decrypt(row['encrypted_domain'], key)
            sent_to = decrypt(row['encrypted_email'], key)
        except Exception:
            domain = '[encrypted]'
            sent_to = '[encrypted]'

        results.append({
            'id': row['id'],
            'response_from': html.escape(row['sender']),
            'response_subject': html.escape(row['subject']),
            'response_preview': html.escape(row['body_preview'][:200]),
            'response_body': html.escape(row['full_body'].strip() if row['full_body'] and row['full_body'].strip() else row['body_preview']),
            'response_date': row['received_at'],
            'sent_to_domain': html.escape(domain),
            'sent_to_email': html.escape(sent_to),
            'sent_from': row['sender_email'],
            'sent_date': row['sent_timestamp'],
            'matched_at': row['matched_at']
        })

    return jsonify({
        'responses': results,
        'total': total,
        'per_page': per_page,
        'current_page': page
    })

@app.route('/scan_responses', methods=['POST'])
@login_required
def scan_responses():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    key = derive_key('decryption-key' + current_user.id, user['salt'])

    sent_rows = db.execute(
        "SELECT id, encrypted_email FROM sent_logs WHERE username=%s",
        (current_user.id,)
    ).fetchall()

    decrypted_sent_map = {}
    for sr in sent_rows:
        try:
            dec = decrypt(sr['encrypted_email'], key).lower()
            dec_email = extract_email_from_header(dec) or dec
            decrypted_sent_map[dec_email] = sr['id']
        except Exception:
            continue

    cred_ids = db.execute(
        "SELECT id FROM credentials WHERE user_id=%s", (user['id'],)
    ).fetchall()

    new_matches = 0
    for cred in cred_ids:
        cached = db.execute(
            "SELECT id, sender, subject FROM inbox_cache WHERE credential_id=%s",
            (cred['id'],)
        ).fetchall()

        for email_row in cached:
            # Skip bounce/NDR emails — they are not real replies
            if is_bounce_or_ndr(email_row['sender'], email_row['subject']):
                continue
            sender_addr = extract_email_from_header(email_row['sender']).lower()
            if sender_addr in decrypted_sent_map:
                sent_log_id = decrypted_sent_map[sender_addr]
                existing = db.execute(
                    "SELECT id FROM responses WHERE inbox_cache_id=%s AND sent_log_id=%s",
                    (email_row['id'], sent_log_id)
                ).fetchone()
                if not existing:
                    db.execute(
                        "INSERT INTO responses (user_id, inbox_cache_id, sent_log_id, credential_id, matched_at) VALUES (%s,%s,%s,%s,%s)",
                        (user['id'], email_row['id'], sent_log_id, cred['id'],
                         now_ist().strftime("%Y-%m-%d %H:%M:%S"))
                    )
                    new_matches += 1

    db.commit()
    return jsonify({"success": True, "new_matches": new_matches})

# ---------- Export ----------
@app.route('/export')
@login_required
def export_page():
    return render_template('export.html')

@app.route('/export_csv')
@login_required
def export_csv():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        flash('User not found.')
        return redirect(url_for('export_page'))

    key = derive_key('decryption-key' + current_user.id, user['salt'])

    rows = db.execute("""
        SELECT r.matched_at,
               ic.sender, ic.subject, ic.body_preview, ic.received_at,
               sl.encrypted_domain, sl.encrypted_email, sl.sender_email, sl.timestamp as sent_timestamp
        FROM responses r
        JOIN inbox_cache ic ON r.inbox_cache_id = ic.id
        JOIN sent_logs sl ON r.sent_log_id = sl.id
        WHERE r.user_id = %s
        ORDER BY r.matched_at DESC
    """, (user['id'],)).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Domain Sent To', 'Email Sent To', 'Sent From', 'Sent Date',
        'Response From', 'Response Subject', 'Response Preview', 'Response Date',
        'Matched At'
    ])

    for row in rows:
        try:
            domain = decrypt(row['encrypted_domain'], key)
            sent_to = decrypt(row['encrypted_email'], key)
        except Exception:
            domain = '[encrypted]'
            sent_to = '[encrypted]'

        writer.writerow([
            domain, sent_to, row['sender_email'], row['sent_timestamp'],
            row['sender'], row['subject'], row['body_preview'][:200],
            row['received_at'], row['matched_at']
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=responses_export_{now_ist().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )

@app.route('/export_json')
@login_required
def export_json():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    key = derive_key('decryption-key' + current_user.id, user['salt'])

    rows = db.execute("""
        SELECT r.matched_at,
               ic.sender, ic.subject, ic.body_preview, ic.received_at,
               sl.encrypted_domain, sl.encrypted_email, sl.sender_email, sl.timestamp as sent_timestamp
        FROM responses r
        JOIN inbox_cache ic ON r.inbox_cache_id = ic.id
        JOIN sent_logs sl ON r.sent_log_id = sl.id
        WHERE r.user_id = %s
        ORDER BY r.matched_at DESC
    """, (user['id'],)).fetchall()

    results = []
    for row in rows:
        try:
            domain = decrypt(row['encrypted_domain'], key)
            sent_to = decrypt(row['encrypted_email'], key)
        except Exception:
            domain = '[encrypted]'
            sent_to = '[encrypted]'

        results.append({
            'domain_sent_to': domain,
            'email_sent_to': sent_to,
            'sent_from': row['sender_email'],
            'sent_date': row['sent_timestamp'],
            'response_from': row['sender'],
            'response_subject': row['subject'],
            'response_preview': row['body_preview'][:200],
            'response_date': row['received_at'],
            'matched_at': row['matched_at']
        })

    json_output = json.dumps(results, indent=2)
    return Response(
        json_output,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=responses_export_{now_ist().strftime("%Y%m%d_%H%M%S")}.json'
        }
    )

# ---------- Credential Health Check ----------
@app.route('/test_credential', methods=['POST'])
@login_required
def test_credential():
    data = request.get_json()
    cred_index = int(data.get('cred_index', 0))

    creds = get_decrypted_credentials(current_user.id)
    if cred_index < 0 or cred_index >= len(creds):
        return jsonify({"error": "Invalid credential"}), 400

    email_addr, app_password = creds[cred_index]

    # Test SMTP
    smtp_ok = False
    smtp_msg = ''
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        server.starttls()
        server.login(email_addr, app_password)
        server.quit()
        smtp_ok = True
        smtp_msg = 'SMTP login OK'
    except smtplib.SMTPAuthenticationError:
        smtp_msg = 'Authentication failed — check app password'
    except Exception as e:
        smtp_msg = f'Connection error: {str(e)[:80]}'

    # Test IMAP
    imap_ok = False
    imap_msg = ''
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', timeout=10)
        mail.login(email_addr, app_password)
        mail.logout()
        imap_ok = True
        imap_msg = 'IMAP login OK'
    except imaplib.IMAP4.error:
        imap_msg = 'IMAP authentication failed'
    except Exception as e:
        imap_msg = f'IMAP error: {str(e)[:80]}'

    usage = get_cred_usage(email_addr)
    remaining = get_cred_remaining(email_addr)

    return jsonify({
        'email': email_addr,
        'smtp': {'ok': smtp_ok, 'message': smtp_msg},
        'imap': {'ok': imap_ok, 'message': imap_msg},
        'daily_usage': usage,
        'daily_remaining': remaining,
        'daily_limit': GMAIL_DAILY_LIMIT
    })

# ---------- MX Domain Verification ----------
@app.route('/check_mx', methods=['POST'])
@login_required
def check_mx():
    data = request.get_json()
    domains = data.get('domains', [])
    results = {}
    for d in domains[:50]:  # Limit to 50 domains per request
        d = d.strip()
        if d and is_valid_domain(d):
            has_mx, details = check_mx_record(d)
            results[d] = {'valid': has_mx, 'mx_hosts': details}
        elif d:
            results[d] = {'valid': False, 'mx_hosts': ['Invalid domain format']}
    return jsonify(results)

# ---------- Stats Dashboard ----------
@app.route('/stats')
@login_required
def stats_page():
    return render_template('stats.html')

@app.route('/get_stats', methods=['GET'])
@login_required
def get_stats():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    key = derive_key('decryption-key' + current_user.id, user['salt'])

    # Date range filtering
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')

    date_filter_sql = ""
    date_params = []
    if date_from:
        date_filter_sql += " AND timestamp >= %s"
        date_params.append(date_from)
    if date_to:
        # Add 1 day to include the end date fully
        date_filter_sql += " AND timestamp < %s"
        try:
            end_date = (datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')
        except ValueError:
            end_date = date_to
        date_params.append(end_date)

    # Total emails sent (with date range)
    total_sent = db.execute(
        "SELECT COUNT(*) as cnt FROM sent_logs WHERE username=%s" + date_filter_sql,
        (current_user.id, *date_params)
    ).fetchone()['cnt']

    # Total responses received (with date range)
    if date_from or date_to:
        resp_sql = "SELECT COUNT(*) as cnt FROM responses r JOIN sent_logs sl ON r.sent_log_id = sl.id WHERE r.user_id=%s" + date_filter_sql.replace("timestamp", "sl.timestamp")
        total_responses = db.execute(resp_sql, (user['id'], *date_params)).fetchone()['cnt']
    else:
        total_responses = db.execute(
            "SELECT COUNT(*) as cnt FROM responses WHERE user_id=%s", (user['id'],)
        ).fetchone()['cnt']

    # Response rate
    response_rate = round((total_responses / total_sent * 100), 1) if total_sent > 0 else 0

    # Emails sent today
    today = now_ist().strftime('%Y-%m-%d')
    sent_today = db.execute(
        "SELECT COUNT(*) as cnt FROM sent_logs WHERE username=%s AND timestamp LIKE %s",
        (current_user.id, f'{today}%')
    ).fetchone()['cnt']

    # Emails sent last 7 days (by date)
    daily_stats = []
    for i in range(6, -1, -1):
        day = (now_ist() - timedelta(days=i)).strftime('%Y-%m-%d')
        count = db.execute(
            "SELECT COUNT(*) as cnt FROM sent_logs WHERE username=%s AND timestamp LIKE %s",
            (current_user.id, f'{day}%')
        ).fetchone()['cnt']
        daily_stats.append({'date': day, 'count': count})

    # Per-domain stats (top 10 domains by sent count, with date range)
    all_logs = db.execute(
        "SELECT encrypted_domain FROM sent_logs WHERE username=%s" + date_filter_sql,
        (current_user.id, *date_params)
    ).fetchall()
    domain_counts = {}
    for log in all_logs:
        try:
            domain = decrypt(log['encrypted_domain'], key)
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except Exception:
            continue
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Per-domain response matching
    domain_response_map = {}
    resp_query = "SELECT sl.encrypted_domain FROM responses r JOIN sent_logs sl ON r.sent_log_id = sl.id WHERE r.user_id = %s"
    if date_from or date_to:
        resp_query += date_filter_sql.replace("timestamp", "sl.timestamp")
    response_rows = db.execute(resp_query, (user['id'], *date_params)).fetchall()
    for row in response_rows:
        try:
            domain = decrypt(row['encrypted_domain'], key)
            domain_response_map[domain] = domain_response_map.get(domain, 0) + 1
        except Exception:
            continue

    domain_stats = []
    for domain, sent_count in top_domains:
        resp_count = domain_response_map.get(domain, 0)
        domain_stats.append({
            'domain': domain,
            'sent': sent_count,
            'responses': resp_count,
            'rate': round((resp_count / sent_count * 100), 1) if sent_count > 0 else 0
        })

    # Credential usage
    creds = get_decrypted_credentials(current_user.id)
    cred_stats = []
    for email_addr, _ in creds:
        usage = get_cred_usage(email_addr)
        remaining = get_cred_remaining(email_addr)
        cred_stats.append({
            'email': email_addr,
            'used_today': usage,
            'remaining': remaining,
            'limit': GMAIL_DAILY_LIMIT,
            'pct': round((usage / GMAIL_DAILY_LIMIT * 100), 1)
        })

    # Unread inbox emails
    unread = db.execute("""
        SELECT COUNT(*) as cnt FROM inbox_cache ic
        JOIN credentials c ON ic.credential_id = c.id
        WHERE c.user_id = %s AND ic.is_read = 0
    """, (user['id'],)).fetchone()['cnt']

    return jsonify({
        'total_sent': total_sent,
        'total_responses': total_responses,
        'response_rate': response_rate,
        'sent_today': sent_today,
        'unread_emails': unread,
        'daily_stats': daily_stats,
        'domain_stats': domain_stats,
        'cred_stats': cred_stats
    })

@app.route('/reset_stats', methods=['POST'])
@login_required
def reset_stats():
    """Reset all statistics for the current user — sent logs, responses, open tracking."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Delete open tracking records
    db.execute("DELETE FROM email_opens WHERE username=%s", (current_user.id,))
    # Delete responses
    db.execute("DELETE FROM responses WHERE user_id=%s", (user['id'],))
    # Delete sent logs
    db.execute("DELETE FROM sent_logs WHERE username=%s", (current_user.id,))
    db.commit()

    # Reset in-memory credential usage counters
    creds = get_decrypted_credentials(current_user.id)
    today = now_ist().strftime('%Y-%m-%d')
    with _cred_usage_lock:
        for email_addr, _ in creds:
            key = f"{email_addr}:{today}"
            if key in _cred_usage:
                del _cred_usage[key]

    return jsonify({'success': True, 'message': 'All statistics have been reset.'})

# ---------- Dark Mode Preference ----------
@app.route('/toggle_dark_mode', methods=['POST'])
@login_required
def toggle_dark_mode():
    session['dark_mode'] = not session.get('dark_mode', False)
    return jsonify({'dark_mode': session['dark_mode']})

@app.route('/get_theme')
@login_required
def get_theme():
    return jsonify({'dark_mode': session.get('dark_mode', False)})

# ---------- Admin ----------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = sanitize_input(request.form['username'])
        new_password = request.form['password']
        new_email = sanitize_input(request.form['email'])
        new_apppass = sanitize_input(request.form['apppass'])
        if not is_valid_email(new_email):
            flash('Invalid email format.')
            return redirect(url_for('admin'))
        save_user(new_username, new_password, 'user')
        add_credential(new_username, new_email, new_apppass)
        flash(f'User {new_username} created/updated with credential.')

    return render_template('admin.html')

@app.route('/get_admin_logs', methods=['GET'])
@login_required
def get_admin_logs():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    page = int(request.args.get('page', 1))
    search = request.args.get('search', '')

    db = get_db()
    rows = db.execute("SELECT * FROM sent_logs ORDER BY id DESC").fetchall()

    # Only decrypt the admin's own logs — other users' data stays encrypted/masked
    admin_user = db.execute("SELECT salt FROM users WHERE username=%s", (current_user.id,)).fetchone()
    admin_key = derive_key('decryption-key' + current_user.id, admin_user['salt']) if admin_user else None

    logs = []
    for row in rows:
        username = row['username']
        is_own_log = (username == current_user.id)

        if is_own_log and admin_key:
            # Admin can see their own logs fully decrypted
            try:
                target_display = decrypt(row['encrypted_email'], admin_key)
            except Exception:
                target_display = '***@***.com'
            try:
                domain_display = decrypt(row['encrypted_domain'], admin_key)
            except Exception:
                domain_display = '***.***'
        else:
            # Other users' logs — show masked/encrypted data for privacy
            target_display = '***@***.com'
            domain_display = '[encrypted]'

        masked_log = [
            row['timestamp'],
            username,
            domain_display,
            target_display,
            row['sender_email'] if is_own_log else mask_email(row['sender_email'])
        ]
        if search and search.lower() not in ' '.join(masked_log).lower():
            continue
        logs.append(masked_log)

    total = len(logs)
    start = (page - 1) * 20
    end = start + 20
    return jsonify({
        'logs': logs[start:end],
        'total': total,
        'per_page': 20,
        'current_page': page
    })

@app.route('/clear_admin_logs', methods=['POST'])
@login_required
def clear_admin_logs():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    db = get_db()
    # Clean up related records first (FK references)
    db.execute("DELETE FROM email_opens")
    db.execute("DELETE FROM responses")
    db.execute("DELETE FROM sent_logs")
    db.commit()
    return jsonify({'success': True})

@app.route('/delete-user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    if username == 'aditya':
        return jsonify({'error': 'Cannot delete main admin'}), 400
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username=%s", (username,)).fetchone()
    if user:
        db.execute("DELETE FROM users WHERE id=%s", (user['id'],))
        db.commit()
        return jsonify({'success': f'User {username} deleted'})
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin_profiles')
@login_required
def admin_profiles():
    if current_user.role != 'admin':
        flash('Unauthorized access!')
        return redirect(url_for('dashboard'))

    db = get_db()
    all_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    user_list = []
    for u in all_users:
        key = derive_key('decryption-key' + u['username'], u['salt'])
        creds = db.execute(
            "SELECT encrypted_email FROM credentials WHERE user_id=%s ORDER BY id",
            (u['id'],)
        ).fetchall()
        decrypted_creds = []
        for c in creds:
            try:
                decrypted_creds.append(decrypt(c['encrypted_email'], key))
            except Exception:
                decrypted_creds.append('Corrupted')

        user_list.append({
            'username': u['username'],
            'role': u['role'],
            'credentials': decrypted_creds,
            'is_protected': u['username'] == 'aditya',
            'last_active': u['last_active'] if u['last_active'] else 'Never'
        })

    return render_template('admin_profiles.html', users=user_list)

# ---------- Admin Password Reset via OTP ----------
@app.route('/admin_send_otp', methods=['POST'])
@login_required
def admin_send_otp():
    """Admin sends OTP to a user's email for password reset."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    target_username = data.get('username', '')
    if not target_username:
        return jsonify({'error': 'Username required'}), 400

    db = get_db()
    target_user = db.execute("SELECT * FROM users WHERE username=%s", (target_username,)).fetchone()
    if not target_user:
        return jsonify({'error': 'User not found'}), 404

    # Get admin's first credential to send the OTP email
    admin_creds = get_decrypted_credentials(current_user.id)
    if not admin_creds:
        return jsonify({'error': 'No admin credentials to send email. Add a sender first.'}), 400

    # Get user's profile email or credential email as recipient
    profile = db.execute("SELECT email FROM profiles WHERE user_id=%s", (target_user['id'],)).fetchone()
    user_email = None
    if profile and profile['email']:
        user_email = profile['email']
    else:
        # Fallback: use user's first credential email
        key = derive_key('decryption-key' + target_username, target_user['salt'])
        user_creds = db.execute(
            "SELECT encrypted_email FROM credentials WHERE user_id=%s ORDER BY id LIMIT 1",
            (target_user['id'],)
        ).fetchone()
        if user_creds:
            try:
                user_email = decrypt(user_creds['encrypted_email'], key)
            except Exception:
                pass

    if not user_email:
        return jsonify({'error': f'No email found for user {target_username}. User has no profile email or credentials.'}), 400

    otp = generate_otp()
    store_otp(target_username, otp)

    # Send OTP email using admin's first credential
    sender_email, sender_pass = admin_creds[0]
    try:
        message = MIMEMultipart()
        message['From'] = f"Mailer Admin <{sender_email}>"
        message['To'] = user_email
        message['Subject'] = f"Password Reset OTP - {otp}"
        body = (
            f"Hello {target_username},\n\n"
            f"Your admin has requested a password reset for your account.\n\n"
            f"Your OTP is: {otp}\n\n"
            f"This OTP expires in 10 minutes.\n"
            f"Enter it on the password reset page to set a new password.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"— Mailer App"
        )
        message.attach(MIMEText(body, 'plain', 'utf-8'))
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=30)
        server.starttls()
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, user_email, message.as_string())
        server.quit()
        return jsonify({'success': True, 'message': f'OTP sent to {mask_email(user_email)}'})
    except Exception as e:
        return jsonify({'error': f'Failed to send OTP: {str(e)}'}), 500

@app.route('/request_otp', methods=['POST'])
def request_otp():
    """Self-service: user requests OTP by username. Sends OTP to their linked email."""
    if not check_rate_limit(f'otp_request:{request.remote_addr}', 3, 300):
        return jsonify({'error': 'Too many attempts. Try again in 5 minutes.'}), 429

    data = request.get_json() if request.is_json else {}
    target_username = data.get('username', '').strip() if data else request.form.get('username', '').strip()
    if not target_username:
        return jsonify({'error': 'Username is required.'}), 400

    with get_pg_conn() as conn:
        target_user = conn.execute("SELECT * FROM users WHERE username=%s", (target_username,)).fetchone()
        if not target_user:
            # Don't reveal if user exists or not
            return jsonify({'success': True, 'message': 'If the account exists, an OTP has been sent to the linked email.'})

        # Find the user's email: profile email or first credential
        user_email = None
        profile = conn.execute("SELECT email FROM profiles WHERE user_id=%s", (target_user['id'],)).fetchone()
        if profile and profile['email']:
            user_email = profile['email']
        else:
            key = derive_key('decryption-key' + target_username, target_user['salt'])
            cred = conn.execute(
                "SELECT encrypted_email FROM credentials WHERE user_id=%s ORDER BY id LIMIT 1",
                (target_user['id'],)
            ).fetchone()
            if cred:
                try:
                    user_email = decrypt(cred['encrypted_email'], key)
                except Exception:
                    pass

        if not user_email:
            return jsonify({'success': True, 'message': 'If the account exists, an OTP has been sent to the linked email.'})

        # Use admin's first credential to send OTP
        admin_user = conn.execute("SELECT * FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
        if not admin_user:
            return jsonify({'error': 'System error. Contact admin.'}), 500

        admin_key = derive_key('decryption-key' + admin_user['username'], admin_user['salt'])
        admin_cred = conn.execute(
            "SELECT encrypted_email, encrypted_app_password FROM credentials WHERE user_id=%s ORDER BY id LIMIT 1",
            (admin_user['id'],)
        ).fetchone()

    if not admin_cred:
        return jsonify({'error': 'System error. Contact admin.'}), 500

    try:
        sender_email = decrypt(admin_cred['encrypted_email'], admin_key)
        sender_pass = decrypt(admin_cred['encrypted_app_password'], admin_key)
    except Exception:
        return jsonify({'error': 'System error. Contact admin.'}), 500

    otp = generate_otp()
    store_otp(target_username, otp)

    try:
        message = MIMEMultipart()
        message['From'] = f"Mailer App <{sender_email}>"
        message['To'] = user_email
        message['Subject'] = f"Password Reset OTP: {otp}"
        body = (
            f"Hello {target_username},\n\n"
            f"You (or someone) requested a password reset for your Mailer account.\n\n"
            f"Your OTP is: {otp}\n\n"
            f"This OTP expires in 10 minutes.\n"
            f"Enter it on the password reset page to set a new password.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"— Mailer App"
        )
        message.attach(MIMEText(body, 'plain', 'utf-8'))
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=30)
        server.starttls()
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, user_email, message.as_string())
        server.quit()
    except Exception:
        pass  # Don't reveal email sending failure to prevent user enumeration

    return jsonify({'success': True, 'message': 'If the account exists, an OTP has been sent to the linked email.'})

@app.route('/reset_with_otp', methods=['GET', 'POST'])
def reset_with_otp():
    """User enters OTP and new password to reset."""
    if request.method == 'GET':
        return render_template('reset_otp.html')

    # POST — verify OTP and reset password
    username = request.form.get('username', '').strip()
    otp = request.form.get('otp', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not username or not otp or not new_password:
        flash('All fields are required.')
        return redirect(url_for('reset_with_otp'))

    if len(new_password) < 6:
        flash('Password must be at least 6 characters.')
        return redirect(url_for('reset_with_otp'))

    if not verify_otp(username, otp):
        flash('Invalid or expired OTP. Please try again.')
        return redirect(url_for('reset_with_otp'))

    # OTP verified — update password
    with get_pg_conn() as conn:
        user = conn.execute("SELECT id FROM users WHERE username=%s", (username,)).fetchone()
        if not user:
            flash('User not found.')
            return redirect(url_for('reset_with_otp'))

        new_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password=%s WHERE username=%s", (new_hash, username))
        conn.commit()

    flash('Password reset successfully! Please log in with your new password.')
    return redirect(url_for('login'))

# ---------- Cached Inbox & Auto-Fetch ----------
@app.route('/cached_inbox', methods=['POST'])
@login_required
def cached_inbox():
    data = request.get_json() or {}
    cred_index = int(data.get('cred_index', 0))
    page = int(data.get('page', 1))
    per_page = 20
    hide_bounces = data.get('hide_bounces', True)
    search_query = data.get('search', '').strip().lower()

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    creds = db.execute(
        "SELECT id FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()

    if cred_index < 0 or cred_index >= len(creds):
        return jsonify({"error": "Invalid credential"}), 400

    cred_id = creds[cred_index]['id']

    # Fetch all for filtering
    cached = db.execute(
        "SELECT id, sender, subject, body_preview, full_body, received_at, fetched_at, is_read FROM inbox_cache WHERE credential_id=%s ORDER BY id DESC",
        (cred_id,)
    ).fetchall()

    # Apply bounce filter
    if hide_bounces:
        cached = [c for c in cached if not is_bounce_or_ndr(c['sender'], c['subject'])]

    # Apply search filter
    if search_query:
        cached = [c for c in cached if search_query in c['sender'].lower() or search_query in c['subject'].lower() or search_query in (c['body_preview'] or '').lower()]

    total = len(cached)
    offset = (page - 1) * per_page
    page_cached = cached[offset:offset + per_page]

    emails_list = [{
        'id': c['id'],
        'from': html.escape(c['sender']),
        'subject': html.escape(c['subject']),
        'date': html.escape(c['received_at']),
        'preview': html.escape(c['body_preview']),
        'full_body': html.escape(c['full_body'].strip() if c['full_body'] and c['full_body'].strip() else c['body_preview']),
        'fetched_at': c['fetched_at'],
        'is_read': c['is_read'],
        'is_bounce': is_bounce_or_ndr(c['sender'], c['subject'])
    } for c in page_cached]

    return jsonify({
        'emails': emails_list,
        'total': total,
        'per_page': per_page,
        'current_page': page
    })

@app.route('/cached_inbox_recent', methods=['POST'])
@login_required
def cached_inbox_recent():
    """Return the 15 most recent non-bounce cached emails across ALL user credentials."""
    data = request.get_json() or {}
    hide_bounces = data.get('hide_bounces', True)
    search_query = data.get('search', '').strip().lower()

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=%s", (current_user.id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 400

    creds = db.execute(
        "SELECT id, encrypted_email FROM credentials WHERE user_id=%s ORDER BY id",
        (user['id'],)
    ).fetchall()

    if not creds:
        return jsonify({'emails': [], 'total': 0, 'per_page': 15, 'current_page': 1})

    cred_ids = [c['id'] for c in creds]

    # Decrypt credential emails for display
    key = derive_key('decryption-key' + current_user.id, user['salt'])
    cred_email_map = {}
    for c in creds:
        try:
            cred_email_map[c['id']] = decrypt(c['encrypted_email'], key)
        except Exception:
            cred_email_map[c['id']] = f"Account #{c['id']}"

    # Fetch more rows so we have enough after bounce/search filtering
    cached = db.execute(
        "SELECT id, credential_id, sender, subject, body_preview, full_body, received_at, fetched_at, is_read FROM inbox_cache WHERE credential_id = ANY(%s) ORDER BY id DESC LIMIT 500",
        (cred_ids,)
    ).fetchall()

    # Apply bounce filter
    if hide_bounces:
        cached = [c for c in cached if not is_bounce_or_ndr(c['sender'], c['subject'])]

    # Apply search filter
    if search_query:
        cached = [c for c in cached if search_query in c['sender'].lower() or search_query in c['subject'].lower() or search_query in (c['body_preview'] or '').lower()]

    total = len(cached)
    recent = cached[:15]

    emails_list = [{
        'id': c['id'],
        'from': html.escape(c['sender']),
        'subject': html.escape(c['subject']),
        'date': html.escape(c['received_at']),
        'preview': html.escape(c['body_preview']),
        'full_body': html.escape(c['full_body'].strip() if c['full_body'] and c['full_body'].strip() else c['body_preview']),
        'fetched_at': c['fetched_at'],
        'is_read': c['is_read'],
        'account': cred_email_map.get(c['credential_id'], ''),
        'is_bounce': is_bounce_or_ndr(c['sender'], c['subject'])
    } for c in recent]

    return jsonify({
        'emails': emails_list,
        'total': total,
        'per_page': 15,
        'current_page': 1
    })

AUTO_FETCH_INTERVAL = 3600
auto_fetch_timer = None

def auto_fetch_all_inboxes():
    global auto_fetch_timer
    conn = None
    try:
        conn = get_pg_conn()

        users = conn.execute("SELECT * FROM users").fetchall()
        for user in users:
            key = derive_key('decryption-key' + user['username'], user['salt'])
            creds = conn.execute(
                "SELECT id, encrypted_email, encrypted_app_password FROM credentials WHERE user_id=%s",
                (user['id'],)
            ).fetchall()

            # Precompute sent recipient map for response matching
            sent_rows = conn.execute(
                "SELECT id, encrypted_email FROM sent_logs WHERE username=%s",
                (user['username'],)
            ).fetchall()
            decrypted_sent_map = {}
            for sr in sent_rows:
                try:
                    dec = decrypt(sr['encrypted_email'], key).lower()
                    dec_email = extract_email_from_header(dec) or dec
                    decrypted_sent_map[dec_email] = sr['id']
                except Exception:
                    continue

            # Get Discord webhook for this user
            profile_row = conn.execute(
                "SELECT discord_webhook_url FROM profiles WHERE user_id=%s",
                (user['id'],)
            ).fetchone()
            user_webhook = ''
            if profile_row and profile_row['discord_webhook_url']:
                try:
                    user_webhook = decrypt(profile_row['discord_webhook_url'], key)
                except Exception:
                    user_webhook = ''

            for cred in creds:
                mail = None
                try:
                    email_addr = decrypt(cred['encrypted_email'], key)
                    app_password = decrypt(cred['encrypted_app_password'], key)
                    cred_id = cred['id']

                    mail = imaplib.IMAP4_SSL('imap.gmail.com')
                    mail.login(email_addr, app_password)
                    mail.select('INBOX', readonly=True)

                    status, messages = mail.search(None, 'ALL')
                    if status != 'OK':
                        continue

                    msg_nums = messages[0].split()
                    msg_nums.reverse()
                    latest = msg_nums[:50]

                    new_emails = []  # Batch for commit

                    for num in latest:
                        status, msg_data = mail.fetch(num, '(RFC822)')
                        if status != 'OK':
                            continue

                        raw_email = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw_email)

                        msg_id = msg.get('Message-ID', f'<no-id-{uuid.uuid4()}>')

                        existing = conn.execute(
                            "SELECT id FROM inbox_cache WHERE message_id=%s", (msg_id,)
                        ).fetchone()
                        if existing:
                            continue

                        subject_header = decode_header(msg.get('Subject', ''))
                        subject = ''
                        for part, encoding in subject_header:
                            if isinstance(part, bytes):
                                subject += part.decode(encoding or 'utf-8', errors='replace')
                            else:
                                subject += str(part)

                        from_header = decode_header(msg.get('From', ''))
                        from_addr = ''
                        for part, encoding in from_header:
                            if isinstance(part, bytes):
                                from_addr += part.decode(encoding or 'utf-8', errors='replace')
                            else:
                                from_addr += str(part)

                        date_str = msg.get('Date', '')

                        # Skip bounce/NDR/auto-reply emails — don't cache or notify
                        if is_bounce_or_ndr(from_addr, subject):
                            continue

                        body = ''
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    charset = part.get_content_charset() or 'utf-8'
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        body = payload.decode(charset, errors='replace')
                                    break
                        else:
                            charset = msg.get_content_charset() or 'utf-8'
                            payload = msg.get_payload(decode=True)
                            if payload:
                                body = payload.decode(charset, errors='replace')

                        body_preview = body[:500] if body else ''
                        full_body = body

                        conn.execute(
                            "INSERT INTO inbox_cache (credential_id, message_id, sender, subject, body_preview, full_body, received_at) VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (message_id) DO NOTHING",
                            (cred_id, msg_id, from_addr[:500], subject[:500], body_preview, full_body, date_str[:100])
                        )

                        new_emails.append((msg_id, from_addr, subject))

                    # Batch commit after processing all emails for this credential
                    conn.commit()

                    # Discord notifications and response matching for new emails
                    for msg_id, from_addr, subject in new_emails:
                        if user_webhook:
                            send_discord_notification(user_webhook, from_addr[:200], subject[:200])

                        # Response matching
                        new_cache_id = conn.execute(
                            "SELECT id FROM inbox_cache WHERE message_id=%s", (msg_id,)
                        ).fetchone()
                        if new_cache_id:
                            sender_email_addr = extract_email_from_header(from_addr).lower()
                            if sender_email_addr and sender_email_addr in decrypted_sent_map:
                                sent_log_id = decrypted_sent_map[sender_email_addr]
                                existing_match = conn.execute(
                                    "SELECT id FROM responses WHERE inbox_cache_id=%s AND sent_log_id=%s",
                                    (new_cache_id['id'], sent_log_id)
                                ).fetchone()
                                if not existing_match:
                                    conn.execute(
                                        "INSERT INTO responses (user_id, inbox_cache_id, sent_log_id, credential_id, matched_at) VALUES (%s,%s,%s,%s,%s)",
                                        (user['id'], new_cache_id['id'], sent_log_id, cred_id,
                                         now_ist().strftime("%Y-%m-%d %H:%M:%S"))
                                    )
                    conn.commit()

                except Exception as e:
                    app.logger.warning(f"[Auto-fetch] Error for credential {cred['id']}: {e}")
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    continue
                finally:
                    # Always close IMAP connection to prevent leaks
                    if mail:
                        try:
                            mail.logout()
                        except Exception:
                            pass

        app.logger.info(f"[Auto-fetch] Completed at {now_ist().strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        app.logger.error(f"[Auto-fetch] Global error: {e}")
    finally:
        if conn:
            conn.close()
        auto_fetch_timer = threading.Timer(AUTO_FETCH_INTERVAL, auto_fetch_all_inboxes)
        auto_fetch_timer.daemon = True
        auto_fetch_timer.start()

def start_auto_fetch():
    global auto_fetch_timer
    auto_fetch_timer = threading.Timer(60, auto_fetch_all_inboxes)
    auto_fetch_timer.daemon = True
    auto_fetch_timer.start()
    print("[Auto-fetch] Scheduler started. First fetch in 60 seconds, then every 1 hour.")

@app.route('/auto_fetch_status')
@login_required
def auto_fetch_status():
    global auto_fetch_timer
    is_active = auto_fetch_timer is not None and auto_fetch_timer.is_alive()
    return jsonify({'active': is_active})

# ---------- Email Open Tracking ----------
# 1x1 transparent GIF (43 bytes)
TRACKING_GIF = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')

@app.route('/track/<token>.gif')
def track_open(token):
    """Serve a 1x1 transparent GIF and record the email open."""
    try:
        with get_pg_conn() as conn:
            row = conn.execute("SELECT id, open_count FROM email_opens WHERE tracking_token=%s", (token,)).fetchone()
            if row:
                ua = request.headers.get('User-Agent', '')[:500]
                conn.execute(
                    "UPDATE email_opens SET open_count=%s, opened_at=%s, user_agent=%s WHERE id=%s",
                    (row['open_count'] + 1, now_ist().strftime('%Y-%m-%d %I:%M %p IST'), ua, row['id'])
                )
                conn.commit()
    except Exception:
        pass
    response = Response(TRACKING_GIF, mimetype='image/gif')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/open_stats')
@login_required
def open_stats():
    """Return open tracking stats for current user."""
    db = get_db()
    user = get_user(current_user.id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    key = derive_key('decryption-key' + current_user.id, user['salt'])
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    if per_page not in (10, 25):
        per_page = 10

    rows = db.execute(
        "SELECT eo.*, sl.encrypted_domain, sl.encrypted_email as log_email, sl.sender_email, sl.timestamp "
        "FROM email_opens eo "
        "JOIN sent_logs sl ON eo.sent_log_id = sl.id "
        "WHERE eo.username=%s ORDER BY eo.created_at DESC",
        (current_user.id,)
    ).fetchall()

    stats = []
    for row in rows:
        try:
            recipient = decrypt(row['recipient_email'], key)
            domain = decrypt(row['encrypted_domain'], key)
        except Exception:
            recipient = 'Unknown'
            domain = 'Unknown'
        stats.append({
            'recipient': recipient,
            'domain': domain,
            'sender': row['sender_email'],
            'sent_at': row['timestamp'],
            'opened': row['open_count'] > 0,
            'open_count': row['open_count'],
            'opened_at': row['opened_at'] or '',
            'user_agent': row['user_agent'] or ''
        })

    total = len(stats)
    start = (page - 1) * per_page
    end = start + per_page

    # Summary
    total_tracked = total
    total_opened = sum(1 for s in stats if s['opened'])
    open_rate = round((total_opened / total_tracked * 100), 1) if total_tracked > 0 else 0

    return jsonify({
        'stats': stats[start:end],
        'total': total,
        'current_page': page,
        'per_page': per_page,
        'summary': {
            'total_tracked': total_tracked,
            'total_opened': total_opened,
            'open_rate': open_rate
        }
    })

# Start auto-fetch when app loads
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true' or not app.debug:
    start_auto_fetch()

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=58000)
