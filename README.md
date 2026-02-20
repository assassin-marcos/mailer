# Mailer - Secure Email Campaign Manager

A privacy-focused email campaign management tool built with Flask and PostgreSQL. Designed for security researchers and authorized penetration testers to manage bulk email outreach with encrypted logging, response tracking, and campaign analytics.

## Features

- **Per-User Encryption** - Sent emails and target domains are encrypted with unique per-user keys (Fernet + PBKDF2-SHA256). Even admins cannot see other users' data.
- **Multi-Credential Support** - Manage multiple Gmail accounts with app passwords, automatic rotation, and daily rate limiting (500/day per credential).
- **Email Open Tracking** - Optional 1x1 tracking pixel with open count, timestamp, and user-agent logging.
- **Auto-Fetch Inbox** - Background thread fetches incoming emails every hour via IMAP, caches them, and auto-matches responses to sent campaigns.
- **Response Matching** - Automatically correlates received replies with sent campaigns for response rate analytics.
- **Bounce/NDR Detection** - Filters out delivery failures, auto-replies, and out-of-office responses.
- **MX Record Validation** - Validates target domains have valid mail servers before sending.
- **Template Engine** - Reusable email templates with variables: `{sender_name}`, `{domain}`, `{email}`, `{date}`, `{time}`.
- **2FA Support** - TOTP-based two-factor authentication with QR code setup.
- **Dark Mode** - Full dark/light theme toggle.
- **Discord Notifications** - Webhook integration for real-time new email alerts.
- **Statistics Dashboard** - Per-domain send counts, response rates, 7-day rolling stats, and date-range filtering.
- **Export** - CSV and JSON export of campaign data.

## Security

- Per-user Fernet encryption (AES-128-CBC) with PBKDF2-derived keys
- CSRF protection on all forms
- Rate limiting on login (5/min), sending (3/min), and OTP requests (3/5min)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Password hashing via Werkzeug (PBKDF2-SHA256)
- Session timeout (30 minutes)
- Parameterized SQL queries throughout (no SQL injection)
- Connection pooling with psycopg2 ThreadedConnectionPool

## Requirements

- Python 3.8+
- PostgreSQL 12+
- Gmail account(s) with [App Passwords](https://support.google.com/accounts/answer/185833) enabled

## Quick Install

### Linux / macOS

```bash
git clone https://github.com/assassin-marcos/mailer.git
cd mailer
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/assassin-marcos/mailer.git
cd mailer
python install.py
```

### Cross-Platform (Python)

```bash
git clone https://github.com/assassin-marcos/mailer.git
cd mailer
python3 install.py
```

## Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create PostgreSQL database
createdb mailer
# Or: psql -c "CREATE DATABASE mailer;"

# 4. Set environment variable
export DATABASE_URL="postgresql://user:password@localhost/mailer"

# 5. Run the app
python3 app.py
```

## Configuration

Set these environment variables before running:

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | `postgresql://postgres:postgres@localhost/mailer` | PostgreSQL connection string |
| `FLASK_SECRET_KEY` | No | Random 32-byte hex | Session encryption key |
| `ADMIN_PASSWORD` | No | (built-in) | Override default admin password |
| `ADMIN_CREDS` | No | (built-in) | Comma-separated `email:apppass` pairs |
| `MAILER_BASE_URL` | No | `https://mailer.adityasec.com` | Base URL for tracking pixels |
| `SESSION_COOKIE_SECURE` | No | `false` | Set `true` for HTTPS-only cookies |

## Migrating from SQLite

If you have an existing SQLite database (`mailer.db`), use the migration script:

```bash
export DATABASE_URL="postgresql://user:password@localhost/mailer"
python3 pg_migrate.py
```

This copies all data (users, credentials, logs, templates, inbox cache, responses, tracking) to PostgreSQL and resets sequences.

## Project Structure

```
mailer/
├── app.py              # Main Flask application (3000+ lines)
├── migrate.py          # CSV-to-PostgreSQL migration script
├── pg_migrate.py       # SQLite-to-PostgreSQL data migration
├── install.py          # Cross-platform Python installer
├── install.sh          # Linux/macOS shell installer
├── requirements.txt    # Python dependencies
├── templates/          # 17 Jinja2 HTML templates
│   ├── layout.html     # Base template (sidebar, dark mode)
│   ├── dashboard.html  # Email sending form
│   ├── inbox.html      # Live/cached inbox viewer
│   ├── my_logs.html    # Sent email history
│   ├── responses.html  # Matched response viewer
│   ├── stats.html      # Campaign statistics
│   ├── templates.html  # Email template manager
│   ├── admin.html      # Admin panel
│   └── ...
└── static/
    ├── css/styles.css  # Dark/light mode styles
    └── js/send.js      # SSE streaming, form handling
```

## Default Login

```
Username: aditya
Password: Aditya@819409557
```

> Change this immediately after first login via the admin panel or `ADMIN_PASSWORD` env var.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/send_emails_start` | Initiate bulk email campaign |
| GET | `/send_emails_stream` | SSE stream for send progress |
| POST | `/fetch_inbox` | Live IMAP inbox fetch |
| POST | `/cached_inbox` | Get auto-fetched cached emails |
| GET | `/get_stats` | Campaign statistics JSON |
| GET | `/open_stats` | Email open tracking data |
| GET | `/get_responses` | Matched response data |
| POST | `/check_mx` | Validate domain MX records |
| GET | `/track/<token>.gif` | Tracking pixel endpoint |

## License

This tool is intended for authorized security research and penetration testing only. Use responsibly and in compliance with applicable laws.

## Author

Built by [assassin-marcos](https://github.com/assassin-marcos)
