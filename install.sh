#!/usr/bin/env bash
#
# Mailer - Linux/macOS Installer
# Usage: chmod +x install.sh && ./install.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$BASE_DIR/venv"

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "  ${RED}[ERROR]${NC} $1"; exit 1; }

echo "============================================================"
echo "  Mailer - Installer"
echo "  Platform: $(uname -s) ($(uname -m))"
echo "============================================================"

# ── 1. Check Python ──────────────────────────────────────────────
echo ""
echo "[1/6] Checking Python..."
if command -v python3 &>/dev/null; then
    PY=$(command -v python3)
elif command -v python &>/dev/null; then
    PY=$(command -v python)
else
    fail "Python 3.8+ is required. Install it first."
fi

PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PY -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PY -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    fail "Python 3.8+ required, found $PY_VER"
fi
ok "Python $PY_VER ($PY)"

# ── 2. Check PostgreSQL ─────────────────────────────────────────
echo ""
echo "[2/6] Checking PostgreSQL..."
if command -v psql &>/dev/null; then
    PG_VER=$(psql --version 2>/dev/null | head -1)
    ok "$PG_VER"
else
    warn "PostgreSQL not found."
    echo ""
    case "$(uname -s)" in
        Linux*)
            if command -v apt &>/dev/null; then
                echo "  Install with: sudo apt install postgresql postgresql-contrib"
            elif command -v dnf &>/dev/null; then
                echo "  Install with: sudo dnf install postgresql-server postgresql"
            elif command -v pacman &>/dev/null; then
                echo "  Install with: sudo pacman -S postgresql"
            fi
            ;;
        Darwin*)
            echo "  Install with: brew install postgresql@16 && brew services start postgresql@16"
            ;;
    esac
    echo ""
    read -p "  Continue anyway? (y/n) " -n 1 -r
    echo ""
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

# ── 3. Create virtual environment ────────────────────────────────
echo ""
echo "[3/6] Setting up virtual environment..."
if [ -d "$VENV_DIR" ]; then
    ok "venv already exists"
else
    $PY -m venv "$VENV_DIR"
    ok "Created venv at $VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"
ok "Activated venv"

# ── 4. Install dependencies ─────────────────────────────────────
echo ""
echo "[4/6] Installing Python dependencies..."
pip install --upgrade pip -q 2>/dev/null || true
pip install -r "$BASE_DIR/requirements.txt" -q
ok "Dependencies installed"

# ── 5. Setup PostgreSQL database ────────────────────────────────
echo ""
echo "[5/6] Setting up PostgreSQL database..."

if [ -n "$DATABASE_URL" ]; then
    ok "DATABASE_URL already set"
else
    if command -v psql &>/dev/null; then
        # Try creating user and database
        sudo -u postgres psql -c "CREATE USER mailer WITH PASSWORD 'mailer123';" 2>/dev/null || \
            sudo -u postgres psql -c "ALTER USER mailer WITH PASSWORD 'mailer123';" 2>/dev/null || true
        sudo -u postgres psql -c "CREATE DATABASE mailer OWNER mailer;" 2>/dev/null || true
        sudo -u postgres psql -d mailer -c "GRANT ALL ON SCHEMA public TO mailer;" 2>/dev/null || true
        ok "Database 'mailer' ready (user: mailer, pass: mailer123)"
    else
        warn "PostgreSQL not available. Create the database manually."
    fi
fi

# ── 6. Summary ──────────────────────────────────────────────────
echo ""
echo "[6/6] Installation complete!"
echo "============================================================"
echo ""
echo "  To start the app:"
echo ""
echo "    cd $BASE_DIR"
echo "    source venv/bin/activate"
echo "    export DATABASE_URL=\"postgresql://mailer:mailer123@localhost/mailer\""
echo "    python3 app.py"
echo ""
echo "  Default login:"
echo "    Username: aditya"
echo "    Password: Aditya@819409557"
echo ""
echo "============================================================"
