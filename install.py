#!/usr/bin/env python3
"""
Mailer - Cross-Platform Installer
Works on Linux, macOS, and Windows.

Usage:
    python3 install.py
    python  install.py          # Windows
    python3 install.py --skip-db    # Skip PostgreSQL setup
"""

import subprocess
import sys
import os
import platform
import shutil

SYSTEM = platform.system()  # Linux, Darwin, Windows
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(BASE_DIR, "venv")


def run(cmd, check=True, shell=True, capture=False):
    """Run a shell command."""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=shell, capture_output=capture, text=True)
    if check and result.returncode != 0:
        if capture:
            print(f"  [WARN] Command failed: {result.stderr or result.stdout}")
        return False
    return result if capture else True


def check_python():
    """Verify Python 3.8+."""
    print("\n[1/6] Checking Python version...")
    v = sys.version_info
    if v.major < 3 or (v.major == 3 and v.minor < 8):
        print(f"  [ERROR] Python 3.8+ required, found {v.major}.{v.minor}.{v.micro}")
        sys.exit(1)
    print(f"  [OK] Python {v.major}.{v.minor}.{v.micro}")


def check_postgres():
    """Check if PostgreSQL is available."""
    print("\n[2/6] Checking PostgreSQL...")
    if shutil.which("psql"):
        result = run("psql --version", capture=True, check=False)
        if result and result.stdout:
            print(f"  [OK] {result.stdout.strip()}")
            return True

    print("  [WARN] PostgreSQL not found on PATH.")
    print("")

    if SYSTEM == "Linux":
        print("  Install with:")
        print("    Ubuntu/Debian: sudo apt install postgresql postgresql-contrib")
        print("    Fedora/RHEL:   sudo dnf install postgresql-server postgresql")
        print("    Arch:          sudo pacman -S postgresql")
    elif SYSTEM == "Darwin":
        print("  Install with:")
        print("    brew install postgresql@16 && brew services start postgresql@16")
    elif SYSTEM == "Windows":
        print("  Download from: https://www.postgresql.org/download/windows/")
        print("  Or: winget install PostgreSQL.PostgreSQL")

    return False


def create_venv():
    """Create Python virtual environment."""
    print("\n[3/6] Setting up virtual environment...")
    if os.path.exists(VENV_DIR):
        print(f"  [OK] venv already exists at {VENV_DIR}")
    else:
        run(f"{sys.executable} -m venv {VENV_DIR}")
        print(f"  [OK] Created venv at {VENV_DIR}")

    # Determine pip path
    if SYSTEM == "Windows":
        pip = os.path.join(VENV_DIR, "Scripts", "pip.exe")
        python = os.path.join(VENV_DIR, "Scripts", "python.exe")
    else:
        pip = os.path.join(VENV_DIR, "bin", "pip")
        python = os.path.join(VENV_DIR, "bin", "python3")

    if not os.path.exists(pip):
        # Fallback
        pip = os.path.join(VENV_DIR, "bin", "pip3") if SYSTEM != "Windows" else pip

    return pip, python


def install_deps(pip):
    """Install Python dependencies."""
    print("\n[4/6] Installing Python dependencies...")
    req_file = os.path.join(BASE_DIR, "requirements.txt")
    run(f'"{pip}" install --upgrade pip', check=False)
    run(f'"{pip}" install -r "{req_file}"')
    print("  [OK] Dependencies installed.")


def setup_database(skip_db=False):
    """Create PostgreSQL database and user."""
    print("\n[5/6] Setting up PostgreSQL database...")

    if skip_db:
        print("  [SKIP] --skip-db flag set. Configure DATABASE_URL manually.")
        return

    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        print(f"  [OK] DATABASE_URL already set: {db_url[:40]}...")
        return

    # Try to create database
    if SYSTEM == "Windows":
        # Windows: assume postgres user with password auth
        print("  On Windows, please create the database manually:")
        print('    psql -U postgres -c "CREATE USER mailer WITH PASSWORD \'mailer123\';"')
        print('    psql -U postgres -c "CREATE DATABASE mailer OWNER mailer;"')
        print("")
        print("  Then set: set DATABASE_URL=postgresql://mailer:mailer123@localhost/mailer")
        return

    # Linux/macOS: try via sudo -u postgres
    print("  Attempting to create database via sudo...")
    created_user = run('sudo -u postgres psql -c "CREATE USER mailer WITH PASSWORD \'mailer123\';" 2>/dev/null', check=False)
    if not created_user:
        run("sudo -u postgres psql -c \"ALTER USER mailer WITH PASSWORD 'mailer123';\" 2>/dev/null", check=False)

    run('sudo -u postgres psql -c "CREATE DATABASE mailer OWNER mailer;" 2>/dev/null', check=False)
    run('sudo -u postgres psql -d mailer -c "GRANT ALL ON SCHEMA public TO mailer;" 2>/dev/null', check=False)

    print("  [OK] Database 'mailer' ready (user: mailer, password: mailer123)")
    print("  DATABASE_URL: postgresql://mailer:mailer123@localhost/mailer")


def print_summary(python):
    """Print final instructions."""
    print("\n[6/6] Installation complete!")
    print("=" * 60)
    print("")

    if SYSTEM == "Windows":
        activate = f"  {VENV_DIR}\\Scripts\\activate"
        run_cmd = f"  set DATABASE_URL=postgresql://mailer:mailer123@localhost/mailer\n  python app.py"
    else:
        activate = f"  source {VENV_DIR}/bin/activate"
        run_cmd = f'  export DATABASE_URL="postgresql://mailer:mailer123@localhost/mailer"\n  python3 app.py'

    print("  To start the app:")
    print("")
    print(f"  cd {BASE_DIR}")
    print(activate)
    print(run_cmd)
    print("")
    print("  Default login:")
    print("    Username: aditya")
    print("    Password: Aditya@819409557")
    print("")
    print("=" * 60)


def main():
    print("=" * 60)
    print("  Mailer - Cross-Platform Installer")
    print(f"  Platform: {SYSTEM} ({platform.machine()})")
    print("=" * 60)

    skip_db = "--skip-db" in sys.argv

    check_python()
    check_postgres()
    pip, python = create_venv()
    install_deps(pip)
    setup_database(skip_db)
    print_summary(python)


if __name__ == "__main__":
    main()
