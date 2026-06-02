import sys
import os


# ── Set working directory to executable location ─────────────
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    base_dir = os.path.dirname(sys.executable)
else:
    # Running as normal Python script
    base_dir = os.path.dirname(os.path.abspath(__file__))

os.chdir(base_dir)
sys.path.insert(0, base_dir)


# ── Load .env ─────────────────────────────────────────────────
env_path = os.path.join(base_dir, '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                os.environ.setdefault(
                    key.strip(), val.strip()
                )
    print("[+] .env loaded")
else:
    print("[!] .env not found — AI features may not work")


# ── Create required directories ───────────────────────────────
for folder in ['storage', 'reports', 'exports']:
    os.makedirs(
        os.path.join(base_dir, folder),
        exist_ok=True
    )


# ── Initialize database ───────────────────────────────────────
try:
    from backend.db import init_db
    init_db()
    print("[+] Database initialized")
except Exception as e:
    print(f"[!] Database init error: {e}")


# ── Launch app ────────────────────────────────────────────────
from PyQt6.QtWidgets import QApplication
from gui.main_window import MainWindow

app    = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec())
