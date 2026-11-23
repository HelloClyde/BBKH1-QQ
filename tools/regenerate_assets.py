"""Repack checked-in artwork and original BDF pixels; no AI/network calls."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
for name in ['build_ui_assets.py','build_small_font.py','pack_skin2008.py','pack_idle2008.py','pack_login2008.py','pack_menu2008.py']:
    subprocess.run([sys.executable,str(ROOT/'h1-qq-native/tools'/name)],cwd=ROOT,check=True)
