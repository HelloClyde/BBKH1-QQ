"""Build the native H1 QQ application using the pinned sdk/ submodule."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,str(ROOT/'h1-qq-native/tools/build_client.py'),'--all',*sys.argv[1:]],cwd=ROOT,check=True)
