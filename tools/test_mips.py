"""Run only offline synthetic-account integration checks on the linked MIPS BDA."""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/client'
commands=[('test_session_resume.py',[]),('test_client_model.py',[]),('test_skin2008.py',[]),('test_local_history.py',[]),('check_login2008.py',[]),('test_client_model.py',['--interaction']),('test_client_model.py',['--navigation']),('test_client_model.py',['--login-rejected']),('test_client_model.py',['--qr-rejected'])]
for name,flags in commands:
    subprocess.run([sys.executable,str(ROOT/'h1-qq-native/tools'/name),'--out',str(OUT),*flags],cwd=ROOT,check=True)
for name in ['session-resume-mips.json','skin-touch-mips.json','local-history-mips.json','login-ui-mips.json','model/report.json','model/interaction.json','model/navigation.json','model/rejection.json','model/qr-rejection.json']:
    assert json.loads((OUT/name).read_text(encoding='utf-8'))['passed'],name
print('PASS offline MIPS integration suite; no physical device or actual account tested')
