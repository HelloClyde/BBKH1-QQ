"""Run recorded native algorithm vectors without an ARM library or network."""
import json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/core';OUT.mkdir(parents=True,exist_ok=True)
cc=os.environ.get('HOST_CC','cc');exe=OUT/('selftest.exe' if os.name=='nt' else 'selftest')
subprocess.run([cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-I',str(ROOT/'h1-qq-native/core'),str(ROOT/'tests/core_selftest.c'),str(ROOT/'h1-qq-native/core/core.c'),str(ROOT/'h1-qq-native/core/selftest.c'),'-o',str(exe)],check=True)
result=subprocess.run([str(exe)],check=True,capture_output=True,text=True);report=json.loads(result.stdout)
assert report['passed'] and report['checks']>0
(OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n');print(result.stdout.strip())
