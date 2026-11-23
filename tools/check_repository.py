"""Check the standalone layout, fixed SDK and exclusion of runtime/private files."""
import json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def git(base,*args):return subprocess.check_output(['git','-c','safe.directory='+base.as_posix(),'-C',str(base),*args])
def main():
    sdk=json.loads((ROOT/'SDK.json').read_text(encoding='utf-8'))
    assert git(ROOT/'sdk','rev-parse','HEAD').decode().strip()==sdk['commit'],'SDK commit differs from SDK.json'
    assert not git(ROOT/'sdk','status','--porcelain').strip(),'SDK must be a clean fixed submodule'
    files=set(git(ROOT,'ls-files','-z','--cached','--others','--exclude-standard').decode().strip('\0').split('\0'))
    assert 'sdk' in files
    for name in sorted(files):
        if name=='sdk':continue
        path=Path(name)
        assert not {'build','dist','.tools','__pycache__'}.intersection(path.parts),name
        assert '.private.' not in name and path.suffix.lower() not in {'.id','.ses','.msg','.avt','.bda','.elf','.exe','.dll','.so','.bin'},name
        p=ROOT/path
        if not p.is_file():continue
        if p.suffix.lower() in {'.py','.c','.h','.json','.md','.txt','.yml','.yaml'}:
            text=p.read_text(encoding='utf-8')
            assert not re.search(r'[A-Za-z]:[/\\]Users[/\\]',text),'Developer path: '+name
            assert not re.search(r'^-----BEGIN (?:RSA |EC )?PRIVATE KEY-----$',text,re.M),'Private key: '+name
    readme=(ROOT/'README.md').read_text(encoding='utf-8')
    for heading in ['快速开始','截图','依赖','感谢']:assert '## '+heading in readme
    images=re.findall(r'!\[[^\]]*\]\(([^)]+)\)',readme);assert len(images)>=3
    for name in images:assert (ROOT/name).is_file(),name
    print('PASS standalone repository, fixed SDK, README screenshots and runtime-file exclusions')
if __name__=='__main__':main()
