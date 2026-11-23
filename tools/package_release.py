"""Package the same MIPS-checked BDA with an explicit installation allowlist."""
import hashlib,json,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];BUILD=ROOT/'build/client';OUT=ROOT/'dist/release'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    version=(ROOT/'VERSION').read_text().strip();native=json.loads((BUILD/'H1QQNative.build.json').read_text());debug=json.loads((BUILD/'H1QQNativeDbg.build.json').read_text())
    artifact=BUILD/'H1QQNative.bda';assert sha(artifact)==native['sha256'] and not native['emulator_linked']
    proofs=['session-resume-mips.json','skin-touch-mips.json','local-history-mips.json','login-ui-mips.json','model/report.json','model/interaction.json','model/navigation.json','model/rejection.json','model/qr-rejection.json']
    for file in proofs:
        proof=json.loads((BUILD/file).read_text(encoding='utf-8'));assert proof['passed'] and proof['debug_bda_sha256']==debug['sha256'],file
    OUT.mkdir(parents=True,exist_ok=True);bda=OUT/artifact.name;bda.write_bytes(artifact.read_bytes())
    files={'应用/程序/H1QQNative.bda':artifact,'README.md':ROOT/'README.md','PC初始化/init_data.py':ROOT/'tools/init_data.py','PC初始化/identity_format.py':ROOT/'h1-qq-native/tools/identity_format.py','LICENSES/COPYING-GPL-3.0.txt':ROOT/'LICENSE','LICENSES/THIRD_PARTY.md':ROOT/'THIRD_PARTY.md','LICENSES/SDK-Apache-2.0.txt':ROOT/'sdk/LICENSE','LICENSES/SDK-NOTICE.txt':ROOT/'sdk/NOTICE','LICENSES/SDK-media.md':ROOT/'sdk/sdk/media/THIRD_PARTY.md','LICENSES/cJSON-MIT.txt':ROOT/'third_party/cjson/LICENSE','LICENSES/micro-ecc-BSD.txt':ROOT/'h1-qq-native/third_party/micro-ecc/LICENSE.txt'}
    for p in (ROOT/'h1-qq-native/app/assets/font12').glob('OFL-*.txt'):files['LICENSES/'+p.name]=p
    for p in (ROOT/'h1-qq-native/third_party/fusion-pixel-12/LICENSES').rglob('*'):
        if p.is_file():files['LICENSES/Fusion-components/'+p.relative_to(ROOT/'h1-qq-native/third_party/fusion-pixel-12/LICENSES').as_posix()]=p
    for source,name in [('musl-1.2.5/COPYRIGHT','musl-COPYRIGHT.txt'),('zlib-1.3.1/LICENSE','zlib-LICENSE.txt'),('libpng-1.6.43/LICENSE','libpng-LICENSE.txt'),('jpeg-9f/README','IJG-README.txt'),('tlsf/tlsf.h','TLSF-notice.h')]:
        files['LICENSES/'+name]=ROOT/'sdk/sdk/media/third_party'/source
    # Monocypher's full dual-licence notice is retained verbatim from its source.
    mono=(ROOT/'h1-qq-native/third_party/monocypher/monocypher.c').read_text(encoding='utf-8').split('#include',1)[0]
    manifest=dict(version=version,sdk=json.loads((ROOT/'SDK.json').read_text()),bda_sha256=native['sha256'],bda_bytes=native['bytes'],offline_mips_checks_passed=True,physical_h1_this_build=False)
    (OUT/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    files['build-manifest.json']=OUT/'build-manifest.json'
    archive=OUT/('BBKH1-QQ-'+version+'-preview.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,p in sorted(files.items()):
            assert p.is_file(),str(p);info=zipfile.ZipInfo(name,(2026,11,24,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,p.read_bytes())
        info=zipfile.ZipInfo('LICENSES/Monocypher-notice.txt',(2026,11,24,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,mono)
    with zipfile.ZipFile(archive) as z:
        assert '应用/程序/H1QQNative.bda' in z.namelist() and not any(n.endswith(('.ID','.SES','.MSG','.avt')) for n in z.namelist())
        assert hashlib.sha256(z.read('应用/程序/H1QQNative.bda')).hexdigest()==native['sha256']
    outputs=[bda,archive,OUT/'build-manifest.json'];(OUT/'SHA256SUMS.txt').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in outputs),encoding='utf-8',newline='\n')
    print('Packaged checked BDA, installation ZIP and SHA256SUMS:',native['sha256'])
if __name__=='__main__':main()
