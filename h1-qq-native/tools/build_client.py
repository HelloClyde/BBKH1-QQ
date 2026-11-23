"""Build native QQ BDA, using ESP byte transport and no desktop account relay."""
import argparse,hashlib,json,os,re,sys
from pathlib import Path
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[2];SRC=ROOT/'h1-qq-native';OUT=ROOT/'build/client';SDK=ROOT/'sdk'
os.environ.setdefault('H1_MEDIA_BUILD',str(ROOT/'build/deps'));os.environ.setdefault('H1_GNU_BIN',str(ROOT/'.tools/toolchain/bin'));sys.path.insert(0,str(SDK))
from h1_bda import media
from h1_bda.header import HeaderFields,encode_header
from h1_bda.resources import PAYLOAD_OFFSET,RESOURCE_OFFSET,RESOURCE_SIZES,build_icon_resources
from h1_bda.validate import validate_bda
ECC=['-DuECC_PLATFORM=uECC_arch_other','-DuECC_WORD_SIZE=4',*['-DuECC_SUPPORTS_'+n+'=0' for n in ('secp160r1','secp192r1','secp224r1','secp256k1')],'-DuECC_SUPPORT_COMPRESSED_POINT=0']
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build(debug):
    OUT.mkdir(parents=True,exist_ok=True);name='H1QQNativeDbg' if debug else 'H1QQNative';group=name.lower();common=SDK/'sdk/esp32/common';zlib=media.ROOT/'third_party/zlib-1.3.1';cjson=ROOT/'third_party/cjson'
    sources=[SRC/'core/core.c',SRC/'third_party/micro-ecc/uECC.c',SRC/'third_party/monocypher/monocypher.c']
    sources += [SRC/'platform'/n for n in ('identity.c','h1_inputs.c','h1_sign_clock.c','material_cache.c','refresh_policy.c','signer.c')]
    sources += [SRC/'net'/n for n in ('qq_crypto.c','qq_qr.c','qq_codec.c','qq_energy.c','qq_session.c','qq_business.c')]
    sources += sorted((SRC/'app').glob('*.c'))+[cjson/'cJSON.c']
    sources += [p for p in media.sources() if p.name not in {'aac.c','audio.c','font16.c','h1net_wire.c','h1net_client.c'}]
    sources += [common/n for n in ('h1net_wire.c','h1net_client.c','h1net_tcp.c')]
    sources += [zlib/(n+'.c') for n in ('adler32','crc32','inflate','inftrees','inffast','zutil','uncompr')]
    headers=list((SRC/'net').glob('*.h'))+list((SRC/'app').rglob('*.h'))+list((SRC/'platform').glob('*.h'))+[SRC/'third_party/monocypher/monocypher.h']
    identity=hashlib.sha256(''.join(digest(p) for p in sources+headers+[Path(__file__)]).encode()).hexdigest();build_id=int(identity[:8],16)
    flags=[*ECC,'-include',str(SRC/'app/paths.h'),*['-I'+str(p) for p in (SRC/'app',SRC/'net',SRC/'platform',SRC/'core',SRC/'third_party/monocypher',common,zlib,cjson)],'-DCJSON_NESTING_LIMIT=24','-Wall','-Wextra','-Werror','-Wno-misleading-indentation']
    if debug:flags+=['-DH1NET_DEBUG_TRANSPORT=1',f'-DH1NET_DBG_BUILD_ID=0x{build_id:08x}u']
    options={'libc.c':['-Wno-unused-parameter'],'uECC.c':['-Dasm=__asm__']}
    for n in ('adler32','crc32','inflate','inftrees','inffast','zutil','uncompr'):options[n+'.c']=['-Wno-parentheses']
    archive=media.compile_group(group,sources,flags,source_options=options)
    elf=OUT/(name+'.elf');raw=elf.with_suffix('.bin');linker=media.ROOT/'runtime/h1.ld'
    media.run([media.CC,*media.FLAGS,'-nostdlib','-Wl,--gc-sections','-Wl,--build-id=none','-Wl,-T,'+str(linker),'-Wl,-Map,'+str(elf.with_suffix('.map')),'-o',elf,'-Wl,--start-group',archive,*[media.BUILD/(n+'.a') for n in ('jpeg','png','zlib','libc')],'-lgcc','-Wl,--end-group'])
    objcopy=media.TC/('mipsel-none-elf-objcopy.exe' if os.name=='nt' else 'mipsel-none-elf-objcopy');media.run([objcopy,'-O','binary',elf,raw]);payload=raw.read_bytes();size=(PAYLOAD_OFFSET+len(payload)+3)&~3
    fields=HeaderFields(category=0x47,file_size_minus_4=size-4,payload_offset=PAYLOAD_OFFSET,resource_offset=RESOURCE_OFFSET,resource_sizes=RESOURCE_SIZES)
    icon=SRC/'app/assets/qq.png';assets=json.loads((icon.parent/'manifest.json').read_text());assert digest(icon)==assets['png_sha256'] and digest(icon.parent/assets['source_file'])==assets['source_sha256'] and digest(icon.parent/'qq_icon.h')==assets['header_sha256'] and digest(icon.parent/assets['prompt_file'])==assets['prompt_sha256']
    skin=SRC/'app/assets/skin2008';skin_meta=json.loads((skin/'manifest.json').read_text())
    for file,key in [('approved.png','approved_sha256'),('clouds-gpt.png','clouds_sha256'),('icons-gpt.png','icons_sha256'),('header.png','header_sha256'),('skin.h','skin_header_sha256')]:assert digest(skin/file)==skin_meta[key]
    small=SRC/'app/assets/font12';font_meta=json.loads((small/'manifest.json').read_text());assert digest(small/'font12_data.h')==font_meta['header_sha256'] and digest(ROOT/font_meta['source'])==font_meta['source_sha256'] and digest(SRC/'tools/build_small_font.py')==font_meta['generator_sha256']
    idle=SRC/'app/assets/idle2008';idle_meta=json.loads((idle/'manifest.json').read_text());assert digest(idle/'idle.h')==idle_meta['header_sha256'] and digest(ROOT/idle_meta['source'])==idle_meta['source_sha256'] and digest(SRC/'tools/pack_idle2008.py')==idle_meta['packer_sha256']
    login=SRC/'app/assets/login2008';login_meta=json.loads((login/'manifest.json').read_text());assert digest(login/'login.h')==login_meta['header_sha256'] and digest(login/login_meta['source'])==login_meta['source_sha256'] and digest(SRC/'tools/pack_login2008.py')==login_meta['packer_sha256']
    menu=SRC/'app/assets/menu2008';menu_meta=json.loads((menu/'manifest.json').read_text())
    for file,key in [('penguin-gpt.png','source_sha256'),('prompt.json','prompt_sha256'),('penguin20.png','png_sha256'),('menu.h','header_sha256')]:assert digest(menu/file)==menu_meta[key]
    assert digest(SRC/'tools/pack_menu2008.py')==menu_meta['packer_sha256']
    bda=elf.with_suffix('.bda');bda.write_bytes((encode_header(fields,title='QQ调试' if debug else 'QQ',build_time='2026-11-22 00:00:00')+build_icon_resources(icon)+payload).ljust(size,b'\0'));validation=validate_bda(bda);assert validation['ok']
    with elf.open('rb') as f:symbols={s.name:s['st_value'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols()}
    assert not [n for n in symbols if re.match(r'(uc_|tcg_|arm_image_|h1_jni_|cpu_exec)',n)]
    fingerprints={}
    for dependency in (group,'jpeg','png','zlib'):
        for stamp in (media.BUILD/dependency).glob('*.json'):
            for path,sha in json.loads(stamp.read_text())['inputs'].items():fingerprints[Path(path).relative_to(ROOT).as_posix()]=sha
    for p in [Path(__file__),linker,*sorted(p for p in (SRC/'app/assets').rglob('*') if p.is_file())]:fingerprints[p.relative_to(ROOT).as_posix()]=digest(p)
    report=dict(built=True,hardware_verified=False,actual_account_login=False,data_dir=r'A:\应用\数据\QQ',artifact=str(bda.relative_to(ROOT)),bytes=size,sha256=digest(bda),elf_sha256=digest(elf),source_sha256=fingerprints,transport='h1debug-mailbox' if debug else 'native-usb-to-esp-tcp',build_id=build_id,validation=validation,emulator_linked=False,symbols={n:v for n,v in symbols.items() if n in ('h1_app_main','qq_last_error','c','people','history','draft','self','busy','pending','notice','qr_width','qr_height')})
    if debug:report['debug_mailbox']=dict(address=symbols['h1net_debug_mailbox'],size=1120,magic=0x31445748,build_id=build_id,tx_offset=64,rx_offset=592,connection_tokens=True)
    (OUT/(name+'.build.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n');print('BUILT',name,size,'bytes; hardware not tested',flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--all',action='store_true');p.add_argument('--debug',action='store_true');p.add_argument('--out',type=Path);a=p.parse_args()
    if a.out:OUT=a.out.resolve()
    media.headers();media.libc();media.images()
    for debug in (False,True) if a.all else (a.debug,):build(debug)
