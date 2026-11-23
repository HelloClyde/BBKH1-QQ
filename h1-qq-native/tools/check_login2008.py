"""Actual MIPS QR composition, phase changes, refresh and cancellation."""
import hashlib,io,json,struct,sys,time
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from unicorn import Uc
from unicorn.mips_const import UC_CPU_MIPS32_4KC
from test_client_model import ClockedFirmware,mailbox
from test_session_resume import firmware
from fake_qq_gateway import Gateway,Server
from identity_format import make_record
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[sys.argv.index('--out')+1]).resolve();sys.path.insert(0,str(ROOT/'.tools/qr-decoder'));import zxingcpp
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    def cpu(*a,**kw):u=Uc(*a,**kw);u.ctl_set_cpu_model(UC_CPU_MIPS32_4KC);return u
    with patch('support.firmware.Uc',cpu):m=ClockedFirmware(OUT/'H1QQNative.elf')
    assert m.call('open_gui');png=(ROOT/'tests/fixtures/qr.png').read_bytes();base=0x81080000;m.put(base,png);m.put(base+18000,b'state\0')
    def image_of(model):return Image.frombytes('RGB',(480,272),model.get(model.fb,480*272*4),'raw','BGRX')
    def show(phase,data=b''):
        if data:m.put(base,data)
        return m.call('qq_login_display',phase,base if data else 0,len(data),base+18000)
    def qr_pixels():
        w,h=m.word('qr_width'),m.word('qr_height');x,y=316-w//2,140-h//2
        return w,h,x,y,b''.join(m.get(m.symbols['pixels']+((y+j)*480+x)*2,w*2) for j in range(h))
    assert show(2,png);w,h,x,y,pixels=qr_pixels();assert w==h==135
    source=zxingcpp.read_barcode(Image.open(io.BytesIO(png)));display=zxingcpp.read_barcode(image_of(m).crop((x-6,y-6,x+w+6,y+h+6)));assert source and display and source.text==display.text
    image_of(m).save(OUT/'login-qr.private.png')
    for py in range(y-6,y+h+6):
        for px in range(x-6,x+w+6):
            if px<x or px>=x+w or py<y or py>=y+h:assert m.get(m.symbols['pixels']+(py*480+px)*2,2)==b'\xff\xff'
    assert show(3) and qr_pixels()[-1]==pixels and m.word('qr_width')==135;image_of(m).save(OUT/'login-confirm.private.png')
    assert show(4) and not m.word('qr_width');image_of(m).save(OUT/'login-auth.png')
    pattern=Image.new('1',(160,160));pattern.putdata([((x//5+y//5)&1) for y in range(160) for x in range(160)]);buffer=io.BytesIO();pattern.save(buffer,'PNG');assert show(2,buffer.getvalue());w,h,x,y,pixels=qr_pixels();assert w==h==160 and (x-6,y-6,x+w+6,y+h+6)==(230,54,402,226)
    assert y-6>=50 and y+h+6<=230 and x-6>=226 and x+w+6<=406;image_of(m).save(OUT/'login-max-160.png')
    assert show(1) and not m.word('qr_width');assert show(2,b'bad')==0 and not m.word('qr_width');m.call('close_gui');m.call('h1ns_heap_release');assert not m.handles and not m.allocations and not m.invalid
    checks=['real native4 QR decodes from actual framebuffer with unchanged payload and six-pixel white border','confirmation updates status while retaining the same QR pixels','login phase clears stale QR; 160px output fits card without touching title/status','malformed image rejected without leaked image memory']
    # Start a fresh complete app with a waiting synthetic server, then drive
    # real touch/keyboard input. No simulated success is written into app RAM.
    data_dir=r'A:\应用\数据\QQ';m=firmware({data_dir+r'\H1QQ.ID':make_record(key=bytes(range(32)),clock_adjustment=0)},True);g=Gateway();g.qr_status=0x30;bridge=None;meta=json.loads((OUT/'H1QQNativeDbg.build.json').read_text())
    def until(pred):
        end=time.monotonic()+90
        while not pred():
            if time.monotonic()>end:raise TimeoutError('QR UI: '+','.join(g.calls))
            m.step()
            if bridge and m.pc!=m.stop and bridge.header()[4]==1:bridge.service()
    until(lambda:m.get(meta['debug_mailbox']['address']+16,4)==b'\1\0\0\0');mailbox.ROOT=ROOT;bridge=mailbox.MailboxBridge(m,OUT/'H1QQNativeDbg.build.json');bridge.backend.close();bridge.server=Server(g);bridge.backend=bridge.server
    until(lambda:g.queries>=1);assert m.word('login_phase')==2 and m.word('qr_width')==135
    m.events.extend([(11,0,346,247),(8,0,346,247)]);until(lambda:g.fetches==2 and g.qr_queries>=1);assert m.word('login_phase')==2 and m.word('qr_width')==135 and not m.word('qq_cancel');checks.append('refresh touch fetches a fresh QR/ECDH session without cancelling login or registering account')
    queries=g.qr_queries;g.qr_status=0x35;until(lambda:g.qr_queries>=queries+2);assert m.word('login_phase')==3 and m.word('qr_width')==135
    g.qr_status=0x30;m.keys.append(4);until(lambda:g.fetches==3 and g.qr_queries>=1);assert m.word('login_phase')==2 and not m.word('qq_cancel');checks.append('confirmed state retains code; keyboard R also restarts QR fetch with reset sequence')
    # H1_KEY_R is verified against SDK input.h; cancellation must exit once.
    m.allow_exit=True;m.events.extend([(11,0,464,10),(8,0,464,10)]);until(lambda:m.pc==m.stop);assert not m.allocations and not m.handles and not m.invalid and 'wtlogin.login' not in g.calls and 'StatSvc.register' not in g.calls;checks.append('close while waiting exits once, releases resources and never authenticates the synthetic account')
    proof=dict(passed=True,physical_h1=False,live_qq=False,checks=checks,qr_fetches=g.fetches,qr_queries=g.queries,same_real_qr_payload=True,elf_sha256=sha(OUT/'H1QQNative.elf'),debug_bda_sha256=meta['sha256'],test_sha256=sha(Path(__file__)),peer_sha256=sha(ROOT/'h1-qq-native/tools/fake_qq_gateway.py'));(OUT/'login-ui-mips.json').write_text(json.dumps(proof,indent=2)+'\n',encoding='utf-8',newline='\n');print('PASS MIPS login UI:',len(checks),'checks; real QR composition, refresh and cancellation')
if __name__=='__main__':main()
