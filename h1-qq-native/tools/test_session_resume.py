"""Fresh linked MIPS processes: QR -> encrypted file -> saved D2 register.
Offline peers exercise recovery; these checks cannot prove QQ server acceptance.
"""
import ctypes,hashlib,json,struct,sys,time
from pathlib import Path
from unittest.mock import patch
from unicorn import Uc,UC_HOOK_CODE
from unicorn.mips_const import UC_CPU_MIPS32_4KC,UC_MIPS_REG_A3,UC_MIPS_REG_PC,UC_MIPS_REG_RA,UC_MIPS_REG_V0
from test_client_model import ClockedFirmware,mailbox
from fake_qq_gateway import Gateway,Server,sso_reply,response,ji,js
from identity_format import make_record
from protocol_fixture import Account
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[sys.argv.index('--out')+1]).resolve();DATA=r'A:\应用\数据\QQ';SESSION=DATA+r'\H1QQ.SES';ID=DATA+r'\H1QQ.ID'

def cpu(*a,**kw):u=Uc(*a,**kw);u.ctl_set_cpu_model(UC_CPU_MIPS32_4KC);return u
def firmware(files,debug=False):
    with patch('support.firmware.Uc',cpu):m=ClockedFirmware(OUT/('H1QQNativeDbg.elf' if debug else 'H1QQNative.elf'))
    m.files.update(files);m.owned_paths.update([DATA+'\\H1QQ.'+s for s in ('ID','LOG','ERR','QR','HAND','SES')]);m.directories.update([r'A:\应用',r'A:\应用\数据',DATA,DATA+r'\AVATAR']);m.u.mem_map(0x10003000,0x1000);m.put(0xb0003000,struct.pack('<II',1,1795305600));return m

class Peer(Gateway):
    mode='normal'
    def handle(self,packet):
        before=len(self.calls);answer=super().handle(packet)
        if self.calls[before]=='StatSvc.register' and self.calls.count('StatSvc.register')==1:
            # Registration reply sequence is the first four bytes of the
            # decrypted SSO header. Parse with the independent peer decoder.
            from protocol_codec_fixture import Reader,decrypt
            r=Reader(packet[4:]);r.word();crypt=r.take(1)[0];r.string();r.take(1);r.string();h=Reader(decrypt(r.take(len(r.b)-r.p),self.d2key if crypt==1 else bytes(16)));h.word();seq=h.word()
            if self.mode=='reject':return sso_reply('StatSvc.register',seq,response(b'SvcRespRegister',ji(2,1)+js(3,b'expired fixture'),True),self.d2key)
            if self.mode=='kick':return sso_reply('StatSvc.register',seq,response(b'SvcRespRegister',ji(2,0)+js(3,b''),True),self.d2key)+sso_reply('MessageSvc.PushForceOffline',65001,b'',self.d2key)
        return answer

def run(files,mode='normal'):
    m=firmware(files,True);g=Peer();g.mode=mode;meta=json.loads((OUT/'H1QQNativeDbg.build.json').read_text());bridge=None
    def until(pred):
        end=time.monotonic()+75
        while not pred():
            if time.monotonic()>end:raise TimeoutError('MIPS session flow: '+mode+'; commands='+','.join(g.calls))
            try:m.step()
            except BaseException:
                pc=m.u.reg_read(UC_MIPS_REG_PC);symbol=min(((abs(v-pc),k) for k,v in m.symbols.items()))[1]
                (OUT/'session-model-failure.json').write_text(json.dumps(dict(pc=hex(pc),near=symbol,code=m.get(pc,32).hex(),invalid=m.invalid,commands=g.calls),indent=2)+'\n',encoding='utf-8',newline='\n')
                raise RuntimeError('MIPS session failure near '+symbol+' at '+hex(pc)+'; commands='+','.join(g.calls)) from None
            if bridge and m.pc!=m.stop and bridge.header()[4]==1:bridge.service()
    until(lambda:m.get(meta['debug_mailbox']['address']+16,4)==b'\1\0\0\0');mailbox.ROOT=ROOT;bridge=mailbox.MailboxBridge(m,OUT/'H1QQNativeDbg.build.json');bridge.backend.close();bridge.server=Server(g);bridge.backend=bridge.server
    if mode=='network':
        # Real transport EOF after receiving register request, before its reply.
        original=bridge.server.dispatch
        def dispatch(frame):
            answer=original(frame)
            if g.calls and g.calls[-1]=='StatSvc.register':bridge.server.output.clear();bridge.server.tcp_state=3
            return answer
        bridge.server.dispatch=dispatch
        until(lambda:bool(m.word('service_error')) or ('连接' in m.cstring(m.word('notice')) and not m.word('busy') and bool(g.calls)))
        assert m.files[SESSION]==files[SESSION] and 'wtlogin.trans_emp' not in g.calls
    else:
        until(lambda:m.word('list_loaded') and not m.word('busy') and not m.word('dirty'))
        assert m.get(m.symbols['self'],21).split(b'\0')[0]==b'10001' and SESSION in m.files
    m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop)
    assert not m.allocations and not m.handles and not m.invalid and not m.timer_running
    return m.files,g.calls

def main():
    checks=[];initial={ID:make_record(key=bytes(range(32)),clock_adjustment=0)}
    files,calls=run(initial);assert calls.count('wtlogin.login')==1;checks.append('QR success saves encrypted session; normal shutdown clears RAM and closes resources')
    fixture=OUT/'session-fixtures';fixture.mkdir(exist_ok=True);(fixture/'session.private.bin').write_bytes(files[SESSION]);(fixture/'identity.private.bin').write_bytes(files[ID])
    resumed,calls=run(files);assert calls[0]=='StatSvc.register' and not any(s.startswith('wtlogin.') for s in calls);assert files[SESSION]!=resumed[SESSION];checks.append('fresh process restores from file, registers and fetches friends without QR/keyrotate/login')
    for mode in ('reject','kick'):
        recovered,calls=run(files,mode);assert calls.count('StatSvc.register')==2 and calls.count('wtlogin.login')==1 and recovered[SESSION]!=files[SESSION];checks.append('saved session '+mode+' invalidates credentials and falls back to exactly one QR flow')
    _,calls=run(files,'network');checks.append('transport EOF during restore retains saved credentials and never starts QR')
    # Native loader rejects malformed or wrong-device files before any network.
    def load(data,key_change=False,uuid_change=False):
        m=firmware({ID:files[ID],SESSION:data});identity=0x81080000;account=0x81081000
        assert m.call('h1qq_h1_identity_open',identity)==1
        if key_change:m.put(identity+16,bytes([99])*32)
        if uuid_change:m.put(identity,bytes([99])*16)
        m.put(account,b'\xa5'*ctypes.sizeof(Account));ok=m.call('qq_saved_session_load',identity,account);raw=m.get(account,ctypes.sizeof(Account));assert not m.handles
        if not ok:assert not any(raw)
        return m,ok,identity,account,raw
    original=files[SESSION];m,ok,identity,account,raw=load(original);assert ok;acc=Account.from_buffer_copy(raw);assert acc.uin==10001 and acc.authenticated and not acc.registered and bytes(acc.d2key)==bytes(range(16,32));checks.append('actual native loader restores bounded account fields with registered reset')
    bad=[original[:-1],original+b'x',bytes(len(original)),original[:8]+b'\0'*4+original[12:]]
    for offset in (12,32,56,72):v=bytearray(original);v[offset]^=1;bad.append(bytes(v))
    for data in bad:assert not load(data)[1]
    assert not load(original,key_change=True)[1] and not load(original,uuid_change=True)[1];checks.append('ten corrupt/truncated/extra/wrong-key/wrong-device cases fail closed and erase output')
    # Filesystem short write is a real failing syscall, not a success fixture.
    def short(u,*_):u.reg_write(UC_MIPS_REG_V0,0);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
    m.u.hook_add(UC_HOOK_CODE,short,begin=0x80e20030,end=0x80e20030);assert not m.call('qq_saved_session_save',identity,account) and SESSION not in m.files and not m.handles;checks.append('short write removes partial session; no leaked file handle')
    report=dict(passed=True,physical_h1=False,live_qq=False,cpu='MIPS32 4Kc',checks=checks,test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),peer_sha256=hashlib.sha256((ROOT/'h1-qq-native/tools/fake_qq_gateway.py').read_bytes()).hexdigest(),elf_sha256=hashlib.sha256((OUT/'H1QQNative.elf').read_bytes()).hexdigest(),debug_bda_sha256=json.loads((OUT/'H1QQNativeDbg.build.json').read_text())['sha256']);(OUT/'session-resume-mips.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n');print('PASS fresh-process MIPS saved-login:',len(checks),'flows')
if __name__=='__main__':main()
