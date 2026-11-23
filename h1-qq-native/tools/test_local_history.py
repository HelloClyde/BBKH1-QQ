"""Real linked MIPS: encrypted journal, cold launches and clear-confirm UI."""
import ctypes,hashlib,json,struct,sys,time
from unittest.mock import patch
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE
from unicorn.mips_const import UC_MIPS_REG_A0,UC_MIPS_REG_A3,UC_MIPS_REG_PC,UC_MIPS_REG_RA,UC_MIPS_REG_V0
from PIL import Image
from test_session_resume import firmware
from test_client_model import mailbox,ClockedFirmware
from test_skin2008 import DelayedServer
from fake_qq_gateway import Gateway,sso_reply,pu,pb
from protocol_codec_fixture import Reader,decrypt
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[sys.argv.index('--out')+1]).resolve();DATA=r'A:\应用\数据\QQ'
ID=DATA+r'\H1QQ.ID';SES=DATA+r'\H1QQ.SES';JOURNAL=DATA+r'\H10001.MSG';OTHER=DATA+r'\H10002.MSG';AVATAR=DATA+r'\AVATAR\u99999.avt'
IDENTITY=0x81080000;MSG=0x81081000;CACHE=0x81082000;MESSAGES=0x81090000;PEOPLE=0x810a0000;KINDS=0x810e0000
class Message(ctypes.LittleEndianStructure):
    _fields_=[(n,ctypes.c_uint64) for n in ('sender','recipient','peer','uid')]+[(n,ctypes.c_uint32) for n in ('sequence','time','group')]+[('sender_name',ctypes.c_char*81),('text',ctypes.c_char*385),('random',ctypes.c_uint32),('flags',ctypes.c_uint32)]
class Person(ctypes.LittleEndianStructure):
    _fields_=[('id',ctypes.c_char*21),('name',ctypes.c_char*81),('nick',ctypes.c_char*81),('category',ctypes.c_uint32)]
class Category(ctypes.LittleEndianStructure):
    _fields_=[('id',ctypes.c_uint32),('count',ctypes.c_uint32),('online',ctypes.c_uint32),('name',ctypes.c_char*81)]
class People(ctypes.LittleEndianStructure):
    _fields_=[('items',Person*1024),('count',ctypes.c_uint32),('truncated',ctypes.c_uint32),('categories',Category*256),('category_count',ctypes.c_uint32)]
class QuietGateway(Gateway):
    """No message replay: restored UI content must come from the journal."""
    fail_groups=False
    def handle(self,packet):
        answer=super().handle(packet)
        command=self.calls[-1]
        if command=='MessageSvc.PbGetMsg':body=pu(1,0)+pb(3,b'fixture-cookie')+pu(4,2)
        elif command=='friendlist.GetTroopListReqV2' and self.fail_groups:body=b'invalid-jce'
        else:return answer
        r=Reader(packet[4:]);kind=r.word();crypt=r.take(1)[0]
        if kind==10:r.string()
        else:seq=r.word()
        r.take(1);r.string();h=Reader(decrypt(r.take(len(r.b)-r.p),self.d2key if crypt==1 else bytes(16)))
        if kind==10:h.word();seq=h.word()
        return sso_reply(command,seq,body,self.d2key)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class FaultFirmware(ClockedFirmware):
    short_write=False
    deny_delete=False
    def hook(self,kind):
        normal=super().hook(kind)
        if kind not in ('fwrite','remove'):return normal
        def call(u,*args):
            if kind=='fwrite' and self.short_write:
                self.handles[u.reg_read(UC_MIPS_REG_A3)][2].write(self.get(u.reg_read(UC_MIPS_REG_A0),17));value=17
            elif kind=='remove' and self.deny_delete:value=0xffffffff
            else:return normal(u,*args)
            u.reg_write(UC_MIPS_REG_V0,value);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
        return call
def direct(files,account=10001):
    with patch('test_session_resume.ClockedFirmware',FaultFirmware):m=firmware(files)
    m.owned_paths.update([JOURNAL,OTHER]);assert m.call('h1qq_h1_identity_open',IDENTITY)==1
    assert m.call('qq_local_bind',IDENTITY,0,account,0)==1;return m
def put_message(m,text,sequence,group=0,sender=10002,peer=10002,uid=0,flags=0,random=0):
    v=Message(sender=sender,recipient=10001 if sender!=10001 else peer,peer=peer,uid=uid,sequence=sequence,time=1795305600+sequence,group=group,sender_name='合成测试'.encode(),text=text.encode(),random=random,flags=flags)
    m.put(MSG,bytes(v));return m.call('qq_local_message',MSG)
def restored(m):
    count=m.call('qq_local_restore',CACHE,96);return [Message.from_buffer_copy(m.get(CACHE+i*ctypes.sizeof(Message),ctypes.sizeof(Message))) for i in range(count)]
def selected_texts(m,group,peer):
    m.call('qq_local_select',group,0,peer,0,CACHE,0,MESSAGES)
    n=struct.unpack('<I',m.get(MESSAGES+6000,4))[0];return [m.get(MESSAGES+i*500+81,385).split(b'\0')[0].decode() for i in range(n)]
class UI:
    def __init__(self,files):
        self.m=m=firmware(files,True);m.owned_paths.update([JOURNAL,OTHER]);self.g=QuietGateway();self.g.sent_push=True;self.bridge=None
        self.boundary=dict(armed=False,hit=False)
        with (OUT/'H1QQNativeDbg.elf').open('rb') as f:main_size=next(s['st_size'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols() if s.name=='h1_app_main')
        def loop(u,*_):
            if self.boundary['armed'] and m.symbols['h1_app_main']<=u.reg_read(UC_MIPS_REG_RA)<m.symbols['h1_app_main']+main_size:self.boundary.update(armed=False,hit=True);u.emu_stop()
        m.u.hook_add(UC_HOOK_CODE,loop,begin=m.symbols['qq_idle'],end=m.symbols['qq_idle'])
        self.meta=json.loads((OUT/'H1QQNativeDbg.build.json').read_text())
        self.until(lambda:m.get(self.meta['debug_mailbox']['address']+16,4)==b'\1\0\0\0')
        mailbox.ROOT=ROOT;self.bridge=mailbox.MailboxBridge(m,OUT/'H1QQNativeDbg.build.json');self.bridge.backend.close();self.bridge.server=DelayedServer(self.g);self.bridge.backend=self.bridge.server
        self.wait(lambda:m.word('list_loaded'))
    def until(self,pred):
        end=time.monotonic()+90
        while not pred():
            if time.monotonic()>end:raise TimeoutError('local history UI; busy='+str(self.m.word('busy'))+'; calls='+','.join(self.g.calls[-4:]))
            self.m.step()
            if self.bridge and self.m.pc!=self.m.stop and self.bridge.header()[4]==1:self.bridge.service()
    def wait(self,pred):
        while True:
            self.until(pred);self.boundary.update(armed=True,hit=False);self.until(lambda:self.boundary['hit'])
            if pred() and not self.m.word('busy') and not self.m.word('pending') and not self.m.word('dirty'):return
    def tap(self,x,y):
        self.m.events.extend([(11,0,x,y),(8,0,x,y)]);self.wait(lambda:not self.m.events and not self.m.word('pen_active'))
    def image(self,name):Image.frombytes('RGB',(480,272),self.m.get(self.m.fb,480*272*4),'raw','BGRX').save(OUT/('history-'+name+'.private.png'))
    def texts(self):
        n=struct.unpack('<I',self.m.get(self.m.symbols['history']+6000,4))[0]
        return [self.m.get(self.m.symbols['history']+i*500+81,385).split(b'\0')[0].decode() for i in range(n)]
    def close(self):
        self.m.allow_exit=True;self.m.events.extend([(11,0,464,10),(8,0,464,10)]);self.until(lambda:self.m.pc==self.m.stop)
        assert not self.m.handles and not self.m.allocations and not self.m.invalid
        return dict(self.m.files)
def main():
    assert ctypes.sizeof(Message)==520 and ctypes.sizeof(Person)==188
    fixture=OUT/'session-fixtures';initial={ID:(fixture/'identity.private.bin').read_bytes(),SES:(fixture/'session.private.bin').read_bytes(),AVATAR:b'untouched avatar',OTHER:b'other-account untouched'};checks=[]
    m=direct(initial)
    assert put_message(m,'相同文字',10,sender=10001,flags=3,random=10)
    assert put_message(m,'相同文字',11,sender=10001,flags=3,random=11)
    assert put_message(m,'相同文字',10,sender=10001,uid=1010,flags=2,random=10)
    assert put_message(m,'私聊持久化',12)
    assert put_message(m,'群聊持久化',13,group=1,sender=10003,peer=20001)
    for peer,name,kind in [(10002,'测试联系人',0),(20001,'H1 开发群',1)]:
        m.put(MSG,bytes(Person(id=str(peer).encode(),name=name.encode(),nick=b'Nick')));assert m.call('qq_local_touch',MSG,kind)
    raw=m.files[JOURNAL];assert len(raw)==7*640 and not any(t.encode() in raw for t in ('相同文字','私聊持久化','群聊持久化','测试联系人'))
    rows=restored(m);assert len(rows)==4 and sum(bytes(r.text).decode()=='相同文字' for r in rows)==2
    assert selected_texts(m,0,10002)==['相同文字','相同文字','私聊持久化'];checks.append('authenticated encrypted append records preserve identical sends and reconcile local ACK/server echo without duplicate rows')
    files=dict(m.files);m.call('qq_local_close');m=direct(files)
    assert len(restored(m))==4 and selected_texts(m,1,20001)==['群聊持久化']
    m.call('qq_local_recent',PEOPLE,KINDS);assert struct.unpack('<I',m.get(PEOPLE+1024*188,4))[0]==2 and m.get(KINDS,2)==bytes([1,0])
    checks.append('a fresh native process restores private/group records and recent peer kinds from disk')
    for i in range(100):assert put_message(m,'其他会话'+str(i),100+i,peer=99998)
    assert all(r.peer!=20001 for r in restored(m)) and selected_texts(m,1,20001)==['群聊持久化'];checks.append('quiet conversations remain on disk after eviction from the 96-message global RAM cache')
    good=m.files[JOURNAL];m.files[JOURNAL]=good+b'torn-tail'
    assert selected_texts(m,1,20001)==['群聊持久化'] and put_message(m,'尾部修复',300,group=1,sender=10003,peer=20001)
    assert m.files[JOURNAL][:len(good)]==good and len(m.files[JOURNAL])==len(good)+640;checks.append('short trailing record is ignored and the next aligned append repairs only the incomplete tail')
    saved=dict(m.files);m=direct(saved,10002);assert not restored(m)
    m.files[OTHER]=saved[JOURNAL];assert not restored(m) and m.call('qq_local_failed')
    m=direct(saved);m.put(IDENTITY+16,b'x'*32);m.call('qq_local_close');assert m.call('qq_local_bind',IDENTITY,0,10001,0) and not restored(m)
    m=direct(saved);damaged=bytearray(m.files[JOURNAL]);damaged[-1]^=1;m.files[JOURNAL]=bytes(damaged);assert '尾部修复' not in selected_texts(m,1,20001) and m.call('qq_local_failed')
    checks.append('wrong-account copies, wrong device key and modified ciphertext fail authentication without exposing records')
    m=direct(saved);prefix=m.files[JOURNAL]
    m.short_write=True;assert not put_message(m,'失败写入',301) and m.files[JOURNAL][:len(prefix)]==prefix and len(m.files[JOURNAL])==len(prefix)+17 and not m.handles
    m.short_write=False;assert put_message(m,'失败后重试',302) and len(m.files[JOURNAL])==len(prefix)+640;checks.append('real short-write syscall preserves old records, closes handles and permits a later complete append')
    m.deny_delete=True;assert not m.call('qq_local_clear') and JOURNAL in m.files;m.deny_delete=False
    untouched={p:m.files[p] for p in (SES,ID,AVATAR,OTHER)};assert m.call('qq_local_clear') and JOURNAL not in m.files and all(m.files[p]==v for p,v in untouched.items()) and m.call('qq_local_clear')
    checks.append('failed deletion is reported; successful clear removes only the current account journal and remains idempotent')
    # Two complete client processes use the records made above, including a
    # quiet group that is no longer represented by the RAM restore window.
    ui=UI(saved);assert ui.g.calls[0]=='StatSvc.register' and not any(c.startswith('wtlogin.') for c in ui.g.calls)
    ui.tap(126,98);assert ui.m.word('group')==2 and ui.m.word('row_count')==3;ui.image('recent-restored');ui.tap(75,149)
    assert ui.m.word('peer_group')==1 and '群聊持久化' in ui.texts();ui.image('restored-chat')
    def compose(u,*_):ui.m.put(u.reg_read(UC_MIPS_REG_A0),'持久发送'.encode()+b'\0');u.reg_write(UC_MIPS_REG_V0,1);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
    ui.m.u.hook_add(UC_HOOK_CODE,compose,begin=ui.m.symbols['qq_edit_text'],end=ui.m.symbols['qq_edit_text'])
    for _ in range(2):ui.tap(225,220);ui.tap(442,257)
    assert len(ui.g.sends)==2;files=ui.close();ui=UI(files);ui.tap(126,98);ui.tap(75,149)
    assert ui.texts().count('持久发送')==2 and '群聊持久化' in ui.texts();checks.append('complete cold client relaunch restores recent group, old disk-only messages and two identical acknowledged sends without a new scan')
    original=ui.m.files[JOURNAL];credentials=ui.m.files[SES];avatar=ui.m.files[AVATAR]
    ui.tap(20,257);ui.tap(30,204);assert ui.m.word('settings_open')==1;ui.image('settings');ui.tap(220,120);assert ui.m.word('settings_open')==2;ui.image('clear-confirm');ui.tap(175,176)
    assert ui.m.word('settings_open')==1 and ui.m.files[JOURNAL]==original;checks.append('actual touchscreen settings and clear confirmation cancel preserve every journal byte')
    ui.tap(220,120);ui.tap(302,176);assert not ui.m.word('settings_open') and JOURNAL not in ui.m.files and not ui.texts(),dict(settings=ui.m.word('settings_open'),journal_exists=JOURNAL in ui.m.files,message_count=len(ui.texts()),recent_file_modes=[x['mode'] for x in ui.m.file_calls if x['path']==JOURNAL][-8:],calls=ui.g.calls[-6:])
    assert ui.m.files[SES]==credentials and ui.m.files[AVATAR]==avatar and ui.m.files[OTHER]==initial[OTHER]
    assert ui.m.get(ui.m.symbols['people']+2*ctypes.sizeof(People)+People.count.offset,4)==b'\0'*4
    files=ui.close();ui=UI(files);ui.tap(126,98);assert ui.m.word('row_count')==0
    ui.g.fail_groups=True;ui.tap(75,98);assert not any(ui.m.get(ui.m.symbols['list_loading'],12)) and ui.m.get(ui.m.symbols['list_error']+4,4)==b'\1\0\0\0' and not ui.m.word('row_count');ui.image('list-load-failed')
    ui.g.fail_groups=False;ui.tap(434,10);assert ui.m.word('row_count')>0 and not any(ui.m.get(ui.m.symbols['list_error'],12));ui.tap(75,149);assert '群聊持久化' not in ui.texts() and '持久发送' not in ui.texts();ui.close()
    checks.append('confirmed clear empties current display and recent list across a cold relaunch while retaining login, avatars and the other account file')
    checks.append('failed initial group fetch stops loading and shows failure; explicit retry replaces it with real rows')
    report=dict(passed=True,physical_h1=False,live_qq=False,checks=checks,encrypted_records=True,record_bytes=640,elf_sha256=sha(OUT/'H1QQNative.elf'),debug_bda_sha256=json.loads((OUT/'H1QQNativeDbg.build.json').read_text())['sha256'],test_sha256=sha(Path(__file__)),peer_sha256=sha(ROOT/'h1-qq-native/tools/fake_qq_gateway.py'))
    (OUT/'local-history-mips.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n');print('PASS native MIPS local history:',len(checks),'flows')
if __name__=='__main__':main()
