"""Full linked MIPS BDA + offline QQ/ESP peers, including user-driven text send."""
import hashlib,json,struct,sys,time
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_HOOK_CODE
from unicorn.mips_const import UC_CPU_MIPS32_4KC,UC_MIPS_REG_A0,UC_MIPS_REG_A1,UC_MIPS_REG_PC,UC_MIPS_REG_RA,UC_MIPS_REG_V0
from fake_qq_gateway import Gateway,Server,TEXT,GROUP_TEXT
from identity_format import make_record,parse_record
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[sys.argv.index('--out')+1]).resolve() if '--out' in sys.argv else ROOT/'build/h1-qq-native/client';MODEL=OUT/'model';sys.path.insert(0,str(ROOT/'tests'))
from support.firmware import FirmwareModel
from support import mailbox

class ClockedFirmware(FirmwareModel):
    """Explicit firmware time inputs; host emulation/render speed is not H1 time."""
    logical_ms=0
    timer_model_origin=0
    quantum_deadline=None
    def step(self):
        # The fake ESP is serviced between CPU slices. Repeated firmware polls
        # within one slice must not invent seconds of network reply latency.
        self.quantum_deadline=self.logical_ms+20
        return super().step()
    def hook(self,kind):
        if kind=='mkdir':
            def mkdir(u,*_):
                path=self.cstring(u.reg_read(UC_MIPS_REG_A0),'gbk');assert path in (r'A:\应用',r'A:\应用\数据',r'A:\应用\数据\QQ',r'A:\应用\数据\QQ\AVATAR');self.directories.add(path);self.mkdir_calls.append(path);u.reg_write(UC_MIPS_REG_V0,0);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
            return mkdir
        if kind not in ('start','stop','time','raw-time','delay'):return super().hook(kind)
        def run(u,*_):
            value=0
            if kind=='start':self.timer_model_origin=self.logical_ms;self.timer_frozen=0;self.timer_running=True
            elif kind=='stop':self.timer_frozen=self.logical_ms-self.timer_model_origin;self.timer_running=False
            elif kind=='time':value=self.logical_ms-self.timer_model_origin if self.timer_running else self.timer_frozen
            elif kind=='raw-time':value=self.logical_ms*80//1000
            else:
                advanced=self.logical_ms+u.reg_read(UC_MIPS_REG_A0)
                self.logical_ms=min(advanced,self.quantum_deadline) if self.quantum_deadline is not None else advanced
            u.reg_write(UC_MIPS_REG_V0,value);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
        return run
def main():
    MODEL.mkdir(parents=True,exist_ok=True);path=OUT/'H1QQNativeDbg.build.json';meta=json.loads(path.read_text());elf=OUT/'H1QQNativeDbg.elf';assert hashlib.sha256(elf.read_bytes()).hexdigest()==meta['elf_sha256']
    def cpu(*args,**kw):u=Uc(*args,**kw);u.ctl_set_cpu_model(UC_CPU_MIPS32_4KC);return u
    with patch('support.firmware.Uc',cpu):m=ClockedFirmware(elf)
    data_dir=r'A:\应用\数据\QQ'
    with elf.open('rb') as f:main_size=next(s['st_size'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols() if s.name=='h1_app_main')
    boundary={'armed':False,'hit':False}
    def loop_boundary(u,*_):
        caller=u.reg_read(UC_MIPS_REG_RA)
        if boundary['armed'] and m.symbols['h1_app_main']<=caller<m.symbols['h1_app_main']+main_size:boundary.update(armed=False,hit=True);u.emu_stop()
    m.u.hook_add(UC_HOOK_CODE,loop_boundary,begin=m.symbols['qq_idle'],end=m.symbols['qq_idle'])
    m.files[r'A:\H1QQ.ID']=make_record(key=bytes(range(32)),clock_adjustment=0);m.u.mem_map(0x10003000,0x1000);m.put(0xb0003000,struct.pack('<II',1,1795305600));gateway=Gateway();bridge=None;checks=[];rejection='--login-rejected' in sys.argv;gateway.reject_login=rejection;qr_rejected='--qr-rejected' in sys.argv;gateway.bad_qr=qr_rejected
    m.files[r'A:\H1QQ.HAND']=b'1';m.owned_paths.add(r'A:\H1QQ.HAND')
    m.owned_paths.update([r'A:\H1QQ.ID',*[data_dir+'\\H1QQ.'+s for s in ('ID','LOG','ERR','QR','HAND','SES')]])
    navigation='--navigation' in sys.argv;interaction='--interaction' in sys.argv
    if navigation or interaction:gateway.friend_count=32
    if interaction:gateway.group_count=16
    report=dict(passed=False,physical_h1=False,physical_esp32=False,live_qq=False,synthetic_account=True,clock='explicit firmware time input, not a performance measurement',checks=checks,debug_bda_sha256=meta['sha256'])
    def notice():return m.cstring(m.word('notice'))
    def until(predicate,timeout=45):
        end=time.monotonic()+timeout
        while not predicate():
            if time.monotonic()>end:raise TimeoutError(f'notice={notice()!r}; error={m.string("qq_last_error")!r}; busy={m.word("busy")}; calls={gateway.calls[-5:]}')
            m.step()
            if bridge and m.pc!=m.stop:
                if bridge.header()[4]==1:bridge.service()
                else:assert m.allow_exit,'Application transport closed unexpectedly'
    def settle():boundary.update(armed=True,hit=False);until(lambda:boundary['hit'])
    def wait(predicate):
        while True:
            until(predicate);settle()
            if not m.word('dirty') and predicate():return
    def key(value,predicate):m.keys.append(value);wait(lambda:not m.keys and not m.word('pending') and predicate())
    def history(s):return s.encode() in m.get(m.symbols['history'],6004)
    def screenshot(name):
        image=Image.frombytes('RGB',(480,272),m.get(m.fb,480*272*4),'raw','BGRX');image.save(MODEL/name);return image
    inputs=[TEXT,GROUP_TEXT]
    search_inputs=['nIcK','另一','10002','没有此用户','', '20001','']
    def edit(u,*_):
        assert not m.drawing and not m.timer_running;data=inputs.pop(0).encode()+b'\0';assert len(data)<=u.reg_read(UC_MIPS_REG_A1);m.put(u.reg_read(UC_MIPS_REG_A0),data);u.reg_write(UC_MIPS_REG_V0,1);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
    m.u.hook_add(UC_HOOK_CODE,edit,begin=m.symbols['qq_edit_text'],end=m.symbols['qq_edit_text'])
    def search_edit(u,*_):
        assert not m.drawing and not m.timer_running;data=search_inputs.pop(0).encode()+b'\0';assert len(data)<=u.reg_read(UC_MIPS_REG_A1);m.put(u.reg_read(UC_MIPS_REG_A0),data);u.reg_write(UC_MIPS_REG_V0,1);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
    m.u.hook_add(UC_HOOK_CODE,search_edit,begin=m.symbols['qq_edit_search'],end=m.symbols['qq_edit_search'])
    try:
        until(lambda:m.word('qq_usb_handoff')==1);assert r'A:\H1QQ.HAND' not in m.files;m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+13000));checks.append('one-shot USB handoff marker consumed before transport acquisition')
        until(lambda:m.get(meta['debug_mailbox']['address']+16,4)==b'\1\0\0\0');mailbox.ROOT=ROOT;bridge=mailbox.MailboxBridge(m,path);bridge.backend.close();bridge.server=Server(gateway);bridge.backend=bridge.server
        bridge.server.hold_next_pull=navigation
        if qr_rejected:
            wait(lambda:'二维码图像无法显示' in notice());assert gateway.calls==['wtlogin.trans_emp'] and not gateway.queries and not gateway.signed
            private=m.files[data_dir+r'\H1QQ.QR'];assert private[:8]==b'H1QQIMG1';seconds,n=struct.unpack('>2I',private[8:16]);assert n==len(private)-16 and f'utc={seconds}\n'.encode() in m.files[data_dir+r'\H1QQ.LOG'];assert b'authenticated=0' in m.files[data_dir+r'\H1QQ.LOG'];checks.append('invalid QR fails immediately, private image snapshot saved, no polling or account request')
            m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop);assert not m.allocations and not m.handles and not m.invalid
            report.update(passed=True,cpu='MIPS32 4Kc',calls=gateway.calls,qr_rejection=True,debugger_runtime_linked=False);print('PASS native MIPS QR rejection diagnostic');return
        if rejection:
            wait(lambda:'测试拒绝说明' in notice());assert '登录提示' in notice();assert 'StatSvc.register' not in gateway.calls
            private=m.files[data_dir+r'\H1QQ.ERR'];assert private[:8]==b'H1QQERR1';seconds,code,n,mode=struct.unpack('>4I',private[8:24]);report['rejection_header']=[seconds,code,n,mode];assert f'utc={seconds}\n'.encode() in m.files[data_dir+r'\H1QQ.LOG'] and code==45 and n==len(private)-24 and mode==1 and '测试拒绝说明'.encode() in private[24:]
            assert b'authenticated=0' in m.files[data_dir+r'\H1QQ.LOG'];screenshot('login-rejected.png');checks.append('45/T146 shown, private rejection snapshot correlated, no account authentication or register')
            m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop);assert not m.allocations and not m.handles and not m.invalid
            report.update(passed=True,cpu='MIPS32 4Kc',calls=gateway.calls,rejection_code=45,credential_unwrap_mode=1,debugger_runtime_linked=False);print('PASS native MIPS login rejection diagnostic');return
        until(lambda:gateway.queries>=1 and m.word('qr_width')>0);screenshot('login.png')
        loaded=lambda:'friendlist.getFriendGroupList' in gateway.calls and m.word('list_loaded')
        if navigation:until(lambda:loaded() and bridge.server.held and not m.word('dirty'))
        else:wait(loaded)
        assert m.get(m.symbols['self'],21).split(b'\0')[0]==b'10001';identity=parse_record(m.files[data_dir+r'\H1QQ.ID']);assert identity['session']==1 and identity['key']==bytes(range(32)) and r'A:\H1QQ.ID' not in m.files;screenshot('friends.png');checks.append('native QR handshake, confirmation, signed login, tickets, register, compressed friend list; legacy identity migrated byte-exact before session update')
        if navigation:
            m.events.extend([(11,0,146,236),(8,0,146,236)]);until(lambda:not m.events and m.word('first')==1)
            assert bridge.server.held and m.word('busy') and not m.word('pending') and not m.word('qq_cancel') and not [x for x in bridge.server.trace if x['opcode']==33];report['scrollbar_responded_during_pull']=True;checks.append('scrollbar reacts immediately while a background pull remains pending')
            until(lambda:bool(bridge.server.held));stream=bridge.server.stream;m.keys.extend([22,22,22]);until(lambda:not m.keys and (any(x['opcode']==33 for x in bridge.server.trace) or m.word('selected')>=15));report.update(cancel_on_paging=m.word('qq_cancel'),selected_during_pull=m.word('selected'),tcp_closes=sum(x['opcode']==33 for x in bridge.server.trace))
            assert not report['tcp_closes'],'Paging must not close the TCP stream while a background request is pending'
            assert m.word('selected')>=15 and m.word('busy') and not [x for x in bridge.server.trace if x['opcode']==33]
            bridge.server.release_pull();wait(lambda:gateway.acks>0);assert bridge.server.stream==stream and gateway.calls.count('StatSvc.register')==1;screenshot('navigation-poll.png');checks.append('paging during delayed pull retains TCP, registration and visible selection')
            def advance(ms):settle();m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+ms))
            def log():return dict(x.split('=',1) for x in m.files[data_dir+r'\H1QQ.LOG'].decode().splitlines()[1:])
            selection=m.word('selected');bridge.server.drop_next_pull=True;advance(6000);wait(lambda:log().get('background_failure_count')=='1')
            assert log()['cancel_reset_count']=='0' and log()['last_reset_reason']=='3' and m.word('selected')==selection
            before=len(gateway.calls);advance(5000);key(27,lambda:m.word('selected')==selection+1);assert len(gateway.calls)==before
            advance(6000);wait(lambda:gateway.calls.count('StatSvc.register')==2 and gateway.acks>=2);assert gateway.queries==2 and gateway.calls.count('wtlogin.login')==1 and m.word('selected')==selection+1 and '注册' not in notice();screenshot('navigation-recovered.png');checks.append('genuine TCP EOF waits for backoff, re-registers tickets, retains list/selection and restores online UI')
            gateway.bad_pull=True;advance(6000);wait(lambda:log().get('background_failure_count')=='2');before=len(gateway.calls);stream=bridge.server.stream;advance(5000);key(37,lambda:m.word('selected')==selection);assert len(gateway.calls)==before
            advance(6000);wait(lambda:gateway.acks>=3);assert bridge.server.stream==stream and gateway.calls.count('StatSvc.register')==2 and log()['cancel_reset_count']=='0';checks.append('malformed background pull is throttled; local navigation continues without TCP reset')
            m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop);assert not m.allocations and not m.handles and not m.invalid
            report.update(passed=True,cpu='MIPS32 4Kc',calls=gateway.calls,debugger_runtime_linked=False);print('PASS native MIPS background navigation');return
        if interaction:
            from fake_qq_gateway import sso_reply,message,pb
            def advance(ms):settle();m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+ms))
            def position(x,y):m.put(0x81090000,struct.pack('<2H',x,y))
            def down(x,y):m.events.append((11,0,x,y));until(lambda:m.word('pen_active') and not m.events)
            def up(x,y):m.events.append((8,0,x,y));until(lambda:not m.word('pen_active') and not m.events);wait(lambda:not m.word('pending'))
            # Deliberately emit no MOVE event: V1.41 coordinates must be polled.
            down(80,198);position(80,115);advance(20);until(lambda:m.word('first')>=3);assert m.word('pen_drag') and not m.word('peer_open');up(80,115);assert not m.word('peer_open');screenshot('friend-swipe.png')
            key(2,lambda:m.word('group')==1 and m.word('row_count')==18);down(80,198);position(80,115);advance(20);until(lambda:m.word('first')>=3);up(80,115);assert not m.word('peer_open');screenshot('group-swipe.png');checks.append('friends and group lists drag without MOVE events, with no accidental conversation opening')
            key(15,lambda:m.word('selected')==0);key(27,lambda:m.word('selected')==1);key(25,lambda:m.word('peer_open') and not m.word('list_focus'))
            before=len(gateway.signed);frame=sso_reply('OnlinePush.PbPushGroupMsg',65101,pb(1,message(True,'晚到的群消息',3001)),gateway.d2key)
            delivered=bridge.server.delivered;bridge.server.publish(frame[:2]);advance(300);until(lambda:bridge.server.delivered>=delivered+2);bridge.server.publish(frame[2:]);advance(300);wait(lambda:history('晚到的群消息'));assert len(gateway.signed)==before;screenshot('group-live-refresh.png');checks.append('late fragmented unsolicited group push appears automatically without a key, refresh request or new signature')
            for i in range(8):bridge.server.publish(sso_reply('OnlinePush.PbPushGroupMsg',65200+i,pb(1,message(True,'滑动记录'+str(i)+'：'+'这是多行内容。'*8,3100+i)),gateway.d2key))
            advance(300);wait(lambda:history('滑动记录7'));bottom=m.word('offset');assert bottom>147
            down(360,100);position(360,175);advance(20);until(lambda:m.word('offset')<bottom);up(360,175);older=m.word('offset');screenshot('history-swipe.png')
            bridge.server.publish(sso_reply('OnlinePush.PbPushGroupMsg',65300,pb(1,message(True,'翻看旧记录时的新消息',3200)),gateway.d2key));advance(300);wait(lambda:history('翻看旧记录时的新消息'));assert m.word('offset')==older;checks.append('history drag uses calibrated coordinate polling; new group messages preserve the scrolled reading position')
            def avatar_ready(kind,identifier):
                base=0x81080000;m.put(base,identifier.encode()+b'\0');return m.call('qq_avatar_peek',kind,base,base+64,base+68,base+72)==1
            until(lambda:avatar_ready(1,'20001') and avatar_ready(0,'10001'),timeout=60);wait(lambda:True);screenshot('loaded-avatars.png');assert any('/gh/' in u for u in bridge.server.avatar_requests) and any('thirdqq.qlogo.cn' in u for u in bridge.server.avatar_requests);assert gateway.calls.count('StatSvc.register')==1;checks.append('real compiled MIPS JPEG and PNG avatar downloads coexist with QQ TCP and render from cache')
            cached=OUT/'avatar-cache-fixtures';cached.mkdir(exist_ok=True);cache_records=[]
            for path,data in m.files.items():
                if path.startswith(data_dir+'\\AVATAR\\') and path.endswith('.avt'):
                    name=path.rsplit('\\',1)[-1];(cached/name).write_bytes(data);cache_records.append({'name':name,'sha256':hashlib.sha256(data).hexdigest()})
            assert {'u10001.avt','g20001.avt'}<=set(x['name'] for x in cache_records);(cached/'manifest.json').write_text(json.dumps(cache_records,indent=2)+'\n',encoding='utf-8',newline='\n');report['persistent_avatar_records']=len(cache_records)
            key(24,lambda:not m.word('peer_open'));m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop);assert not m.allocations and not m.handles and not m.invalid;checks.append('avatar jobs and image allocations cleanly release on application exit')
            report.update(passed=True,cpu='MIPS32 4Kc',calls=gateway.calls,avatar_requests=len(bridge.server.avatar_requests),http_releases=bridge.server.http_releases,debugger_runtime_linked=False);print('PASS MIPS live group refresh, three swipe surfaces and native avatars');return
        # Exercise actual accordion and search actions in the linked application.
        assert m.word('row_count')==4 and m.word('selected')==1
        before=gateway.calls.count('friendlist.getFriendGroupList');key(37,lambda:m.word('selected')==0);key(25,lambda:m.word('row_count')==3);screenshot('friends-folded.png');key(25,lambda:m.word('row_count')==4);assert gateway.calls.count('friendlist.getFriendGroupList')==before and gateway.calls.count('StatSvc.register')==1
        for expected in (1,1,1,0,2):
            key(11,lambda:m.word('matched_count')==expected);assert m.word('list_focus');assert not m.string('draft')
            if expected==0:assert not m.word('row_count');screenshot('search-empty.png')
            elif search_inputs and search_inputs[0]=='另一':screenshot('search-nickname.png')
        assert m.word('selected')==1;checks.append('real friend folders fold locally; search remark, nickname, number, no-result and clear through firmware input boundary')
        key(25,lambda:history('你好，H1！'));screenshot('private-chat.png');checks.append('native private pull, cookie, receipt ACK, text decoding')
        key(29,lambda:m.string('draft')==TEXT);gateway.deny=True;key(25,lambda:'拒绝请求' in notice());assert m.string('draft')==TEXT and not gateway.sends
        key(2,lambda:'friendlist.GetTroopListReqV2' in gateway.calls);key(25,lambda:'草稿' in notice());assert m.string('draft')==TEXT and not gateway.sends
        gateway.deny=False;key(35,lambda:not m.word('list_focus'));key(25,lambda:len(gateway.sends)==1 and not m.string('draft'));assert gateway.sends[0]['text']==TEXT;checks.append('reject preserves draft, peer guard, literal private text, signed send and ACK')
        key(40,lambda:m.word('list_focus'));screenshot('groups.png');key(11,lambda:m.word('matched_count')==1);screenshot('group-search.png');key(11,lambda:m.word('row_count')==3);assert not search_inputs;checks.append('group owner categories, independent group-number search and clear')
        key(25,lambda:history('群里的问候'));key(29,lambda:m.string('draft')==GROUP_TEXT);key(25,lambda:len(gateway.sends)==2 and not m.string('draft'));assert gateway.sends[1]['group'] and gateway.sends[1]['text']==GROUP_TEXT;screenshot('group-chat.png');checks.append('group list, asynchronous group push, group text send')
        # Fast-forward the legal time input; run the actual heartbeat, no sleep.
        base=m.word('clock_base');m.put(m.symbols['clock_base'],struct.pack('<I',base+31000));wait(lambda:'Heartbeat.Alive' in gateway.calls);checks.append('unencrypted heartbeat header and account connection retained')
        assert gateway.acks and gateway.queries==2 and len(gateway.signed)>=4 and not inputs
        key(24,lambda:not m.word('peer_open'));m.allow_exit=True;m.keys.append(24);until(lambda:m.pc==m.stop)
        assert not m.drawing and not m.timer_running and not m.allocations and not m.handles and not m.invalid
        with elf.open('rb') as f:state_size=next(s['st_size'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols() if s.name=='c')
        assert not any(m.get(m.symbols['c'],state_size)) and not any(m.get(m.symbols['draft'],385));assert b'authenticated=1' in m.files[data_dir+r'\H1QQ.LOG'] and b'sent_acks=2' in m.files[data_dir+r'\H1QQ.LOG'];checks.append('normal exit clears all session state and retains closed diagnostic snapshot')
        report.update(passed=True,cpu='MIPS32 4Kc',calls=gateway.calls,sends=gateway.sends,receipt_acks=gateway.acks,signed_commands=gateway.signed,minimum_stack=m.minimum_stack,debugger_runtime_linked=False)
    except BaseException as e:report.update(error=repr(e),calls=gateway.calls,notice=notice(),qq_error=m.string('qq_last_error'),tcp_closes=sum(x['opcode']==33 for x in bridge.server.trace) if bridge else None);raise
    finally:
        report['test_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();report['peer_sha256']=hashlib.sha256((Path(__file__).parent/'fake_qq_gateway.py').read_bytes()).hexdigest();report['qr_png_sha256']=hashlib.sha256((ROOT/'tests/fixtures/qr.png').read_bytes()).hexdigest();(MODEL/('navigation.json' if navigation else 'interaction.json' if interaction else 'qr-rejection.json' if qr_rejected else 'rejection.json' if rejection else 'report.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS full native MIPS application:',len(checks),'flows; offline synthetic QQ/ESP peers')
if __name__=='__main__':main()
