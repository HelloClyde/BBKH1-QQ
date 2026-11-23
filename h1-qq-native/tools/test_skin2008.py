"""Drive actual touchscreen events through the linked MIPS QQ2008 interface."""
import hashlib,json,struct,sys,time
from pathlib import Path
from unittest.mock import patch
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_HOOK_CODE
from unicorn.mips_const import UC_CPU_MIPS32_4KC,UC_MIPS_REG_A0,UC_MIPS_REG_RA,UC_MIPS_REG_PC,UC_MIPS_REG_V0
from PIL import Image
from test_client_model import ClockedFirmware,mailbox
from fake_qq_gateway import Gateway,Server,sso_reply,message,pb
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[sys.argv.index('--out')+1]).resolve();DATA=r'A:\应用\数据\QQ'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class DelayedServer(Server):
    """Hold a real peer response until UI interaction has been observed."""
    hold_command=None
    def dispatch(self,frame):
        before=len(self.gateway.calls);reply=super().dispatch(frame)
        if len(self.gateway.calls)>before and self.hold_command==self.gateway.calls[-1]:
            assert not self.held and self.output
            self.held=bytes(self.output);self.total-=len(self.held);self.output.clear();self.hold_command=None
        return reply

def main():
    def cpu(*a,**kw):u=Uc(*a,**kw);u.ctl_set_cpu_model(UC_CPU_MIPS32_4KC);return u
    with patch('support.firmware.Uc',cpu):m=ClockedFirmware(OUT/'H1QQNativeDbg.elf')
    fixture=OUT/'session-fixtures'
    for kind,name in [('ID','identity'),('SES','session')]:m.files[DATA+'\\H1QQ.'+kind]=(fixture/(name+'.private.bin')).read_bytes()
    m.owned_paths.update(DATA+'\\H1QQ.'+s for s in ('ID','SES','LOG','QR','ERR','HAND'));m.directories.update([r'A:\应用',r'A:\应用\数据',DATA,DATA+r'\AVATAR']);m.u.mem_map(0x10003000,0x1000);m.put(0xb0003000,struct.pack('<II',1,1795305600))
    meta=json.loads((OUT/'H1QQNativeDbg.build.json').read_text());g=Gateway();g.friend_count=32;bridge=None;checks=[];boundary={'armed':False,'hit':False};edit_count={'compose':0,'search':0}
    with (OUT/'H1QQNativeDbg.elf').open('rb') as f:main_size=next(s['st_size'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols() if s.name=='h1_app_main')
    def loop(u,*_):
        if boundary['armed'] and m.symbols['h1_app_main']<=u.reg_read(UC_MIPS_REG_RA)<m.symbols['h1_app_main']+main_size:boundary.update(armed=False,hit=True);u.emu_stop()
    m.u.hook_add(UC_HOOK_CODE,loop,begin=m.symbols['qq_idle'],end=m.symbols['qq_idle'])
    def until(pred):
        end=time.monotonic()+75
        while not pred():
            if time.monotonic()>end:raise TimeoutError('UI wait; commands='+','.join(g.calls))
            m.step()
            if bridge and m.pc!=m.stop and bridge.header()[4]==1:bridge.service()
    def settle():boundary.update(armed=True,hit=False);until(lambda:boundary['hit'])
    def wait(pred):
        while True:
            until(pred);settle()
            if not m.word('dirty') and pred():return
    def tap(x,y):
        m.events.append((11,0,x,y));until(lambda:m.word('pen_active') and not m.events)
        m.events.append((8,0,x,y));wait(lambda:not m.events and not m.word('pen_active') and not m.word('pending') and not m.word('busy'))
    def local_tap(x,y):
        m.events.extend([(11,0,x,y),(8,0,x,y)])
        until(lambda:not m.events and not m.word('pen_active') and not m.word('dirty'))
    def screenshot(name):Image.frombytes('RGB',(480,272),m.get(m.fb,480*272*4),'raw','BGRX').save(OUT/('skin-'+name+'.png'))
    def idle_matches():
        expected=(ROOT/'h1-qq-native/app/assets/idle2008/idle.rgb565').read_bytes();actual=b''.join(m.get(m.symbols['pixels']+(y*480+154)*2,326*2) for y in range(22,272));assert actual==expected
    def editor(text):
        def run(u,*_):edit_count['compose' if text=='skin touch send' else 'search']+=1;m.put(u.reg_read(UC_MIPS_REG_A0),text.encode()+b'\0');u.reg_write(UC_MIPS_REG_V0,1);u.reg_write(UC_MIPS_REG_PC,u.reg_read(UC_MIPS_REG_RA))
        return run
    m.u.hook_add(UC_HOOK_CODE,editor('skin touch send'),begin=m.symbols['qq_edit_text'],end=m.symbols['qq_edit_text']);m.u.hook_add(UC_HOOK_CODE,editor('20001'),begin=m.symbols['qq_edit_search'],end=m.symbols['qq_edit_search'])
    until(lambda:m.get(meta['debug_mailbox']['address']+16,4)==b'\1\0\0\0');mailbox.ROOT=ROOT;bridge=mailbox.MailboxBridge(m,OUT/'H1QQNativeDbg.build.json');bridge.backend.close();bridge.server=DelayedServer(g);bridge.backend=bridge.server
    wait(lambda:m.word('list_loaded'));assert g.calls[0]=='StatSvc.register' and not any(c.startswith('wtlogin.') for c in g.calls);screenshot('friends');checks.append('fresh UI launch restores valid saved session without QR and paints the actual 480x272 screen')
    idle_matches();assert not m.word('selection_visible');tap(174,74);tap(230,220);tap(442,257);assert not any(edit_count.values()) and not m.word('peer_open') and m.word('group')==0;idle_matches();checks.append('idle pane matches approved packed artwork pixel-for-pixel; hidden chat controls have no active hitboxes')
    tap(146,236);assert m.word('first')==1 and not m.word('peer_open');tap(146,116);assert m.word('first')==0 and not m.word('peer_open');checks.append('visible scrollbar arrows scroll the list without opening a conversation')
    count=g.calls.count('friendlist.getFriendGroupList');stream=bridge.server.stream;frames=m.word('frames')
    bridge.server.hold_command='friendlist.getFriendGroupList';m.events.extend([(11,0,434,10),(8,0,434,10)])
    until(lambda:bridge.server.held and m.word('busy') and not m.word('background') and not m.word('dirty'))
    local_tap(434,10);local_tap(146,236);assert m.word('first')==1 and not m.word('pending')
    m.events.extend([(11,0,75,190),(12,0,75,155),(8,0,75,155)])
    until(lambda:not m.events and not m.word('pen_active') and not m.word('dirty'));first=m.word('first')
    assert first>=2 and m.word('frames')>frames and bridge.server.held and m.word('busy') and not m.word('qq_cancel')
    screenshot('manual-list-refresh');bridge.server.release_pull();wait(lambda:not m.word('busy'))
    assert m.word('first')==first and g.calls.count('friendlist.getFriendGroupList')==count+1 and bridge.server.stream==stream
    checks.append('manual contact refresh keeps touch scrolling and redraw live before a held reply; duplicate refresh taps coalesce and reading position survives')
    bridge.server.hold_command='friendlist.GetTroopListReqV2';m.events.extend([(11,0,75,98),(8,0,75,98)])
    until(lambda:bridge.server.held and m.word('group')==1 and m.get(m.symbols['list_loading']+4,4)==b'\1\0\0\0' and not m.word('dirty'))
    assert not m.word('row_count');screenshot('groups-loading');frames=m.word('frames')
    m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+180));until(lambda:m.word('frames')>frames and not m.word('dirty'))
    assert bridge.server.held and not m.word('row_count');bridge.server.release_pull();wait(lambda:not m.word('busy'))
    assert not any(m.get(m.symbols['list_loading'],12)) and m.word('row_count')>0
    checks.append('empty group tab immediately shows an animated loading state while the real reply is held, then replaces it with loaded rows')
    tap(75,149);assert m.word('peer_open') and m.word('peer_group')==1
    tap(225,220);assert m.string('draft')=='skin touch send';tap(442,257);assert len(g.sends)==1 and g.sends[0]['group'] and not m.string('draft');screenshot('chat');checks.append('new group tab, contact row, editor and send button work through real DOWN/UP coordinates')
    compose=edit_count['compose']
    for x in (174,209,244):tap(x,74)
    assert edit_count['compose']==compose and m.word('peer_open') and m.word('group')==1 and not m.word('pending')
    checks.append('removed chat toolbar has no hidden edit, refresh or recent-tab hitboxes')
    for i in range(8):bridge.server.publish(sso_reply('OnlinePush.PbPushGroupMsg',65400+i,pb(1,message(True,'刷新滑动'+str(i)+'：'+'多行聊天内容。'*8,3300+i)),g.d2key))
    m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+300))
    wait(lambda:'刷新滑动7'.encode() in m.get(m.symbols['history'],6000) and m.word('offset')>100)
    bottom=m.word('offset');bridge.server.hold_command='MessageSvc.PbGetMsg'
    m.put(m.symbols['clock_base'],struct.pack('<I',m.word('clock_base')+6000));m.events.extend([(11,0,434,10),(8,0,434,10)])
    until(lambda:bridge.server.held and m.word('busy') and not m.word('background') and not m.word('dirty'))
    m.events.extend([(11,0,360,68),(12,0,360,145),(8,0,360,145)])
    until(lambda:not m.events and not m.word('pen_active') and not m.word('dirty'));assert m.word('offset')<bottom and bridge.server.held and not m.word('qq_cancel')
    screenshot('manual-history-refresh');m.keys.append(41);until(lambda:not m.word('peer_open') and not m.word('dirty'));idle_matches()
    assert bridge.server.held and m.word('busy') and not m.word('qq_cancel') and bridge.server.stream==stream
    bridge.server.release_pull();wait(lambda:not m.word('busy'));idle_matches();assert not m.word('peer_open') and m.get(m.symbols['history']+6000,4)==b'\0'*4
    tap(75,149);assert m.word('peer_open')
    checks.append('manual history refresh keeps the enlarged upper message area draggable; Back restores idle before the reply without TCP cancellation or reviving the closed chat')
    before=sum(c.startswith('friendlist.') for c in g.calls);tap(126,98);assert m.word('group')==2 and m.word('row_count')==2;tap(75,149);assert m.word('peer_group')==1 and sum(c.startswith('friendlist.') for c in g.calls)==before;screenshot('recent');checks.append('recent tab opens the remembered group with correct peer type and no synthetic network list request')
    tap(20,257);assert m.word('menu_open');screenshot('menu');tap(30,180);assert not m.word('menu_open') and m.word('matched_count')==1;tap(141,74)
    assert not m.get(m.symbols['query']+2*65,65).split(b'\0')[0];checks.append('menu selection survives DOWN/UP; real native search and clear hitboxes work')
    m.keys.append(41);wait(lambda:not m.word('peer_open'));idle_matches();assert not m.word('selection_visible');screenshot('idle-return');tap(75,149);assert m.word('peer_open') and m.word('peer_group')==1;checks.append('back from chat restores the exact idle illustration and clears the stale selection highlight')
    m.keys.append(29);wait(lambda:bool(m.string('draft')));tap(464,10);assert not m.word('closing') and '草稿' in m.cstring(m.word('notice'));m.keys.append(38);wait(lambda:not m.string('draft'))
    # Explicit close exits from an open chat in one tap; preserves login file.
    m.allow_exit=True;m.events.extend([(11,0,464,10),(8,0,464,10)]);until(lambda:m.pc==m.stop);assert DATA+r'\H1QQ.SES' in m.files and not m.handles and not m.allocations and not m.invalid;checks.append('close protects an unsent draft; after clearing it, closes from chat and retains encrypted login')
    report=dict(passed=True,physical_h1=False,live_qq=False,checks=checks,debug_bda_sha256=meta['sha256'],test_sha256=sha(Path(__file__)),peer_sha256=sha(ROOT/'h1-qq-native/tools/fake_qq_gateway.py'),restore_fixture_sha256=sha(fixture/'session.private.bin'));(OUT/'skin-touch-mips.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n');print('PASS MIPS QQ2008 touchscreen:',len(checks),'flows')
if __name__=='__main__':main()
