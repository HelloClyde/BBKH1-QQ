"""Offline protocol peer for the MIPS application. Never accesses actual QQ.
The fixture confirms a synthetic account; this is not login-server acceptance.
"""
import hashlib,io,json,struct,sys,zlib
from PIL import Image
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from protocol_fixture import pu,pb,ji,js,jb,jm,jl,st,response,records
from protocol_codec_fixture import encrypt,decrypt,Reader,u16,u32,short,long,tlv
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tests'));from support import http_peer as wire
UIN=10001;FRIEND=10002;GROUP=20001
TEXT='从 H1 发来的原生消息 "\\ [CQ:at,qq=all]';GROUP_TEXT='群聊原生文字'
def protobuf(data):
    def number(at):
        x=0
        for i in range(10):
            b=data[at];at+=1;x|=(b&127)<<(7*i)
            if b<128:return x,at
        raise ValueError('bad varint')
    out={};at=0
    while at<len(data):
        h,at=number(at);tag,t=h>>3,h&7
        if t==0:v,at=number(at)
        elif t==2:n,at=number(at);v=data[at:at+n];at+=n;assert at<=len(data)
        else:raise ValueError('unneeded fixture wire type')
        out.setdefault(tag,[]).append(v)
    return out
def first(data,tag,default=0):return protobuf(data).get(tag,[default])[0]
def sso_reply(command,seq,body,key=None,compression=0):
    if compression:body=zlib.compress(body)
    h=u32(seq)+u32(0)+long(b'')+long(command.encode())+long(b'abcd')+u32(compression)
    return long(u32(10)+bytes([1 if key else 2,0])+long(str(UIN).encode())+encrypt(long(h)+long(body),key or bytes(16)))
def oicq_reply(command,body,key):
    h=b'\2\0\0'+u16(8001)+u16(command)+u16(1)+u32(UIN)+bytes(3);packet=h+encrypt(body,key)+b'\3';return packet[:1]+u16(len(packet))+packet[3:]
def message(group=False,text='你好，H1！',uid=1000):
    head=pu(1,FRIEND)+pu(2,UIN)+pu(3,82 if group else 166)+pu(5,50)+pu(6,1795305600)+pu(7,uid)+pb(14,'测试联系人'.encode())
    if group:head+=pb(9,pu(1,GROUP)+pb(4,'群成员'.encode()))
    return pb(1,head)+pb(3,pb(1,pb(2,pb(1,pb(1,text.encode())))))
class Gateway:
    def __init__(self):
        self.private=ec.derive_private_key(0x123456789abcdef123456789abcdef,ec.SECP256R1());self.public=self.private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        self.share=None;self.tgtgt=bytes(range(16));self.d2key=bytes(range(16,32));self.calls=[];self.sends=[];self.deny=False;self.queries=0;self.qr_queries=0;self.fetches=0;self.qr_status=None;self.signed=[];self.acks=0;self.config_acks=0;self.sent_push=False
        self.key_json=json.dumps({'PubKeyMeta':{'KeyVer':1,'PubKey':self.public.hex().upper()}}).encode();self.reject_login=False;self.bad_qr=False;self.friend_count=2;self.group_count=1;self.bad_pull=False
        image=Image.new('RGB',(100,100));image.putdata([((x*5)%256,(y*7)%256,((x+y)*3)%256) for y in range(100) for x in range(100)]);png=io.BytesIO();jpeg=io.BytesIO();image.save(png,'PNG');image.save(jpeg,'JPEG',quality=85);self.avatar_png=png.getvalue();self.avatar_jpeg=jpeg.getvalue()
    def handle(self,packet):
        assert int.from_bytes(packet[:4],'big')==len(packet);r=Reader(packet[4:]);kind=r.word();crypt=r.take(1)[0]
        if kind==10:r.string();seq=None
        else:assert kind==11;seq=r.word()
        assert r.take(1)==b'\0';r.string();encrypted=r.take(len(r.b)-r.p)
        clear=encrypted if not crypt else decrypt(encrypted,self.d2key if crypt==1 else bytes(16));h=Reader(clear);head=h.word()
        if kind==10:seq=h.word();profile=(h.word(),h.word());h.take(12);h.string()
        command=h.string().decode();h.string()
        if kind==10:assert profile==(537214131,)*2,(command,profile)
        if kind==10:device_id=h.string();h.word();h.take(int.from_bytes(h.take(2),'big')-2)
        if command in ('wtlogin.login','MessageSvc.PbSendMsg'):
            secure=protobuf(h.string());sec=protobuf(secure[24][0]);assert len(sec[1][0])==68 and len(sec[2][0])==12 and sec[3][0];assert protobuf(sec[3][0])[2][0]==b'V1_AND_SQ_8.9.68_0_RDM_B';self.signed.append(command)
        elif command=='wtlogin.trans_emp':assert h.string()==b''
        h.string();assert h.p==head,(command,h.p,head);payload=Reader(clear[head:]).string();self.calls.append(command)
        if command=='wtlogin.trans_emp':
            public=payload[52:117]
            self.share=hashlib.md5(self.private.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),public))[:16]).digest()
            body=decrypt(payload[117:-1],self.share);cmd=int.from_bytes(body[21:23],'big');prefix=bytes(8)+u16(cmd)+bytes(38)
            assert int.from_bytes(body[49:53],'big')==(0 if cmd==0x31 else self.qr_queries+1)
            if cmd==0x31:
                self.fetches+=1;self.qr_queries=0
                # GUID from QR T16; confirmed credentials are wrapped for phone.
                q=Reader(body[61:-1]);q.take(19);fields=records(q.take(len(q.b)-q.p));self.guid=fields[0x16][12:28];assert len(self.guid)==16 and device_id==self.guid.hex().encode();assert fields[0x35]==u32(111)
                png=(ROOT/'tests/fixtures/qr.png').read_bytes()
                if self.bad_qr:png=png[:-1]+bytes([png[-1]^1])
                body=prefix+bytes(6)+b'\0'+short(bytes(range(24)))+u16(1)+tlv(0x17,png)+b'\3'
            else:
                assert cmd==0x12;self.queries+=1;self.qr_queries+=1;status=self.qr_status if self.qr_status is not None else 0x35 if self.qr_queries==1 else 0;body=prefix+u16(0)+u32(16)+bytes([status])
                if not status:
                    wrapped=encrypt(b'fixture-password'+self.tgtgt,self.guid)
                    body+=UIN.to_bytes(8,'big')+u32(0)+u16(4)+tlv(0x18,wrapped[:-16])+tlv(0x19,b'fixture-no-pic')+tlv(0x1e,wrapped[-16:])+tlv(0x65,b'fixture-qr-ticket')
                body+=b'\3'
            return sso_reply(command,seq,oicq_reply(0x812,body,self.share))
        if command=='wtlogin.login':
            body=decrypt(payload[117:-1],self.share);assert body[:4]==u16(9)+u16(25);fields=records(body[4:]);assert fields[0x106]==b'fixture-password' and fields[0x154]==u32(seq);assert decrypt(fields[0x144],self.tgtgt).startswith(u16(5))
            assert fields[0x100]==u16(1)+u32(18)+u32(16)+u32(537214131)+u32(0)+u32(34869472)
            assert fields[0x544][:2]==b'\x0c\x19' and len(fields[0x544])==68 and fields[0x191]==b'\x82' and fields[0x542]==bytes.fromhex('4a026001')
            if self.reject_login:
                body=u16(9)+b'\x2d'+u16(1)+tlv(0x146,bytes(4)+short('登录提示'.encode())+short('测试拒绝说明'.encode()))
                return sso_reply(command,seq,oicq_reply(0x810,body,self.share))
            nick='学习机测试号'.encode();tickets=u16(5)+tlv(0x10a,b'fixture-tgt')+tlv(0x143,b'fixture-d2')+tlv(0x305,self.d2key)+tlv(0x108,b'fixture-ksid')+tlv(0x11a,b'\0\0\x14\0'+bytes([len(nick)])+nick)
            body=u16(9)+b'\0'+u16(1)+tlv(0x119,encrypt(tickets,self.tgtgt));return sso_reply(command,seq,oicq_reply(0x810,body,self.share))
        assert crypt==1 or command=='Heartbeat.Alive',command
        if command=='StatSvc.register':body=response(b'SvcRespRegister',ji(2,0)+js(3,b''),True)
        elif command=='friendlist.getFriendGroupList':body=response(b'FLRESP',ji(5,self.friend_count)+jl(7,[st(ji(0,FRIEND)+ji(1,0)+js(3,'测试联系人'.encode())+js(14,b'Nick')),st(ji(0,10003)+ji(1,1)+js(3,b'')+js(14,'另一联系人'.encode()))]+[st(ji(0,10004+i)+ji(1,0)+js(3,('Fixture'+str(i+3)).encode())) for i in range(self.friend_count-2)])+jl(14,[st(ji(0,0)+js(1,'我的好友'.encode())+ji(2,self.friend_count-1)),st(ji(0,1)+js(1,'同学'.encode())+ji(2,1))]))
        elif command=='friendlist.GetTroopListReqV2':body=response(b'GetTroopListRespV2',jb(4,b'')+jl(5,[st(ji(0,21000001+i)+ji(1,GROUP+i)+js(4,('H1 开发群' if not i else '测试群'+str(i)).encode())+ji(23,UIN if not i else 10003)) for i in range(self.group_count)]))
        elif command=='MessageSvc.PbGetMsg':
            body=b'\x0a\x02\x00' if self.bad_pull else pu(1,0)+pb(3,b'fixture-cookie')+pu(4,2)+pb(5,pb(4,message()));self.bad_pull=False
        elif command=='MessageSvc.PbDeleteMsg':assert protobuf(payload)[1];self.acks+=1;body=pu(1,0)
        elif command=='MessageSvc.PbSendMsg':
            fields=protobuf(payload);route=protobuf(fields[1][0]);group=2 in route;peer=first(route[2 if group else 1][0],1);text=first(first(first(first(fields[3][0],1,b''),2,b''),1,b''),1,b'').decode();assert peer==(GROUP if group else FRIEND)
            body=pu(1,1200)+pb(2,'测试夹具拒绝请求'.encode()) if self.deny else pu(1,0)
            if not self.deny:self.sends.append(dict(group=group,peer=peer,text=text))
        elif command=='Heartbeat.Alive':assert crypt==0;body=b''
        elif command=='ConfigPushSvc.PushResp':self.config_acks+=1;body=b''
        else:raise AssertionError('Unexpected QQ command: '+command)
        result=sso_reply(command,seq,body,self.d2key,compression=1 if command=='friendlist.getFriendGroupList' else 0)
        if command=='StatSvc.register' and not self.sent_push:
            result+=sso_reply('OnlinePush.PbPushGroupMsg',65000,pb(1,message(True,'群里的问候',2000)),self.d2key);self.sent_push=True
        return result
class Server:
    def __init__(self,gateway):self.gateway=gateway;self.last=0;self.ready=False;self.stream=0;self.next_stream=100;self.input=bytearray();self.output=bytearray();self.accepted=self.delivered=self.total=0;self.http=b'';self.http_at=0;self.trace=[];self.hold_next_pull=False;self.held=b'';self.tcp_state=2;self.drop_next_pull=False;self.avatar_requests=[];self.http_releases=0
    def release_pull(self):self.output+=self.held;self.total+=len(self.held);self.held=b''
    def publish(self,data):self.output+=data;self.total+=len(data)
    def close(self):pass
    def dispatch(self,frame):
        op,seq,status,p=frame;assert not status
        if op==1:assert not p;self.last=seq;self.ready=True;self.stream=0;return wire.encode(op|128,seq,wire.IDENTITY,0)
        assert self.ready and seq==(self.last+1)&65535;self.last=seq;reply=b'';error=0
        if op==10:reply=struct.pack('<4I',1,4,8192,1|2|8|64)
        elif op==3:
            url=p[8:].decode()
            if url.startswith('https://keyrotate.qq.com/'):self.http=self.gateway.key_json
            else:
                assert url.startswith(('https://thirdqq.qlogo.cn/g?b=sdk&s=100&nk=','https://p.qlogo.cn/gh/'));self.avatar_requests.append(url)
                self.http=self.gateway.avatar_jpeg if '/gh/' in url else b'invalid image' if url.endswith('nk=10003') else self.gateway.avatar_png
            self.http_at=0;reply=struct.pack('<I',1)
        elif op==4:reply=struct.pack('<8I',1,3,200,len(self.http),len(self.http),self.http_at,len(self.http)-self.http_at,0)
        elif op==5:
            job,n=struct.unpack('<II',p);assert job==1;data=self.http[self.http_at:self.http_at+n];reply=struct.pack('<III',1,self.http_at,len(data))+data;self.http_at+=len(data)
        elif op==11:self.http_releases+=1
        elif op==6:pass
        elif op==29:
            port,timeout=struct.unpack('<II',p[:8]);assert port==8080 and p[8:]==b'msfwifi.3g.qq.com';self.next_stream+=1;self.stream=self.next_stream;self.tcp_state=2;self.input.clear();self.output.clear();self.accepted=self.delivered=self.total=0;reply=struct.pack('<I',self.stream)
        elif op in (30,31,32,33):
            job=int.from_bytes(p[:4],'little');assert job==self.stream
            if op==30:reply=struct.pack('<9I',job,self.tcp_state,0,self.total,self.delivered,len(self.output),self.accepted,self.accepted,0)
            elif op==31:
                offset=int.from_bytes(p[4:8],'little');assert offset==self.accepted;self.input+=p[8:];self.accepted+=len(p)-8;reply=struct.pack('<II',job,self.accepted)
                while len(self.input)>=4:
                    size=int.from_bytes(self.input[:4],'big')
                    if len(self.input)<size:break
                    answer=self.gateway.handle(bytes(self.input[:size]));del self.input[:size]
                    if self.gateway.calls[-1]=='MessageSvc.PbGetMsg' and self.hold_next_pull:self.held=answer;self.hold_next_pull=False
                    elif self.gateway.calls[-1]=='MessageSvc.PbGetMsg' and self.drop_next_pull:self.tcp_state=3;self.drop_next_pull=False
                    else:self.output+=answer;self.total+=len(answer)
            elif op==32:
                _,offset,wanted=struct.unpack('<III',p);assert offset==self.delivered;data=bytes(self.output[:min(wanted,113)]);del self.output[:len(data)];self.delivered+=len(data);reply=struct.pack('<III',job,offset,len(data))+data
            else:self.stream=0
        else:raise AssertionError('Unexpected H1NET opcode '+str(op))
        self.trace.append(dict(opcode=op,request_bytes=len(p),reply_bytes=len(reply)));return wire.encode(op|128,seq,reply,error)
