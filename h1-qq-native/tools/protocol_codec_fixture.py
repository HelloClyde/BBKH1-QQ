"""Independent offline codec fixtures; no network or actual account data."""
import struct,secrets
def u16(x):return struct.pack('>H',x)

def u32(x):return struct.pack('>I',x)

def short(b):return u16(len(b))+b

def long(b):return u32(len(b)+4)+b

def tlv(t,b):return u16(t)+short(b)

def block(data,key,decrypt=False):
    a,b=struct.unpack('>II',data);k=struct.unpack('>4I',key);mask=0xffffffff
    if decrypt:
        total=0xe3779b90
        for _ in range(16):
            b=(b-(((a<<4)+k[2])^(a+total)^((a>>5)+k[3])))&mask
            a=(a-(((b<<4)+k[0])^(b+total)^((b>>5)+k[1])))&mask;total=(total-0x9e3779b9)&mask
    else:
        total=0
        for _ in range(16):
            total=(total+0x9e3779b9)&mask;a=(a+(((b<<4)+k[0])^(b+total)^((b>>5)+k[1])))&mask
            b=(b+(((a<<4)+k[2])^(a+total)^((a>>5)+k[3])))&mask
    return struct.pack('>II',a,b)

def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def encrypt(data,key):
    fill=10-(len(data)+1)%8;clear=bytes([0xf8|fill-3])+secrets.token_bytes(fill-1)+data+bytes(7)
    prev_c=prev_x=bytes(8);out=bytearray()
    for i in range(0,len(clear),8):
        x=xor(clear[i:i+8],prev_c);cipher=xor(block(x,key),prev_x);out+=cipher;prev_x=x;prev_c=cipher
    return bytes(out)

def decrypt(data,key):
    assert len(data)>=16 and not len(data)%8
    prev_c=prev_x=bytes(8);out=bytearray()
    for i in range(0,len(data),8):
        cipher=data[i:i+8];x=block(xor(cipher,prev_x),key,True);out+=xor(x,prev_c);prev_x=x;prev_c=cipher
    start=(out[0]&7)+3;assert start<=len(out)-7 and out[-7:]==bytes(7)
    return bytes(out[start:-7])

class Reader:
    def __init__(self,b):self.b=b;self.p=0
    def take(self,n):assert 0<=n<=len(self.b)-self.p;v=self.b[self.p:self.p+n];self.p+=n;return v
    def word(self):return int.from_bytes(self.take(4),'big')
    def string(self):return self.take(self.word()-4)
