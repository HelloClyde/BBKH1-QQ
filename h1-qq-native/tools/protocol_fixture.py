"""Independent offline codec fixtures; no network or actual account data."""
import ctypes as c,struct
class View(c.Structure):_fields_=[('data',c.c_void_p),('size',c.c_uint32)]

class Ticket(c.Structure):_fields_=[('size',c.c_uint16),('data',c.c_ubyte*2048)]

class Account(c.Structure):
    _fields_=[('uin',c.c_uint64),*[(n,Ticket) for n in ('pwd','sig','qr','tgt','d2')],*[(n,c.c_ubyte*k) for n,k in [('tgtgt',16),('d2key',16),('wtkey',16),('sessionid',4),('ksid',64)]],('ksid_size',c.c_uint),('authenticated',c.c_uint),('registered',c.c_uint),('nickname',c.c_char*81)]

def vi(x):
    out=bytearray()
    while x>127:out.append((x&127)|128);x>>=7
    return bytes(out)+bytes([x])

def pu(tag,x):return vi(tag<<3)+vi(x)

def pb(tag,b):return vi(tag<<3|2)+vi(len(b))+b

def jh(tag,t):return bytes([(min(tag,15)<<4)|t])+ (bytes([tag]) if tag>=15 else b'')

def ji(tag,x):
    if not x:return jh(tag,12)
    for t,n in enumerate((1,2,4,8)):
        if -(1<<(8*n-1))<=x<(1<<(8*n-1)):return jh(tag,t)+x.to_bytes(n,'big',signed=True)

def js(tag,b):return jh(tag,6 if len(b)<256 else 7)+len(b).to_bytes(1 if len(b)<256 else 4,'big')+b

def jb(tag,b):return jh(tag,13)+b'\0'+ji(0,len(b))+b

def jm(tag,entries):return jh(tag,8)+ji(0,len(entries))+b''.join(entries)

def jl(tag,items):return jh(tag,9)+ji(0,len(items))+b''.join(items)

def st(b):return b'\x0a'+b+b'\x0b'

def response(key,body,v2=False):
    value=jb(1,st(body));value=jm(1,[js(0,b'QQService.SvcRespRegister')+value]) if v2 else value
    return ji(1,3)+jb(7,jm(0,[js(0,key)+value]))

def records(b):
    out={};at=0
    while at<len(b):tag,n=struct.unpack_from('>HH',b,at);at+=4;assert at+n<=len(b);out[tag]=b[at:at+n];at+=n
    return out
