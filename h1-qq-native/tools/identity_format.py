"""Identity record format. Never print or include the secret key in reports."""
import secrets,struct,zlib
MAGIC=b'H1QQID1\0'
def make_record(key=None,offset=480,clock_adjustment=None):
    if key is None:key=secrets.token_bytes(32)
    assert len(key)==32 and any(key) and -840<=offset<=840
    prefix=MAGIC+bytes(16)+key+struct.pack('<QiiI',0,offset,clock_adjustment or 0,2 if clock_adjustment is not None else 0)
    assert len(prefix)==76
    return prefix+struct.pack('<I',zlib.crc32(prefix))
def parse_record(data):
    assert len(data)==80 and data[:8]==MAGIC
    assert zlib.crc32(data[:76])==struct.unpack_from('<I',data,76)[0]
    session,offset,adjustment,flags=struct.unpack_from('<QiiI',data,56)
    assert flags<=3 and -840<=offset<=840 and (flags&2 or adjustment==0)
    return dict(uuid=data[8:24],key=data[24:56],session=session,offset=offset,adjustment=adjustment,flags=flags)
def calibrate_record(data,adjustment):
    parse_record(data);out=bytearray(data)
    struct.pack_into('<i',out,68,adjustment);struct.pack_into('<I',out,72,struct.unpack_from('<I',out,72)[0]|2)
    struct.pack_into('<I',out,76,zlib.crc32(out[:76]));return bytes(out)
def parse_log(data):
    assert len(data)==324
    magic,result,lo,hi,local,utc,seed,mask,offset,ms=struct.unpack_from('<10I',data)
    assert magic==0x31444951 and result==0
    if offset>=0x80000000:offset-=0x100000000
    return dict(session=lo+(hi<<32),local_seconds=local,utc_seconds=utc,
        random_seed=seed,mask_seed=mask,offset=offset,elapsed_ms=ms,
        uuid=data[40:56].hex(),entropy=data[56:61].hex(),clock_calibrated=bool(data[61]),
        cached_sign_calls=data[62],material_generations=data[63],report=data[64:98].hex(),
        material=data[100:244].decode(),token=data[244:256].decode(),sign=data[256:324].hex())
