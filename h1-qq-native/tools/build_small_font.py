"""Pack pinned Fusion Pixel 12px BDF rows without rasterizing or scaling.
Rare unsupported characters retain their original 16px Unifont bitmap.
"""
import gzip,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];SRC=ROOT/'h1-qq-native';ASSETS=SRC/'app/assets/font12';SDK=ROOT/'sdk/sdk/media/fonts';FUSION=SRC/'third_party/fusion-pixel-12'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bdf_glyphs(data):
    glyphs={};fields={};bitmap=None
    for line in data.decode('ascii').splitlines():
        if line.startswith('STARTCHAR '):fields={};bitmap=None
        elif line.startswith('ENCODING '):fields['cp']=int(line.split()[1])
        elif line.startswith('DWIDTH '):fields['width']=int(line.split()[1])
        elif line.startswith('BBX '):fields['box']=list(map(int,line.split()[1:]))
        elif line=='BITMAP':bitmap=[]
        elif line=='ENDCHAR':
            if fields.get('cp',-1)>=0:glyphs[fields['cp']]=(fields['width'],fields['box'],bitmap)
            bitmap=None
        elif bitmap is not None:bitmap.append(int(line,16))
    return glyphs

def main():
    ASSETS.mkdir(exist_ok=True);source=FUSION/'source.json';provenance=json.loads(source.read_text());compressed=FUSION/provenance['bdf_file'];assert sha(compressed)==provenance['compressed_sha256'];data=gzip.decompress(compressed.read_bytes());assert hashlib.sha256(data).hexdigest()==provenance['bdf_uncompressed_sha256']
    assert b'FONTBOUNDINGBOX 12 12 0 -2' in data and b'FONT_ASCENT 10' in data;parsed=bdf_glyphs(data)
    # Combining/vertical glyphs can exceed a single 12px cell in the upstream
    # BDF. Keep the existing native 16px glyph for those, never crop or shrink.
    glyphs={}
    for cp,info in parsed.items():
        advance,(w,h,xoff,yoff),bitmap=info
        if advance in (6,12) and len(bitmap)==h and xoff>=0 and xoff+w<=advance and 0<=10-yoff-h and 10-yoff<=12:glyphs[cp]=info
    original=(SDK/'font16_data.h').read_text();assert sha(SDK/'font16_data.h')==json.loads((SDK/'font.json').read_text())['header_sha256'];chars=[int(x,16) for x in re.findall(r'0x[0-9a-f]+',original.split('h1_font_cp[H1_FONT_COUNT]={',1)[1].split('};',1)[0])]
    unifont={int(line[:4],16):bytes.fromhex(line[5:]) for line in gzip.decompress((SDK/'unifont-16.0.04.hex.gz').read_bytes()).decode().splitlines()};rows=[];widths=[];fallback=[]
    for cp in chars:
        if cp in glyphs:
            advance,(w,h,xoff,yoff),bitmap=glyphs[cp];assert advance in (6,12) and len(bitmap)==h and 0<=xoff and xoff+w<=advance
            top=10-yoff-h;assert 0<=top and top+h<=12;row=[0]*16;packed_width=(w+7)//8*8
            for y,mask in enumerate(bitmap):
                assert not mask&((1<<(packed_width-w))-1)
                shift=16-packed_width-xoff;row[top+y]=mask<<shift if shift>=0 else mask>>-shift
            widths.append(advance);rows.append(row)
        else:
            fallback.append(cp);old=unifont[cp];widths.append(8 if len(old)==16 else 16);rows.append([old[y]<<8 if len(old)==16 else int.from_bytes(old[y*2:y*2+2],'big') for y in range(16)])
    assert len(chars)==22369 and len(fallback)==467
    parts=['/* QQSmall12: losslessly packed Fusion Pixel 12px BDF, SIL OFL-1.1. */','/* Native 16px Unifont fallback for unsupported characters; no scaling. */','#ifndef H1QQ_FONT12_DATA_H','#define H1QQ_FONT12_DATA_H','static const uint16_t qq12_cp[]={']
    parts.extend(','.join(hex(c) for c in chars[i:i+24])+',' for i in range(0,len(chars),24));parts+=['};','static const uint8_t qq12_width[]={'];parts.extend(','.join(str(c) for c in widths[i:i+48])+',' for i in range(0,len(chars),48));parts+=['};','static const uint16_t qq12_rows[][16]={'];parts.extend('{'+','.join(hex(c) for c in row)+'},' for row in rows);parts+=['};','static const uint16_t qq12_fallback_cp[]={'+','.join(hex(c) for c in fallback)+'};']
    title=list(range(32,127))+[0x2026,0x25a1];parts+=['static const uint16_t qq16_title_cp[]={'+','.join(hex(c) for c in title)+'};','static const uint8_t qq16_title_width[]={'+','.join(str(8 if len(unifont[c])==16 else 16) for c in title)+'};','static const uint16_t qq16_title_rows[][16]={']
    for cp in title:
        old=unifont[cp];parts.append('{'+','.join(hex(old[y]<<8 if len(old)==16 else int.from_bytes(old[y*2:y*2+2],'big')) for y in range(16))+'},')
    parts+=['};','#endif'];out=ASSETS/'font12_data.h';out.write_text('\n'.join(parts)+'\n',encoding='utf-8',newline='\n');(ASSETS/'OFL-Fusion.txt').write_bytes((FUSION/'OFL.txt').read_bytes());(ASSETS/'OFL-Unifont.txt').write_bytes((SDK/'OFL-1.1.txt').read_bytes())
    meta=dict(font='QQSmall12 (Fusion Pixel 12px BDF subset)',upstream='Fusion Pixel 12px Mono zh_Hans',version=provenance['release'],nominal_size=12,line_height=14,fallback_line_height=18,source=compressed.relative_to(ROOT).as_posix(),source_sha256=sha(compressed),provenance_sha256=sha(source),codepoint_source_sha256=sha(SDK/'font16_data.h'),glyphs=len(chars),original_coverage_preserved=True,primary_bitmap_glyphs=len(chars)-len(fallback),native16_fallback_codepoints=fallback,original_bitmap_shapes=True,no_resampling=True,no_grayscale_threshold=True,max_advance=max(widths),rows_per_glyph=16,ascii_title_16px=True,title_glyphs=len(title),header_sha256=sha(out),generator_sha256=sha(Path(__file__)),runtime_outline_rasterizer=False)
    (ASSETS/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8',newline='\n');print('Packed lossless 12px BDF:',len(chars)-len(fallback),'glyphs;',len(fallback),'native 16px fallbacks')
if __name__=='__main__':main()
