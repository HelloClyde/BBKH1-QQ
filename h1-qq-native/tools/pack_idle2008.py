"""Pack the approved GPT Image idle artwork, without repainting its details.
Only the art-only right pane and fixed brand are baked; user text stays live.
"""
import hashlib,json
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[2];DESIGN=ROOT/'h1-qq-native/design/qq2008-idle';OUT=ROOT/'h1-qq-native/app/assets/idle2008'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    OUT.mkdir(exist_ok=True);approved=DESIGN/'preview.png';assert sha(approved)==json.loads((DESIGN/'manifest.json').read_text())['sha256']
    # Resample once into H1 coordinates, keeping the approved placement of the
    # penguin, speech motifs, cloud bands, globe and glass frame as a unit.
    native=Image.open(approved).convert('RGB').resize((480,272),Image.Resampling.LANCZOS)
    regions={'idle':(154,22,480,272),'brand':(0,0,396,22)};lines=['/* Exact GPT Image design crops, packed by tools/pack_idle2008.py. */','#ifndef H1QQ_IDLE2008_H','#define H1QQ_IDLE2008_H'];records={}
    for name,bounds in regions.items():
        tile=native.crop(bounds);tile.save(OUT/(name+'.png'));values=[((r>>3)<<11)|((g>>2)<<5)|(b>>3) for r,g,b in tile.get_flattened_data()]
        (OUT/(name+'.rgb565')).write_bytes(b''.join(v.to_bytes(2,'little') for v in values));lines.append('static const uint16_t qq08_%s[%u]={'%(name,len(values)));lines.extend(','.join('0x%04x'%v for v in values[i:i+20])+',' for i in range(0,len(values),20));lines.append('};');records[name]=dict(bounds=bounds,size=tile.size,png_sha256=sha(OUT/(name+'.png')),raw_sha256=sha(OUT/(name+'.rgb565')))
    lines.append('#endif');header=OUT/'idle.h';header.write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n');(OUT/'manifest.json').write_text(json.dumps(dict(source=approved.relative_to(ROOT).as_posix(),source_sha256=sha(approved),mode='approved built-in GPT Image artwork; mechanical crop/resize/RGB565 packing only',native_size=[480,272],regions=records,header_sha256=sha(header),packer_sha256=sha(Path(__file__))),indent=2)+'\n',encoding='utf-8',newline='\n');print('Packed approved idle pane and brand; runtime drawing uses no allocations or image decoding')
if __name__=='__main__':main()
