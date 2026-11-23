"""Mechanical sprite packing of approved GPT Image artwork; no painted substitutes."""
import hashlib,json
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[2];ASSETS=ROOT/'h1-qq-native/app/assets/skin2008'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    cloud=Image.open(ASSETS/'clouds-gpt.png').convert('RGB')
    rows=[]
    for y in range(cloud.height):
        count=sum(1 for x in range(0,cloud.width,8) if (lambda p:p[2]>p[0]+20 and p[1]>p[0]+15)(cloud.getpixel((x,y))))
        if count>cloud.width//16:rows.append(y)
    assert rows;bounds=(0,min(rows),cloud.width,max(rows)+1);cloud=cloud.crop(bounds).resize((480,60),Image.Resampling.LANCZOS);cloud.save(ASSETS/'header.png')
    lines=['/* Packed GPT Image assets; see skin2008/manifest.json. */','#ifndef H1QQ_SKIN2008_H','#define H1QQ_SKIN2008_H']
    values=[((r>>3)<<11)|((g>>2)<<5)|(b>>3) for r,g,b in cloud.get_flattened_data()];lines.append('static const uint16_t qq08_header[480*60]={')
    lines.extend(','.join('0x%04x'%v for v in values[i:i+20])+',' for i in range(0,len(values),20));lines.append('};')
    sheet=Image.open(ASSETS/'icons-gpt.png').convert('RGBA');names=['group','recent','search','refresh','edit','online','menu','message'];tiles=[]
    for i,name in enumerate(names):
        x,y=i%4,i//4;tile=sheet.crop((x*sheet.width//4,y*sheet.height//2,(x+1)*sheet.width//4,(y+1)*sheet.height//2));bbox=tile.getchannel('A').point(lambda a:255 if a>=64 else 0).getbbox();assert bbox;tile=tile.crop(bbox)
        for size in (16,20,24):
            scaled=tile.copy();scaled.thumbnail((size,size),Image.Resampling.LANCZOS);sprite=Image.new('RGBA',(size,size));sprite.alpha_composite(scaled,((size-scaled.width)//2,(size-scaled.height)//2));sprite.save(ASSETS/(name+str(size)+'.png'))
            vals=[(a<<24)|(r<<16)|(g<<8)|b for r,g,b,a in sprite.get_flattened_data()];lines.append('static const uint32_t qq08_%s_%u[%u]={'%(name,size,size*size));lines.extend(','.join('0x%08xu'%v for v in vals[j:j+12])+',' for j in range(0,len(vals),12));lines.append('};')
        tiles.append(dict(name=name,cell=i,alpha_crop=bbox))
    lines.append('#endif');(ASSETS/'skin.h').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    (ASSETS/'manifest.json').write_text(json.dumps(dict(renderer='built-in GPT Image reference edit; Pillow crop/resize/packing only',approved_sha256=sha(ASSETS/'approved.png'),clouds_sha256=sha(ASSETS/'clouds-gpt.png'),icons_sha256=sha(ASSETS/'icons-gpt.png'),header_crop=bounds,header_sha256=sha(ASSETS/'header.png'),skin_header_sha256=sha(ASSETS/'skin.h'),icons=tiles),indent=2)+'\n',encoding='utf-8',newline='\n');print('Packed cloud band and eight GPT Image icons at 16/20/24px')
if __name__=='__main__':main()
