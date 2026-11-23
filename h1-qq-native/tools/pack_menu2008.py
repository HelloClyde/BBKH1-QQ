"""Mechanically pack a transparent GPT Image penguin for the footer menu."""
import hashlib,json
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[2]
ASSETS=ROOT/'h1-qq-native/app/assets/menu2008'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    source=Image.open(ASSETS/'penguin-gpt.png').convert('RGBA')
    alpha=source.getchannel('A');assert alpha.getextrema()==(0,255)
    bounds=alpha.point(lambda a:255 if a>=64 else 0).getbbox();assert bounds
    penguin=source.crop(bounds);penguin.thumbnail((20,20),Image.Resampling.LANCZOS)
    sprite=Image.new('RGBA',(20,20));sprite.alpha_composite(penguin,((20-penguin.width)//2,(20-penguin.height)//2))
    sprite.save(ASSETS/'penguin20.png')
    values=[(a<<24)|(r<<16)|(g<<8)|b for r,g,b,a in sprite.get_flattened_data()]
    lines=['/* GPT Image transparent penguin; mechanical alpha crop and resize. */','#ifndef H1QQ_MENU2008_H','#define H1QQ_MENU2008_H','static const uint32_t qq08_menu_penguin_20[20*20]={']
    lines.extend(','.join('0x%08xu'%v for v in values[i:i+10])+',' for i in range(0,len(values),10));lines+=['};','#endif']
    (ASSETS/'menu.h').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    manifest=dict(renderer='built-in GPT Image extraction; mechanical alpha crop/resize/ARGB packing',source='penguin-gpt.png',source_sha256=sha(ASSETS/'penguin-gpt.png'),prompt_sha256=sha(ASSETS/'prompt.json'),alpha_crop=bounds,size=[20,20],png_sha256=sha(ASSETS/'penguin20.png'),header_sha256=sha(ASSETS/'menu.h'),packer_sha256=sha(Path(__file__)))
    (ASSETS/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Packed transparent 20px penguin menu sprite')
if __name__=='__main__':main()
