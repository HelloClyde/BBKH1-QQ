"""Pack cleaned GPT login art; code and state labels are drawn at runtime."""
import hashlib,json
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'h1-qq-native/app/assets/login2008'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    source=OUT/'clean-gpt.png';im=Image.open(source).convert('RGB').resize((480,272),Image.Resampling.LANCZOS)
    # The approved composition is retained; its blank card is mechanically
    # enlarged to leave a white quiet zone even for the decoder's 160px output.
    card=im.crop((236,53,394,213)).resize((180,180),Image.Resampling.LANCZOS);im.paste(card,(226,50));im.save(OUT/'background.png')
    values=[((r>>3)<<11)|((g>>2)<<5)|(b>>3) for r,g,b in im.get_flattened_data()];(OUT/'background.rgb565').write_bytes(b''.join(v.to_bytes(2,'little') for v in values))
    lines=['/* Clean GPT art; never includes a QR pattern or dynamic label. */','#ifndef H1QQ_LOGIN2008_H','#define H1QQ_LOGIN2008_H','static const uint16_t qq08_login_background[480*272]={'];lines.extend(','.join('0x%04x'%v for v in values[i:i+20])+',' for i in range(0,len(values),20));lines+=['};','#endif'];(OUT/'login.h').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    manifest=dict(source='clean-gpt.png',source_sha256=sha(source),approved_design='h1-qq-native/design/qq2008-login/preview.png',approved_sha256=sha(ROOT/'h1-qq-native/design/qq2008-login/preview.png'),prompt_sha256=sha(OUT/'prompt.json'),png_sha256=sha(OUT/'background.png'),raw_sha256=sha(OUT/'background.rgb565'),header_sha256=sha(OUT/'login.h'),packer_sha256=sha(Path(__file__)),card_rect=[226,50,180,180],qr_center=[316,140],qr_max=160,synthetic_qr_removed=True)
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n');print('Packed cleaned login art; reserved 180px card for up to 160px real QR')
if __name__=='__main__':main()
