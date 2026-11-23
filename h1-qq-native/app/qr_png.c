#include "qr_png.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include "zlib.h"
#pragma GCC diagnostic pop
#include <string.h>
static uint32_t be32(const uint8_t *p){return(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static unsigned distance(int x){return(unsigned)(x<0?-x:x);}
static unsigned gcd(unsigned a,unsigned b){while(b){unsigned n=a%b;a=b;b=n;}return a;}
static unsigned bit(const uint8_t *raw,unsigned stride,unsigned x,unsigned y)
{return(raw[y*(stride+1)+1+x/8]>>(7-x%8))&1;}
int qq_qr_png(const uint8_t *png,unsigned n,uint8_t pixels[40000],unsigned *width,unsigned *height)
{
    static const uint8_t magic[8]={137,80,78,71,13,10,26,10};
    if(!png||!pixels||!width||!height)return 0;*width=*height=0;
    if(n<45||n>16384||memcmp(png,magic,8))return 0;
    uint8_t compressed[16384],raw[512*65];unsigned used=0,w=0,h=0,end=0,at=8;
    while(at<=n&&n-at>=12){
        unsigned size=be32(png+at);if(size>n-at-12)return 0;const uint8_t *type=png+at+4,*data=png+at+8;
        uLong crc=crc32(0,type,4);crc=crc32(crc,data,size);if((uint32_t)crc!=be32(data+size))return 0;
        if(!memcmp(type,"IHDR",4)){
            if(w||at!=8||size!=13)return 0;w=be32(data);h=be32(data+4);if(!w||!h||w>512||h>512||data[8]!=1||data[9]!=0||data[10]||data[11]||data[12])return 0;
        }else if(!memcmp(type,"IDAT",4)){if(!w||size>sizeof compressed-used)return 0;memcpy(compressed+used,data,size);used+=size;}
        else if(!memcmp(type,"IEND",4)){if(size||at+12!=n)return 0;end=1;break;}
        else if(!(type[0]&32))return 0;
        at+=size+12;
    }
    unsigned stride=(w+7)/8,expected=(stride+1)*h;uLongf size=sizeof raw;
    if(!w||!end||!used||uncompress(raw,&size,compressed,used)!=Z_OK||size!=expected)return 0;
    for(unsigned y=0;y<h;++y){
        uint8_t *row=raw+y*(stride+1)+1,*previous=y?row-(stride+1):0;unsigned filter=row[-1];if(filter>4)return 0;
        for(unsigned x=0;x<stride;++x){unsigned left=x?row[x-1]:0,up=previous?previous[x]:0,corner=x&&previous?previous[x-1]:0,p=0;
            if(filter==1)p=left;else if(filter==2)p=up;else if(filter==3)p=(left+up)/2;else if(filter==4){int q=(int)left+(int)up-(int)corner;unsigned a=distance(q-(int)left),b=distance(q-(int)up),c=distance(q-(int)corner);p=a<=b&&a<=c?left:b<=c?up:corner;}row[x]=(uint8_t)(row[x]+p);}
    }
    unsigned pitch=1,scale=1;
    if(w>160||h>160){
        pitch=0;
        /* A QR is an integer grid. Include both axes and the quiet border;
         * downsample only when every cell is an exact constant square. */
        for(unsigned y=0;y<h;++y){unsigned start=0;for(unsigned x=1;x<=w;++x)if(x==w||bit(raw,stride,x,y)!=bit(raw,stride,start,y)){pitch=gcd(pitch,x-start);start=x;}}
        for(unsigned x=0;x<w;++x){unsigned start=0;for(unsigned y=1;y<=h;++y)if(y==h||bit(raw,stride,x,y)!=bit(raw,stride,x,start)){pitch=gcd(pitch,y-start);start=y;}}
        if(!pitch||w%pitch||h%pitch)return 0;unsigned columns=w/pitch,rows=h/pitch;
        scale=160/columns;if(scale>160/rows)scale=160/rows;if(!scale)return 0;
    }
    unsigned ow=w/pitch*scale,oh=h/pitch*scale;
    for(unsigned y=0;y<oh;++y)for(unsigned x=0;x<ow;++x)pixels[y*ow+x]=(uint8_t)bit(raw,stride,x/scale*pitch,y/scale*pitch);
    *width=ow;*height=oh;return 1;
}
