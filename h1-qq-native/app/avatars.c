/* Public QQ thumbnails: ESP HTTP transport, bounded native JPEG/PNG decoding.
 * Each service call completes at most one RPC; QQ TCP retains priority. */
#include "avatars.h"
#include "h1_image.h"
#include "h1_filesystem.h"
#include "h1_rtc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
enum {AVATAR_SLOTS=48,AVATAR_BYTES=32768};
static struct {char id[21];unsigned group,w,h,loading,stale;uint16_t *pixels;uint32_t touched,retry;} cache[AVATAR_SLOTS];
static struct {uint32_t job,next,started;unsigned phase,slot,used;uint8_t bytes[AVATAR_BYTES];} fetch;
static uint32_t avatar_revision,avatar_stamp;
extern uint32_t qq_time(void);
uint32_t qq_avatar_revision(void){return avatar_revision;}
static void disk_path(unsigned slot,char path[96])
{snprintf(path,96,QQ_AVATAR_DIR "\\%c%s.avt",cache[slot].group?'g':'u',cache[slot].id);}
static int disk_load(unsigned slot)
{
    uint8_t data[48+32*32*2],extra;char path[96];disk_path(slot,path);h1_file *file=h1_fopen(path,"rb");if(!file)return 0;
    unsigned count=h1_fread(data,1,48,file);int valid=count==48;
    unsigned w=valid?data[9]:0,h=valid?data[10]:0,n=valid?h1net_u32(data+16):0;
    valid=valid&&!memcmp(data,"H1QQAV1",8)&&data[8]==cache[slot].group&&w&&h&&w<=32&&h<=32&&n==w*h*2&&!memcmp(data+24,cache[slot].id,21);
    if(valid)valid=h1_fread(data+48,1,n,file)==n&&!h1_fread(&extra,1,1,file);int closed=h1_fclose(file);if(!valid||closed)return 0;
    uint32_t expected=h1net_u32(data+20);h1net_put32(data+20,0);if(h1net_crc32(data,48+n)!=expected)return 0;
    uint16_t *pixels=malloc(n);if(!pixels)return 0;memcpy(pixels,data+48,n);cache[slot].pixels=pixels;cache[slot].w=w;cache[slot].h=h;
    uint32_t now=0,saved=h1net_u32(data+12);cache[slot].stale=h1_rtc_read_local_seconds(&now)&&(!saved||now<saved||now-saved>=7u*86400u);return 1;
}
static void disk_save(unsigned slot)
{
    uint8_t data[48+32*32*2];char path[96];unsigned n=cache[slot].w*cache[slot].h*2;uint32_t now=0;(void)h1_rtc_read_local_seconds(&now);
    memset(data,0,48);memcpy(data,"H1QQAV1",8);data[8]=(uint8_t)cache[slot].group;data[9]=(uint8_t)cache[slot].w;data[10]=(uint8_t)cache[slot].h;
    h1net_put32(data+12,now);h1net_put32(data+16,n);memcpy(data+24,cache[slot].id,21);memcpy(data+48,cache[slot].pixels,n);h1net_put32(data+20,h1net_crc32(data,48+n));
    disk_path(slot,path);h1_file *file=h1_fopen(path,"wb");if(!file)return;unsigned written=h1_fwrite(data,1,48+n,file);int closed=h1_fclose(file);if(written!=48+n||closed)(void)h1_remove(path);
}
int qq_avatar_peek(int group,const char *id,const uint16_t **pixels,unsigned *w,unsigned *h)
{
    if(!id||!*id)return 0;unsigned n=0;for(;id[n];++n)if(n>=20||id[n]<'0'||id[n]>'9')return 0;
    unsigned slot=AVATAR_SLOTS;uint32_t oldest=UINT32_MAX;
    for(unsigned i=0;i<AVATAR_SLOTS;++i){
        if(cache[i].id[0]&&cache[i].group==(unsigned)group&&!strcmp(cache[i].id,id)){cache[i].touched=++avatar_stamp;if(!cache[i].pixels)return 0;*pixels=cache[i].pixels;*w=cache[i].w;*h=cache[i].h;return 1;}
        if(!cache[i].loading&&cache[i].touched<oldest){oldest=cache[i].touched;slot=i;}
    }
    if(slot==AVATAR_SLOTS)return 0;h1_image_free(cache[slot].pixels);memset(&cache[slot],0,sizeof cache[slot]);memcpy(cache[slot].id,id,n+1);cache[slot].group=(unsigned)group;cache[slot].touched=++avatar_stamp;
    if(!disk_load(slot))return 0;*pixels=cache[slot].pixels;*w=cache[slot].w;*h=cache[slot].h;return 1;
}
int qq_avatars_due(uint32_t now)
{
    if((int32_t)(now-fetch.next)<0)return 0;if(fetch.phase)return 1;
    for(unsigned i=0;i<AVATAR_SLOTS;++i)if(cache[i].id[0]&&(!cache[i].pixels||cache[i].stale)&&(int32_t)(now-cache[i].retry)>=0)return 1;return 0;
}
static void failed(uint32_t now){cache[fetch.slot].retry=now+60000;fetch.phase=4;}
void qq_avatars_service(h1net_client *rpc,uint32_t now)
{
    if(!qq_avatars_due(now))return;fetch.next=now+25;
    if(!fetch.phase){
        unsigned slot=AVATAR_SLOTS;uint32_t newest=0;
        for(unsigned i=0;i<AVATAR_SLOTS;++i)if(cache[i].id[0]&&(!cache[i].pixels||cache[i].stale)&&(int32_t)(now-cache[i].retry)>=0&&cache[i].touched>=newest){slot=i;newest=cache[i].touched;}
        if(slot==AVATAR_SLOTS)return;char url[160];fetch.slot=slot;cache[slot].loading=1;fetch.used=0;fetch.started=now;
        if(cache[slot].group)snprintf(url,sizeof url,"https://p.qlogo.cn/gh/%s/%s/100",cache[slot].id,cache[slot].id);
        else snprintf(url,sizeof url,"https://thirdqq.qlogo.cn/g?b=sdk&s=100&nk=%s",cache[slot].id);
        if(h1net_http_open(rpc,url,AVATAR_BYTES,6000,&fetch.job)){cache[slot].loading=0;cache[slot].retry=now+60000;fetch.job=0;return;}fetch.phase=1;return;
    }
    if(fetch.phase<=2&&now-fetch.started>8000){failed(now);return;}
    if(fetch.phase==1){
        h1net_info info;if(h1net_http_info(rpc,fetch.job,&info)||info.state==H1NET_FAILED||info.state==H1NET_CANCELLED||(info.http_status&&info.http_status!=200)){failed(now);return;}
        if(info.buffered){if(fetch.used==AVATAR_BYTES){failed(now);return;}fetch.phase=2;return;}
        if(info.state!=H1NET_DONE){fetch.next=now+150;return;}
        uint16_t *pixels=0;unsigned w=0,h=0;
        if(!h1_image_decode_rgb565(fetch.bytes,fetch.used,&pixels,&w,&h,32,32)){h1_image_free(cache[fetch.slot].pixels);cache[fetch.slot].pixels=pixels;cache[fetch.slot].w=w;cache[fetch.slot].h=h;cache[fetch.slot].stale=0;disk_save(fetch.slot);++avatar_revision;}else cache[fetch.slot].retry=now+60000;
        fetch.phase=5;return;
    }
    if(fetch.phase==2){unsigned n=0,wanted=AVATAR_BYTES-fetch.used;if(wanted>496)wanted=496;
        if(h1net_http_read(rpc,fetch.job,fetch.used,fetch.bytes+fetch.used,wanted,&n)){failed(now);return;}fetch.used+=n;if(n)fetch.started=now;fetch.phase=1;return;
    }
    if(fetch.phase==4){(void)h1net_http_cancel(rpc,fetch.job);fetch.phase=5;return;}
    (void)h1net_http_release(rpc,fetch.job);cache[fetch.slot].loading=0;fetch.job=0;fetch.phase=0;fetch.used=0;
}
void qq_avatars_network_reset(void)
{
    if(fetch.phase){cache[fetch.slot].loading=0;cache[fetch.slot].retry=qq_time()+1000;}memset(&fetch,0,sizeof fetch);
}
void qq_avatars_close(h1net_client *rpc)
{
    if(fetch.job&&rpc){(void)h1net_http_cancel(rpc,fetch.job);(void)h1net_http_release(rpc,fetch.job);}
    for(unsigned i=0;i<AVATAR_SLOTS;++i)h1_image_free(cache[i].pixels);memset(cache,0,sizeof cache);memset(&fetch,0,sizeof fetch);avatar_revision=avatar_stamp=0;
}
