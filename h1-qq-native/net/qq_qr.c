#include "qq_qr.h"
#include "qq_crypto.h"
#include "qq_profile.h"
typedef struct {uint8_t *p;uint32_t n,cap;int ok;} writer;
static void bytes(writer *w,const uint8_t *p,uint32_t n)
{if(!w->ok||n>w->cap-w->n){w->ok=0;return;}for(uint32_t i=0;i<n;++i)w->p[w->n+i]=p?p[i]:0;w->n+=n;}
static void number(writer *w,uint64_t x,unsigned n){uint8_t b[8];for(unsigned i=0;i<n;++i)b[i]=(uint8_t)(x>>(8*(n-1-i)));bytes(w,b,n);}
static void small(writer *w,const uint8_t *p,uint32_t n){if(n>65535){w->ok=0;return;}number(w,n,2);bytes(w,p,n);}
static void large(writer *w,const uint8_t *p,uint32_t n){number(w,n+4,4);bytes(w,p,n);}
static void patch(writer *w,uint32_t at,uint32_t x,unsigned n){if(at+n>w->n){w->ok=0;return;}for(unsigned i=0;i<n;++i)w->p[at+i]=(uint8_t)(x>>(8*(n-1-i)));}
static void text_small(writer *w,const char *s){unsigned n=0;while(s[n])++n;small(w,(const uint8_t *)s,n);}
static void tlv_begin(writer *w,unsigned tag,uint32_t *at){number(w,tag,2);*at=w->n;number(w,0,2);}
static void tlv_end(writer *w,uint32_t at){patch(w,at,w->n-at-2,2);}
static int packet(const qq_qr_session *s,const uint8_t *inner,uint32_t n,uint8_t *out,uint32_t capacity,uint32_t *size)
{
    uint8_t encrypted[2048],oicq[2304],sso[3072];uint32_t length;
    if(!qq_tea_encrypt(s->share_key,inner,n,s->pad,encrypted,sizeof encrypted,&length))return 0;
    writer o={oicq,0,sizeof oicq,1};number(&o,2,1);number(&o,0,2);number(&o,8001,2);number(&o,0x812,2);number(&o,1,2);
    number(&o,0,4);number(&o,3,1);number(&o,0x87,1);number(&o,0,1);number(&o,2,4);bytes(&o,0,8);
    number(&o,2,1);number(&o,1,1);bytes(&o,s->random_key,16);number(&o,0x131,2);number(&o,s->key_version,2);
    small(&o,s->public_key,65);bytes(&o,encrypted,length);number(&o,3,1);patch(&o,1,o.n,2);
    writer h={sso,0,sizeof sso,1};number(&h,0,4);number(&h,s->sequence,4);number(&h,QQ_NATIVE_SUB_APP_ID,4);number(&h,QQ_NATIVE_SUB_APP_ID,4);
    static const uint8_t dummy[12]={1,0,0,0,0,0,0,0,0,0,1,0};bytes(&h,dummy,12);number(&h,4,4);
    static const char command[]="wtlogin.trans_emp";
    large(&h,(const uint8_t *)command,sizeof command-1);number(&h,8,4);bytes(&h,0,4);
    char id[33];qq_native_device_id(s->guid,id);large(&h,(const uint8_t *)id,32);number(&h,4,4);number(&h,2,2);number(&h,4,4);number(&h,4,4);
    patch(&h,0,h.n,4);large(&h,oicq,o.n);
    if(!o.ok||!h.ok)return 0;
    uint8_t wrapped[4096],zero[16]={0};
    if(!qq_tea_encrypt(zero,sso,h.n,s->pad+9,wrapped,sizeof wrapped,&length))return 0;
    writer w={out,0,capacity,1};number(&w,0,4);number(&w,10,4);number(&w,2,1);number(&w,4,4);number(&w,0,1);large(&w,(const uint8_t *)"0",1);
    bytes(&w,wrapped,length);patch(&w,0,w.n,4);if(!w.ok)return 0;*size=w.n;return 1;
}
static int inner_packet(const qq_qr_session *s,uint16_t cmd,const uint8_t *payload,uint32_t n,uint8_t *output,uint32_t cap,uint32_t *size)
{
    uint8_t code[1500],inner[1600];writer c={code,0,sizeof code,1};number(&c,2,1);number(&c,0,2);number(&c,cmd,2);bytes(&c,0,21);
    number(&c,3,1);number(&c,0,2);number(&c,50,2);number(&c,s->code_sequence,4);bytes(&c,0,8);bytes(&c,payload,n);number(&c,3,1);patch(&c,1,c.n,2);
    writer i={inner,0,sizeof inner,1};number(&i,0,1);number(&i,c.n+4,2);number(&i,16,4);number(&i,0x72,4);bytes(&i,0,3);number(&i,s->seconds,4);bytes(&i,code,c.n);
    return c.ok&&i.ok&&packet(s,inner,i.n,output,cap,size);
}
int qq_qr_fetch(const qq_qr_session *s,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!s||!out||!size)return 0;
    uint8_t payload[1024];writer w={payload,0,sizeof payload,1};number(&w,0,2);number(&w,16,4);bytes(&w,0,8);number(&w,8,1);number(&w,0,2);number(&w,6,2);
    uint32_t at;tlv_begin(&w,0x16,&at);number(&w,QQ_NATIVE_SSO_VERSION,4);number(&w,16,4);number(&w,QQ_NATIVE_SUB_APP_ID,4);bytes(&w,s->guid,16);
    text_small(&w,QQ_NATIVE_APK_ID);text_small(&w,QQ_NATIVE_VERSION);static const uint8_t signature[16]={0xa6,0xb7,0x45,0xbf,0x24,0xa2,0xc2,0x77,0x52,0x77,0x16,0xf6,0xf3,0x6e,0xb6,0x8d};small(&w,signature,16);tlv_end(&w,at);
    tlv_begin(&w,0x1b,&at);number(&w,0,4);number(&w,0,4);number(&w,8,4);number(&w,4,4);number(&w,72,4);number(&w,2,4);number(&w,2,4);number(&w,0,2);tlv_end(&w,at);
    tlv_begin(&w,0x1d,&at);number(&w,1,1);number(&w,QQ_NATIVE_MISC_BITMAP,4);bytes(&w,0,9);tlv_end(&w,at);
    tlv_begin(&w,0x1f,&at);number(&w,0,1);text_small(&w,"android");text_small(&w,"7.1.2");number(&w,2,2);text_small(&w,"China Mobile GSM");number(&w,0,2);text_small(&w,"wifi");tlv_end(&w,at);
    tlv_begin(&w,0x33,&at);bytes(&w,s->guid,16);tlv_end(&w,at);tlv_begin(&w,0x35,&at);number(&w,QQ_NATIVE_DEVICE_TYPE,4);tlv_end(&w,at);
    return w.ok&&inner_packet(s,0x31,payload,w.n,out,cap,size);
}
int qq_qr_query(const qq_qr_session *s,const uint8_t *sig,uint32_t n,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!s||!sig||n>1024||!out||!size)return 0;
    uint8_t payload[1200];writer w={payload,0,sizeof payload,1};number(&w,5,2);number(&w,1,1);number(&w,QQ_NATIVE_DEVICE_TYPE,4);number(&w,16,4);small(&w,sig,n);bytes(&w,0,8);number(&w,8,1);number(&w,0,2);number(&w,0,2);
    return w.ok&&inner_packet(s,0x12,payload,w.n,out,cap,size);
}
typedef struct {const uint8_t *p;uint32_t n,at;int ok;} reader;
static const uint8_t *take(reader *r,uint32_t n){if(!r->ok||n>r->n-r->at){r->ok=0;return 0;}const uint8_t *p=r->p+r->at;r->at+=n;return p;}
static uint32_t readnum(reader *r,unsigned n){const uint8_t *p=take(r,n);uint32_t v=0;if(p)for(unsigned i=0;i<n;++i)v=v<<8|p[i];return v;}
static const uint8_t *readlarge(reader *r,uint32_t *n){uint32_t size=readnum(r,4);if(size<4){r->ok=0;return 0;}*n=size-4;return take(r,*n);}
int qq_sso_decode(const uint8_t *data,uint32_t n,const uint8_t key[16],qq_sso_reply *reply,uint8_t *body,uint32_t cap)
{
    if(!data||!key||!reply||!body||n<15||n>cap)return 0;
    reader r={data,n,0,1};if(readnum(&r,4)!=n)return 0;uint32_t type=readnum(&r,4);if(type!=10&&type!=11)return 0;
    unsigned crypt=readnum(&r,1);if(readnum(&r,1))return 0;uint32_t len=0;readlarge(&r,&len);if(!r.ok)return 0;
    const uint8_t *encrypted=take(&r,n-r.at);uint32_t size;
    if(crypt==2){uint8_t zero[16]={0};if(!qq_tea_decrypt(zero,encrypted,(uint32_t)(data+n-encrypted),body,cap,&size))return 0;}
    else if(crypt==1){if(!qq_tea_decrypt(key,encrypted,(uint32_t)(data+n-encrypted),body,cap,&size))return 0;}
    else if(crypt==0){size=(uint32_t)(data+n-encrypted);for(uint32_t i=0;i<size;++i)body[i]=encrypted[i];}else return 0;
    reader h={body,size,0,1};uint32_t header=readnum(&h,4);if(header<4||header>size)return 0;
    qq_sso_reply result={0};result.sequence=readnum(&h,4);result.sso_return=(int32_t)readnum(&h,4);readlarge(&h,&len);
    const uint8_t *cmd=readlarge(&h,&len);if(!h.ok||len>=sizeof result.command)return 0;
    for(uint32_t i=0;i<len;++i)result.command[i]=(char)cmd[i];const uint8_t *session=readlarge(&h,&len);
    if(!h.ok||len>4)return 0;for(uint32_t i=0;i<len;++i)result.session_id[i]=session[i];result.compression=readnum(&h,4);
    if(!h.ok||h.at>header)return 0;h.at=header;const uint8_t *payload=readlarge(&h,&len);if(!h.ok)return 0;
    for(uint32_t i=0;i<len;++i)body[i]=payload[i];result.body_size=len;*reply=result;return 1;
}
int qq_qr_decode(const qq_qr_session *s,const uint8_t *data,uint32_t n,uint8_t *scratch,uint32_t cap,
    uint32_t *command,uint32_t *status,const uint8_t **sig,uint32_t *sig_size,const uint8_t **png,uint32_t *png_size)
{
    if(!s||!data||n<18||!scratch||!command||!status||!sig||!sig_size||!png||!png_size||data[0]!=2||data[n-1]!=3)return 0;
    if(data[14]!=0)return 0;
    uint32_t size;
    if(!qq_tea_decrypt(s->share_key,data+16,n-17,scratch,cap,&size)&&!qq_tea_decrypt(s->random_key,data+16,n-17,scratch,cap,&size))return 0;
    if(size<49)return 0;
    reader r={scratch,size,0,1};take(&r,8);*command=readnum(&r,2);take(&r,38);*sig=0;*png=0;*sig_size=*png_size=0;
    if(*command==0x31){
        take(&r,6);*status=readnum(&r,1);if(!r.ok)return 0;if(*status)return 1;
        *sig_size=readnum(&r,2);*sig=take(&r,*sig_size);uint32_t count=readnum(&r,2);
        for(uint32_t i=0;i<count&&r.ok;++i){uint32_t tag=readnum(&r,2),len=readnum(&r,2);const uint8_t *p=take(&r,len);if(tag==0x17){*png=p;*png_size=len;}}
        return r.ok&&*png&&*sig;
    }
    if(*command==0x12){
        uint32_t skip=readnum(&r,2);if(skip){--skip;if(readnum(&r,1)==2){if(skip<8)return 0;take(&r,8);skip-=8;}take(&r,skip);}
        take(&r,4);*status=readnum(&r,1);return r.ok;
    }
    return 0;
}
