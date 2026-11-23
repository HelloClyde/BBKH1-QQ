#include "qq_codec.h"
void qq_clear(void *p,uint32_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
void qq_put(qq_writer *w,const void *v,uint32_t n)
{const uint8_t *p=v;if(!w->ok||n>w->capacity-w->size){w->ok=0;return;}for(uint32_t i=0;i<n;++i)w->data[w->size+i]=p?p[i]:0;w->size+=n;}
void qq_num(qq_writer *w,uint64_t x,unsigned n)
{uint8_t p[8];if(n>8){w->ok=0;return;}for(unsigned i=0;i<n;++i)p[i]=(uint8_t)(x>>(8*(n-1-i)));qq_put(w,p,n);}
void qq_patch(qq_writer *w,uint32_t at,uint64_t x,unsigned n)
{if(n>8||at>w->size||n>w->size-at){w->ok=0;return;}for(unsigned i=0;i<n;++i)w->data[at+i]=(uint8_t)(x>>(8*(n-1-i)));}
void qq_short(qq_writer *w,qq_view v){if(v.size>65535){w->ok=0;return;}qq_num(w,v.size,2);qq_put(w,v.data,v.size);}
void qq_long(qq_writer *w,qq_view v){if(v.size>UINT32_MAX-4){w->ok=0;return;}qq_num(w,v.size+4,4);qq_put(w,v.data,v.size);}
const uint8_t *qq_take(qq_reader *r,uint32_t n)
{if(!r->ok||n>r->size-r->at){r->ok=0;return 0;}const uint8_t *p=r->data+r->at;r->at+=n;return p;}
uint64_t qq_read(qq_reader *r,unsigned n)
{if(n>8){r->ok=0;return 0;}const uint8_t *p=qq_take(r,n);uint64_t x=0;if(p)for(unsigned i=0;i<n;++i)x=x<<8|p[i];return x;}
qq_view qq_string(const char *s){qq_view v={(const uint8_t *)s,0};if(s)while(s[v.size])++v.size;return v;}
int qq_copy_text(char *out,unsigned cap,qq_view v)
{if(!out||!cap||(!v.data&&v.size))return 0;unsigned n=v.size;if(n>=cap)n=cap-1;while(n<v.size&&n&&(v.data[n]&0xc0)==0x80)--n;for(unsigned i=0;i<n;++i)out[i]=(char)v.data[i];out[n]=0;return n==v.size;}
static void varint(qq_writer *w,uint64_t n)
{do{uint8_t c=(uint8_t)(n&127);n>>=7;if(n)c|=128;qq_put(w,&c,1);}while(n&&w->ok);}
void qq_pb_uint(qq_writer *w,unsigned tag,uint64_t x){if(!tag||tag>0x1fffffff){w->ok=0;return;}varint(w,(uint64_t)tag<<3);varint(w,x);}
void qq_pb_bytes(qq_writer *w,unsigned tag,qq_view v)
{if(!tag||tag>0x1fffffff){w->ok=0;return;}varint(w,((uint64_t)tag<<3)|2);varint(w,v.size);qq_put(w,v.data,v.size);}
static uint64_t read_varint(qq_reader *r)
{uint64_t x=0;for(unsigned i=0;i<10;++i){uint8_t c=(uint8_t)qq_read(r,1);if(!r->ok||(i==9&&c>1)){r->ok=0;return 0;}x|=(uint64_t)(c&127)<<(i*7);if(!(c&128))return x;}r->ok=0;return 0;}
int qq_pb_next(qq_reader *r,qq_field *f)
{
    if(!r->ok||r->at==r->size)return 0;uint64_t h=read_varint(r);*f=(qq_field){0};f->tag=(unsigned)(h>>3);f->type=(unsigned)(h&7);
    if(!r->ok||!f->tag||h>>32){r->ok=0;return 0;}
    if(f->type==0)f->value=read_varint(r);
    else if(f->type==1||f->type==5){unsigned n=f->type==1?8:4;const uint8_t *p=qq_take(r,n);if(p)for(unsigned i=0;i<n;++i)f->value|=(uint64_t)p[i]<<(i*8);}
    else if(f->type==2){uint64_t n=read_varint(r);if(n>UINT32_MAX){r->ok=0;return 0;}f->bytes.size=(uint32_t)n;f->bytes.data=qq_take(r,(uint32_t)n);}
    else r->ok=0;return r->ok;
}
int qq_pb_find(qq_view v,unsigned tag,qq_field *f)
{qq_reader r={v.data,v.size,0,1};while(qq_pb_next(&r,f))if(f->tag==tag)return 1;return 0;}
void qq_jce_head(qq_writer *w,unsigned tag,unsigned type)
{if(tag>255||type>13){w->ok=0;return;}qq_num(w,(tag<15?tag:15)<<4|type,1);if(tag>=15)qq_num(w,tag,1);}
void qq_jce_int(qq_writer *w,unsigned tag,int64_t x)
{unsigned n=x>=-128&&x<=127?1:x>=-32768&&x<=32767?2:x>=INT32_MIN&&x<=INT32_MAX?4:8;if(!x){qq_jce_head(w,tag,12);return;}qq_jce_head(w,tag,n==1?0:n==2?1:n==4?2:3);qq_num(w,(uint64_t)x,n);}
void qq_jce_string(qq_writer *w,unsigned tag,qq_view v)
{qq_jce_head(w,tag,v.size<256?6:7);qq_num(w,v.size,v.size<256?1:4);qq_put(w,v.data,v.size);}
void qq_jce_bytes(qq_writer *w,unsigned tag,qq_view v)
{qq_jce_head(w,tag,13);qq_jce_head(w,0,0);qq_jce_int(w,0,v.size);qq_put(w,v.data,v.size);}
static int jce_next(qq_reader *r,qq_jce_field *f,unsigned depth)
{
    if(!r->ok||r->at==r->size)return 0;if(depth>16){r->ok=0;return 0;}
    unsigned h=(unsigned)qq_read(r,1);*f=(qq_jce_field){0};f->type=h&15;f->tag=h>>4;if(f->tag==15)f->tag=(unsigned)qq_read(r,1);
    unsigned type=f->type;if(type<=3){unsigned n=1u<<type;uint64_t x=qq_read(r,n);if(n<8&&x&((uint64_t)1<<(n*8-1)))x|=UINT64_MAX<<(n*8);f->value=(int64_t)x;}
    else if(type==4||type==5)qq_take(r,type==4?4:8);
    else if(type==6||type==7){f->bytes.size=(uint32_t)qq_read(r,type==6?1:4);f->bytes.data=qq_take(r,f->bytes.size);}
    else if(type==8||type==9||type==13){
        if(type==13&&qq_read(r,1)!=0){r->ok=0;return 0;}qq_jce_field count;
        if(!jce_next(r,&count,depth+1)||(count.type>3&&count.type!=12)||count.value<0||count.value>65536){r->ok=0;return 0;}
        f->count=(unsigned)count.value;uint32_t start=r->at;
        if(type==13)qq_take(r,f->count);
        else {unsigned n=f->count*(type==8?2:1);for(unsigned i=0;i<n&&r->ok;++i){qq_jce_field child;if(!jce_next(r,&child,depth+1))r->ok=0;}}
        f->bytes=(qq_view){r->data+start,r->at-start};
    }else if(type==10){uint32_t start=r->at;int ended=0;while(r->ok&&r->at<r->size){qq_jce_field child;uint32_t at=r->at;if(!jce_next(r,&child,depth+1))break;if(child.type==11){f->bytes=(qq_view){r->data+start,at-start};ended=1;break;}}if(!ended)r->ok=0;}
    else if(type!=11&&type!=12)r->ok=0;return r->ok;
}
int qq_jce_next(qq_reader *r,qq_jce_field *f){return jce_next(r,f,0);}
int qq_jce_find(qq_view v,unsigned tag,qq_jce_field *f)
{qq_reader r={v.data,v.size,0,1};while(qq_jce_next(&r,f))if(f->tag==tag)return 1;return 0;}
static int equals(qq_view a,const char *b){qq_view v=qq_string(b);if(a.size!=v.size)return 0;for(uint32_t i=0;i<a.size;++i)if(a.data[i]!=v.data[i])return 0;return 1;}
int qq_jce_payload(qq_view packet,const char *key,qq_view *payload)
{
    qq_jce_field f;if(!qq_jce_find(packet,7,&f)||f.type!=13)return 0;
    qq_view data=f.bytes;for(unsigned depth=0;depth<3;++depth){
        if(!qq_jce_find(data,0,&f)||f.type!=8)return 0;unsigned count=f.count;qq_reader r={f.bytes.data,f.bytes.size,0,1};int found=0;
        for(unsigned i=0;i<count;++i){qq_jce_field k,v;if(!qq_jce_next(&r,&k)||!qq_jce_next(&r,&v))return 0;if(!key||equals(k.bytes,key)||depth){f=v;found=1;break;}}
        if(!found)return 0;if(f.type==13){qq_reader inner={f.bytes.data,f.bytes.size,0,1};qq_jce_field body;
            if(qq_jce_next(&inner,&body)&&body.type==10){*payload=body.bytes;return 1;}*payload=f.bytes;return 1;}
        if(f.type!=8)return 0;/* v2 nested map: reconstruct view including its header. */
        data=f.bytes;qq_reader nested={data.data,data.size,0,1};qq_jce_field k,v;
        if(!f.count||!qq_jce_next(&nested,&k)||!qq_jce_next(&nested,&v)||v.type!=13)return 0;
        qq_reader inner={v.bytes.data,v.bytes.size,0,1};qq_jce_field body;if(qq_jce_next(&inner,&body)&&body.type==10)*payload=body.bytes;else *payload=v.bytes;return 1;
    }return 0;
}
int qq_jce_request(qq_writer *out,uint32_t seq,const char *servant,const char *function,const char *key,qq_view body,unsigned packet_type)
{
    uint8_t wrapped[8192],map[8500];qq_writer w={wrapped,0,sizeof wrapped,1};qq_jce_head(&w,0,10);qq_put(&w,body.data,body.size);qq_jce_head(&w,0,11);
    qq_writer m={map,0,sizeof map,1};qq_jce_head(&m,0,8);qq_jce_int(&m,0,1);qq_jce_string(&m,0,qq_string(key));qq_jce_bytes(&m,1,(qq_view){wrapped,w.size});
    qq_jce_int(out,1,3);qq_jce_int(out,2,packet_type);qq_jce_int(out,3,0);qq_jce_int(out,4,seq);qq_jce_string(out,5,qq_string(servant));qq_jce_string(out,6,qq_string(function));qq_jce_bytes(out,7,(qq_view){map,m.size});qq_jce_int(out,8,0);
    for(unsigned i=9;i<=10;++i){qq_jce_head(out,i,8);qq_jce_int(out,0,0);}return w.ok&&m.ok&&out->ok;
}
int qq_tlv_find(qq_view data,unsigned tag,qq_view *v)
{qq_reader r={data.data,data.size,0,1};while(r.ok&&r.at<r.size){unsigned t=(unsigned)qq_read(&r,2),n=(unsigned)qq_read(&r,2);const uint8_t *p=qq_take(&r,n);if(!r.ok)return 0;if(t==tag){*v=(qq_view){p,n};return 1;}}return 0;}
