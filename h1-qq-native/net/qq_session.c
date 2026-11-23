#include "qq_session.h"
#include "qq_crypto.h"
#include "qq_profile.h"
#include "../core/core.h"
static void copy(void *d,const void *s,unsigned n){uint8_t *a=d;const uint8_t *b=s;for(unsigned i=0;i<n;++i)a[i]=b[i];}
static int ticket(qq_ticket *t,qq_view v){if(!v.size||v.size>sizeof t->data)return 0;t->size=(uint16_t)v.size;copy(t->data,v.data,v.size);return 1;}
static uint32_t tlv_begin(qq_writer *w,unsigned tag){qq_num(w,tag,2);uint32_t at=w->size;qq_num(w,0,2);return at;}
static void tlv_end(qq_writer *w,uint32_t at){if(w->size-at-2>65535){w->ok=0;return;}qq_patch(w,at,w->size-at-2,2);}
static void tlv(qq_writer *w,unsigned tag,qq_view v){qq_num(w,tag,2);qq_short(w,v);}
static int md5(qq_view v,uint8_t out[16]){h1qq_bytes z={0,0},d={v.data,v.size};return h1qq_sign_digest(z,z,d,out);}
int qq_qr_credentials(qq_view plain,qq_account *account)
{
    if(plain.size<49||plain.data[8]!=0||plain.data[9]!=0x12)return 0;qq_reader r={plain.data,plain.size,48,1};unsigned skip=(unsigned)qq_read(&r,2);
    if(skip){--skip;if(qq_read(&r,1)==2){if(skip<8)return 0;qq_take(&r,8);skip-=8;}qq_take(&r,skip);}
    qq_read(&r,4);if(qq_read(&r,1)!=0||!r.ok)return 0;
    qq_account next={0};next.uin=qq_read(&r,8);qq_read(&r,4);qq_read(&r,2);if(!r.ok||!next.uin)return 0;
    qq_view records={plain.data+r.at,plain.size-r.at},v;
    if(!qq_tlv_find(records,0x18,&v)||!ticket(&next.tmp_pwd,v)||!qq_tlv_find(records,0x19,&v)||!ticket(&next.tmp_sig,v)||!qq_tlv_find(records,0x1e,&v)||v.size!=16){qq_clear(&next,sizeof next);return 0;}
    copy(next.tgtgt_key,v.data,16);if(qq_tlv_find(records,0x65,&v)&&v.size&&!ticket(&next.qr_ticket,v)){qq_clear(&next,sizeof next);return 0;}
    *account=next;qq_clear(&next,sizeof next);return 1;
}
int qq_qr_unwrap(const uint8_t guid[16],qq_account *a,unsigned *mode)
{
    static const uint8_t fallback[16]={0x25,0x34,0x3b,0x37,0x74,0x3e,0x3b,0x32,0x38,0x3c,0x66,0x63,0x2e,0x35,0x2a,0x36};
    if(!guid||!a||!mode||!a->tmp_pwd.size||a->tmp_pwd.size>sizeof a->tmp_pwd.data)return 0;
    uint8_t joined[2064],plain[2064];unsigned total=a->tmp_pwd.size+16;uint32_t n=0;
    copy(joined,a->tmp_pwd.data,a->tmp_pwd.size);copy(joined+a->tmp_pwd.size,a->tgtgt_key,16);*mode=0;
    if(qq_tea_decrypt(guid,joined,total,plain,sizeof plain,&n)&&n)*mode=1;
    else if(qq_tea_decrypt(fallback,joined,total,plain,sizeof plain,&n)&&n)*mode=2;
    else{copy(plain,joined,total);n=total;*mode=3;}
    int ok=n>=17&&n-16<=sizeof a->tmp_pwd.data;
    if(ok){qq_clear(&a->tmp_pwd,sizeof a->tmp_pwd);a->tmp_pwd.size=(uint16_t)(n-16);copy(a->tmp_pwd.data,plain,n-16);copy(a->tgtgt_key,plain+n-16,16);}
    qq_clear(joined,sizeof joined);qq_clear(plain,sizeof plain);return ok;
}
int qq_oicq_open(const qq_qr_session *s,const qq_account *a,qq_view packet,uint8_t *out,uint32_t cap,qq_view *body)
{
    if(!s||!out||!body||packet.size<18||packet.data[0]!=2||packet.data[packet.size-1]!=3)return 0;
    uint32_t n=0;qq_view encrypted={packet.data+16,packet.size-17};unsigned type=packet.data[14];int ok=0;
    if(type==0)ok=qq_tea_decrypt(s->share_key,encrypted.data,encrypted.size,out,cap,&n)||qq_tea_decrypt(s->random_key,encrypted.data,encrypted.size,out,cap,&n);
    else if(type==3&&a)ok=qq_tea_decrypt(a->wt_key,encrypted.data,encrypted.size,out,cap,&n);
    if(!ok)return 0;*body=(qq_view){out,n};return 1;
}
int qq_oicq_wrap(const qq_qr_session *s,uint64_t uin,unsigned command,qq_view inner,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!s||!out||!size||cap<118)return 0;qq_writer w={out,0,cap,1};qq_num(&w,2,1);qq_num(&w,0,2);qq_num(&w,8001,2);qq_num(&w,command,2);qq_num(&w,1,2);qq_num(&w,uin,4);
    qq_num(&w,3,1);qq_num(&w,0x87,1);qq_num(&w,0,1);qq_num(&w,2,4);qq_put(&w,0,8);qq_num(&w,2,1);qq_num(&w,1,1);qq_put(&w,s->random_key,16);qq_num(&w,0x131,2);qq_num(&w,s->key_version,2);qq_short(&w,(qq_view){s->public_key,65});
    uint32_t n=0;if(!w.ok||!qq_tea_encrypt(s->share_key,inner.data,inner.size,s->pad,w.data+w.size,w.capacity-w.size-1,&n))return 0;w.size+=n;qq_num(&w,3,1);if(w.size>65535)return 0;qq_patch(&w,1,w.size,2);if(!w.ok)return 0;*size=w.size;return 1;
}
static int device_tlvs(const qq_qr_session *s,const qq_account *a,uint8_t *out,unsigned cap,unsigned *n)
{
    uint8_t inner[1600],device[512],digest[16];char id[33];static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i){id[2*i]=hex[s->guid[i]>>4];id[2*i+1]=hex[s->guid[i]&15];}id[32]=0;
    qq_writer pb={device,0,sizeof device,1};const char *values[]={"unknown","Linux version 3.0.0","REL","5891938","BBK/H1/H1:7.1.2/REL/5891938:user/release-keys",id,id,"", "5891938"};
    for(unsigned i=0;i<9;++i)qq_pb_bytes(&pb,i+1,qq_string(values[i]));
    qq_writer w={inner,0,sizeof inner,1};qq_num(&w,5,2);md5(qq_string(id),digest);tlv(&w,0x109,(qq_view){digest,16});tlv(&w,0x52d,(qq_view){device,pb.size});
    uint32_t at=tlv_begin(&w,0x124);qq_short(&w,qq_string("android"));qq_short(&w,qq_string("7.1.2"));qq_num(&w,2,2);qq_short(&w,qq_string("China Mobile GSM"));qq_short(&w,(qq_view){0,0});qq_short(&w,qq_string("wifi"));tlv_end(&w,at);
    at=tlv_begin(&w,0x128);qq_num(&w,0,2);qq_num(&w,0,1);qq_num(&w,1,1);qq_num(&w,0,1);qq_num(&w,0x01000000,4);qq_short(&w,qq_string("H1"));qq_short(&w,(qq_view){s->guid,16});qq_short(&w,qq_string("BBK"));tlv_end(&w,at);tlv(&w,0x16e,qq_string("H1"));
    uint32_t written=0;int ok=w.ok&&pb.ok&&qq_tea_encrypt(a->tgtgt_key,inner,w.size,s->pad,out,cap,&written);qq_clear(inner,sizeof inner);qq_clear(digest,16);if(ok)*n=written;return ok;
}
int qq_login_body(const qq_qr_session *s,const qq_account *a,const uint8_t entropy[32],qq_view energy,qq_view qimei,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!s||!a||!a->uin||!a->tmp_pwd.size||!a->tmp_sig.size||!entropy||!energy.data||!energy.size||energy.size>2048||qimei.size>64)return 0;
    uint8_t encoded[2048],digest[16];unsigned n=0;if(!device_tlvs(s,a,encoded,sizeof encoded,&n))return 0;
    qq_writer w={out,0,cap,1};qq_num(&w,9,2);qq_num(&w,24,2);uint32_t at=tlv_begin(&w,0x18);qq_num(&w,1,2);qq_num(&w,1536,4);qq_num(&w,16,4);qq_num(&w,0,4);qq_num(&w,a->uin,4);qq_num(&w,0,4);tlv_end(&w,at);
    at=tlv_begin(&w,1);qq_num(&w,1,2);qq_put(&w,entropy,4);qq_num(&w,a->uin,4);qq_num(&w,s->seconds,4);qq_num(&w,0,4);qq_num(&w,0,2);tlv_end(&w,at);
    tlv(&w,0x106,(qq_view){a->tmp_pwd.data,a->tmp_pwd.size});
    at=tlv_begin(&w,0x116);qq_num(&w,0,1);qq_num(&w,QQ_NATIVE_MISC_BITMAP,4);qq_num(&w,0x10400,4);qq_num(&w,0,1);tlv_end(&w,at);
    at=tlv_begin(&w,0x100);qq_num(&w,1,2);qq_num(&w,QQ_NATIVE_SSO_VERSION,4);qq_num(&w,16,4);qq_num(&w,QQ_NATIVE_SUB_APP_ID,4);qq_num(&w,0,4);qq_num(&w,QQ_NATIVE_MAIN_SIGMAP,4);tlv_end(&w,at);
    at=tlv_begin(&w,0x107);qq_num(&w,0,5);qq_num(&w,1,1);tlv_end(&w,at);
    at=tlv_begin(&w,0x142);qq_num(&w,0,2);qq_short(&w,qq_string(QQ_NATIVE_APK_ID));tlv_end(&w,at);
    tlv(&w,0x144,(qq_view){encoded,n});tlv(&w,0x145,(qq_view){s->guid,16});
    static const uint8_t signature[16]={0xa6,0xb7,0x45,0xbf,0x24,0xa2,0xc2,0x77,0x52,0x77,0x16,0xf6,0xf3,0x6e,0xb6,0x8d};
    at=tlv_begin(&w,0x147);qq_num(&w,16,4);qq_short(&w,qq_string(QQ_NATIVE_VERSION));qq_short(&w,(qq_view){signature,16});tlv_end(&w,at);
    tlv(&w,0x16a,(qq_view){a->tmp_sig.data,a->tmp_sig.size});at=tlv_begin(&w,0x154);qq_num(&w,s->sequence,4);tlv_end(&w,at);
    at=tlv_begin(&w,0x141);qq_num(&w,1,2);qq_short(&w,qq_string("China Mobile GSM"));qq_num(&w,2,2);qq_short(&w,qq_string("wifi"));tlv_end(&w,at);
    at=tlv_begin(&w,8);qq_num(&w,0,2);qq_num(&w,2052,4);qq_num(&w,0,2);tlv_end(&w,at);
    static const char *domains[]={"tenpay.com","openmobile.qq.com","docs.qq.com","connect.qq.com","qzone.qq.com","vip.qq.com","qun.qq.com","game.qq.com","qqweb.qq.com","office.qq.com","ti.qq.com","mail.qq.com","gamecenter.qq.com","mma.qq.com"};
    at=tlv_begin(&w,0x511);qq_num(&w,sizeof domains/sizeof *domains,2);for(unsigned i=0;i<sizeof domains/sizeof *domains;++i){qq_num(&w,1,1);qq_short(&w,qq_string(domains[i]));}tlv_end(&w,at);
    md5(qq_string("02:00:00:00:00:00"),digest);tlv(&w,0x187,(qq_view){digest,16});
    char android_id[33];static const char hex[]="0123456789abcdef";for(unsigned i=0;i<16;++i){android_id[2*i]=hex[s->guid[i]>>4];android_id[2*i+1]=hex[s->guid[i]&15];}android_id[32]=0;
    md5(qq_string(android_id),digest);tlv(&w,0x188,(qq_view){digest,16});
    at=tlv_begin(&w,0x191);qq_num(&w,0x82,1);tlv_end(&w,at);
    at=tlv_begin(&w,0x177);qq_num(&w,1,1);qq_num(&w,QQ_NATIVE_BUILD_TIME,4);qq_short(&w,qq_string(QQ_NATIVE_SDK));tlv_end(&w,at);
    at=tlv_begin(&w,0x516);qq_num(&w,0,4);tlv_end(&w,at);at=tlv_begin(&w,0x521);qq_num(&w,QQ_NATIVE_DEVICE_TYPE,4);qq_num(&w,0,2);tlv_end(&w,at);
    tlv(&w,0x318,(qq_view){a->qr_ticket.data,a->qr_ticket.size});tlv(&w,0x544,energy);tlv(&w,0x545,qimei);static const uint8_t t542[]={0x4a,2,0x60,1};tlv(&w,0x542,(qq_view){t542,4});
    qq_clear(encoded,sizeof encoded);qq_clear(digest,16);if(!w.ok)return 0;qq_patch(&w,2,25,2);*size=w.size;return 1;
}
static int rejection_text(qq_view v,unsigned skip,char error[256])
{
    qq_reader r={v.data,v.size,0,1};qq_take(&r,skip);unsigned n=(unsigned)qq_read(&r,2);const uint8_t *p=qq_take(&r,n);qq_view title={p,n};n=(unsigned)qq_read(&r,2);p=qq_take(&r,n);if(!r.ok)return 0;
    if(title.size&&n){qq_copy_text(error,128,title);unsigned used=0;while(error[used])++used;error[used++]=':';error[used++]=' ';qq_copy_text(error+used,256-used,(qq_view){p,n});}
    else qq_copy_text(error,256,n?(qq_view){p,n}:title);return 1;
}
int qq_login_result(qq_account *a,qq_view plain,uint8_t *scratch,uint32_t cap,unsigned *status,char error[256])
{
    if(!a||plain.size<5)return 0;*status=plain.data[2];error[0]=0;qq_view records={plain.data+5,plain.size-5},v;
    if(*status){if(qq_tlv_find(records,0x149,&v))rejection_text(v,2,error);if(!error[0]&&qq_tlv_find(records,0x146,&v))rejection_text(v,4,error);return 1;}
    if(!qq_tlv_find(records,0x119,&v))return 0;uint32_t n=0;if(!qq_tea_decrypt(a->tgtgt_key,v.data,v.size,scratch,cap,&n)||n<2)return 0;records=(qq_view){scratch+2,n-2};
    qq_ticket tgt={0},d2={0};uint8_t d2_key[16];
    if(!qq_tlv_find(records,0x10a,&v)||!ticket(&tgt,v)||!qq_tlv_find(records,0x143,&v)||!ticket(&d2,v)||!qq_tlv_find(records,0x305,&v)||v.size!=16){qq_clear(&tgt,sizeof tgt);qq_clear(&d2,sizeof d2);qq_clear(scratch,n);return 0;}
    copy(d2_key,v.data,16);a->tgt=tgt;a->d2=d2;copy(a->d2_key,d2_key,16);
    if(qq_tlv_find(records,0x108,&v)&&v.size<=sizeof a->ksid){copy(a->ksid,v.data,v.size);a->ksid_size=v.size;}
    if(qq_tlv_find(records,0x134,&v)&&v.size==16)copy(a->wt_key,v.data,16);
    if(qq_tlv_find(records,0x11a,&v)&&v.size>=5){unsigned length=v.data[4];if(length<=v.size-5)qq_copy_text(a->nickname,sizeof a->nickname,(qq_view){v.data+5,length});}
    a->authenticated=1;qq_clear(&a->tmp_pwd,sizeof a->tmp_pwd);qq_clear(&a->tmp_sig,sizeof a->tmp_sig);qq_clear(&a->qr_ticket,sizeof a->qr_ticket);
    qq_clear(&tgt,sizeof tgt);qq_clear(&d2,sizeof d2);qq_clear(d2_key,16);qq_clear(scratch,n);return 1;
}
static qq_view decimal(uint64_t x,char s[21])
{char r[20];unsigned n=0;do{r[n++]=(char)('0'+x%10);x/=10;}while(x);for(unsigned i=0;i<n;++i)s[i]=r[n-1-i];s[n]=0;return(qq_view){(const uint8_t *)s,n};}
int qq_session_packet(qq_packet_work *work,const qq_qr_session *s,const qq_account *a,unsigned login_type,const char *command,qq_view body,qq_view reserve,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!work||!s||!a||!command||!out||!size)return 0;qq_writer w={work->plain,0,sizeof work->plain,1};qq_num(&w,0,4);
    if(login_type){qq_num(&w,s->sequence,4);qq_num(&w,QQ_NATIVE_SUB_APP_ID,4);qq_num(&w,QQ_NATIVE_SUB_APP_ID,4);static const uint8_t dummy[12]={1,0,0,0,0,0,0,0,0,0,1,0};qq_put(&w,dummy,12);qq_long(&w,(qq_view){a->tgt.data,a->tgt.size});}
    qq_long(&w,qq_string(command));qq_long(&w,(qq_view){a->session_id,4});
    if(login_type){char id[33];qq_native_device_id(s->guid,id);qq_long(&w,qq_string(id));qq_num(&w,4,4);qq_num(&w,a->ksid_size+2,2);qq_put(&w,a->ksid,a->ksid_size);}
    /* Legacy Watch simple packets have no reserve slot unless command signing
     * is required. Caller indicates that with reserve.data, even if size zero. */
    if(reserve.data)qq_long(&w,reserve);qq_num(&w,4,4);qq_patch(&w,0,w.size,4);qq_long(&w,body);if(!w.ok)return 0;
    uint8_t zero[16]={0};unsigned crypt=login_type==2?0:a->authenticated&&a->d2.size?1:2;uint32_t n=0;
    if(!crypt){copy(work->encrypted,work->plain,w.size);n=w.size;}
    else if(!qq_tea_encrypt(crypt==1?a->d2_key:zero,work->plain,w.size,s->pad+9,work->encrypted,sizeof work->encrypted,&n))return 0;
    qq_writer packet={out,0,cap,1};qq_num(&packet,0,4);qq_num(&packet,login_type?10:11,4);qq_num(&packet,crypt,1);
    if(login_type)qq_long(&packet,crypt==1?(qq_view){a->d2.data,a->d2.size}:(qq_view){0,0});else qq_num(&packet,s->sequence,4);
    qq_num(&packet,0,1);char uin[21];qq_long(&packet,decimal(a->uin,uin));qq_put(&packet,work->encrypted,n);qq_patch(&packet,0,packet.size,4);
    if(!packet.ok)return 0;*size=packet.size;return 1;
}
