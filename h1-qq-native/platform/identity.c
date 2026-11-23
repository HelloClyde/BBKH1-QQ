#include "identity.h"

static uint32_t load32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void store32(uint8_t *p,uint32_t x)
{for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(x>>(8*i));}
static uint32_t rotate(uint32_t x,unsigned n){return x<<n|x>>(32-n);}
static void quarter(uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d)
{
    *a+=*b;*d=rotate(*d^*a,16);*c+=*d;*b=rotate(*b^*c,12);
    *a+=*b;*d=rotate(*d^*a,8);*c+=*d;*b=rotate(*b^*c,7);
}
/* Independently written from RFC 8439 section 2.3 (no QQ algorithm changes). */
void h1qq_chacha20_block(const uint8_t key[32],uint32_t counter,
    const uint8_t nonce[12],uint8_t output[64])
{
    uint32_t initial[16]={0x61707865u,0x3320646eu,0x79622d32u,0x6b206574u},s[16];
    for(unsigned i=0;i<8;++i)initial[4+i]=load32(key+4*i);
    initial[12]=counter;
    for(unsigned i=0;i<3;++i)initial[13+i]=load32(nonce+4*i);
    for(unsigned i=0;i<16;++i)s[i]=initial[i];
    for(unsigned i=0;i<10;++i){
        quarter(s,s+4,s+8,s+12);quarter(s+1,s+5,s+9,s+13);
        quarter(s+2,s+6,s+10,s+14);quarter(s+3,s+7,s+11,s+15);
        quarter(s,s+5,s+10,s+15);quarter(s+1,s+6,s+11,s+12);
        quarter(s+2,s+7,s+8,s+13);quarter(s+3,s+4,s+9,s+14);
    }
    for(unsigned i=0;i<16;++i)store32(output+4*i,s[i]+initial[i]);
}
static uint32_t crc32(const uint8_t *p,unsigned n)
{
    uint32_t crc=~0u;
    for(unsigned i=0;i<n;++i){crc^=p[i];for(unsigned j=0;j<8;++j)crc=(crc>>1)^(0xedb88320u&(0u-(crc&1)));}
    return ~crc;
}
static int equal(const uint8_t *a,const uint8_t *b,unsigned n)
{unsigned difference=0;for(unsigned i=0;i<n;++i)difference|=a[i]^b[i];return !difference;}
void h1qq_identity_close(h1qq_identity *state)
{
    if(state){volatile uint8_t *p=(volatile uint8_t *)state;for(unsigned i=0;i<sizeof *state;++i)p[i]=0;}
}
int h1qq_identity_open(h1qq_identity *state,const h1qq_identity_io *io)
{
    static const uint8_t magic[8]={'H','1','Q','Q','I','D','1',0};
    uint8_t record[H1QQ_IDENTITY_SIZE],check[H1QQ_IDENTITY_SIZE],nonce[12]={0},block[64];
    h1qq_identity next={0};
    if(!state)return 0;
    h1qq_identity_close(state);
    if(!io||!io->read||!io->write||!io->read(io->context,record))return 0;
    uint32_t flags=load32(record+72);
    if(!equal(record,magic,8)||load32(record+76)!=crc32(record,76)||flags>3)return 0;
    next.utc_offset_minutes=(int32_t)load32(record+64);
    next.clock_adjustment_seconds=(int32_t)load32(record+68);next.clock_calibrated=(flags>>1)&1;
    if(!next.clock_calibrated&&next.clock_adjustment_seconds)return 0;
    if(next.utc_offset_minutes < -840||next.utc_offset_minutes>840)return 0;
    unsigned nonzero=0;
    for(unsigned i=0;i<32;++i){next.key[i]=record[24+i];nonzero|=next.key[i];}
    if(!nonzero)return 0;
    next.session=(uint64_t)load32(record+56)|((uint64_t)load32(record+60)<<32);
    if(next.session==UINT64_MAX)return 0;
    if(!(flags&1)){
        if(next.session)return 0;
        for(unsigned i=0;i<16;++i)if(record[8+i])return 0;
        h1qq_chacha20_block(next.key,0,nonce,block);
        for(unsigned i=0;i<16;++i)record[8+i]=block[i];
        record[14]=(record[14]&15)|0x40;record[16]=(record[16]&63)|0x80;
        store32(record+72,flags|1);
    }else if(!next.session||(record[14]&0xf0)!=0x40||(record[16]&0xc0)!=0x80)return 0;
    for(unsigned i=0;i<16;++i)next.uuid[i]=record[8+i];
    ++next.session;store32(record+56,(uint32_t)next.session);store32(record+60,(uint32_t)(next.session>>32));
    store32(record+76,crc32(record,76));
    /* Reserve the entire session before using its stream. Never silently fall
     * back to an older record or generate a weak identity on an I/O failure. */
    if(!io->write(io->context,record)||!io->read(io->context,check)||!equal(record,check,sizeof record))return 0;
    next.ready=1;*state=next;return 1;
}
int h1qq_identity_random(h1qq_identity *state,uint8_t *out,uint32_t n)
{
    if(!state||!state->ready||(!out&&n))return 0;
    /* Check exhaustion before changing either state or output. */
    uint64_t capacity=(uint64_t)(UINT32_MAX-state->counter)*64+state->available;
    if(n>capacity)return 0;
    while(n){
        if(!state->available){
            uint8_t nonce[12]={0};store32(nonce,(uint32_t)state->session);store32(nonce+4,(uint32_t)(state->session>>32));
            h1qq_chacha20_block(state->key,state->counter++,nonce,state->buffer);state->available=64;
        }
        unsigned count=n<state->available?n:state->available;
        for(unsigned i=0;i<count;++i)out[i]=state->buffer[64-state->available+i];
        out+=count;n-=count;state->available-=count;
    }
    return 1;
}
int h1qq_identity_utc(const h1qq_identity *state,uint32_t local_seconds,uint32_t *utc)
{
    if(!state||!state->ready||!utc||local_seconds<946684800u||local_seconds>=4102444800u)return 0;
    int64_t value=(int64_t)local_seconds-(int64_t)state->utc_offset_minutes*60+state->clock_adjustment_seconds;
    if(value<946684800||value>=4102444800LL)return 0;
    *utc=(uint32_t)value;return 1;
}
