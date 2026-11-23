/* Algorithms recovered from the pinned Switch release's native components.
 * This target is freestanding C and is compiled directly for the H1 CPU. */
#include "core.h"
#include "febound_tables.h"

static int valid(const h1qq_bit_reader *r)
{return r&&r->available<=32&&r->offset<=r->size&&(!r->size||r->data);}

static int refill(h1qq_bit_reader *r)
{
    uint32_t n=r->size-r->offset;
    if(!n||!r->data)return 0;
    if(n>4)n=4;
    uint32_t value=0;
    for(uint32_t i=0;i<n;++i)value|=(uint32_t)r->data[r->offset+i]<<(8*i);
    r->buffered=value;r->available=n*8;r->offset+=n;
    return 1;
}

static int consume(h1qq_bit_reader *r,unsigned bits,uint32_t *out)
{
    if(bits>32)return 0;
    uint32_t value=0;unsigned shift=0;
    if(bits>r->available){
        shift=r->available;value=shift?r->buffered:0;bits-=shift;
        if(!refill(r)||bits>r->available)return 0;
    }
    uint32_t mask=bits==32?UINT32_MAX:(UINT32_C(1)<<bits)-1;
    value|=(r->buffered&mask)<<shift;
    /* Original reader retains the buffer on a 32-bit masked shift. */
    r->buffered>>=bits&31u;r->available-=bits;*out=value;
    return 1;
}

int h1qq_read_bits(h1qq_bit_reader *reader,unsigned bits,uint32_t *out)
{
    if(!valid(reader)||!out||bits>32)return 0;
    h1qq_bit_reader copy=*reader;uint32_t value;
    if(!consume(&copy,bits,&value))return 0;
    *reader=copy;*out=value;return 1;
}

int h1qq_read_varint(h1qq_bit_reader *reader,unsigned bits,unsigned width,uint64_t *out)
{
    if(!valid(reader)||!out||bits<2||bits>32||(width!=32&&width!=64))return 0;
    h1qq_bit_reader copy=*reader;uint32_t word,continuation=UINT32_C(1)<<(bits-1),mask=continuation-1;
    if(!consume(&copy,bits,&word))return 0;
    uint64_t value=word&mask;unsigned shift=0;
    while(word&continuation){
        shift+=bits-1;
        if(shift>=width||!consume(&copy,bits,&word))return 0;
        value|=(uint64_t)(word&mask)<<shift;
    }
    *reader=copy;*out=width==32?(uint32_t)value:value;return 1;
}

int h1qq_seed_extend(uint32_t words[624],unsigned first,uint32_t *last,uint32_t multiplier)
{
    if(!words||!last||first<1||first>=624)return 0;
    uint32_t value=*last;
    for(unsigned i=first;i<624;++i){value=(value^(value>>30))*multiplier+i;words[i]=value;}
    *last=value;return 1;
}

int h1qq_transform(unsigned selector,const uint8_t *input,uint8_t *output,uint32_t size)
{
    if(selector<1||selector>2||(size&&(!input||!output)))return 0;
    const uint8_t (*table)[16]=febound_tables[selector-1];
    for(uint32_t i=0;i<size;++i){
        unsigned row=(i%16)*2;uint8_t value=input[i];
        output[i]=(uint8_t)((table[row][value>>4]<<4)|table[row+1][value&15]);
    }
    return 1;
}

#include "encoder_tables.h"
typedef struct {uint32_t words[624];unsigned index;} encoder_random;
static void encoder_seed(encoder_random *state,uint32_t seed)
{
    state->words[0]=seed;state->index=0;
    for(unsigned i=1;i<624;++i){seed=(seed^(seed>>30))*UINT32_C(0x6c078965)+i;state->words[i]=seed;}
}
static uint8_t encoder_byte(encoder_random *state)
{
    unsigned i=state->index,next=(i+1)%624;
    uint32_t a=state->words[i],b=state->words[next];
    uint32_t x=state->words[(i+397)%624]^(((a&0x80000000u)|(b&0x7ffffffeu))>>1);
    if(b&1)x^=0x9908b0dfu;
    state->words[i]=x;state->index=next;
    x^=x>>11;x^=(x<<7)&0x9d2c5680u;x^=(x<<15)&0xefc60000u;x^=x>>18;
    return (uint8_t)((x&127)+1);
}
static uint32_t encoder_load(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void encoder_store(uint8_t *p,uint32_t x)
{for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(x>>(8*i));}
/* The original uses a left shift, rather than MD5's rotate, and repeats the
 * first round's shift schedule in every round. Preserve these differences. */
static void encoder_digest(const uint8_t prefix[8],h1qq_bytes data,uint8_t out[8])
{
    uint8_t block[64]={0};uint32_t words[16];
    for(unsigned i=0;i<data.size;++i)block[i]=data.data[i];
    for(unsigned i=0;i<8;++i)block[i+data.size]=prefix[i];
    block[data.size+8]=128;unsigned bits=(data.size+8)*8;block[56]=(uint8_t)bits;block[57]=(uint8_t)(bits>>8);
    for(unsigned i=0;i<16;++i)words[i]=encoder_load(block+i*4);
    uint32_t a=0x67452301u,b=0xefcdab89u,c=0x98badcfeu,d=0x10325476u;
    static const unsigned shifts[4]={7,12,17,22};
    for(unsigned i=0;i<64;++i){
        uint32_t f;unsigned g;
        if(i<16){f=(b&c)|(~b&d);g=i;}
        else if(i<32){f=(d&b)|(~d&c);g=(i*5+1)&15;}
        else if(i<48){f=b^c^d;g=(i*3+5)&15;}
        else {f=c^(b|~d);g=(i*7)&15;}
        uint32_t next=b+((a+f+encoder_constants[i]+words[g])<<shifts[i&3]);
        a=d;d=c;c=b;b=next;
    }
    encoder_store(out,a+0x67452301u);encoder_store(out+4,b+0xefcdab89u);
}
static unsigned encoder_hex(uint8_t *out,uint32_t value)
{
    static const uint8_t hex[]="0123456789abcdef";unsigned digits=1;
    for(uint32_t x=value;x>=16;x>>=4)++digits;
    for(unsigned i=0;i<digits;++i)out[digits-1-i]=hex[(value>>(i*4))&15];
    return digits;
}
/* Buckets are ten bytes apart, even when a bucket contains more than ten
 * bytes. This overlap is observable in the original encoder's output. */
static void encoder_sort(uint8_t text[16])
{
    unsigned maximum=0;for(unsigned i=0;i<16;++i)if(text[i]>maximum)maximum=text[i];
    for(unsigned divisor=1;divisor<=maximum;divisor*=10){
        uint8_t buckets[106]={0},count[10]={0};
        for(unsigned i=0;i<16;++i){unsigned digit=text[i]/divisor%10;buckets[digit*10+count[digit]++]=text[i];}
        unsigned n=0;for(unsigned digit=0;digit<10;++digit)
            for(unsigned i=0;i<count[digit];++i)text[n++]=buckets[digit*10+i];
    }
}
static int encode_data(h1qq_bytes data,uint32_t random_seed,
    uint32_t seconds,uint32_t mask_seed,uint32_t environment_word,uint8_t output[68])
{
    if(data.size>47||(!data.data&&data.size)||!output)return 0;
    encoder_random random;uint8_t payload[64]={12,25,0,0,1,10,11,12,1},nonce[9],text[80]={0},key[4];
    encoder_seed(&random,random_seed);
    for(unsigned i=0;i<9;++i)nonce[i]=encoder_byte(&random);
    for(unsigned i=0;i<8;++i)payload[9+i]=nonce[i];
    encoder_digest(nonce,data,payload+17);
    uint32_t values[9];values[0]=environment_word;
    for(unsigned i=1;i<9;++i){seconds=seconds*1103515245u+12345;values[i]=seconds&0x7fffffffu;}
    values[4]=(values[4]&4095)|0x4000;values[5]=(values[5]%16383)|0x8000;
    unsigned length=0;
    for(unsigned i=0;i<9;++i){
        length+=encoder_hex(text+length,values[i]);
        if(i==1||i==2||i==3||i==4||i==7)text[length++]='-';
    }
    encoder_sort(text);
    for(unsigned i=0;i<26;++i)payload[25+i]=text[i];
    uint32_t sum=1;for(unsigned i=4;i<55;++i)sum+=payload[i];sum%=65521;
    payload[2]=(uint8_t)(sum>>8);payload[3]=(uint8_t)sum;
    for(unsigned i=0;i<9;++i)payload[55+i]=nonce[i];
    mask_seed=(mask_seed>>24)|((mask_seed>>8)&0xff00)|((mask_seed<<8)&0xff0000)|(mask_seed<<24);
    encoder_seed(&random,mask_seed);for(unsigned i=0;i<4;++i)key[i]=encoder_byte(&random);
    output[0]=payload[0];output[1]=payload[1];for(unsigned i=0;i<4;++i)output[2+i]=key[i];
    for(unsigned i=0;i<62;++i)output[6+i]=payload[2+i]^key[i&3];
    return 1;
}

int h1qq_encode_sign(const uint8_t digest[16],uint32_t random_seed,
    uint32_t seconds,uint32_t mask_seed,uint32_t environment_word,uint8_t output[68])
{return encode_data((h1qq_bytes){digest,16},random_seed,seconds,mask_seed,environment_word,output);}
int h1qq_encode_data(h1qq_bytes data,const h1qq_sign_clock *clock,uint8_t output[68])
{return clock&&encode_data(data,clock->random_seed,clock->seconds,clock->mask_seed,clock->environment_word,output);}

typedef struct {uint32_t state[4],used;uint64_t size;uint8_t block[64];} sign_digest_state;
static void sign_digest_block(sign_digest_state *s,const uint8_t block[64])
{
    static const unsigned shifts[16]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};
    uint32_t words[16],a=s->state[0],b=s->state[1],c=s->state[2],d=s->state[3];
    for(unsigned i=0;i<16;++i)words[i]=encoder_load(block+i*4);
    for(unsigned i=0;i<64;++i){
        uint32_t f;unsigned g,shift=shifts[(i/16)*4+(i&3)];
        if(i<16){f=(b&c)|(~b&d);g=i;}
        else if(i<32){f=(d&b)|(~d&c);g=(i*5+1)&15;}
        else if(i<48){f=b^c^d;g=(i*3+5)&15;}
        else {f=c^(b|~d);g=(i*7)&15;}
        uint32_t x=a+f+encoder_constants[i]+words[g];
        uint32_t next=b+((x<<shift)|(x>>(32-shift)));
        a=d;d=c;c=b;b=next;
    }
    s->state[0]+=a;s->state[1]+=b;s->state[2]+=c;s->state[3]+=d;
}
static void sign_digest_update(sign_digest_state *s,h1qq_bytes bytes)
{
    s->size+=bytes.size;
    while(bytes.size){
        if(!s->used&&bytes.size>=64){sign_digest_block(s,bytes.data);bytes.data+=64;bytes.size-=64;continue;}
        unsigned n=64-s->used;if(n>bytes.size)n=bytes.size;
        for(unsigned i=0;i<n;++i)s->block[s->used+i]=bytes.data[i];
        s->used+=n;bytes.data+=n;bytes.size-=n;
        if(s->used==64){sign_digest_block(s,s->block);s->used=0;}
    }
}
int h1qq_sign_digest(h1qq_bytes token,h1qq_bytes extra,h1qq_bytes body,uint8_t digest[16])
{
    if(!digest||(token.size&&!token.data)||(extra.size&&!extra.data)||(body.size&&!body.data))return 0;
    sign_digest_state s={{0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u},0,0,{0}};
    sign_digest_update(&s,token);sign_digest_update(&s,extra);sign_digest_update(&s,body);
    uint64_t bits=s.size*8;s.block[s.used++]=128;
    if(s.used>56){while(s.used<64)s.block[s.used++]=0;sign_digest_block(&s,s.block);s.used=0;}
    while(s.used<56)s.block[s.used++]=0;
    for(unsigned i=0;i<8;++i)s.block[56+i]=(uint8_t)(bits>>(8*i));
    sign_digest_block(&s,s.block);for(unsigned i=0;i<4;++i)encoder_store(digest+i*4,s.state[i]);
    return 1;
}
int h1qq_sign(h1qq_bytes token,h1qq_bytes extra,h1qq_bytes body,
    const h1qq_sign_clock *clock,uint8_t sign[68])
{
    if(!clock||!sign)return 0;
    uint8_t digest[16];if(!h1qq_sign_digest(token,extra,body,digest))return 0;
    return h1qq_encode_sign(digest,clock->random_seed,clock->seconds,clock->mask_seed,clock->environment_word,sign);
}
int h1qq_security_token(h1qq_bytes material,uint8_t token[12])
{
    if(!token)return 0;
    static const uint8_t alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    h1qq_bytes empty={0,0};uint8_t digest[16];
    if(!h1qq_sign_digest(empty,empty,material,digest))return 0;
    for(unsigned i=0;i<3;++i){
        const uint8_t *p=digest+i*3;uint8_t *out=token+i*4;
        out[0]=alphabet[p[0]>>2];out[1]=alphabet[((p[0]&3)<<4)|(p[1]>>4)];
        out[2]=alphabet[((p[1]&15)<<2)|(p[2]>>6)];out[3]=alphabet[p[2]&63];
    }
    return 1;
}
static unsigned extra_varint_size(uint32_t value)
{unsigned n=1;while(value>=128){value>>=7;++n;}return n;}
static unsigned extra_varint(uint8_t *out,uint32_t value)
{
    unsigned n=0;do{uint8_t byte=(uint8_t)(value&127);value>>=7;if(value)byte|=128;out[n++]=byte;}while(value);return n;
}
int h1qq_build_extra(h1qq_bytes qua,h1qq_bytes material,uint8_t *output,
    uint32_t capacity,uint32_t *size)
{
    if(!qua.size||!qua.data||(material.size&&!material.data)||!output||!size)return 0;
    uint64_t required=(uint64_t)qua.size+1+extra_varint_size(qua.size);
    if(material.size)required+=(uint64_t)material.size+1+extra_varint_size(material.size);
    if(required>capacity)return 0;
    uint32_t n=0;output[n++]=18;n+=extra_varint(output+n,qua.size);
    for(unsigned i=0;i<qua.size;++i)output[n++]=qua.data[i];
    if(material.size){output[n++]=26;n+=extra_varint(output+n,material.size);
        for(unsigned i=0;i<material.size;++i)output[n++]=material.data[i];}
    *size=n;return 1;
}

#include "material_tables.h"
static uint8_t material_xtime(uint8_t value)
{return (uint8_t)((value<<1)^((value&128)?0x1b:0));}
static void material_encrypt(uint8_t *data,unsigned size,const uint8_t key[16])
{
    const uint8_t *box=material_sboxes[key[4]%5];uint8_t expanded[176],round=1;
    for(unsigned i=0;i<16;++i)expanded[i]=key[i];
    for(unsigned n=16;n<176;n+=4){
        uint8_t t[4];for(unsigned i=0;i<4;++i)t[i]=expanded[n-4+i];
        if(!(n&15)){
            uint8_t first=t[0];for(unsigned i=0;i<3;++i)t[i]=box[t[i+1]];t[3]=box[first];
            t[0]^=round;round=material_xtime(round);
        }
        for(unsigned i=0;i<4;++i)expanded[n+i]=expanded[n+i-16]^t[i];
    }
    for(unsigned offset=0;offset<size;offset+=16){
        uint8_t state[16],shifted[16];
        for(unsigned i=0;i<16;++i)state[i]=data[offset+i]^expanded[i];
        for(unsigned r=1;r<=10;++r){
            for(unsigned col=0;col<4;++col)for(unsigned row=0;row<4;++row)
                shifted[col*4+row]=box[state[((col+row)&3)*4+row]];
            if(r!=10)for(unsigned col=0;col<4;++col){
                uint8_t *a=shifted+col*4,t=a[0]^a[1]^a[2]^a[3],first=a[0];
                for(unsigned i=0;i<3;++i)a[i]^=t^material_xtime(a[i]^a[i+1]);
                a[3]^=t^material_xtime(a[3]^first);
            }
            for(unsigned i=0;i<16;++i)state[i]=shifted[i]^expanded[r*16+i];
        }
        for(unsigned i=0;i<16;++i)data[offset+i]=state[i];
    }
}
int h1qq_build_material(const uint8_t report[34],uint32_t seconds,
    const uint8_t entropy[5],uint8_t material[144])
{
    if(!report||!entropy||!material)return 0;
    uint8_t inner[48],outer[64]={0},key1[16]={0},key2[16]={0},packed[72];
    encoder_store(inner,seconds^0xde9dc120u);
    for(unsigned i=0;i<34;++i)inner[i+4]=report[i];
    for(unsigned i=38;i<48;++i)inner[i]=10;
    key1[1]=entropy[4];key1[4]=entropy[1];key1[8]=entropy[3];key1[12]=entropy[2];key1[14]=entropy[0];
    key2[0]=entropy[0];key2[4]=entropy[2];key2[7]=entropy[1];key2[10]=entropy[4];key2[13]=entropy[3];
    material_encrypt(inner,sizeof inner,key1);outer[3]=48;
    for(unsigned i=0;i<48;++i)outer[i+5]=inner[i];
    for(unsigned i=53;i<64;++i)outer[i]=11;
    material_encrypt(outer,sizeof outer,key2);packed[0]=0xa3;
    for(unsigned i=0;i<5;++i)packed[i+1]=entropy[i];
    packed[6]=64;packed[7]=0;
    for(unsigned i=0;i<64;++i)packed[i+8]=outer[i];
    static const uint8_t hex[]="0123456789ABCDEF";
    for(unsigned i=0;i<72;++i){material[i*2]=hex[packed[i]>>4];material[i*2+1]=hex[packed[i]&15];}
    return 1;
}
static uint32_t report_be32(const uint8_t *p)
{return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void report_store_be32(uint8_t *p,uint32_t value)
{for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(value>>(24-i*8));}
int h1qq_report_uuid(const uint8_t uuid[16],uint8_t report[34])
{
    if(!uuid||!report)return 0;
    uint8_t out[34]={0x32,0x62};
    for(unsigned i=0;i<16;++i)out[i+2]=uuid[i];
    out[8]=uuid[8];out[9]=uuid[9];out[10]=uuid[6];out[11]=uuid[7];
    uint32_t x=report_be32(uuid)^report_be32(uuid+12),y=report_be32(uuid+4)^report_be32(uuid+8);
    report_store_be32(out+18,y^0x37462913u);report_store_be32(out+22,y^0xa8b36d9fu);
    report_store_be32(out+26,x^0xeeee8888u);report_store_be32(out+30,x^0x29db81fcu);
    for(unsigned i=0;i<34;++i)report[i]=out[i];
    return 1;
}
