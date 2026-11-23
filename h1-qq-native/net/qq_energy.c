#include "qq_energy.h"
#include "qq_energy_tables.h"
#include "qq_codec.h"
#include "qq_profile.h"
#include "../core/core.h"
static void copy(uint8_t *d,const uint8_t *s,unsigned n){for(unsigned i=0;i<n;++i)d[i]=s[i];}
static void be32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(24-8*i));}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint32_t rol(uint32_t n,unsigned k){return n<<k|n>>(32-k);}
/* The Switch deliberately reproduces JS binary64 rounding for its LCG.
 * Real UTC milliseconds fit this bounded integer implementation. */
static uint64_t round53(uint64_t n)
{unsigned bits=0;for(uint64_t v=n;v;v>>=1)++bits;if(bits<=53)return n;unsigned shift=bits-53;uint64_t mask=((uint64_t)1<<shift)-1,half=(uint64_t)1<<(shift-1),tail=n&mask,head=n>>shift;if(tail>half||(tail==half&&(head&1)))++head;return head<<shift;}
static uint32_t random_next(uint64_t *seed)
{uint64_t n=round53(*seed*9301);n=round53(n+49297);*seed=n%233280;return (uint32_t)((*seed*2147483647+233279)/233280);}
static void rc4(uint8_t key[8])
{uint8_t box[256],out[8];for(unsigned i=0;i<256;++i)box[i]=(uint8_t)i;unsigned j=0;for(unsigned i=0;i<256;++i){j=(j+box[i]+key[i&7])&255;uint8_t t=box[i];box[i]=box[j];box[j]=t;}j=0;for(unsigned i=1;i<=8;++i){j=(j+box[i])&255;uint8_t t=box[i];box[i]=box[j];box[j]=t;out[i-1]=key[i-1]^box[(box[i]+box[j])&255];}copy(key,out,8);qq_clear(box,sizeof box);qq_clear(out,8);}
static void quarter(uint32_t x[16],unsigned a,unsigned b,unsigned c,unsigned d)
{x[a]+=x[b];x[d]=rol(x[d]^x[a],16);x[c]+=x[d];x[b]=rol(x[b]^x[c],12);x[a]+=x[b];x[d]=rol(x[d]^x[a],8);x[c]+=x[d];x[b]=rol(x[b]^x[c],7);}
static void crypt_a(uint8_t *data,unsigned size,const uint8_t key[32])
{
    uint32_t initial[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574,0,0,0,0,0,0,0,0,0,0,0xc4675540,0x6eedcf0d},x[16];
    for(unsigned i=0;i<8;++i)initial[i+4]=le32(key+4*i);
    for(unsigned at=0;at<size;){for(unsigned i=0;i<16;++i)x[i]=initial[i];for(unsigned r=0;r<10;++r){quarter(x,0,4,8,12);quarter(x,1,5,9,13);quarter(x,2,6,10,14);quarter(x,3,7,11,15);quarter(x,0,5,10,15);quarter(x,1,6,11,12);quarter(x,2,7,8,13);quarter(x,3,4,9,14);}for(unsigned i=0;i<16;++i)x[i]+=initial[i];for(unsigned i=0;i<64&&at<size;++i,++at)data[at]^=(uint8_t)(x[i/4]>>(8*(i&3)));++initial[12];}
    qq_clear(initial,sizeof initial);qq_clear(x,sizeof x);
}
static uint32_t substitute(uint32_t n)
{return (uint32_t)energy_sbox[n>>24]<<24|(uint32_t)energy_sbox[n>>16&255]<<16|(uint32_t)energy_sbox[n>>8&255]<<8|energy_sbox[n&255];}
static void crypt_b(uint8_t block[16],const uint32_t keys[44])
{
    static const uint8_t key_map[16]={3,6,9,12,7,10,13,0,11,14,1,4,15,2,5,8};uint8_t temp[16],kb[16];
    for(unsigned r=0;r<10;++r){
        copy(temp,block,16);for(unsigned i=0;i<16;++i)block[i]=temp[energy_permute[i]];
        for(unsigned i=0;i<4;++i){uint32_t v=keys[4*r+i];for(unsigned j=0;j<4;++j)kb[4*i+j]=(uint8_t)(v>>(8*j));}
        for(unsigned i=0;i<16;++i)block[i]=energy_sbox[block[i]^kb[key_map[i]]];
        if(r<9)for(unsigned i=0;i<16;i+=4){uint8_t a=block[i],b=block[i+1],c=block[i+2],d=block[i+3];block[i]=c^d^energy_mix[a*6]^energy_mix[b*6+1];block[i+1]=a^d^energy_mix[b*6]^energy_mix[c*6+1];block[i+2]=a^b^energy_mix[d*6+1]^energy_mix[c*6];block[i+3]=b^c^energy_mix[a*6+1]^energy_mix[d*6];}
    }
    for(unsigned i=0;i<16;++i)block[i]^=(uint8_t)(keys[40+i/4]>>(24-8*(i&3)));qq_clear(temp,16);qq_clear(kb,16);
}
static void transform(uint8_t bytes[21],const uint8_t table[512])
{for(unsigned i=0;i<21;++i)bytes[i]=(uint8_t)(table[((2*i)&31)*16+(bytes[i]>>4)]<<4|table[((2*i+1)&31)*16+(bytes[i]&15)]);}
static int energy(uint64_t ms,const uint8_t *salt,unsigned salt_size,uint8_t out[39])
{
    if(ms>(UINT64_MAX-49297)/9301||salt_size>156)return 0;uint64_t seed=ms;uint32_t time=(uint32_t)(ms%1000000);uint8_t kt[40]={0},data[160],crc[21]={0},hash[16];
    copy(data,salt,salt_size);be32(data+salt_size,time);kt[0]=energy_rng_chars[random_next(&seed)%50]+50;kt[1]=energy_rng_chars[random_next(&seed)%50]+50;kt[2]=kt[1]+20;kt[3]=kt[2]+20;
    static const uint8_t k1[]="a$(e",k2[]="&O9!";copy(kt+6,k1,4);for(unsigned i=0;i<4;++i)kt[10+i]=k2[i]^kt[i];kt[4]=kt[12];kt[5]=kt[13];kt[12]=kt[13]=0;rc4(kt+4);crypt_a(data,salt_size+4,kt+4);
    h1qq_bytes empty={0,0},input={data,salt_size+4};int ok=h1qq_sign_digest(empty,empty,input,hash);if(!ok)goto done;
    crc[2]=1;copy(crc+5,kt,4);be32(crc+9,time);copy(crc+13,hash,8);uint32_t sum=~0u;for(unsigned i=2;i<21;++i)sum=energy_crc[(sum^crc[i])&255]^(sum>>8);sum=~sum;crc[0]=(uint8_t)sum;crc[1]=(uint8_t)(sum>>24);
    uint32_t nonce=random_next(&seed);nonce^=random_next(&seed);nonce^=random_next(&seed);uint8_t counter[16],block[16];for(unsigned i=0;i<4;++i)be32(counter+4*i,nonce);
    uint32_t keys[44];for(unsigned i=0;i<4;++i)keys[i]=energy_key_words[i];for(unsigned i=4;i<44;++i){uint32_t v=keys[i-1];if(!(i&3))v=substitute(rol(v,8))^energy_round_constants[i/4-1];keys[i]=keys[i-4]^v;}
    transform(crc,energy_encode);out[0]=12;out[1]=5;be32(out+2,nonce);
    for(unsigned i=0;i<21;++i){if(!(i&15)){copy(block,counter,16);crypt_b(block,keys);for(unsigned j=16;j;--j)if(++counter[j-1])break;}unsigned at=(i&15)*512;out[6+i]=(uint8_t)(energy_combine[at+(crc[i]>>4)*16+(block[i&15]>>4)]<<4|energy_combine[at+256+(crc[i]&15)*16+(block[i&15]&15)]);}
    transform(out+6,energy_decode);for(unsigned i=27;i<39;++i)out[i]=0;out[31]=energy_tail_chars[random_next(&seed)%50];out[32]=energy_tail_chars[random_next(&seed)%50];unsigned add=0;for(unsigned i=0;i<64&&!(add&1);++i)add=random_next(&seed)%9;
    if(!(add&1))ok=0;else{out[33]=(uint8_t)(out[31]+add);out[34]=(uint8_t)(out[32]+10-add);}
    qq_clear(keys,sizeof keys);qq_clear(counter,16);qq_clear(block,16);
done:qq_clear(kt,sizeof kt);qq_clear(data,sizeof data);qq_clear(crc,sizeof crc);qq_clear(hash,16);if(!ok)qq_clear(out,39);return ok;
}
int qq_legacy_energy_login(uint64_t ms,uint32_t uin,const uint8_t guid[16],uint8_t out[39])
{if(!guid||!out||!uin)return 0;uint8_t salt[64];qq_writer w={salt,0,sizeof salt,1};/* v9 uses the sign-extended high UIN word, matching Switch 0xa71ac. */qq_num(&w,(uint32_t)((int32_t)uin>>31),4);qq_short(&w,(qq_view){guid,16});qq_short(&w,qq_string("6.0.0.2559"));qq_num(&w,9,4);qq_num(&w,0,4);int ok=w.ok&&energy(ms,salt,w.size,out);qq_clear(salt,sizeof salt);return ok;}
int qq_energy_login(const h1qq_sign_clock *clock,uint32_t uin,const uint8_t guid[16],uint8_t out[68])
{if(!clock||!guid||!out)return 0;uint8_t salt[64];qq_writer w={salt,0,sizeof salt,1};qq_num(&w,(uint32_t)((int32_t)uin>>31),4);qq_short(&w,(qq_view){guid,16});qq_short(&w,qq_string(QQ_NATIVE_SDK));qq_num(&w,9,4);qq_num(&w,0,4);int ok=w.ok&&h1qq_encode_data((h1qq_bytes){salt,w.size},clock,out);qq_clear(salt,sizeof salt);return ok;}
