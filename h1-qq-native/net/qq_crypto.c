#include "qq_crypto.h"
#include "../core/core.h"
#include "../third_party/micro-ecc/uECC.h"
static uint32_t be32(const uint8_t *p)
{return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void put32(uint8_t *p,uint32_t x){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(x>>(24-8*i));}
static void erase(void *p,unsigned n){volatile uint8_t *b=p;while(n--)*b++=0;}
int qq_ecdh(const uint8_t private_key[32],const uint8_t server_key[65],uint8_t public_key[65],uint8_t share_key[16])
{return qq_ecdh_with_rng(private_key,server_key,public_key,share_key,0);}
int qq_ecdh_with_rng(const uint8_t private_key[32],const uint8_t server_key[65],uint8_t public_key[65],uint8_t share_key[16],int (*rng)(uint8_t *,unsigned))
{
    uint8_t public_bytes[64],secret[32],digest[16];
    if(!private_key||!server_key||!public_key||!share_key||server_key[0]!=4)return 0;
    uECC_Curve curve=uECC_secp256r1();uECC_set_rng(rng);
    if(!uECC_valid_public_key(server_key+1,curve)||!uECC_compute_public_key(private_key,public_bytes,curve)||
       !uECC_shared_secret(server_key+1,private_key,secret,curve)){uECC_set_rng(0);erase(secret,sizeof secret);return 0;}
    uECC_set_rng(0);
    h1qq_bytes empty={0,0},data={secret,16};int ok=h1qq_sign_digest(empty,empty,data,digest);erase(secret,sizeof secret);
    if(!ok)return 0;
    public_key[0]=4;for(unsigned i=0;i<64;++i)public_key[i+1]=public_bytes[i];
    for(unsigned i=0;i<16;++i)share_key[i]=digest[i];erase(digest,sizeof digest);return 1;
}
static void tea_block(const uint8_t in[8],uint8_t out[8],const uint8_t key[16],int decrypt)
{
    uint32_t a=be32(in),b=be32(in+4),k[4];for(unsigned i=0;i<4;++i)k[i]=be32(key+4*i);
    uint32_t sum=decrypt?0xe3779b90u:0;
    for(unsigned i=0;i<16;++i){
        if(decrypt){b-=((a<<4)+k[2])^(a+sum)^((a>>5)+k[3]);a-=((b<<4)+k[0])^(b+sum)^((b>>5)+k[1]);sum-=0x9e3779b9u;}
        else{sum+=0x9e3779b9u;a+=((b<<4)+k[0])^(b+sum)^((b>>5)+k[1]);b+=((a<<4)+k[2])^(a+sum)^((a>>5)+k[3]);}
    }
    put32(out,a);put32(out+4,b);
}
int qq_tea_encrypt(const uint8_t key[16],const uint8_t *input,uint32_t n,const uint8_t pad[9],uint8_t *output,uint32_t cap,uint32_t *written)
{
    if(!key||(!input&&n)||!pad||!output||!written)return 0;
    *written=0;
    uint32_t fill=10-(n+1)%8;
    if(n>cap||fill+7>cap-n)return 0;
    uint32_t total=fill+n+7;
    uint8_t previous_c[8]={0},previous_x[8]={0},x[8],c[8];
    for(uint32_t at=0;at<total;at+=8){
        for(unsigned i=0;i<8;++i){uint32_t pos=at+i;uint8_t b=pos==0?(uint8_t)(0xf8u|(fill-3)):pos<fill?pad[pos-1]:pos<fill+n?input[pos-fill]:0;x[i]=b^previous_c[i];}
        tea_block(x,c,key,0);
        for(unsigned i=0;i<8;++i){previous_c[i]=c[i]^previous_x[i];previous_x[i]=x[i];output[at+i]=previous_c[i];}
    }
    *written=total;return 1;
}
int qq_tea_decrypt(const uint8_t key[16],const uint8_t *input,uint32_t n,uint8_t *output,uint32_t cap,uint32_t *written)
{
    if(!key||!input||!output||!written||n<16||(n&7)||n>cap)return 0;
    *written=0;uint8_t previous_c[8]={0},previous_x[8]={0},c[8],x[8];
    for(uint32_t at=0;at<n;at+=8){
        for(unsigned i=0;i<8;++i){c[i]=input[at+i];x[i]=c[i]^previous_x[i];}
        tea_block(x,x,key,1);
        for(unsigned i=0;i<8;++i){output[at+i]=x[i]^previous_c[i];previous_x[i]=x[i];previous_c[i]=c[i];}
    }
    uint32_t start=(output[0]&7)+3;unsigned invalid=start>n-7;
    for(unsigned i=0;i<7;++i)invalid|=output[n-1-i];
    if(invalid){erase(output,n);return 0;}
    uint32_t size=n-start-7;for(uint32_t i=0;i<size;++i)output[i]=output[start+i];*written=size;return 1;
}
