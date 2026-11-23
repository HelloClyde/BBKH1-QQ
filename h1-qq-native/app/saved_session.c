#include "saved_session.h"
#include "qq_profile.h"
#include "h1_filesystem.h"
#include "monocypher.h"
#include <string.h>

enum {HEADER=72,AD=56,CAPACITY=4608};
static void key_for(const h1qq_identity *id,uint8_t key[32])
{
    /* Domain-separated HChaCha20 subkeys keep all derivation on 32-bit words.
     * The authenticated header separately binds the exact QQ app profile. */
    static const uint8_t domain[]="H1QQ session v1!";
    uint8_t subkey[32];crypto_chacha20_h(subkey,id->key,domain);crypto_chacha20_h(key,subkey,id->uuid);qq_clear(subkey,sizeof subkey);
}
static int usable(const qq_account *a)
{
    uint8_t nonzero=0;for(unsigned i=0;i<16;++i)nonzero|=a->d2_key[i];
    return a->authenticated&&a->uin&&a->tgt.size&&a->tgt.size<=sizeof a->tgt.data&&a->d2.size&&a->d2.size<=sizeof a->d2.data&&a->ksid_size<=sizeof a->ksid&&nonzero&&memchr(a->nickname,0,sizeof a->nickname);
}
static int copy(qq_reader *r,void *dst,unsigned n)
{const uint8_t *p=qq_take(r,n);if(!p)return 0;memcpy(dst,p,n);return 1;}
static int ticket(qq_reader *r,qq_ticket *t)
{unsigned n=(unsigned)qq_read(r,2);if(!r->ok||!n||n>sizeof t->data)return 0;t->size=(uint16_t)n;return copy(r,t->data,n);}
void qq_saved_session_forget(void){(void)h1_remove(QQ_SESSION_PATH);}
int qq_saved_session_load(const h1qq_identity *id,qq_account *a)
{
    uint8_t data[CAPACITY],key[32]={0},extra;int ok=0;unsigned n=0;h1_file *f=0;
    qq_clear(a,sizeof *a);if(!id->ready)goto done;
    f=h1_fopen(QQ_SESSION_PATH,"rb");if(!f)goto done;
    if(h1_fread(data,1,HEADER,f)!=HEADER)goto done;
    qq_reader h={data,AD,8,1};uint32_t profile=(uint32_t)qq_read(&h,4);const uint8_t *uuid=qq_take(&h,16);n=(unsigned)qq_read(&h,4);
    if(memcmp(data,"H1QQSES1",8)||profile!=QQ_NATIVE_SUB_APP_ID||!uuid||memcmp(uuid,id->uuid,16)||n<50||n>sizeof data-HEADER)goto done;
    if(h1_fread(data+HEADER,1,n,f)!=n||h1_fread(&extra,1,1,f))goto done;
    {int closed=h1_fclose(f);f=0;if(closed)goto done;}
    key_for(id,key);if(crypto_aead_unlock(data+HEADER,data+56,key,data+32,data,AD,data+HEADER,n))goto done;
    qq_reader r={data+HEADER,n,0,1};a->uin=qq_read(&r,8);
    if(!ticket(&r,&a->tgt)||!ticket(&r,&a->d2)||!copy(&r,a->d2_key,16)||!copy(&r,a->wt_key,16)||!copy(&r,a->session_id,4))goto done;
    a->ksid_size=(unsigned)qq_read(&r,2);if(!r.ok||a->ksid_size>sizeof a->ksid||!copy(&r,a->ksid,a->ksid_size))goto done;
    unsigned nick=(unsigned)qq_read(&r,2);if(!r.ok||nick>=sizeof a->nickname||!copy(&r,a->nickname,nick)||r.at!=r.size)goto done;
    a->authenticated=1;a->registered=0;ok=usable(a);
done:
    if(f)(void)h1_fclose(f);if(!ok)qq_clear(a,sizeof *a);qq_clear(data,sizeof data);qq_clear(key,sizeof key);return ok;
}
int qq_saved_session_save(h1qq_identity *id,const qq_account *a)
{
    uint8_t data[CAPACITY],key[32]={0},check[256];int ok=0;h1_file *f=0;
    if(!id->ready||!usable(a))goto done;
    memset(data,0,HEADER);qq_writer w={data+HEADER,0,sizeof data-HEADER,1};
    qq_num(&w,a->uin,8);qq_short(&w,(qq_view){a->tgt.data,a->tgt.size});qq_short(&w,(qq_view){a->d2.data,a->d2.size});
    qq_put(&w,a->d2_key,16);qq_put(&w,a->wt_key,16);qq_put(&w,a->session_id,4);qq_short(&w,(qq_view){a->ksid,a->ksid_size});qq_short(&w,qq_string(a->nickname));
    if(!w.ok)goto done;unsigned size=w.size+HEADER;
    qq_writer h={data,0,32,1};qq_put(&h,"H1QQSES1",8);qq_num(&h,QQ_NATIVE_SUB_APP_ID,4);qq_put(&h,id->uuid,16);qq_num(&h,w.size,4);
    if(!h1qq_identity_random(id,data+32,24))goto done;key_for(id,key);
    crypto_aead_lock(data+HEADER,data+56,key,data+32,data,AD,data+HEADER,w.size);
    f=h1_fopen(QQ_SESSION_PATH,"wb");if(!f)goto done;
    {unsigned written=h1_fwrite(data,1,size,f);int closed=h1_fclose(f);f=0;if(written!=size||closed)goto failed;}
    f=h1_fopen(QQ_SESSION_PATH,"rb");if(!f)goto failed;
    for(unsigned at=0;at<size;){unsigned n=size-at;if(n>sizeof check)n=sizeof check;if(h1_fread(check,1,n,f)!=n||memcmp(check,data+at,n))goto failed;at+=n;}
    if(h1_fread(check,1,1,f))goto failed;
    {int closed=h1_fclose(f);f=0;if(closed)goto failed;}ok=1;goto done;
failed:
    if(f){(void)h1_fclose(f);f=0;}qq_saved_session_forget();
done:
    if(f)(void)h1_fclose(f);qq_clear(data,sizeof data);qq_clear(key,sizeof key);qq_clear(check,sizeof check);return ok;
}
