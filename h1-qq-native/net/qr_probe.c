/* Temporary RAM harness: native QQ anonymous QR protocol, byte-only host relay.
 * No account credentials, password, chat send or runtime ARM compatibility. */
#include "module_abi.h"
#include "qq_qr.h"
#include "qq_crypto.h"
#include "identity.h"
#include <stddef.h>
uint8_t qr_incoming[8192];
static uint8_t qr_body[8192],qr_scratch[8192],qr_signature[1024];
static uint32_t qr_ready,qr_signature_size;
static qq_qr_session qr_session;
static h1qq_identity qr_random;
static uint32_t word(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void clear(void *p,unsigned n){volatile uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *to,const void *from,unsigned n)
{uint8_t *a=to;const uint8_t *b=from;for(unsigned i=0;i<n;++i)a[i]=b[i];}
static int same(const char *a,const char *b)
{while(*a&&*a==*b){++a;++b;}return *a==*b;}
static void cleanup(void)
{
    clear(&qr_session,sizeof qr_session);h1qq_identity_close(&qr_random);
    clear(qr_signature,sizeof qr_signature);clear(qr_incoming,sizeof qr_incoming);
    clear(qr_body,sizeof qr_body);clear(qr_scratch,sizeof qr_scratch);
    qr_ready=qr_signature_size=0;
}
int h1_module_entry(const h1_exec_api *api,h1_exec_call *call)
{
    if(api->version!=1||call->version!=1||call->output_capacity<4096)return -1;
    if(api->poll_cancel())return -2;
    uint32_t *out=(uint32_t *)(void *)call->output;
    clear(call->output,call->output_capacity);call->output_size=64;
    out[0]=0x31525151;out[1]=call->opcode;uint32_t begin=api->tick_80hz();int ok=0;
    if(call->opcode==0&&call->arg_size==123){
        cleanup();qr_random.ready=1;qr_random.session=1;
        copy(qr_random.key,call->args,32);copy(qr_session.guid,call->args+32,16);
        qr_session.key_version=(uint16_t)(call->args[113]|call->args[114]<<8);
        qr_session.sequence=word(call->args+115);qr_session.seconds=word(call->args+119);
        copy(qr_session.imei,"123456789012345",16);
        uint8_t private_key[32];
        for(unsigned attempt=0;attempt<8;++attempt){
            if(api->poll_cancel()){clear(private_key,32);cleanup();return -2;}
            if(!h1qq_identity_random(&qr_random,private_key,32))break;
            if(qq_ecdh(private_key,call->args+48,qr_session.public_key,qr_session.share_key)){ok=1;break;}
        }
        clear(private_key,sizeof private_key);
        if(ok)ok=h1qq_identity_random(&qr_random,qr_session.random_key,16);
        if(ok){qr_ready=1;copy(call->output+64,qr_session.public_key,65);out[3]=65;call->output_size=129;}
        else cleanup();
    }else if((call->opcode==1||call->opcode==3)&&qr_ready&&call->arg_size==4){
        qr_session.seconds=word(call->args);++qr_session.sequence;
        ok=h1qq_identity_random(&qr_random,qr_session.pad,18);uint32_t size=0;
        if(ok&&call->opcode==1){qr_signature_size=0;ok=qq_qr_fetch(&qr_session,call->output+64,call->output_capacity-64,&size);}
        else if(ok)ok=qr_signature_size&&qq_qr_query(&qr_session,qr_signature,qr_signature_size,call->output+64,call->output_capacity-64,&size);
        if(ok){out[3]=size;call->output_size=64+size;}
    }else if(call->opcode==4&&qr_ready&&call->arg_size>4){
        uint32_t offset=word(call->args),size=call->arg_size-4;
        ok=offset<=sizeof qr_incoming&&size<=sizeof qr_incoming-offset;
        if(ok)copy(qr_incoming+offset,call->args+4,size);
    }else if(call->opcode==2&&qr_ready&&call->arg_size==4){
        qq_sso_reply reply;uint8_t zero[16]={0};uint32_t size=word(call->args);
        ok=size<=sizeof qr_incoming&&qq_sso_decode(qr_incoming,size,zero,&reply,qr_body,sizeof qr_body);
        if(ok){
            out[4]=(uint32_t)reply.sso_return;out[5]=reply.sequence;out[6]=reply.compression;
            ok=!reply.sso_return&&reply.sequence==qr_session.sequence&&!reply.compression&&same(reply.command,"wtlogin.trans_emp");
        }
        if(ok){
            const uint8_t *sig=0,*png=0;uint32_t sig_size=0,png_size=0,cmd=0,status=0;
            ok=qq_qr_decode(&qr_session,qr_body,reply.body_size,qr_scratch,sizeof qr_scratch,&cmd,&status,&sig,&sig_size,&png,&png_size);
            out[7]=cmd;out[8]=status;
            if(ok&&cmd==0x31&&!status){
                ok=sig_size&&sig_size<=sizeof qr_signature&&png_size<=call->output_capacity-64;
                if(ok){copy(qr_signature,sig,sig_size);qr_signature_size=sig_size;copy(call->output+64,png,png_size);out[3]=png_size;call->output_size=64+png_size;}
            }
        }
        clear(qr_incoming,sizeof qr_incoming);clear(qr_body,sizeof qr_body);clear(qr_scratch,sizeof qr_scratch);
    }else if(call->opcode==9){cleanup();ok=1;}
    out[2]=ok?0:1;out[9]=api->tick_80hz()-begin;out[10]=qr_ready;out[11]=qr_signature_size;
    if(api->poll_cancel())return -2;
    return ok?0:1;
}
