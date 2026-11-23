#include "core.h"
#include "selftest.h"
static int equal_bytes(const void *left,const void *right,unsigned n)
{const uint8_t *a=left,*b=right;for(unsigned i=0;i<n;++i)if(a[i]!=b[i])return 0;return 1;}
typedef struct {
    uint8_t data[64];
    uint32_t size,buffered,available,offset,bits,width;
    uint64_t result;
    uint32_t after[3];
} core_case;
#include "test_vectors.h"
typedef struct {
    uint8_t digest[16];uint32_t seed,seconds,mask_seed,environment_word;uint8_t expected[68];
} encoder_case;
#include "encoder_vectors.h"
typedef struct {uint32_t size,token_size,extra_size,seed;uint8_t expected[16];} digest_case;
typedef struct {
    uint8_t token[12],extra[173],body[6];uint32_t token_size,extra_size;
    h1qq_sign_clock clock;uint8_t expected[68];
} pipeline_case;
#include "digest_vectors.h"
#include "pipeline_vectors.h"
typedef struct {uint32_t size,seed;uint8_t token[12];uint32_t extra_size;uint8_t extra_digest[16];} state_case;
#include "state_vectors.h"
typedef struct {uint8_t report[34];uint32_t seconds;uint8_t entropy[5],expected[144];} material_case;
#include "material_vectors.h"
typedef struct {uint8_t uuid[16],expected[34];} report_case;
typedef struct {uint8_t token[12],extra[173],sign[68];uint32_t token_size,extra_size;h1qq_sign_clock clock;} corrected_case;
#include "report_vectors.h"
static int corrected_compute_case(const corrected_case *v,uint8_t sign[68],uint8_t token[12],uint8_t *extra,uint32_t *size)
{
    uint8_t report[34],material[144];
    if(!h1qq_report_uuid(report_original_uuid,report)||!h1qq_build_material(report,material_original_seconds,material_original_entropy,material))return 0;
    h1qq_bytes qua={state_qua,sizeof state_qua},body={(const uint8_t *)"\x0a\x02\x08\x01\x10\x01",6};
    h1qq_bytes mat={material,v->token_size?144:0};
    if(v->token_size&&!h1qq_security_token(mat,token))return 0;
    if(!h1qq_build_extra(qua,mat,extra,1120,size))return 0;
    h1qq_bytes tok={token,v->token_size},ext={extra,*size};return h1qq_sign(tok,ext,body,&v->clock,sign);
}
static int state_compute_case(const pipeline_case *v,uint8_t sign[68],uint8_t token[12],uint8_t *extra,uint32_t *size)
{
    uint8_t generated[144];
    if(v->token_size&&!h1qq_build_material(material_original_report,material_original_seconds,material_original_entropy,generated))return 0;
    h1qq_bytes qua={state_qua,sizeof state_qua},material={generated,v->token_size?sizeof generated:0};
    h1qq_bytes body={v->body,6},token_bytes={token,v->token_size};
    if(material.size&&!h1qq_security_token(material,token))return 0;
    if(!h1qq_build_extra(qua,material,extra,1120,size))return 0;
    h1qq_bytes extra_bytes={extra,*size};return h1qq_sign(token_bytes,extra_bytes,body,&v->clock,sign);
}

int h1qq_core_selftest(h1qq_core_results *out)
{
    h1qq_core_results result={0};
#define VERIFY(condition) do {++result.checks;if(!(condition)){result.failed=result.checks;*out=result;return 0;}}while(0)
    for(unsigned i=0;i<sizeof core_cases/sizeof core_cases[0];++i){
        const core_case *v=&core_cases[i];
        h1qq_bit_reader reader={v->data,v->size,v->buffered,v->available,v->offset};
        uint64_t value=0;int success;
        if(v->width){success=h1qq_read_varint(&reader,v->bits,v->width,&value);++result.varints;}
        else {uint32_t word=0;success=h1qq_read_bits(&reader,v->bits,&word);value=word;++result.bits;}
        VERIFY(success&&value==v->result&&reader.buffered==v->after[0]&&reader.available==v->after[1]&&reader.offset==v->after[2]);
    }
    uint32_t words[624]={0},last=0x12345678;words[0]=last;
    VERIFY(h1qq_seed_extend(words,1,&last,0x6c078965)&&equal_bytes(words,core_seed_expected,sizeof words));++result.seeds;
    static const uint8_t expected[2][38]={
        "\x16\xa7\x7c\x4d\xd5\x63\x1a\x47\xca\x6d\xc8\x2b\x76\xa9\x50\xf8\x46\x87\xcc"
        "\xdd\x85\x33\x5a\x07\xea\xad\xf8\x6b\x06\xe9\x00\xa8\xa6\xb7\x2c\x7d\x05",
        "\xf7\x48\x79\xc1\xe3\x96\xf6\xe0\xd8\x83\xb6\xbc\xbb\x47\x27\x3a\x37\x68\x69"
        "\xe1\x93\x66\x76\x90\x08\xd3\x66\x4c\x6b\x37\x47\x8a\xc7\x88\xe9\x71\xd3"};
    uint8_t input[37],output[37];for(unsigned i=0;i<37;++i)input[i]=(uint8_t)(i*73+19);
    for(unsigned selector=1;selector<=2;++selector){
        VERIFY(h1qq_transform(selector,input,output,37)&&equal_bytes(output,expected[selector-1],37));++result.transforms;
    }
    uint8_t invalid[16];for(unsigned i=0;i<sizeof invalid;++i)invalid[i]=255;
    h1qq_bit_reader reader={invalid,sizeof invalid,0,0,0};uint64_t value=0x12345678;
    VERIFY(!h1qq_read_varint(&reader,8,32,&value)&&value==0x12345678&&!reader.buffered&&!reader.available&&!reader.offset);
    VERIFY(!h1qq_seed_extend(words,0,&last,1)&&equal_bytes(words,core_seed_expected,sizeof words));
    VERIFY(!h1qq_transform(0,input,output,37));
    uint8_t sign[68];
    for(unsigned i=0;i<sizeof encoder_cases/sizeof encoder_cases[0];++i){
        const encoder_case *v=encoder_cases+i;
        VERIFY(h1qq_encode_sign(v->digest,v->seed,v->seconds,v->mask_seed,v->environment_word,sign)&&
            equal_bytes(sign,v->expected,68));++result.encoders;
    }
    VERIFY(!h1qq_encode_sign(0,0,0,0,0,sign));
    VERIFY(!h1qq_encode_sign(input,0,0,0,0,0));
    uint8_t material[2048],digest[16];
    for(unsigned i=0;i<sizeof digest_cases/sizeof digest_cases[0];++i){
        const digest_case *v=digest_cases+i;uint32_t x=v->seed;
        for(unsigned j=0;j<v->size;++j){x^=x<<13;x^=x>>17;x^=x<<5;material[j]=(uint8_t)x;}
        h1qq_bytes token={material,v->token_size},extra={material+v->token_size,v->extra_size};
        h1qq_bytes body={material+v->token_size+v->extra_size,v->size-v->token_size-v->extra_size};
        VERIFY(h1qq_sign_digest(token,extra,body,digest)&&equal_bytes(digest,v->expected,16));++result.digests;
    }
    for(unsigned i=0;i<sizeof pipeline_cases/sizeof pipeline_cases[0];++i){
        const pipeline_case *v=pipeline_cases+i;
        h1qq_bytes token={v->token,v->token_size},extra={v->extra,v->extra_size},body={v->body,6};
        VERIFY(h1qq_sign(token,extra,body,&v->clock,sign)&&equal_bytes(sign,v->expected,68));++result.signs;
    }
    h1qq_bytes empty={0,0},bad={0,1};h1qq_sign_clock clock={0,0,0,0};
    VERIFY(!h1qq_sign_digest(empty,empty,empty,0));
    VERIFY(!h1qq_sign_digest(bad,empty,empty,digest));
    VERIFY(!h1qq_sign(empty,empty,empty,0,sign));
    VERIFY(!h1qq_sign(empty,empty,bad,&clock,sign));
    uint8_t token[12],extra_bytes[1120];uint32_t extra_size;
    h1qq_bytes qua={state_qua,sizeof state_qua};
    for(unsigned i=0;i<sizeof state_cases/sizeof state_cases[0];++i){
        const state_case *v=state_cases+i;uint32_t x=v->seed;
        for(unsigned j=0;j<v->size;++j){x^=x<<13;x^=x>>17;x^=x<<5;material[j]=(uint8_t)x;}
        h1qq_bytes source={material,v->size};
        VERIFY(h1qq_security_token(source,token)&&equal_bytes(token,v->token,12));++result.state_tokens;
        int built=h1qq_build_extra(qua,source,extra_bytes,sizeof extra_bytes,&extra_size);
        h1qq_bytes extra={extra_bytes,extra_size};
        VERIFY(built&&extra_size==v->extra_size&&h1qq_sign_digest(empty,empty,extra,digest)&&equal_bytes(digest,v->extra_digest,16));++result.state_extras;
    }
    for(unsigned i=0;i<sizeof pipeline_cases/sizeof pipeline_cases[0];++i){
        const pipeline_case *v=pipeline_cases+i;
        VERIFY(state_compute_case(v,sign,token,extra_bytes,&extra_size)&&extra_size==v->extra_size&&
            equal_bytes(token,v->token,v->token_size)&&equal_bytes(extra_bytes,v->extra,extra_size)&&equal_bytes(sign,v->expected,68));++result.state_results;
    }
    VERIFY(!h1qq_security_token(bad,token));
    VERIFY(!h1qq_security_token(empty,0));
    VERIFY(!h1qq_build_extra(empty,empty,extra_bytes,sizeof extra_bytes,&extra_size));
    VERIFY(!h1qq_build_extra(qua,bad,extra_bytes,sizeof extra_bytes,&extra_size));
    extra_bytes[0]=0xa5;extra_size=0x12345678;
    VERIFY(!h1qq_build_extra(qua,empty,extra_bytes,1,&extra_size)&&extra_bytes[0]==0xa5&&extra_size==0x12345678);
    uint8_t generated[144];
    for(unsigned i=0;i<sizeof material_cases/sizeof material_cases[0];++i){
        const material_case *v=material_cases+i;
        VERIFY(h1qq_build_material(v->report,v->seconds,v->entropy,generated)&&equal_bytes(generated,v->expected,144));++result.materials;
    }
    VERIFY(h1qq_build_material(material_original_report,material_original_seconds,material_original_entropy,generated)&&
        equal_bytes(generated,state_original_material,144));++result.materials;
    VERIFY(!h1qq_build_material(0,0,material_original_entropy,generated));
    VERIFY(!h1qq_build_material(material_original_report,0,0,generated));
    VERIFY(!h1qq_build_material(material_original_report,0,material_original_entropy,0));
    uint8_t report[34];
    for(unsigned i=0;i<sizeof report_cases/sizeof report_cases[0];++i){
        const report_case *v=report_cases+i;
        VERIFY(h1qq_report_uuid(v->uuid,report)&&equal_bytes(report,v->expected,34));++result.reports;
    }
    for(unsigned i=0;i<sizeof corrected_cases/sizeof corrected_cases[0];++i){
        const corrected_case *v=corrected_cases+i;
        VERIFY(corrected_compute_case(v,sign,token,extra_bytes,&extra_size)&&extra_size==v->extra_size&&
            equal_bytes(token,v->token,v->token_size)&&equal_bytes(extra_bytes,v->extra,extra_size)&&equal_bytes(sign,v->sign,68));++result.corrected_results;
    }
    VERIFY(!h1qq_report_uuid(0,report));
    VERIFY(!h1qq_report_uuid(report_original_uuid,0));
    *out=result;return 1;
#undef VERIFY
}
