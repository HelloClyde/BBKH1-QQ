#include "signer.h"
void h1qq_signer_close(h1qq_signer *state)
{
    if(state){volatile uint8_t *p=(volatile uint8_t *)state;for(unsigned i=0;i<sizeof *state;++i)p[i]=0;}
}
int h1qq_signer_init(h1qq_signer *state,h1qq_identity *identity)
{
    if(!state)return 0;
    h1qq_signer_close(state);
    if(!identity||!identity->ready||!identity->clock_calibrated)return 0;
    state->identity=identity;return 1;
}
int h1qq_signer_poll(h1qq_signer *state,uint32_t seconds)
{
    if(!state||!state->identity||!state->identity->ready)return -1;
    if(state->pending){
        if(!h1qq_refresh_publish(&state->refresh,state->pending_uuid,state->pending_seconds,state->pending_entropy))return -1;
        for(unsigned i=0;i<16;++i)state->report_uuid[i]=state->pending_uuid[i];
        for(unsigned i=0;i<5;++i)state->entropy[i]=state->pending_entropy[i];
        state->published_seconds=state->pending_seconds;state->pending=0;++state->publications;return 2;
    }
    if(seconds<946684800u||seconds>=4102444800u)return -1;
    if(!h1qq_refresh_due(&state->refresh,seconds))return 0;
    uint8_t random[21];
    if(!h1qq_identity_random(state->identity,random,sizeof random))return -1;
    if(!h1qq_refresh_begin(&state->refresh,seconds))return -1;
    random[6]=(random[6]&15)|0x40;random[8]=(random[8]&63)|0x80;
    for(unsigned i=0;i<16;++i)state->pending_uuid[i]=random[i];
    for(unsigned i=0;i<5;++i)state->pending_entropy[i]=random[16+i];
    state->pending_seconds=seconds;state->pending=1;++state->begun;return 1;
}
int h1qq_signer_request(h1qq_signer *state,h1qq_bytes qua,h1qq_bytes body,
    const h1qq_sign_clock *clock,h1qq_cached_result *result,uint8_t *extra,uint32_t capacity)
{
    if(!state||!state->identity||!state->identity->ready)return 0;
    if(!h1qq_cached_sign(&state->refresh.cache,qua,body,clock,result,extra,capacity))return 0;
    ++state->requests;return 1;
}
