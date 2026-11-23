#include "material_cache.h"
void h1qq_material_clear(h1qq_material_cache *cache)
{if(cache){volatile uint8_t *p=(volatile uint8_t *)cache;for(unsigned i=0;i<sizeof *cache;++i)p[i]=0;}}
int h1qq_material_prepare(h1qq_material_cache *cache,const uint8_t uuid[16],
    uint32_t seconds,const uint8_t entropy[5])
{
    if(!cache)return 0;
    h1qq_material_cache next={0};uint8_t report[34];
    h1qq_bytes material={next.material,sizeof next.material};
    if(!h1qq_report_uuid(uuid,report)||!h1qq_build_material(report,seconds,entropy,next.material)||
       !h1qq_security_token(material,next.token))return 0;
    next.ready=1;*cache=next;return 1;
}
int h1qq_cached_sign(const h1qq_material_cache *cache,h1qq_bytes qua,h1qq_bytes body,
    const h1qq_sign_clock *clock,h1qq_cached_result *out,uint8_t *extra,uint32_t capacity)
{
    if(!cache||!out||!clock||(!body.data&&body.size))return 0;
    h1qq_cached_result next={0};h1qq_bytes material={cache->material,cache->ready?144:0};
    if(!h1qq_build_extra(qua,material,extra,capacity,&next.extra_size))return 0;
    next.token_size=cache->ready?12:0;
    for(unsigned i=0;i<next.token_size;++i)next.token[i]=cache->token[i];
    h1qq_bytes token={next.token,next.token_size},extra_bytes={extra,next.extra_size};
    if(!h1qq_sign(token,extra_bytes,body,clock,next.sign))return 0;
    *out=next;return 1;
}
