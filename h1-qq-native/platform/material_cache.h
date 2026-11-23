#ifndef H1QQ_MATERIAL_CACHE_H
#define H1QQ_MATERIAL_CACHE_H
#include "core.h"
/* Explicit publish boundary for the observed provider cache. No guessed TTL,
 * hidden first-call counter, account policy or background thread emulation. */
typedef struct {uint8_t material[144],token[12];uint32_t ready;} h1qq_material_cache;
typedef struct {uint8_t token[12],sign[68];uint32_t token_size,extra_size;} h1qq_cached_result;
void h1qq_material_clear(h1qq_material_cache *);
int h1qq_material_prepare(h1qq_material_cache *,const uint8_t uuid[16],
    uint32_t seconds,const uint8_t entropy[5]);
int h1qq_cached_sign(const h1qq_material_cache *,h1qq_bytes qua,h1qq_bytes body,
    const h1qq_sign_clock *,h1qq_cached_result *,uint8_t *extra,uint32_t capacity);
#endif
