#ifndef H1QQ_REFRESH_POLICY_H
#define H1QQ_REFRESH_POLICY_H
#include "material_cache.h"
/* Expiry/start and completion/publication are separate events. The caller
 * supplies their actual ordering relative to requests; no emulated threads. */
typedef struct {h1qq_material_cache cache;uint32_t started_seconds,scheduled;} h1qq_refresh_state;
void h1qq_refresh_clear(h1qq_refresh_state *);
int h1qq_refresh_due(const h1qq_refresh_state *,uint32_t seconds);
int h1qq_refresh_begin(h1qq_refresh_state *,uint32_t seconds);
int h1qq_refresh_publish(h1qq_refresh_state *,const uint8_t uuid[16],
    uint32_t seconds,const uint8_t entropy[5]);
#endif
