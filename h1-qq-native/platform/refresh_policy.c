#include "refresh_policy.h"
void h1qq_refresh_clear(h1qq_refresh_state *state)
{if(state){h1qq_material_clear(&state->cache);state->started_seconds=0;state->scheduled=0;}}
int h1qq_refresh_due(const h1qq_refresh_state *state,uint32_t seconds)
{
    if(!state)return 0;
    if(!state->scheduled)return 1;
    return seconds>=state->started_seconds&&seconds-state->started_seconds>7200u;
}
int h1qq_refresh_begin(h1qq_refresh_state *state,uint32_t seconds)
{
    if(!h1qq_refresh_due(state,seconds))return 0;
    state->started_seconds=seconds;state->scheduled=1;return 1;
}
int h1qq_refresh_publish(h1qq_refresh_state *state,const uint8_t uuid[16],
    uint32_t seconds,const uint8_t entropy[5])
{
    return state&&state->scheduled&&h1qq_material_prepare(&state->cache,uuid,seconds,entropy);
}
