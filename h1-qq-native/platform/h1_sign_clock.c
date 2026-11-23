#include "h1_sign_clock.h"
#include "h1_rtc.h"
#include "h1_time.h"
int h1qq_h1_sign_clock(const h1qq_identity *identity,uint32_t *local_seconds,h1qq_sign_clock *clock)
{
    uint32_t local,utc;
    if(!identity||!identity->clock_calibrated||!local_seconds||!clock||
       !h1_rtc_read_local_seconds(&local)||!h1qq_identity_utc(identity,local,&utc))return 0;
    h1qq_sign_clock next={h1_timer_read_ms()%1000u*1000u,utc,h1_timer_read_ms()%1000u*1000u,0x04040404u};
    *clock=next;*local_seconds=local;return 1;
}
