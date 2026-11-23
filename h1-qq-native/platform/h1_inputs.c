#include "h1_inputs.h"
#include "h1_filesystem.h"
#include "h1_rtc.h"
#include "h1_time.h"
static int read_identity(void *unused,uint8_t record[H1QQ_IDENTITY_SIZE])
{
    (void)unused;uint8_t extra;h1_file *file=h1_fopen(H1QQ_IDENTITY_PATH,"rb");
    if(!file)return 0;
    unsigned count=h1_fread(record,1,H1QQ_IDENTITY_SIZE,file),tail=h1_fread(&extra,1,1,file);
    int result=h1_fclose(file);
    return count==H1QQ_IDENTITY_SIZE&&!tail&&!result;
}
static int write_identity(void *unused,const uint8_t record[H1QQ_IDENTITY_SIZE])
{
    (void)unused;h1_file *file=h1_fopen(H1QQ_IDENTITY_PATH,"wb");
    if(!file)return 0;
    unsigned count=h1_fwrite(record,1,H1QQ_IDENTITY_SIZE,file);int result=h1_fclose(file);
    return count==H1QQ_IDENTITY_SIZE&&!result;
}
int h1qq_h1_identity_open(h1qq_identity *state)
{
    const h1qq_identity_io io={0,read_identity,write_identity};
    return h1qq_identity_open(state,&io);
}
int h1qq_h1_sample(h1qq_identity *state,uint32_t *local_seconds,
    uint8_t entropy[5],h1qq_sign_clock *clock)
{
    uint32_t local,utc;
    if(!state||!state->clock_calibrated||!local_seconds||!entropy||!clock||
       !h1_rtc_read_local_seconds(&local)||!h1qq_identity_utc(state,local,&utc))return 0;
    h1qq_sign_clock next={h1_timer_read_ms()%1000u*1000u,utc,0,0x04040404u};
    if(!h1qq_identity_random(state,entropy,5))return 0;
    next.mask_seed=h1_timer_read_ms()%1000u*1000u;
    *local_seconds=local;*clock=next;return 1;
}
