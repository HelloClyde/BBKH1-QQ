#ifndef H1QQ_IDENTITY_H
#define H1QQ_IDENTITY_H
#include <stdint.h>
#define H1QQ_IDENTITY_SIZE 80u
/* Platform state, separate from the recovered QQ algorithms. No implicit seed.
 * read/write return 1 only for an exact, closed record. open verifies readback
 * before exposing random bytes. A missing/corrupt record is an error. */
typedef struct {
    void *context;
    int (*read)(void *,uint8_t record[H1QQ_IDENTITY_SIZE]);
    int (*write)(void *,const uint8_t record[H1QQ_IDENTITY_SIZE]);
} h1qq_identity_io;
typedef struct {
    uint8_t uuid[16],key[32],buffer[64];
    uint64_t session;
    uint32_t counter,available,ready;
    int32_t utc_offset_minutes,clock_adjustment_seconds;
    uint32_t clock_calibrated;
} h1qq_identity;
void h1qq_chacha20_block(const uint8_t key[32],uint32_t counter,
    const uint8_t nonce[12],uint8_t output[64]);
int h1qq_identity_open(h1qq_identity *,const h1qq_identity_io *);
int h1qq_identity_random(h1qq_identity *,uint8_t *,uint32_t size);
void h1qq_identity_close(h1qq_identity *);
/* RTC stores local civil seconds; signing expects UTC epoch seconds. */
int h1qq_identity_utc(const h1qq_identity *,uint32_t local_seconds,uint32_t *utc);
#endif
