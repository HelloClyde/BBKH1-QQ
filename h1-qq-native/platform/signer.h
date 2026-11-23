#ifndef H1QQ_SIGNER_H
#define H1QQ_SIGNER_H
#include "identity.h"
#include "refresh_policy.h"
/* Single caller, cooperative service. Identity is borrowed and remains owned
 * by the application; requests neither read files nor consume random bytes. */
typedef struct {
    h1qq_identity *identity;
    h1qq_refresh_state refresh;
    uint32_t pending,requests,publications,begun;
    uint32_t pending_seconds,published_seconds;
    uint8_t pending_uuid[16],pending_entropy[5],report_uuid[16],entropy[5];
} h1qq_signer;
int h1qq_signer_init(h1qq_signer *,h1qq_identity *);
void h1qq_signer_close(h1qq_signer *);
/* One work step: 0 idle, 1 queued, 2 published, -1 unavailable input/error.
 * The application chooses work-step ordering relative to incoming requests. */
int h1qq_signer_poll(h1qq_signer *,uint32_t utc_seconds);
int h1qq_signer_request(h1qq_signer *,h1qq_bytes qua,h1qq_bytes body,
    const h1qq_sign_clock *,h1qq_cached_result *,uint8_t *extra,uint32_t capacity);
#endif
