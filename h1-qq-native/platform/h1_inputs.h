#ifndef H1QQ_H1_INPUTS_H
#define H1QQ_H1_INPUTS_H
#include "identity.h"
#include "core.h"
#ifndef H1QQ_IDENTITY_PATH
#define H1QQ_IDENTITY_PATH "A:\\H1QQ.ID"
#endif
int h1qq_h1_identity_open(h1qq_identity *);
/* Caller must start the SDK timer. Input sampling does not decide QQ refresh
 * policy; every call explicitly requests fresh material and sign clocks. */
int h1qq_h1_sample(h1qq_identity *,uint32_t *local_seconds,
    uint8_t entropy[5],h1qq_sign_clock *);
#endif
