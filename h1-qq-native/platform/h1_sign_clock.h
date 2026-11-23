#ifndef H1QQ_H1_SIGN_CLOCK_H
#define H1QQ_H1_SIGN_CLOCK_H
#include "identity.h"
#include "core.h"
/* Does not open files or consume entropy; SDK timer must already be running. */
int h1qq_h1_sign_clock(const h1qq_identity *,uint32_t *local_seconds,h1qq_sign_clock *);
#endif
