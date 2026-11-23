#ifndef H1QQ_CORE_SELFTEST_H
#define H1QQ_CORE_SELFTEST_H
#include <stdint.h>
typedef struct { uint32_t checks,bits,varints,seeds,transforms,encoders,digests,signs,state_tokens,state_extras,state_results,materials,reports,corrected_results,failed; } h1qq_core_results;
int h1qq_core_selftest(h1qq_core_results *);
#endif
