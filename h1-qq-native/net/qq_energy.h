#ifndef H1QQ_ENERGY_H
#define H1QQ_ENERGY_H
#include <stdint.h>
#include "../core/core.h"
/* Recovered Switch 0xa7060 salt (login subcommand 9) and 0xa54a0 energy.
 * Whole algorithm in C. The NRO is needed only by the desktop reference test. */
int qq_legacy_energy_login(uint64_t milliseconds,uint32_t uin,const uint8_t guid[16],uint8_t out[39]);
/* Active native4 protocol 3: original Dandelion.energy raw salt encoder. */
int qq_energy_login(const h1qq_sign_clock *,uint32_t uin,const uint8_t guid[16],uint8_t out[68]);
#endif
