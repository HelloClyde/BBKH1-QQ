#ifndef H1QQ_AVATARS_H
#define H1QQ_AVATARS_H
#include <stdint.h>
#include "h1net_client.h"
int qq_avatar_peek(int group,const char *id,const uint16_t **pixels,unsigned *w,unsigned *h);
uint32_t qq_avatar_revision(void);
int qq_avatars_due(uint32_t now);
void qq_avatars_service(h1net_client *,uint32_t now);
void qq_avatars_network_reset(void);
void qq_avatars_close(h1net_client *);
#endif
