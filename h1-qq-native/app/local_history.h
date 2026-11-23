#ifndef H1QQ_LOCAL_HISTORY_H
#define H1QQ_LOCAL_HISTORY_H
#include "identity.h"
#include "qq.h"
#include "qq_business.h"
int qq_local_bind(h1qq_identity *,uint64_t account);
void qq_local_close(void);
unsigned qq_local_restore(qq_text_message *,unsigned capacity);
int qq_local_message(const qq_text_message *);
void qq_local_select(unsigned group,uint64_t peer,const qq_text_message *,unsigned count,qq_messages *);
void qq_local_recent(qq_people *,uint8_t kinds[QQ_PEOPLE_MAX]);
int qq_local_touch(const qq_person *,unsigned group);
int qq_local_clear(void);
int qq_local_failed(void);
#endif
