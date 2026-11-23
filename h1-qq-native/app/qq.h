#ifndef H1QQ_APP_H
#define H1QQ_APP_H
#include <stdint.h>
#include "qq_contacts.h"
enum {QQ_MESSAGES_MAX=12,QQ_TEXT_MAX=385};
enum qq_result {QQ_OK,QQ_OFFLINE,QQ_FIRMWARE,QQ_NETWORK,QQ_AUTH,QQ_HTTP,QQ_TOO_LARGE,QQ_RESPONSE,QQ_REJECTED,QQ_CANCELLED};
typedef struct {unsigned native;} qq_config;
typedef struct {char id[21],name[81],nick[81];unsigned category;} qq_person;
typedef struct {qq_person items[QQ_PEOPLE_MAX];unsigned count,truncated;qq_category categories[QQ_CATEGORIES_MAX];unsigned category_count;} qq_people;
typedef struct {char sender[81],text[385];unsigned mine;uint32_t time;char sender_id[21];} qq_message;
typedef struct {qq_message items[12];unsigned count;} qq_messages;
void qq_net_reset(void);
void qq_native_shutdown(void);
void qq_native_save_report(void);
enum qq_result qq_identity(const qq_config *,qq_person *);
enum qq_result qq_contacts(const qq_config *,int group,qq_people *);
enum qq_result qq_history(const qq_config *,int group,const char *id,const char *self,qq_messages *);
enum qq_result qq_history_cached(int group,const char *id,qq_messages *);
uint32_t qq_history_revision(void);
void qq_recent_restore(qq_people *,uint8_t kinds[QQ_PEOPLE_MAX]);
int qq_recent_save(const qq_person *,unsigned group);
int qq_clear_local_history(void);
int qq_local_history_failed(void);
int qq_avatar_tick_due(void);
void qq_avatar_tick(void);
enum qq_result qq_send(const qq_config *,int group,const char *id,const char *message);
int qq_tick_due(void);
enum qq_result qq_tick(void);
enum qq_login_phase {QQ_LOGIN_NONE,QQ_LOGIN_PREPARE,QQ_LOGIN_WAIT,QQ_LOGIN_CONFIRM,QQ_LOGIN_AUTH,QQ_LOGIN_REGISTER};
int qq_login_display(enum qq_login_phase,const uint8_t *png,unsigned size,const char *status);
int qq_login_refresh_requested(void);
extern char qq_last_error[256];
extern int qq_cancel;
uint32_t qq_time(void);
void qq_idle(void *);
#endif
