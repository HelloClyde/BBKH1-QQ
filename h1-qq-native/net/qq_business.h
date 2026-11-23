#ifndef H1QQ_BUSINESS_H
#define H1QQ_BUSINESS_H
#include "qq_session.h"
#include "qq_contacts.h"
typedef struct {uint64_t id,owner;char name[81],nick[81];unsigned category;} qq_contact;
typedef struct {qq_contact items[QQ_PEOPLE_MAX];unsigned count,total,truncated;uint8_t cookie[1024];unsigned cookie_size;qq_category categories[QQ_CATEGORIES_MAX];unsigned category_count;} qq_contact_list;
enum {QQ_MESSAGE_LOCAL=1,QQ_MESSAGE_RANDOM=2};
typedef struct {uint64_t sender,recipient,peer,uid;uint32_t sequence,time;unsigned group;char sender_name[81],text[385];uint32_t random,flags;} qq_text_message;
typedef int (*qq_message_sink)(void *,const qq_text_message *);
/* 0 separate row, 1 already represented, 2 local ACK upgraded to server echo. */
int qq_message_reconcile(qq_text_message *,const qq_text_message *,uint64_t self);
int qq_register_body(const qq_account *,const uint8_t guid[16],uint32_t sequence,uint8_t *,uint32_t,uint32_t *);
int qq_register_result(qq_view,char error[256]);
int qq_contacts_body(uint64_t uin,int group,unsigned start,qq_view cookie,uint32_t sequence,uint8_t *,uint32_t,uint32_t *);
int qq_contacts_result(qq_view,int group,qq_contact_list *);
int qq_text_send_body(uint64_t peer,int group,qq_view text,uint32_t sequence,uint32_t random,uint32_t time,uint8_t *,uint32_t,uint32_t *);
int qq_text_send_result(qq_view,unsigned *result,char error[256]);
int qq_get_messages_body(qq_view cookie,unsigned flag,uint32_t now,uint8_t *,uint32_t,uint32_t *);
int qq_text_message_parse(qq_view,uint64_t self,unsigned group,qq_text_message *);
int qq_get_messages_result(qq_view,uint64_t self,uint8_t cookie[1024],unsigned *cookie_size,unsigned *flag,qq_message_sink,void *);
int qq_delete_messages_body(qq_view get_response,uint8_t *,uint32_t,uint32_t *);
#endif
