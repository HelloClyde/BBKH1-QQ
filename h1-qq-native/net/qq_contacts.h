#ifndef H1QQ_CONTACTS_H
#define H1QQ_CONTACTS_H
enum {QQ_PEOPLE_MAX=1024,QQ_CATEGORIES_MAX=256};
typedef struct {unsigned id,count,online;char name[81];} qq_category;
#endif
