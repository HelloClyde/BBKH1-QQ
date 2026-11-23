#include "local_history.h"
#include "h1_filesystem.h"
#include "monocypher.h"
#include <stdio.h>
#include <string.h>

/* Account-bound, authenticated, append-only records. A short final write is
 * ignored by readers and overwritten at the next aligned append. Existing
 * complete records are never rewritten while saving a message. */
enum {RECORD=640,HEADER=64,AD=48,PAYLOAD=RECORD-HEADER,MESSAGE=1,RECENT=2};
static struct {h1qq_identity *identity;uint64_t account;uint8_t key[32];char path[96];int failed;} local;
static uint8_t record[RECORD];
static qq_text_message history_selected[QQ_MESSAGES_MAX];

static uint64_t number(const char *s)
{uint64_t n=0;if(!s||!*s)return 0;while(*s){if(*s<'0'||*s>'9'||n>(UINT64_MAX-(unsigned)(*s-'0'))/10)return 0;n=n*10+(unsigned)(*s++-'0');}return n;}
static void decimal(uint64_t n,char out[21])
{char digits[20];unsigned k=0;do{digits[k++]=(char)('0'+n%10);n/=10;}while(n);for(unsigned i=0;i<k;++i)out[i]=digits[k-1-i];out[k]=0;}
static int string(qq_reader *r,char *out,unsigned cap)
{unsigned n=(unsigned)qq_read(r,2);const uint8_t *p=qq_take(r,n);if(!p||n>=cap||memchr(p,0,n))return 0;memcpy(out,p,n);out[n]=0;return 1;}
static int valid(const qq_text_message *m)
{return m->group<=1&&m->peer&&m->sender&&memchr(m->text,0,sizeof m->text)&&m->text[0]&&memchr(m->sender_name,0,sizeof m->sender_name);}
int qq_local_bind(h1qq_identity *identity,uint64_t account)
{
    if(!identity||!identity->ready||!account)return 0;
    if(local.identity==identity&&local.account==account)return 1;
    qq_local_close();local.identity=identity;local.account=account;
    uint8_t key[32];static const uint8_t domain[]="H1QQ history v1!";
    crypto_chacha20_h(key,identity->key,domain);crypto_chacha20_h(local.key,key,identity->uuid);qq_clear(key,sizeof key);
    char id[21];decimal(account,id);snprintf(local.path,sizeof local.path,QQ_DATA_DIR "\\H%s.MSG",id);return 1;
}
void qq_local_close(void){qq_clear(&local,sizeof local);qq_clear(record,sizeof record);qq_clear(history_selected,sizeof history_selected);}
int qq_local_failed(void){return local.failed;}
static int size(h1_file *f)
{int end=h1_fseek(f,0,H1_SEEK_END);if(end<0)local.failed=1;return end;}
static int read_record(h1_file *f,int at,unsigned *kind)
{
    if(h1_fseek(f,at,H1_SEEK_SET)!=at||h1_fread(record,1,RECORD,f)!=RECORD){local.failed=1;return 0;}
    qq_reader h={record,24,8,1};uint64_t account=qq_read(&h,8);*kind=(unsigned)qq_read(&h,4);unsigned bytes=(unsigned)qq_read(&h,4);
    if(memcmp(record,"H1QQHST1",8)||account!=local.account||(*kind!=MESSAGE&&*kind!=RECENT)||bytes!=PAYLOAD||crypto_aead_unlock(record+HEADER,record+48,local.key,record+24,record,AD,record+HEADER,PAYLOAD)){local.failed=1;return 0;}
    return 1;
}
static int append(unsigned kind)
{
    if(!local.identity||!local.account)return 0;
    memset(record,0,HEADER);qq_writer h={record,0,24,1};qq_put(&h,"H1QQHST1",8);qq_num(&h,local.account,8);qq_num(&h,kind,4);qq_num(&h,PAYLOAD,4);
    if(!h1qq_identity_random(local.identity,record+24,24)){local.failed=1;return 0;}
    crypto_aead_lock(record+HEADER,record+48,local.key,record+24,record,AD,record+HEADER,PAYLOAD);
    h1_file *f=h1_fopen(local.path,"r+b");if(!f){f=h1_fopen(local.path,"rb");if(f){h1_fclose(f);local.failed=1;return 0;}f=h1_fopen(local.path,"wb");}if(!f){local.failed=1;return 0;}
    int end=size(f),ok=0;
    if(end>=0&&end<=0x7fffffff-RECORD){int at=end-end%RECORD;ok=h1_fseek(f,at,H1_SEEK_SET)==at&&h1_fwrite(record,1,RECORD,f)==RECORD;}
    if(h1_fclose(f))ok=0;if(!ok)local.failed=1;return ok;
}
int qq_local_message(const qq_text_message *m)
{
    if(!valid(m)){local.failed=1;return 0;}
    memset(record+HEADER,0,PAYLOAD);qq_writer w={record+HEADER,0,PAYLOAD,1};
    qq_num(&w,m->group,1);qq_num(&w,m->sender,8);qq_num(&w,m->recipient,8);qq_num(&w,m->peer,8);qq_num(&w,m->uid,8);
    qq_num(&w,m->sequence,4);qq_num(&w,m->time,4);qq_num(&w,m->random,4);qq_num(&w,m->flags,4);
    qq_short(&w,qq_string(m->sender_name));qq_short(&w,qq_string(m->text));return w.ok&&append(MESSAGE);
}
static int message(qq_text_message *m)
{
    qq_reader r={record+HEADER,PAYLOAD,0,1};memset(m,0,sizeof *m);
    m->group=(unsigned)qq_read(&r,1);m->sender=qq_read(&r,8);m->recipient=qq_read(&r,8);m->peer=qq_read(&r,8);m->uid=qq_read(&r,8);
    m->sequence=(uint32_t)qq_read(&r,4);m->time=(uint32_t)qq_read(&r,4);m->random=(uint32_t)qq_read(&r,4);m->flags=(uint32_t)qq_read(&r,4);
    return string(&r,m->sender_name,sizeof m->sender_name)&&string(&r,m->text,sizeof m->text)&&r.ok&&valid(m);
}
static int represented(qq_text_message *out,unsigned count,const qq_text_message *m)
{for(unsigned i=0;i<count;++i)if(qq_message_reconcile(&out[i],m,local.account))return 1;return 0;}
static unsigned scan(qq_text_message *out,unsigned count,unsigned capacity,unsigned group,uint64_t peer)
{
    h1_file *f=local.account?h1_fopen(local.path,"rb"):0;if(!f)return count;
    unsigned scanned=0;int end=size(f);if(end>=0)for(int at=end-end%RECORD-RECORD;at>=0&&count<capacity;at-=RECORD){
        if(++scanned%32==0){qq_idle(0);if(qq_cancel)break;}
        unsigned kind;qq_text_message m;if(!read_record(f,at,&kind)||kind!=MESSAGE)continue;
        if(!message(&m)){local.failed=1;continue;}if(peer&&(m.peer!=peer||m.group!=group))continue;
        if(!represented(out,count,&m))out[count++]=m;
    }
    if(h1_fclose(f))local.failed=1;return count;
}
static void chronological(qq_text_message *out,unsigned count)
{
    for(unsigned i=0;i<count/2;++i){qq_text_message m=out[i];out[i]=out[count-1-i];out[count-1-i]=m;}
    for(unsigned i=1;i<count;++i){qq_text_message m=out[i];unsigned j=i;while(j&&out[j-1].time>m.time){out[j]=out[j-1];--j;}out[j]=m;}
}
unsigned qq_local_restore(qq_text_message *out,unsigned capacity)
{unsigned count=scan(out,0,capacity,0,0);chronological(out,count);return count;}
void qq_local_select(unsigned group,uint64_t peer,const qq_text_message *cache,unsigned count,qq_messages *out)
{
    unsigned used=0;for(unsigned i=count;i>0&&used<QQ_MESSAGES_MAX;--i){const qq_text_message *m=&cache[i-1];if(m->group==group&&m->peer==peer&&!represented(history_selected,used,m))history_selected[used++]=*m;}
    used=scan(history_selected,used,QQ_MESSAGES_MAX,group,peer);chronological(history_selected,used);memset(out,0,sizeof *out);
    for(unsigned i=0;i<used;++i){qq_text_message *m=&history_selected[i];qq_message *to=&out->items[out->count++];to->mine=m->sender==local.account;to->time=m->time;decimal(m->sender,to->sender_id);memcpy(to->text,m->text,sizeof to->text);memcpy(to->sender,m->sender_name,sizeof to->sender);if(!to->sender[0])decimal(m->sender,to->sender);}
    qq_clear(history_selected,sizeof history_selected);
}
int qq_local_touch(const qq_person *person,unsigned group)
{
    uint64_t peer=number(person->id);if(group>1||!peer||!memchr(person->name,0,sizeof person->name)||!memchr(person->nick,0,sizeof person->nick))return 0;
    memset(record+HEADER,0,PAYLOAD);qq_writer w={record+HEADER,0,PAYLOAD,1};qq_num(&w,group,1);qq_num(&w,peer,8);qq_short(&w,qq_string(person->name));qq_short(&w,qq_string(person->nick));return w.ok&&append(RECENT);
}
void qq_local_recent(qq_people *out,uint8_t kinds[QQ_PEOPLE_MAX])
{
    memset(out,0,sizeof *out);memset(kinds,0,QQ_PEOPLE_MAX);h1_file *f=local.account?h1_fopen(local.path,"rb"):0;if(!f)return;
    unsigned scanned=0;int end=size(f);if(end>=0)for(int at=end-end%RECORD-RECORD;at>=0&&out->count<16;at-=RECORD){
        if(++scanned%32==0){qq_idle(0);if(qq_cancel)break;}
        unsigned kind;if(!read_record(f,at,&kind)||kind!=RECENT)continue;
        qq_reader r={record+HEADER,PAYLOAD,0,1};unsigned group=(unsigned)qq_read(&r,1);uint64_t peer=qq_read(&r,8);qq_person p={0};decimal(peer,p.id);
        if(group>1||!peer||!string(&r,p.name,sizeof p.name)||!string(&r,p.nick,sizeof p.nick)||!r.ok){local.failed=1;continue;}
        unsigned i=0;while(i<out->count&&(kinds[i]!=group||strcmp(out->items[i].id,p.id)))++i;if(i<out->count)continue;
        out->items[out->count]=p;kinds[out->count++]=(uint8_t)group;
    }
    if(h1_fclose(f))local.failed=1;out->category_count=1;memcpy(out->categories[0].name,"最近聊天",13);
}
int qq_local_clear(void)
{
    if(!local.account)return 0;h1_file *f=h1_fopen(local.path,"rb");if(!f)return 1;
    if(h1_fclose(f)||h1_remove(local.path)){local.failed=1;return 0;}return 1;
}
