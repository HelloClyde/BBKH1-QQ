#include "qq_business.h"
#include <string.h>
static void copy(void *d,const void *s,unsigned n){uint8_t *a=d;const uint8_t *b=s;for(unsigned i=0;i<n;++i)a[i]=b[i];}
static uint64_t pbnum(qq_view v,unsigned tag){qq_field f;return qq_pb_find(v,tag,&f)&&f.type==0?f.value:0;}
static qq_view pbbytes(qq_view v,unsigned tag){qq_field f;return qq_pb_find(v,tag,&f)&&f.type==2?f.bytes:(qq_view){0,0};}
int qq_register_body(const qq_account *a,const uint8_t guid[16],uint32_t seq,uint8_t *out,uint32_t cap,uint32_t *size)
{
    uint8_t body[2048];qq_writer w={body,0,sizeof body,1};qq_jce_int(&w,0,(int64_t)a->uin);qq_jce_int(&w,1,7);qq_jce_int(&w,2,0);qq_jce_string(&w,3,qq_string(""));qq_jce_int(&w,4,11);
    for(unsigned i=5;i<=10;++i)qq_jce_int(&w,i,0);qq_jce_int(&w,11,25);qq_jce_int(&w,12,1);qq_jce_string(&w,13,qq_string(""));qq_jce_int(&w,14,0);qq_jce_bytes(&w,15,(qq_view){0,0});qq_jce_bytes(&w,16,(qq_view){guid,16});qq_jce_int(&w,17,2052);qq_jce_int(&w,18,0);
    qq_jce_string(&w,19,qq_string("H1"));qq_jce_string(&w,20,qq_string("H1"));qq_jce_string(&w,21,qq_string("7.1.2"));qq_jce_int(&w,22,1);qq_jce_int(&w,23,1551);qq_jce_int(&w,24,0);qq_jce_int(&w,26,0);qq_jce_int(&w,27,31806887127679168LL);qq_jce_string(&w,28,qq_string(""));qq_jce_int(&w,29,0);qq_jce_string(&w,30,qq_string("BBK"));qq_jce_string(&w,31,qq_string("android"));qq_jce_string(&w,32,qq_string(""));
    static const uint8_t b769[]={10,4,8,46,16,0,10,5,8,0x9b,2,16,0};qq_jce_bytes(&w,33,(qq_view){b769,sizeof b769});qq_jce_int(&w,34,0);qq_jce_bytes(&w,35,(qq_view){0,0});qq_jce_int(&w,36,0);qq_jce_int(&w,38,0);qq_jce_int(&w,39,0);
    qq_writer packet={out,0,cap,1};if(!w.ok||!qq_jce_request(&packet,seq,"PushService","SvcReqRegister","SvcReqRegister",(qq_view){body,w.size},0))return 0;*size=packet.size;return 1;
}
int qq_register_result(qq_view data,char error[256])
{
    error[0]=0;qq_view payload;qq_jce_field code,message;
    if(!qq_jce_payload(data,"SvcRespRegister",&payload)||!qq_jce_find(payload,2,&code)||(code.type>3&&code.type!=12))return 0;
    if(qq_jce_find(payload,3,&message)){if(message.type!=6&&message.type!=7)return 0;qq_copy_text(error,256,message.bytes);if(message.bytes.size)return -1;}return code.value?-1:1;
}
int qq_contacts_body(uint64_t uin,int group,unsigned start,qq_view cookie,uint32_t seq,uint8_t *out,uint32_t cap,uint32_t *size)
{
    uint8_t body[2048];qq_writer w={body,0,sizeof body,1};const char *function,*key;
    if(group){
        qq_jce_int(&w,0,(int64_t)uin);qq_jce_int(&w,1,1);qq_jce_bytes(&w,2,cookie);qq_jce_head(&w,3,9);qq_jce_int(&w,0,0);qq_jce_int(&w,4,1);qq_jce_int(&w,5,7);qq_jce_int(&w,6,0);qq_jce_int(&w,7,1);qq_jce_int(&w,8,1);function=key="GetTroopListReqV2Simplify";
    }else{
        if(start>32767)return 0;qq_jce_int(&w,0,3);qq_jce_int(&w,1,start?1:0);qq_jce_int(&w,2,(int64_t)uin);qq_jce_int(&w,3,start);qq_jce_int(&w,4,100);
        qq_jce_int(&w,5,0);qq_jce_int(&w,6,1);qq_jce_int(&w,7,0);qq_jce_int(&w,8,127);qq_jce_int(&w,9,0);qq_jce_int(&w,10,1);qq_jce_int(&w,11,27);qq_jce_head(&w,12,9);qq_jce_int(&w,0,0);for(unsigned i=13;i<=15;++i)qq_jce_int(&w,i,0);
        uint8_t d50[64];qq_writer pb={d50,0,sizeof d50,1};qq_pb_uint(&pb,1,1002);qq_pb_uint(&pb,91001,1);qq_pb_uint(&pb,101001,1);qq_pb_uint(&pb,151001,1);qq_pb_uint(&pb,181001,1);qq_jce_bytes(&w,16,(qq_view){d50,pb.size});qq_jce_bytes(&w,17,(qq_view){0,0});qq_jce_head(&w,18,9);qq_jce_int(&w,0,3);for(unsigned i=13580;i<=13582;++i)qq_jce_int(&w,0,i);function="GetFriendListReq";key="FL";
    }
    qq_writer packet={out,0,cap,1};if(!w.ok||!qq_jce_request(&packet,seq,"mqq.IMService.FriendListServiceServantObj",function,key,(qq_view){body,w.size},group?0:3))return 0;*size=packet.size;return 1;
}
int qq_contacts_result(qq_view data,int group,qq_contact_list *list)
{
    qq_view payload;qq_jce_field fields,field;if(!qq_jce_payload(data,group?"GetTroopListRespV2":"FLRESP",&payload)||!qq_jce_find(payload,group?5:7,&fields)||fields.type!=9)return 0;
    if(!group&&qq_jce_find(payload,5,&field)&&field.value>=0)list->total=(unsigned)field.value;
    list->cookie_size=0;if(group&&qq_jce_find(payload,4,&field)){if(field.type!=13||field.bytes.size>sizeof list->cookie)return 0;list->cookie_size=field.bytes.size;copy(list->cookie,field.bytes.data,field.bytes.size);}
    if(!group&&qq_jce_find(payload,14,&field)){
        if(field.type!=9)return 0;qq_reader groups={field.bytes.data,field.bytes.size,0,1};
        for(unsigned i=0;i<field.count;++i){qq_jce_field item,id,name,n;unsigned category;
            if(!qq_jce_next(&groups,&item)||item.type!=10||!qq_jce_find(item.bytes,0,&id)||(id.type>3&&id.type!=12)||id.value < -128||id.value>255||!qq_jce_find(item.bytes,1,&name)||(name.type!=6&&name.type!=7))return 0;
            category=(uint8_t)id.value;unsigned k=0;while(k<list->category_count&&list->categories[k].id!=category)++k;
            if(k==list->category_count){if(k>=QQ_CATEGORIES_MAX)return 0;++list->category_count;}
            qq_category *out=&list->categories[k];out->id=category;qq_copy_text(out->name,sizeof out->name,name.bytes);
            if(qq_jce_find(item.bytes,2,&n)&&n.value>=0)out->count=(unsigned)n.value;
            if(qq_jce_find(item.bytes,3,&n)&&n.value>=0)out->online=(unsigned)n.value;
        }if(!groups.ok)return 0;
    }
    qq_reader r={fields.bytes.data,fields.bytes.size,0,1};for(unsigned i=0;i<fields.count;++i){
        qq_jce_field item,id,name;if(!qq_jce_next(&r,&item)||item.type!=10||!qq_jce_find(item.bytes,group?1:0,&id)||(id.type>3&&id.type!=12)||id.value<=0)return 0;
        qq_view text={0,0};if(qq_jce_find(item.bytes,group?4:3,&name)&&(name.type==6||name.type==7))text=name.bytes;
        if(!group&&!text.size&&qq_jce_find(item.bytes,14,&name)&&(name.type==6||name.type==7))text=name.bytes;
        unsigned category=0;uint64_t owner=0;qq_view nick={0,0};
        if(!group&&qq_jce_find(item.bytes,1,&name)){if((name.type>3&&name.type!=12)||name.value < -128||name.value>255)return 0;category=(uint8_t)name.value;}
        if(!group&&qq_jce_find(item.bytes,14,&name)&&(name.type==6||name.type==7))nick=name.bytes;
        if(group&&qq_jce_find(item.bytes,23,&name)){if((name.type>3&&name.type!=12)||name.value<0)return 0;owner=(uint64_t)name.value;}
        if(list->count>=QQ_PEOPLE_MAX){list->truncated=1;continue;}qq_contact *out=&list->items[list->count++];out->id=(uint64_t)id.value;out->owner=owner;out->category=category;qq_copy_text(out->name,sizeof out->name,text);qq_copy_text(out->nick,sizeof out->nick,nick);
    }
    if(group)list->total=list->count;return r.ok;
}
static unsigned cookie_make(uint32_t now,uint8_t out[64])
{qq_writer w={out,0,64,1};qq_pb_uint(&w,2,now);qq_pb_uint(&w,3,758330138);qq_pb_uint(&w,4,2480149246u);qq_pb_uint(&w,5,1167238020);qq_pb_uint(&w,11,3913056418u);qq_pb_uint(&w,12,0x1d);return w.size;}
int qq_text_send_body(uint64_t peer,int group,qq_view text,uint32_t seq,uint32_t random,uint32_t now,uint8_t *out,uint32_t cap,uint32_t *size)
{
    if(!peer||!text.size||text.size>384)return 0;uint8_t a[1024],b[1100],c[1200],route[32],content[32],cookie[64];
    qq_writer target={a,0,sizeof a,1};qq_pb_uint(&target,1,peer);qq_writer routing={route,0,sizeof route,1};qq_pb_bytes(&routing,group?2:1,(qq_view){a,target.size});
    qq_writer head={content,0,sizeof content,1};qq_pb_uint(&head,1,1);qq_pb_uint(&head,2,0);qq_pb_uint(&head,3,0);
    qq_writer t={a,0,sizeof a,1};qq_pb_bytes(&t,1,text);qq_writer elem={b,0,sizeof b,1};qq_pb_bytes(&elem,1,(qq_view){a,t.size});qq_writer rich={a,0,sizeof a,1};qq_pb_bytes(&rich,2,(qq_view){b,elem.size});qq_writer body={c,0,sizeof c,1};qq_pb_bytes(&body,1,(qq_view){a,rich.size});
    qq_writer w={out,0,cap,1};qq_pb_bytes(&w,1,(qq_view){route,routing.size});qq_pb_bytes(&w,2,(qq_view){content,head.size});qq_pb_bytes(&w,3,(qq_view){c,body.size});qq_pb_uint(&w,4,seq);qq_pb_uint(&w,5,random);unsigned n=group?0:cookie_make(now,cookie);qq_pb_bytes(&w,6,(qq_view){cookie,n});if(group)qq_pb_uint(&w,8,1);
    if(!w.ok||!head.ok||!routing.ok||!body.ok||!rich.ok||!elem.ok||!t.ok)return 0;*size=w.size;return 1;
}
int qq_text_send_result(qq_view data,unsigned *result,char error[256])
{
    qq_reader r={data.data,data.size,0,1};qq_field f;*result=0;error[0]=0;while(qq_pb_next(&r,&f)){if(f.tag==1){if(f.type!=0||f.value>UINT32_MAX)return 0;*result=(unsigned)f.value;}else if(f.tag==2){if(f.type!=2)return 0;qq_copy_text(error,256,f.bytes);}}return r.ok;
}
int qq_get_messages_body(qq_view cookie,unsigned flag,uint32_t now,uint8_t *out,uint32_t cap,uint32_t *size)
{
    uint8_t generated[64];if(!cookie.size){cookie=(qq_view){generated,cookie_make(now,generated)};}
    qq_writer w={out,0,cap,1};qq_pb_uint(&w,1,flag);qq_pb_bytes(&w,2,cookie);qq_pb_uint(&w,3,0);qq_pb_uint(&w,4,20);qq_pb_uint(&w,5,3);qq_pb_uint(&w,6,1);qq_pb_uint(&w,7,1);qq_pb_uint(&w,9,1);if(!w.ok)return 0;*size=w.size;return 1;
}
int qq_message_reconcile(qq_text_message *old,const qq_text_message *message,uint64_t self)
{
        if(old->peer!=message->peer||old->group!=message->group||old->sender!=message->sender)return 0;
        int both_random=(old->flags&message->flags&QQ_MESSAGE_RANDOM)!=0;
        if((old->uid&&old->uid==message->uid)||(!old->uid&&!message->uid&&old->sequence==message->sequence&&old->time==message->time&&(!both_random||old->random==message->random)))return 1;
        if(old->sender!=self||!((old->flags^message->flags)&QQ_MESSAGE_LOCAL))return 0;
        uint32_t distance=old->time>message->time?old->time-message->time:message->time-old->time;
        if(strcmp(old->text,message->text)||!(both_random?old->random==message->random:!old->group&&old->sequence==message->sequence&&distance<=120))return 0;
        /* A server echo may arrive either before or after the successful ACK. */
        if(old->flags&QQ_MESSAGE_LOCAL){uint32_t saved_random=old->random,saved_flags=old->flags;*old=*message;
            if(!(old->flags&QQ_MESSAGE_RANDOM)&&(saved_flags&QQ_MESSAGE_RANDOM)){old->random=saved_random;old->flags|=QQ_MESSAGE_RANDOM;}return 2;}
    return 1;
}
int qq_text_message_parse(qq_view message,uint64_t self,unsigned group,qq_text_message *out)
{
    *out=(qq_text_message){0};qq_view head=pbbytes(message,1),body=pbbytes(message,3),rich=pbbytes(body,1);if(!head.size||!rich.size)return 0;
    out->sender=pbnum(head,1);out->recipient=pbnum(head,2);out->sequence=(uint32_t)pbnum(head,5);out->time=(uint32_t)pbnum(head,6);out->uid=pbnum(head,7);out->group=group;
    qq_field random;if(qq_pb_find(pbbytes(rich,1),3,&random)&&random.type==0){out->random=(uint32_t)random.value;out->flags|=QQ_MESSAGE_RANDOM;}
    if(group){qq_view info=pbbytes(head,9);out->peer=pbnum(info,1);qq_copy_text(out->sender_name,sizeof out->sender_name,pbbytes(info,4));}else out->peer=out->sender==self?out->recipient:out->sender;
    if(!out->sender_name[0])qq_copy_text(out->sender_name,sizeof out->sender_name,pbbytes(head,14));
    qq_reader r={rich.data,rich.size,0,1};qq_field f;unsigned used=0,nontext=0;
    while(qq_pb_next(&r,&f))if(f.tag==2&&f.type==2){qq_view text=pbbytes(f.bytes,1),str=pbbytes(text,1);if(str.size){unsigned room=sizeof out->text-1-used,n=str.size;if(n>room)n=room;while(n<str.size&&n&&(str.data[n]&0xc0)==0x80)--n;copy(out->text+used,str.data,n);used+=n;out->text[used]=0;}else nontext=1;}
    if(!used&&nontext)qq_copy_text(out->text,sizeof out->text,qq_string("[非文字消息]"));
    return r.ok&&out->sender&&out->peer&&out->text[0];
}
int qq_get_messages_result(qq_view data,uint64_t self,uint8_t cookie[1024],unsigned *cookie_size,unsigned *flag,qq_message_sink sink,void *context)
{
    qq_reader r={data.data,data.size,0,1};qq_field f;unsigned result=0;while(qq_pb_next(&r,&f)){
        if(f.tag==1){if(f.type!=0)return 0;result=(unsigned)f.value;}
        else if(f.tag==3){if(f.type!=2||f.bytes.size>1024)return 0;copy(cookie,f.bytes.data,f.bytes.size);*cookie_size=f.bytes.size;}
        else if(f.tag==4){if(f.type!=0||f.value>2)return 0;*flag=(unsigned)f.value;}
        else if(f.tag==5&&f.type==2){qq_reader pair={f.bytes.data,f.bytes.size,0,1};qq_field msg;
            while(qq_pb_next(&pair,&msg))if(msg.tag==4&&msg.type==2){qq_text_message parsed;if(qq_text_message_parse(msg.bytes,self,0,&parsed)&&sink(context,&parsed))return 0;}if(!pair.ok)return 0;}
    }return r.ok&&!result;
}
int qq_delete_messages_body(qq_view data,uint8_t *out,uint32_t cap,uint32_t *size)
{
    qq_writer w={out,0,cap,1};qq_reader r={data.data,data.size,0,1};qq_field f;
    while(qq_pb_next(&r,&f))if(f.tag==5&&f.type==2){qq_reader pair={f.bytes.data,f.bytes.size,0,1};qq_field message;
        while(qq_pb_next(&pair,&message))if(message.tag==4&&message.type==2){qq_view head=pbbytes(message.bytes,1);uint64_t from=pbnum(head,1),to=pbnum(head,2);if(!from||!to)continue;
            uint8_t item[96];qq_writer i={item,0,sizeof item,1};qq_pb_uint(&i,1,from);qq_pb_uint(&i,2,to);qq_pb_uint(&i,3,pbnum(head,3));qq_pb_uint(&i,4,pbnum(head,5));qq_pb_uint(&i,5,pbnum(head,7));if(!i.ok)return 0;qq_pb_bytes(&w,1,(qq_view){item,i.size});}if(!pair.ok)return 0;
    }
    if(!w.ok||!r.ok)return 0;*size=w.size;return 1;
}
