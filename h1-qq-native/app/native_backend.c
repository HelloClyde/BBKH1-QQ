#include "qq.h"
#include "qq_business.h"
#include "qq_crypto.h"
#include "qq_profile.h"
#include "qq_energy.h"
#include "h1net_tcp.h"
#include "transport.h"
#include "h1_inputs.h"
#include "h1_sign_clock.h"
#include "h1_filesystem.h"
#include "signer.h"
#include "cJSON.h"
#include "avatars.h"
#include "saved_session.h"
#include "local_history.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include "zlib.h"
#pragma GCC diagnostic pop
#include <string.h>
#include <stdio.h>
char qq_last_error[256];
static struct {
    h1net_client rpc;h1qq_identity identity;h1qq_signer signer;
    qq_qr_session qr;qq_account account;qq_packet_work work;
    uint8_t tx[QQ_PACKET_MAX+64],rx[QQ_PACKET_MAX],body[QQ_PACKET_MAX],login[16384],plain[16384],png[16384],cookie[1024];
    uint32_t stream,epoch,sent,received,rx_used,rx_need,last_heartbeat,last_sync,message_seq,retry_after,poll_retry_after,last_push_poll,cache_revision;
    uint32_t resets,cancel_resets,registrations,background_failures,last_failure,last_reset_reason,last_tcp_state,last_tcp_error;
    int last_rpc_error;uint32_t last_remote_status;int32_t last_sso_return;
    char active_command[64],last_failure_command[64];
    unsigned png_size,qr_sig_size,cookie_size,sync_flag,need_sync,cache_count,phase,sent_acks,friend_count,group_count,qr_credential_mode;
    unsigned session_checked,session_restored,session_saved,session_fallbacks;
    uint64_t history_account;
    qq_text_message cache[96];qq_contact_list contacts;
} c;
static uint32_t now_ms(void *unused){(void)unused;return qq_time();}
static int random_bytes(uint8_t *out,unsigned n){return h1qq_identity_random(&c.identity,out,n);}
static void history_bind(void)
{
    if(!c.account.uin||c.history_account==c.account.uin)return;
    if(!qq_local_bind(&c.identity,c.account.uin))return;
    c.cache_count=qq_local_restore(c.cache,96);c.history_account=c.account.uin;++c.cache_revision;
}
static uint64_t number(const char *s)
{uint64_t x=0;if(!s||!*s)return 0;while(*s){if(*s<'0'||*s>'9'||x>(UINT64_MAX-(unsigned)(*s-'0'))/10)return 0;x=x*10+(unsigned)(*s++-'0');}return x;}
static void decimal(uint64_t x,char out[21])
{char r[20];unsigned n=0;do{r[n++]=(char)('0'+x%10);x/=10;}while(x);for(unsigned i=0;i<n;++i)out[i]=r[n-1-i];out[n]=0;}
static enum qq_result error(enum qq_result code,const char *text)
{if(text)qq_copy_text(qq_last_error,sizeof qq_last_error,qq_string(text));qq_native_save_report();return code;}
void qq_native_save_report(void)
{
    char report[1600];uint32_t seconds=0,local=0;h1qq_sign_clock clock;
    if(c.identity.ready&&h1qq_h1_sign_clock(&c.identity,&local,&clock))seconds=clock.seconds;
    int n=snprintf(report,sizeof report,"H1QQ_NATIVE/1\nphase=%u\nauthenticated=%u\nregistered=%u\nfriends=%u\ngroups=%u\nmessage_cache=%u\nsent_acks=%u\nutc=%lu\nerror=%s\nactive_command=%s\nlast_failure_command=%s\nlast_failure=%lu\nlast_rpc_error=%d\nlast_remote_status=%lu\nlast_tcp_state=%lu\nlast_tcp_error=%lu\nlast_sso_return=%ld\nreset_count=%lu\ncancel_reset_count=%lu\nregistration_count=%lu\nbackground_failure_count=%lu\nlast_reset_reason=%lu\n",c.phase,c.account.authenticated,c.account.registered,c.friend_count,c.group_count,c.cache_count,c.sent_acks,(unsigned long)seconds,qq_last_error,c.active_command,c.last_failure_command,(unsigned long)c.last_failure,c.last_rpc_error,(unsigned long)c.last_remote_status,(unsigned long)c.last_tcp_state,(unsigned long)c.last_tcp_error,(long)c.last_sso_return,(unsigned long)c.resets,(unsigned long)c.cancel_resets,(unsigned long)c.registrations,(unsigned long)c.background_failures,(unsigned long)c.last_reset_reason);
    if(n>0&&(unsigned)n<sizeof report){int extra=snprintf(report+n,sizeof report-(unsigned)n,"session_restored=%u\nsession_saved=%u\nsession_fallbacks=%u\n",c.session_restored,c.session_saved,c.session_fallbacks);if(extra<0||(unsigned)extra>=sizeof report-(unsigned)n)return;n+=extra;}
    if(n<=0||(unsigned)n>=sizeof report)return;h1_file *file=h1_fopen(QQ_LOG_PATH,"wb");if(file){(void)h1_fwrite(report,1,(unsigned)n,file);(void)h1_fclose(file);}qq_clear(report,sizeof report);
}
static int utc(uint32_t *now,h1qq_sign_clock *clock)
{uint32_t local;if(!h1qq_h1_sign_clock(&c.identity,&local,clock))return 0;*now=clock->seconds;return 1;}
enum {RESET_USER=1,RESET_TRANSPORT,RESET_NETWORK,RESET_CANCEL,RESET_SHUTDOWN};
static void net_reset(unsigned reason)
{
    qq_avatars_network_reset();
    if(c.stream||c.rpc.ready||c.account.registered){++c.resets;c.last_reset_reason=reason;if(reason==RESET_CANCEL)++c.cancel_resets;}
    if(c.stream&&c.rpc.ready&&!c.rpc.broken&&h1net_transport_connected()&&c.epoch==h1net_transport_epoch())(void)h1net_tcp_close(&c.rpc,c.stream);
    c.stream=0;c.rpc.ready=0;c.account.registered=0;c.rx_used=0;c.rx_need=4;c.sent=c.received=0;c.retry_after=qq_time()+10000;
}
void qq_net_reset(void){net_reset(RESET_USER);}
void qq_native_shutdown(void){qq_avatars_close(c.rpc.ready&&!c.rpc.broken?&c.rpc:0);net_reset(RESET_SHUTDOWN);qq_local_close();h1qq_signer_close(&c.signer);h1qq_identity_close(&c.identity);qq_clear(&c,sizeof c);qq_clear(qq_last_error,sizeof qq_last_error);}
static enum qq_result transport(void)
{
    if(!h1net_transport_connected())return error(QQ_OFFLINE,"等待 ESP32 连接");
    if(c.rpc.ready&&!c.rpc.broken&&c.epoch==h1net_transport_epoch())return QQ_OK;
    net_reset(RESET_TRANSPORT);c.epoch=h1net_transport_epoch();h1net_transport_bind();h1net_io io={0,h1net_transport_write,h1net_transport_read,h1net_transport_finish,qq_idle,now_ms};h1net_client_init(&c.rpc,&io,2500);
    if(h1net_hello(&c.rpc)||h1net_capabilities(&c.rpc))return error(QQ_NETWORK,"ESP32 握手失败");
    if(!(c.rpc.features&H1NET_CAP_TCP_STREAM))return error(QQ_FIRMWARE,"请更新支持 TCP 的 ESP32 固件");
    if(!c.identity.ready){
        if(!h1qq_h1_identity_open(&c.identity)||!h1qq_signer_init(&c.signer,&c.identity))return error(QQ_AUTH,"H1QQ.ID 不可用，请先初始化身份");
    }
    if(!c.session_checked){
        c.session_checked=1;c.session_restored=(unsigned)qq_saved_session_load(&c.identity,&c.account);c.session_saved=c.session_restored;
        if(c.session_restored){uint8_t seed[8];if(!random_bytes(seed,sizeof seed))return QQ_AUTH;memcpy(c.qr.guid,c.identity.uuid,16);c.qr.sequence=10000+((unsigned)seed[0]*256+seed[1])%20000;c.message_seq=((uint32_t)seed[2]<<24|(uint32_t)seed[3]<<16|(uint32_t)seed[4]<<8|seed[5])&0x7fffffffu;qq_clear(seed,sizeof seed);}
    }
    return QQ_OK;
}
static enum qq_result stream_open(void)
{
    enum qq_result e=transport();if(e)return e;if(c.stream)return QQ_OK;
    c.phase=1;
    if(h1net_tcp_open(&c.rpc,"msfwifi.3g.qq.com",8080,10000,&c.stream))return error(QQ_NETWORK,"QQ TCP 建连请求失败");
    uint32_t begin=qq_time();for(;;){
        if(qq_cancel)return QQ_CANCELLED;h1net_tcp_info info;if(h1net_tcp_get_info(&c.rpc,c.stream,&info))return error(QQ_NETWORK,"无法读取 QQ 连接状态");
        c.last_tcp_state=info.state;c.last_tcp_error=info.error;if(info.state==H1NET_TCP_CONNECTED)break;if(info.state>=H1NET_TCP_EOF||qq_time()-begin>13000)return error(QQ_NETWORK,"QQ 网关连接失败");qq_idle(0);
    }
    c.sent=c.received=c.rx_used=0;c.rx_need=4;return QQ_OK;
}
static enum qq_result send_bytes(const uint8_t *packet,unsigned size)
{
    unsigned offset=0;uint32_t begin=qq_time();while(offset<size){
        if(qq_cancel)return QQ_CANCELLED;unsigned n=size-offset;if(n>504)n=504;
        int e=h1net_tcp_write(&c.rpc,c.stream,c.sent,packet+offset,n);
        if(e==H1NET_REMOTE&&c.rpc.remote_status==H1NET_BUSY){if(qq_time()-begin>15000)return error(QQ_NETWORK,"QQ 发送缓冲等待超时");qq_idle(0);continue;}
        if(e){c.last_rpc_error=e;c.last_remote_status=c.rpc.remote_status;return error(QQ_NETWORK,"发送状态未知，请核对消息，勿重复发送");}offset+=n;c.sent+=n;begin=qq_time();
    }return QQ_OK;
}
static int next_frame(unsigned wait_ms)
{
    uint32_t begin=qq_time();for(;;){
        if(qq_cancel)return -QQ_CANCELLED;unsigned wanted=c.rx_need-c.rx_used;if(wanted>500)wanted=500;unsigned n=0;
        int e=h1net_tcp_read(&c.rpc,c.stream,c.received,c.rx+c.rx_used,wanted,&n);if(e){c.last_rpc_error=e;c.last_remote_status=c.rpc.remote_status;return -QQ_NETWORK;}
        c.rx_used+=n;c.received+=n;
        if(c.rx_used==c.rx_need){
            if(c.rx_need==4){c.rx_need=(uint32_t)c.rx[0]<<24|(uint32_t)c.rx[1]<<16|(uint32_t)c.rx[2]<<8|c.rx[3];if(c.rx_need<15||c.rx_need>sizeof c.rx)return -QQ_TOO_LARGE;}
            else {unsigned size=c.rx_need;c.rx_used=0;c.rx_need=4;return (int)size;}
        }
        if(!n){h1net_tcp_info info;e=h1net_tcp_get_info(&c.rpc,c.stream,&info);if(e){c.last_rpc_error=e;c.last_remote_status=c.rpc.remote_status;return -QQ_NETWORK;}c.last_tcp_state=info.state;c.last_tcp_error=info.error;if(info.state>=H1NET_TCP_EOF)return -QQ_NETWORK;
            if(qq_time()-begin>=wait_ms)return 0;qq_idle(0);}
    }
}
static int store_message(void *unused,const qq_text_message *message)
{
    (void)unused;history_bind();for(unsigned i=0;i<c.cache_count;++i){int found=qq_message_reconcile(&c.cache[i],message,c.account.uin);if(found){if(found==2){(void)qq_local_message(&c.cache[i]);++c.cache_revision;}return 0;}}
    if(c.cache_count==96){memmove(c.cache,c.cache+1,95*sizeof *c.cache);--c.cache_count;}c.cache[c.cache_count++]=*message;(void)qq_local_message(message);++c.cache_revision;return 0;
}
static int signing(const char *command){return !strcmp(command,"wtlogin.login")||!strcmp(command,"MessageSvc.PbSendMsg");}
static int reserve(qq_view body,uint8_t out[1024],unsigned *size)
{
    uint32_t seconds;h1qq_sign_clock clock;if(!utc(&seconds,&clock))return 0;
    if(h1qq_signer_poll(&c.signer,seconds)<0||h1qq_signer_poll(&c.signer,seconds)<0)return 0;
    h1qq_cached_result result;uint8_t extra[512],secure[768];qq_view q=qq_string(QQ_NATIVE_QUA);h1qq_bytes qua={q.data,q.size},data={body.data,body.size};
    if(!h1qq_signer_request(&c.signer,qua,data,&clock,&result,extra,sizeof extra))return 0;
    qq_writer sec={secure,0,sizeof secure,1};qq_pb_bytes(&sec,1,(qq_view){result.sign,68});qq_pb_bytes(&sec,2,(qq_view){result.token,result.token_size});qq_pb_bytes(&sec,3,(qq_view){extra,result.extra_size});
    qq_writer w={out,0,1024,1};char uin[21];decimal(c.account.uin,uin);qq_pb_bytes(&w,16,qq_string(uin));qq_pb_uint(&w,19,1);qq_pb_uint(&w,20,1);qq_pb_bytes(&w,24,(qq_view){secure,sec.size});*size=w.size;
    qq_clear(&result,sizeof result);qq_clear(extra,sizeof extra);qq_clear(secure,sizeof secure);return sec.ok&&w.ok;
}
static enum qq_result packet_send(const char *command,qq_view body,unsigned login_type,uint32_t *sequence)
{
    h1qq_sign_clock clock;uint32_t now;if(!utc(&now,&clock))return error(QQ_AUTH,"应用 UTC 时钟不可用");
    c.qr.seconds=now;c.qr.sequence=(c.qr.sequence+1)&0x7fffffffu;if(!random_bytes(c.qr.pad,18))return QQ_AUTH;uint8_t sec[1024];unsigned sec_size=0;qq_view secure={0,0};
    if(signing(command)){if(!reserve(body,sec,&sec_size))return error(QQ_AUTH,"原生签名不可用");secure=(qq_view){sec,sec_size};}
    uint32_t size;if(!qq_session_packet(&c.work,&c.qr,&c.account,login_type,command,body,secure,c.tx,sizeof c.tx,&size))return QQ_TOO_LARGE;
    *sequence=c.qr.sequence;enum qq_result e=send_bytes(c.tx,size);qq_clear(sec,sizeof sec);return e;
}
static enum qq_result push(qq_sso_reply *reply)
{
    qq_view data={c.body,reply->body_size};
    if(!strcmp(reply->command,"OnlinePush.PbPushGroupMsg")){
        qq_field f;qq_text_message message;if(qq_pb_find(data,1,&f)&&f.type==2&&qq_text_message_parse(f.bytes,c.account.uin,1,&message))store_message(0,&message);
    }else if(!strcmp(reply->command,"MessageSvc.PushNotify"))c.need_sync=1;
    else if(!strcmp(reply->command,"MessageSvc.PushForceOffline")||!strcmp(reply->command,"StatSvc.ReqMSFOffline")){
        qq_saved_session_forget();c.session_saved=0;qq_clear(&c.account,sizeof c.account);return error(QQ_AUTH,"QQ 账号已离线，请重新扫码");
    }else if(!strcmp(reply->command,"ConfigPushSvc.PushReq")){
        qq_view payload;qq_jce_field t,buffer,seq;
        if(qq_jce_payload(data,"PushReq",&payload)&&qq_jce_find(payload,1,&t)&&qq_jce_find(payload,2,&buffer)&&qq_jce_find(payload,3,&seq)&&buffer.type==13){
            uint8_t fields[12288],packet[14000];qq_writer w={fields,0,sizeof fields,1};qq_jce_int(&w,1,t.value);qq_jce_int(&w,2,seq.value);qq_jce_bytes(&w,3,buffer.bytes);qq_writer req={packet,0,sizeof packet,1};uint32_t s;
            if(w.ok&&qq_jce_request(&req,c.qr.sequence+1,"QQService.ConfigPushSvc.MainServant","PushResp","PushResp",(qq_view){fields,w.size},0))return packet_send("ConfigPushSvc.PushResp",(qq_view){packet,req.size},0,&s);
        }
    }return QQ_OK;
}
static enum qq_result decode_frame(unsigned n,qq_sso_reply *reply)
{
    if(!qq_sso_decode(c.rx,n,c.account.d2_key,reply,c.body,sizeof c.body))return error(QQ_RESPONSE,"QQ SSO 响应格式不支持");
    if(reply->sso_return){c.last_sso_return=reply->sso_return;snprintf(qq_last_error,sizeof qq_last_error,"QQ SSO 拒绝：%ld",(long)reply->sso_return);return QQ_REJECTED;}
    if(reply->compression==1){uLongf size=sizeof c.work.encrypted;if(uncompress(c.work.encrypted,&size,c.body,reply->body_size)!=Z_OK||size>sizeof c.body)return QQ_TOO_LARGE;memcpy(c.body,c.work.encrypted,size);reply->body_size=(uint32_t)size;}
    else if(reply->compression!=0)return error(QQ_RESPONSE,"QQ 压缩模式不支持");
    memcpy(c.account.session_id,reply->session_id,4);return QQ_OK;
}
static enum qq_result receive(const char *command,uint32_t sequence,qq_view *body)
{
    uint32_t begin=qq_time();while(qq_time()-begin<15000){int n=next_frame(1000);if(n<0)return (enum qq_result)-n;if(!n)continue;
        qq_sso_reply reply;enum qq_result e=decode_frame((unsigned)n,&reply);if(e)return e;
        if(reply.sequence==sequence&&!strcmp(reply.command,command)){*body=(qq_view){c.body,reply.body_size};return QQ_OK;}
        e=push(&reply);if(e)return e;
    }return error(QQ_NETWORK,"QQ 响应超时，结果未确认");
}
static enum qq_result request(const char *command,qq_view payload,unsigned type,qq_view *response)
{qq_copy_text(c.active_command,sizeof c.active_command,qq_string(command));uint32_t seq;enum qq_result e=packet_send(command,payload,type,&seq);if(!e)e=receive(command,seq,response);if(e){c.last_failure=(unsigned)e;qq_copy_text(c.last_failure_command,sizeof c.last_failure_command,qq_string(command));}if(e==QQ_NETWORK||e==QQ_CANCELLED)net_reset(e==QQ_CANCELLED?RESET_CANCEL:RESET_NETWORK);if(e)qq_native_save_report();c.active_command[0]=0;return e;}
static int key_sink(void *context,const uint8_t *data,unsigned n)
{unsigned *used=context;if(n>sizeof c.plain-1-*used)return 1;memcpy(c.plain+*used,data,n);*used+=n;return 0;}
static int key_progress(void *unused,const h1net_info *info){(void)unused;(void)info;return qq_cancel;}
static enum qq_result prepare_qr(void)
{
    c.phase=2;
    unsigned used=0;h1net_info info;if(h1net_download(&c.rpc,"https://keyrotate.qq.com/rotate_key?cipher_suite_ver=305&uin=0",8192,10000,key_sink,key_progress,&used,&info))return error(QQ_NETWORK,"获取 QQ 公共密钥失败");
    if(c.rpc.features&H1NET_CAP_RELEASE)(void)h1net_http_release(&c.rpc,info.job);
    c.plain[used]=0;cJSON *root=cJSON_ParseWithLengthOpts((char *)c.plain,used+1,0,1);cJSON *meta=cJSON_GetObjectItemCaseSensitive(root,"PubKeyMeta"),*ver=cJSON_GetObjectItemCaseSensitive(meta,"KeyVer");const char *hex=cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(meta,"PubKey"));uint8_t server[65],private_key[32];int valid=hex&&strlen(hex)==130&&cJSON_IsNumber(ver)&&ver->valuedouble>=1&&ver->valuedouble<=65535;
    if(valid)for(unsigned i=0;i<65;++i){unsigned b=0;for(unsigned j=0;j<2;++j){char ch=hex[2*i+j];unsigned x=ch>='0'&&ch<='9'?(unsigned)(ch-'0'):ch>='A'&&ch<='F'?(unsigned)(ch-'A'+10):ch>='a'&&ch<='f'?(unsigned)(ch-'a'+10):99;if(x>15)valid=0;b=b*16+x;}server[i]=(uint8_t)b;}
    if(valid)c.qr.key_version=(uint16_t)ver->valueint;cJSON_Delete(root);if(!valid)return error(QQ_RESPONSE,"QQ 公共密钥格式错误");
    qq_login_display(QQ_LOGIN_PREPARE,0,0,"正在准备本机握手…");valid=0;for(unsigned i=0;i<8&&!valid;++i){if(!random_bytes(private_key,32))break;valid=qq_ecdh_with_rng(private_key,server,c.qr.public_key,c.qr.share_key,random_bytes);}
    qq_clear(private_key,32);qq_clear(server,65);if(!valid)return error(QQ_AUTH,"原生握手失败");
    if(!random_bytes(c.qr.random_key,16))return QQ_AUTH;memcpy(c.qr.guid,c.identity.uuid,16);
    unsigned sum=0;for(unsigned i=0;i<14;++i){unsigned d=c.qr.guid[i]%10;c.qr.imei[i]=(char)('0'+d);unsigned x=i&1?d*2:d;sum+=x>9?x-9:x;}c.qr.imei[14]=(char)('0'+(10-sum%10)%10);c.qr.imei[15]=0;
    uint8_t seed[4];random_bytes(seed,4);c.qr.sequence=10000+((unsigned)seed[0]*256+seed[1])%20000;c.qr.code_sequence=0;return QQ_OK;
}
static enum qq_result qr_exchange(int query,qq_view *response)
{
    h1qq_sign_clock clock;uint32_t now,size;if(!utc(&now,&clock)||!random_bytes(c.qr.pad,18))return QQ_AUTH;c.qr.seconds=now;++c.qr.sequence;
    int ok=query?qq_qr_query(&c.qr,c.login,c.qr_sig_size,c.tx,sizeof c.tx,&size):qq_qr_fetch(&c.qr,c.tx,sizeof c.tx,&size);
    if(!ok)return QQ_RESPONSE;++c.qr.code_sequence;enum qq_result e=send_bytes(c.tx,size);return e?e:receive("wtlogin.trans_emp",c.qr.sequence,response);
}
static enum qq_result login(void)
{
restart:
    ;qq_clear(&c.account,sizeof c.account);
    enum qq_result e=prepare_qr();if(e)return e;qq_view response;uint32_t cmd,status,sig_size,png_size;const uint8_t *sig,*png;
    c.phase=3;e=qr_exchange(0,&response);if(e)return e;
    if(!qq_qr_decode(&c.qr,response.data,response.size,c.plain,sizeof c.plain,&cmd,&status,&sig,&sig_size,&png,&png_size)||cmd!=0x31||status||sig_size>sizeof c.login||png_size>sizeof c.png)return error(QQ_RESPONSE,"QQ 二维码解析失败");
    memcpy(c.login,sig,sig_size);c.qr_sig_size=sig_size;memcpy(c.png,png,png_size);c.png_size=png_size;c.phase=4;qq_native_save_report();
    if(!qq_login_display(QQ_LOGIN_WAIT,c.png,png_size,"请用手机 QQ 扫码并确认登录")){
        uint8_t header[16];qq_writer w={header,0,sizeof header,1};qq_put(&w,"H1QQIMG1",8);qq_num(&w,c.qr.seconds,4);qq_num(&w,png_size,4);
        h1_file *file=h1_fopen(QQ_QR_PATH,"wb");if(file){(void)h1_fwrite(header,1,w.size,file);(void)h1_fwrite(c.png,1,png_size,file);(void)h1_fclose(file);}
        return error(QQ_RESPONSE,"二维码图像无法显示，按 R 重新取码");
    }
    uint32_t start=qq_time();while(qq_time()-start<180000){
        uint32_t wait=qq_time();while(qq_time()-wait<1500){if(qq_cancel)return QQ_CANCELLED;if(qq_login_refresh_requested())goto restart;qq_idle(0);}
        e=qr_exchange(1,&response);if(e)return e;if(qq_login_refresh_requested())goto restart;qq_view clear;
        if(!qq_oicq_open(&c.qr,&c.account,response,c.plain,sizeof c.plain,&clear)||!qq_qr_decode(&c.qr,response.data,response.size,c.work.plain,sizeof c.work.plain,&cmd,&status,&sig,&sig_size,&png,&png_size)||cmd!=0x12)return error(QQ_RESPONSE,"QQ 扫码状态解析失败");
        if(status==0x30)continue;if(status==0x35){qq_login_display(QQ_LOGIN_CONFIRM,0,0,"已扫码，请在手机上确认");continue;}
        if(status==0x11)return error(QQ_AUTH,"二维码已过期，按 R 重新取码");if(status==0x36)return error(QQ_CANCELLED,"手机取消了登录");if(status)return error(QQ_REJECTED,"QQ 拒绝了扫码确认");
        if(!qq_qr_credentials(clear,&c.account)||!qq_qr_unwrap(c.qr.guid,&c.account,&c.qr_credential_mode))return error(QQ_RESPONSE,"扫码凭据不完整");break;
    }
    if(!c.account.uin)return error(QQ_AUTH,"等待扫码超时，按 R 重试");c.phase=5;qq_login_display(QQ_LOGIN_AUTH,0,0,"正在原生登录 QQ…");
    uint8_t entropy[32];if(!random_bytes(entropy,32))return QQ_AUTH;uint32_t n,previous=c.qr.sequence;
    /* TLV154 and the outer SSO must use the same upcoming sequence. */
    c.qr.sequence=(previous+1)&0x7fffffffu;
    h1qq_sign_clock clock;uint8_t energy[68];if(!utc(&c.qr.seconds,&clock)||!qq_energy_login(&clock,(uint32_t)c.account.uin,c.qr.guid,energy)){qq_clear(entropy,32);c.qr.sequence=previous;return error(QQ_AUTH,"原生登录材料生成失败");}
    int built=qq_login_body(&c.qr,&c.account,entropy,(qq_view){energy,68},(qq_view){0,0},c.plain,sizeof c.plain,&n);qq_clear(entropy,32);qq_clear(energy,sizeof energy);
    uint32_t oicq_size;if(!built||!qq_oicq_wrap(&c.qr,c.account.uin,0x810,(qq_view){c.plain,n},c.login,sizeof c.login,&oicq_size)){c.qr.sequence=previous;return QQ_RESPONSE;}c.qr.sequence=previous;
    e=request("wtlogin.login",(qq_view){c.login,oicq_size},1,&response);if(e)return e;qq_view clear;if(!qq_oicq_open(&c.qr,&c.account,response,c.plain,sizeof c.plain,&clear))return QQ_RESPONSE;
    unsigned code;if(!qq_login_result(&c.account,clear,c.work.plain,sizeof c.work.plain,&code,qq_last_error))return error(QQ_RESPONSE,"QQ 登录票据解析失败");
    if(code){/* Rejection only: local private diagnostic for unsupported TLVs.
         * Success tickets are never persisted here. */
        uint8_t header[24];qq_writer w={header,0,sizeof header,1};qq_put(&w,"H1QQERR1",8);qq_num(&w,c.qr.seconds,4);qq_num(&w,code,4);qq_num(&w,clear.size,4);qq_num(&w,c.qr_credential_mode,4);
        h1_file *file=h1_fopen(QQ_ERROR_PATH,"wb");if(file){(void)h1_fwrite(header,1,w.size,file);(void)h1_fwrite(clear.data,1,clear.size,file);(void)h1_fclose(file);}
        if(!qq_last_error[0])snprintf(qq_last_error,sizeof qq_last_error,"QQ 登录被拒绝，代码 %u",code);qq_native_save_report();return QQ_REJECTED;}return QQ_OK;
}
static enum qq_result online(void)
{
again:
    ;enum qq_result e=stream_open();if(e){qq_net_reset();return e;}
    if(!c.account.authenticated){qq_clear(&c.account,sizeof c.account);c.cookie_size=0;c.cache_count=0;c.history_account=0;qq_local_close();e=login();if(e){qq_clear(&c.account,sizeof c.account);qq_net_reset();return e;}}
    if(!c.account.registered){qq_login_display(QQ_LOGIN_REGISTER,0,0,"正在注册在线状态…");uint32_t n;if(!qq_register_body(&c.account,c.qr.guid,c.qr.sequence+1,c.login,sizeof c.login,&n))return QQ_RESPONSE;qq_view response;
        e=request("StatSvc.register",(qq_view){c.login,n},1,&response);
        if(!e){int result=qq_register_result(response,qq_last_error);if(result!=1)e=result?QQ_REJECTED:QQ_RESPONSE;}
        /* Some gateways ACK register before pushing an expired-session kick.
         * Check the initial push window before exposing a restored account. */
        if(!e&&c.session_restored){uint32_t begin=qq_time();while(qq_time()-begin<1000){int size=next_frame(100);if(size<0){e=(enum qq_result)-size;break;}if(size){qq_sso_reply reply;e=decode_frame((unsigned)size,&reply);if(!e)e=push(&reply);if(e)break;}qq_idle(0);}}
        if(e){
            if(e==QQ_AUTH||e==QQ_REJECTED){qq_saved_session_forget();c.session_saved=0;qq_clear(&c.account,sizeof c.account);if(c.session_restored){c.session_restored=0;++c.session_fallbacks;net_reset(RESET_USER);qq_last_error[0]=0;goto again;}}
            if(e==QQ_NETWORK||e==QQ_CANCELLED)net_reset(e==QQ_CANCELLED?RESET_CANCEL:RESET_NETWORK);return e;
        }
        c.account.registered=1;++c.registrations;c.phase=6;c.last_heartbeat=qq_time();c.need_sync=1;
        c.session_saved=(unsigned)qq_saved_session_save(&c.identity,&c.account);qq_native_save_report();}
    history_bind();
    return QQ_OK;
}
enum qq_result qq_identity(const qq_config *cfg,qq_person *self)
{(void)cfg;enum qq_result e=online();if(e)return e;memset(self,0,sizeof *self);decimal(c.account.uin,self->id);qq_copy_text(self->name,sizeof self->name,qq_string(c.account.nickname));return QQ_OK;}
enum qq_result qq_contacts(const qq_config *cfg,int group,qq_people *people)
{
    (void)cfg;enum qq_result e=online();if(e)return e;memset(&c.contacts,0,sizeof c.contacts);unsigned page=0;
    do{unsigned before=c.contacts.count;uint32_t n;if(!qq_contacts_body(c.account.uin,group,before,(qq_view){c.contacts.cookie,c.contacts.cookie_size},c.qr.sequence+1,c.login,sizeof c.login,&n))return QQ_RESPONSE;qq_view response;
        e=request(group?"friendlist.GetTroopListReqV2":"friendlist.getFriendGroupList",(qq_view){c.login,n},0,&response);if(e)return e;if(!qq_contacts_result(response,group,&c.contacts))return QQ_RESPONSE;
        if(c.contacts.count==before)break;if(!group&&c.contacts.count>=c.contacts.total)break;if(group&&!c.contacts.cookie_size)break;
    }while(c.contacts.count<QQ_PEOPLE_MAX&&++page<32);
    memset(people,0,sizeof *people);people->count=c.contacts.count;people->truncated=c.contacts.truncated||(!group&&c.contacts.total>c.contacts.count)||(group&&c.contacts.cookie_size);
    if(group){people->category_count=2;people->categories[0].id=0;people->categories[1].id=1;qq_copy_text(people->categories[0].name,81,qq_string("我创建的群"));qq_copy_text(people->categories[1].name,81,qq_string("其他QQ群"));}
    else{people->category_count=c.contacts.category_count;memcpy(people->categories,c.contacts.categories,people->category_count*sizeof(qq_category));}
    for(unsigned i=0;i<people->count;++i){qq_contact *src=&c.contacts.items[i];qq_person *dst=&people->items[i];decimal(src->id,dst->id);qq_copy_text(dst->name,sizeof dst->name,qq_string(src->name));qq_copy_text(dst->nick,sizeof dst->nick,qq_string(src->nick));dst->category=group?(src->owner==c.account.uin?0:1):src->category;if(group)++people->categories[dst->category].count;if(!dst->name[0])memcpy(dst->name,dst->id,21);}if(group)c.group_count=people->count;else c.friend_count=people->count;c.phase=7;qq_native_save_report();return QQ_OK;
}
int qq_tick_due(void){return c.account.authenticated&&(int32_t)(qq_time()-c.poll_retry_after)>=0&&(!c.account.registered?(int32_t)(qq_time()-c.retry_after)>=0:c.need_sync||qq_time()-c.last_sync>=5000||qq_time()-c.last_heartbeat>=30000||qq_time()-c.last_push_poll>=250);}
static enum qq_result service_tick(void)
{
    if(!c.account.authenticated)return QQ_OK;enum qq_result e=online();if(e)return e;qq_view response;
    if(qq_time()-c.last_push_poll>=250){
        for(unsigned i=0;i<8;++i){int n=next_frame(0);if(n<0){e=(enum qq_result)-n;if(e==QQ_NETWORK||e==QQ_CANCELLED)net_reset(e==QQ_CANCELLED?RESET_CANCEL:RESET_NETWORK);return e;}if(!n)break;qq_sso_reply reply;e=decode_frame((unsigned)n,&reply);if(!e)e=push(&reply);if(e)return e;}
        c.last_push_poll=qq_time();
    }
    if(qq_time()-c.last_heartbeat>=30000){e=request("Heartbeat.Alive",(qq_view){0,0},2,&response);if(e)return e;c.last_heartbeat=qq_time();}
    if(c.need_sync||qq_time()-c.last_sync>=5000){
        unsigned flag=0;for(unsigned batch=0;batch<16;++batch){uint32_t n,now;h1qq_sign_clock clock;if(!utc(&now,&clock)||!qq_get_messages_body((qq_view){c.cookie,c.cookie_size},flag,now,c.login,sizeof c.login,&n))return QQ_RESPONSE;
            e=request("MessageSvc.PbGetMsg",(qq_view){c.login,n},0,&response);if(e)return e;flag=2;if(!qq_get_messages_result(response,c.account.uin,c.cookie,&c.cookie_size,&flag,store_message,0))return QQ_RESPONSE;
            if(!qq_delete_messages_body(response,c.login,sizeof c.login,&n))return QQ_TOO_LARGE;if(n){e=request("MessageSvc.PbDeleteMsg",(qq_view){c.login,n},0,&response);if(e)return e;}if(flag==2)break;}
        c.last_sync=qq_time();c.need_sync=flag!=2;
    }return QQ_OK;
}
enum qq_result qq_tick(void)
{enum qq_result e=service_tick();if(e&&e!=QQ_CANCELLED){c.poll_retry_after=qq_time()+10000;++c.background_failures;qq_native_save_report();}else if(!e)c.poll_retry_after=0;return e;}
enum qq_result qq_history(const qq_config *cfg,int group,const char *id,const char *self,qq_messages *out)
{
    (void)cfg;(void)self;enum qq_result e=online();if(e)return e;e=qq_tick();if(e)return e;return qq_history_cached(group,id,out);
}
uint32_t qq_history_revision(void){return c.cache_revision;}
void qq_recent_restore(qq_people *out,uint8_t kinds[QQ_PEOPLE_MAX]){history_bind();qq_local_recent(out,kinds);}
int qq_recent_save(const qq_person *person,unsigned group){history_bind();return qq_local_touch(person,group);}
int qq_clear_local_history(void){history_bind();if(!qq_local_clear())return 0;qq_clear(c.cache,sizeof c.cache);c.cache_count=0;++c.cache_revision;return 1;}
int qq_local_history_failed(void){return qq_local_failed();}
int qq_avatar_tick_due(void){return c.account.authenticated&&c.account.registered&&c.rpc.ready&&!c.rpc.broken&&qq_avatars_due(qq_time());}
void qq_avatar_tick(void){if(qq_avatar_tick_due())qq_avatars_service(&c.rpc,qq_time());}
enum qq_result qq_history_cached(int group,const char *id,qq_messages *out)
{
    history_bind();qq_local_select((unsigned)group,number(id),c.cache,c.cache_count,out);return QQ_OK;
}
enum qq_result qq_send(const qq_config *cfg,int group,const char *id,const char *message)
{
    (void)cfg;enum qq_result e=online();if(e)return e;uint32_t now,n;h1qq_sign_clock clock;if(!utc(&now,&clock))return QQ_AUTH;uint8_t random[4];if(!random_bytes(random,4))return QQ_AUTH;uint32_t r=(uint32_t)random[0]<<24|(uint32_t)random[1]<<16|(uint32_t)random[2]<<8|random[3];uint64_t peer=number(id);unsigned seq=++c.message_seq;
    if(!qq_text_send_body(peer,group,qq_string(message),seq,r,now,c.login,sizeof c.login,&n))return QQ_TOO_LARGE;qq_view response;e=request("MessageSvc.PbSendMsg",(qq_view){c.login,n},0,&response);if(e)return e;unsigned result;if(!qq_text_send_result(response,&result,qq_last_error))return QQ_RESPONSE;if(result)return QQ_REJECTED;
    qq_text_message own={0};own.sender=c.account.uin;own.recipient=own.peer=peer;own.sequence=seq;own.time=now;own.group=(unsigned)group;own.random=r;own.flags=QQ_MESSAGE_LOCAL|QQ_MESSAGE_RANDOM;qq_copy_text(own.text,sizeof own.text,qq_string(message));qq_copy_text(own.sender_name,sizeof own.sender_name,qq_string(c.account.nickname));store_message(0,&own);++c.sent_acks;c.phase=8;qq_native_save_report();return QQ_OK;
}
