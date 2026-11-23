#ifndef H1QQ_SESSION_H
#define H1QQ_SESSION_H
#include "qq_codec.h"
#include "qq_qr.h"
#define QQ_PACKET_MAX 65536u
typedef struct {uint16_t size;uint8_t data[2048];} qq_ticket;
typedef struct {
    uint64_t uin;
    qq_ticket tmp_pwd,tmp_sig,qr_ticket,tgt,d2;
    uint8_t tgtgt_key[16],d2_key[16],wt_key[16],session_id[4],ksid[64];
    unsigned ksid_size,authenticated,registered;
    char nickname[81];
} qq_account;
typedef struct {
    uint8_t plain[QQ_PACKET_MAX],encrypted[QQ_PACKET_MAX+32];
} qq_packet_work;
int qq_qr_credentials(qq_view plaintext,qq_account *);
/* Switch 0xa0640: GUID TEA, fixed-key TEA, then legacy plaintext. */
int qq_qr_unwrap(const uint8_t guid[16],qq_account *,unsigned *mode);
int qq_oicq_open(const qq_qr_session *,const qq_account *,qq_view encrypted,uint8_t *,uint32_t,qq_view *);
int qq_oicq_wrap(const qq_qr_session *,uint64_t uin,unsigned command,qq_view inner,uint8_t *,uint32_t,uint32_t *);
int qq_login_body(const qq_qr_session *,const qq_account *,const uint8_t entropy[32],qq_view energy,qq_view qimei,uint8_t *,uint32_t,uint32_t *);
int qq_login_result(qq_account *,qq_view plaintext,uint8_t *scratch,uint32_t capacity,unsigned *status,char error[256]);
/* reserve is already protobuf encoded by the native signing integration. */
int qq_session_packet(qq_packet_work *,const qq_qr_session *,const qq_account *,unsigned login_type,
    const char *command,qq_view body,qq_view reserve,uint8_t *,uint32_t,uint32_t *);
#endif
