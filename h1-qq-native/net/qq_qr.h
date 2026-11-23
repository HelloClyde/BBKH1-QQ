#ifndef H1QQ_QQ_QR_H
#define H1QQ_QQ_QR_H
#include <stdint.h>
typedef struct {
    uint8_t public_key[65],share_key[16],random_key[16],guid[16];
    uint16_t key_version;uint32_t sequence,seconds;
    uint8_t pad[18];char imei[16];uint32_t code_sequence;
} qq_qr_session;
typedef struct {int32_t sso_return;uint32_t sequence,compression;char command[128];uint32_t body_size;uint8_t session_id[4];} qq_sso_reply;
int qq_qr_fetch(const qq_qr_session *,uint8_t *output,uint32_t capacity,uint32_t *size);
int qq_qr_query(const qq_qr_session *,const uint8_t *sig,uint32_t sig_size,uint8_t *output,uint32_t capacity,uint32_t *size);
int qq_sso_decode(const uint8_t *,uint32_t,const uint8_t key[16],qq_sso_reply *,uint8_t *body,uint32_t capacity);
/* Decodes OICQ + code2d; keeps signature and PNG as views into caller's scratch. */
int qq_qr_decode(const qq_qr_session *,const uint8_t *,uint32_t,uint8_t *scratch,uint32_t capacity,
    uint32_t *command,uint32_t *status,const uint8_t **sig,uint32_t *sig_size,const uint8_t **png,uint32_t *png_size);
#endif
