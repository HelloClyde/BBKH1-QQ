#ifndef H1QQ_SERVICE_PROTOCOL_H
#define H1QQ_SERVICE_PROTOCOL_H
#include <stdint.h>
#define H1QQ_SERVICE_MAGIC 0x31535148u
#define H1QQ_SERVICE_BODY 4096u
#define H1QQ_SERVICE_QUA 128u
#define H1QQ_SERVICE_EXTRA 512u
enum {SERVICE_MAGIC,SERVICE_VERSION,SERVICE_BUILD,SERVICE_PHASE,SERVICE_ERROR,
    SERVICE_REQUESTS,SERVICE_PUBLICATIONS,SERVICE_PENDING,SERVICE_UTC,SERVICE_SESSION_LO,
    SERVICE_SESSION_HI,SERVICE_RANDOM_BLOCKS,SERVICE_RANDOM_AVAILABLE,SERVICE_CONSUMED,
    SERVICE_REPLY_SEQ,SERVICE_REPLY_ERROR,SERVICE_SIGN_MS,SERVICE_MATERIAL_SECONDS,
    SERVICE_BEGUN,SERVICE_LOCAL_SECONDS,SERVICE_STATUS_WORDS};
typedef struct {
    volatile uint32_t sequence;
    uint32_t operation,qua_size,body_size;
    uint8_t qua[H1QQ_SERVICE_QUA],body[H1QQ_SERVICE_BODY];
} h1qq_service_input;
/* Debug transport: one writer, one outstanding request. Write operation,
 * lengths and payload first, then commit sequence. Read reply only after its
 * matching SERVICE_REPLY_SEQ. These are owned BDA globals, not arbitrary RAM. */
#endif
