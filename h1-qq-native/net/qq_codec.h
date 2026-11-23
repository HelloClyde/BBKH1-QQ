#ifndef H1QQ_CODEC_H
#define H1QQ_CODEC_H
#include <stdint.h>
typedef struct {const uint8_t *data;uint32_t size;} qq_view;
typedef struct {uint8_t *data;uint32_t size,capacity;int ok;} qq_writer;
typedef struct {const uint8_t *data;uint32_t size,at;int ok;} qq_reader;
void qq_put(qq_writer *,const void *,uint32_t);
void qq_num(qq_writer *,uint64_t,unsigned bytes);
void qq_patch(qq_writer *,uint32_t,uint64_t,unsigned);
void qq_short(qq_writer *,qq_view);
void qq_long(qq_writer *,qq_view);
const uint8_t *qq_take(qq_reader *,uint32_t);
uint64_t qq_read(qq_reader *,unsigned);
qq_view qq_string(const char *);
void qq_pb_uint(qq_writer *,unsigned tag,uint64_t);
void qq_pb_bytes(qq_writer *,unsigned tag,qq_view);
typedef struct {unsigned tag,type;uint64_t value;qq_view bytes;} qq_field;
int qq_pb_next(qq_reader *,qq_field *);
int qq_pb_find(qq_view,unsigned tag,qq_field *);
void qq_jce_head(qq_writer *,unsigned tag,unsigned type);
void qq_jce_int(qq_writer *,unsigned tag,int64_t);
void qq_jce_string(qq_writer *,unsigned tag,qq_view);
void qq_jce_bytes(qq_writer *,unsigned tag,qq_view);
typedef struct {unsigned tag,type,count;int64_t value;qq_view bytes;} qq_jce_field;
int qq_jce_next(qq_reader *,qq_jce_field *);
int qq_jce_find(qq_view,unsigned tag,qq_jce_field *);
/* Decodes a RequestPacket / map v2 or v3 and its struct wrapper. */
int qq_jce_payload(qq_view,const char *key,qq_view *payload);
int qq_jce_request(qq_writer *,uint32_t sequence,const char *servant,const char *function,const char *key,qq_view body,unsigned packet_type);
int qq_tlv_find(qq_view,unsigned tag,qq_view *value);
void qq_clear(void *,uint32_t);
int qq_copy_text(char *out,unsigned capacity,qq_view);
#endif
