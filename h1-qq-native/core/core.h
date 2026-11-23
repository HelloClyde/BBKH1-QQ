#ifndef H1QQ_CORE_H
#define H1QQ_CORE_H
#include <stdint.h>

/* Native pointers and algorithm state. No guest CPU or virtual addresses. */
typedef struct {
    const uint8_t *data;
    uint32_t size,buffered,available,offset;
} h1qq_bit_reader;

/* Failed decoding leaves reader and result unchanged. */
int h1qq_read_bits(h1qq_bit_reader *,unsigned bits,uint32_t *result);
int h1qq_read_varint(h1qq_bit_reader *,unsigned group_bits,unsigned width,uint64_t *result);
int h1qq_seed_extend(uint32_t words[624],unsigned first,uint32_t *last,uint32_t multiplier);
int h1qq_transform(unsigned selector,const uint8_t *,uint8_t *,uint32_t size);
/* Final encoder only. The upstream 16-byte signing digest is still required.
 * Seeds are the two system-clock microsecond remainders, seconds is time(0).
 * environment_word is the four-byte prefix read from the original platform
 * material (normally 0x04040404); all dependencies are explicit inputs. */
int h1qq_encode_sign(const uint8_t digest[16],uint32_t random_seed,
    uint32_t seconds,uint32_t mask_seed,uint32_t environment_word,uint8_t output[68]);
typedef struct {const uint8_t *data;uint32_t size;} h1qq_bytes;
typedef struct {uint32_t random_seed,seconds,mask_seed,environment_word;} h1qq_sign_clock;
/* Same original encoder, with raw input for Dandelion.energy. The recovered
 * single-block path accepts 0..47 bytes (login salt is 42); bounds are explicit. */
int h1qq_encode_data(h1qq_bytes,const h1qq_sign_clock *,uint8_t output[68]);
/* The caller supplies current token and serialized extra. Their generation,
 * refresh and account lifecycle are outside this native calculation API. */
int h1qq_sign_digest(h1qq_bytes token,h1qq_bytes extra,h1qq_bytes body,uint8_t digest[16]);
int h1qq_sign(h1qq_bytes token,h1qq_bytes extra,h1qq_bytes body,
    const h1qq_sign_clock *,uint8_t sign[68]);
/* Hash the material's original bytes (hex text stays text), then Base64 the
 * first nine digest bytes. Caller decides when material is ready/current. */
int h1qq_security_token(h1qq_bytes material,uint8_t token[12]);
/* Known extra fields: nonempty QUA at field 2, optional material at field 3.
 * Fails before writing when pointers/capacity are invalid. */
int h1qq_build_extra(h1qq_bytes qua,h1qq_bytes material,uint8_t *output,
    uint32_t capacity,uint32_t *size);
/* Fresh ciphertext/format generation from the collected 34-byte report,
 * epoch seconds and five entropy bytes. Report collection is still external.
 * Writes exactly 144 uppercase ASCII bytes; no terminating NUL. */
int h1qq_build_material(const uint8_t report[34],uint32_t seconds,
    const uint8_t entropy[5],uint8_t material[144]);
/* Native report for the no-Android-ID UUID fallback profile. UUID persistence
 * and other Android-ID/cache branches are managed by the caller. */
int h1qq_report_uuid(const uint8_t uuid[16],uint8_t report[34]);
#endif
