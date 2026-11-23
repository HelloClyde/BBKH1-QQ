#ifndef H1QQ_QQ_CRYPTO_H
#define H1QQ_QQ_CRYPTO_H
#include <stdint.h>
int qq_ecdh(const uint8_t private_key[32],const uint8_t server_key[65],uint8_t public_key[65],uint8_t share_key[16]);
int qq_ecdh_with_rng(const uint8_t private_key[32],const uint8_t server_key[65],uint8_t public_key[65],uint8_t share_key[16],int (*rng)(uint8_t *,unsigned));
/* Separate input/output buffers; pad supplies at least nine random bytes. */
int qq_tea_encrypt(const uint8_t key[16],const uint8_t *input,uint32_t size,const uint8_t pad[9],
    uint8_t *output,uint32_t capacity,uint32_t *written);
int qq_tea_decrypt(const uint8_t key[16],const uint8_t *input,uint32_t size,
    uint8_t *output,uint32_t capacity,uint32_t *written);
#endif
