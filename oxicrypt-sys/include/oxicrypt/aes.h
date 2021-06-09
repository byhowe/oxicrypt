#ifndef OXICRYPT_AES_H_
#define OXICRYPT_AES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Type definitions. */

typedef struct oxi_aes128_ctx_t {
  uint8_t round_keys[176];
} oxi_aes128_ctx_t;

typedef struct oxi_aes192_ctx_t {
  uint8_t round_keys[208];
} oxi_aes192_ctx_t;

typedef struct oxi_aes256_ctx_t {
  uint8_t round_keys[240];
} oxi_aes256_ctx_t;

/* Constants that could be useful while working with AES. */

#define OXI_AES_BLOCK_LEN 16

#define OXI_AES128_KEY_LEN 16
#define OXI_AES192_KEY_LEN 24
#define OXI_AES256_KEY_LEN 32

#define OXI_AES128_KEY_SCHEDULE_LEN 176
#define OXI_AES192_KEY_SCHEDULE_LEN 208
#define OXI_AES256_KEY_SCHEDULE_LEN 240

/* Set key functions. */

void oxi_aes128_set_encrypt_key(oxi_aes128_ctx_t* ctx, const uint8_t* key);
void oxi_aes192_set_encrypt_key(oxi_aes192_ctx_t* ctx, const uint8_t* key);
void oxi_aes256_set_encrypt_key(oxi_aes256_ctx_t* ctx, const uint8_t* key);
void oxi_aes128_set_decrypt_key(oxi_aes128_ctx_t* ctx, const uint8_t* key);
void oxi_aes192_set_decrypt_key(oxi_aes192_ctx_t* ctx, const uint8_t* key);
void oxi_aes256_set_decrypt_key(oxi_aes256_ctx_t* ctx, const uint8_t* key);

/* Inverse key functions. */

void oxi_aes128_inverse_key(oxi_aes128_ctx_t* ctx);
void oxi_aes192_inverse_key(oxi_aes192_ctx_t* ctx);
void oxi_aes256_inverse_key(oxi_aes256_ctx_t* ctx);

/* Encrypt functions. */

void oxi_aes128_encrypt(oxi_aes128_ctx_t* ctx, uint8_t* block);
void oxi_aes192_encrypt(oxi_aes192_ctx_t* ctx, uint8_t* block);
void oxi_aes256_encrypt(oxi_aes256_ctx_t* ctx, uint8_t* block);

/* Decrypt functions. */

void oxi_aes128_decrypt(oxi_aes128_ctx_t* ctx, uint8_t* block);
void oxi_aes192_decrypt(oxi_aes192_ctx_t* ctx, uint8_t* block);
void oxi_aes256_decrypt(oxi_aes256_ctx_t* ctx, uint8_t* block);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_AES_H_
