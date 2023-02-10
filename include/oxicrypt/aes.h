#ifndef OXICRYPT_AES_H_
#define OXICRYPT_AES_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Useful constants */
const size_t OXI_AES_BLOCK_LEN = 16;

const size_t OXI_AES128_ROUNDS = 10;
const size_t OXI_AES128_KEY_LEN = 16;
const size_t OXI_AES128_KEY_SCHEDULE_LEN = 176;

const size_t OXI_AES192_ROUNDS = 12;
const size_t OXI_AES192_KEY_LEN = 24;
const size_t OXI_AES192_KEY_SCHEDULE_LEN = 208;

const size_t OXI_AES256_ROUNDS = 14;
const size_t OXI_AES256_KEY_LEN = 32;
const size_t OXI_AES256_KEY_SCHEDULE_LEN = 240;

/* Key schedules */
typedef void oxi_aes128_key_t;
typedef void oxi_aes192_key_t;
typedef void oxi_aes256_key_t;

oxi_aes128_key_t* oxi_aes128_new();
oxi_aes192_key_t* oxi_aes192_new();
oxi_aes256_key_t* oxi_aes256_new();

void oxi_aes128_drop(oxi_aes128_key_t* ctx);
void oxi_aes192_drop(oxi_aes192_key_t* ctx);
void oxi_aes256_drop(oxi_aes256_key_t* ctx);

/* AES SET ENCRYPT KEY */
void oxi_aes128_set_encrypt_key(oxi_aes128_key_t* ctx, const uint8_t* key);
void oxi_aes192_set_encrypt_key(oxi_aes192_key_t* ctx, const uint8_t* key);
void oxi_aes256_set_encrypt_key(oxi_aes256_key_t* ctx, const uint8_t* key);

/* AES SET DECRYPT KEY */
void oxi_aes128_set_decrypt_key(oxi_aes128_key_t* ctx, const uint8_t* key);
void oxi_aes192_set_decrypt_key(oxi_aes192_key_t* ctx, const uint8_t* key);
void oxi_aes256_set_decrypt_key(oxi_aes256_key_t* ctx, const uint8_t* key);

/* AES INVERSE KEY */
void oxi_aes128_inverse_key(oxi_aes128_key_t* ctx);
void oxi_aes192_inverse_key(oxi_aes192_key_t* ctx);
void oxi_aes256_inverse_key(oxi_aes256_key_t* ctx);

/* AES ENCRYPT/DECRYPT */
void oxi_aes128_encrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);
void oxi_aes192_encrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);
void oxi_aes256_encrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);
void oxi_aes128_decrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);
void oxi_aes192_decrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);
void oxi_aes256_decrypt(const oxi_aes128_key_t* ctx, uint8_t* block, size_t blocklen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_AES_H_
