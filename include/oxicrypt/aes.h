#ifndef OXICRYPT_AES_H_
#define OXICRYPT_AES_H_

#if defined(__x86_64__) || defined(__i386__)
#define OXI_HAVE_X86
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oxicrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Useful constants. */

#define OXI_AES_BLOCK_LEN 16

#define OXI_AES128_ROUNDS 10
#define OXI_AES128_KEY_LEN 16
#define OXI_AES128_KEY_SCHEDULE_LEN 176

#define OXI_AES192_ROUNDS 12
#define OXI_AES192_KEY_LEN 24
#define OXI_AES192_KEY_SCHEDULE_LEN 208

#define OXI_AES256_ROUNDS 14
#define OXI_AES256_KEY_LEN 32
#define OXI_AES256_KEY_SCHEDULE_LEN 240

/* Raw AES functions. */

void oxi_aes128_expand_key_lut(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes128_inverse_key_lut(uint8_t* key_schedule);
void oxi_aes128_encrypt1_lut(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt1_lut(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes192_expand_key_lut(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes192_inverse_key_lut(uint8_t* key_schedule);
void oxi_aes192_encrypt1_lut(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt1_lut(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes256_expand_key_lut(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes256_inverse_key_lut(uint8_t* key_schedule);
void oxi_aes256_encrypt1_lut(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt1_lut(uint8_t* block, const uint8_t* key_schedule);

#ifdef OXI_HAVE_X86
void oxi_aes128_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes128_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes128_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_encrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_encrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_encrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes192_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes192_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes192_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_encrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_encrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_encrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes256_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes256_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes256_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_encrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_encrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_encrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt2_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt4_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt8_aesni(uint8_t* block, const uint8_t* key_schedule);
#endif

/* Key schedules. */

typedef struct oxi_aes128_key_t {
  uint8_t k[176];
} oxi_aes128_key_t;

typedef struct oxi_aes192_key_t {
  uint8_t k[208];
} oxi_aes192_key_t;

typedef struct oxi_aes256_key_t {
  uint8_t k[240];
} oxi_aes256_key_t;

void oxi_aes128_set_encrypt_key(
    oxi_aes128_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes128_set_decrypt_key(
    oxi_aes128_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes128_inverse_key(oxi_aes128_key_t* ctx, oxi_implementation_t implementation);
void oxi_aes128_encrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);
void oxi_aes128_decrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);

void oxi_aes192_set_encrypt_key(
    oxi_aes192_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes192_set_decrypt_key(
    oxi_aes192_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes192_inverse_key(oxi_aes192_key_t* ctx, oxi_implementation_t implementation);
void oxi_aes192_encrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);
void oxi_aes192_decrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);

void oxi_aes256_set_encrypt_key(
    oxi_aes256_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes256_set_decrypt_key(
    oxi_aes256_key_t* ctx, oxi_implementation_t implementation, const uint8_t* key);
void oxi_aes256_inverse_key(oxi_aes256_key_t* ctx, oxi_implementation_t implementation);
void oxi_aes256_encrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);
void oxi_aes256_decrypt1(
    const oxi_aes128_key_t* ctx, oxi_implementation_t implementation, uint8_t* block);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_AES_H_
