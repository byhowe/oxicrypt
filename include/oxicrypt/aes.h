#ifndef OXICRYPT_AES_H_
#define OXICRYPT_AES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#if defined(__x86_64__) || defined(__i386__)
void oxi_aes128_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes128_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes128_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes128_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes192_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes192_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes192_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes192_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);

void oxi_aes256_expand_key_aesni(const uint8_t* key, uint8_t* key_schedule);
void oxi_aes256_inverse_key_aesni(uint8_t* key_schedule);
void oxi_aes256_encrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
void oxi_aes256_decrypt1_aesni(uint8_t* block, const uint8_t* key_schedule);
#endif

/* Implementations. */

typedef enum oxi_aes_implementation_t {
  OXI_AES_IMPL_LUT = 0,

#if defined(__x86_64__) || defined(__i386__)
  OXI_AES_IMPL_AESNI = 1,
#endif
} oxi_aes_implementation_t;

oxi_aes_implementation_t oxi_aes_implementation_fastest();
oxi_aes_implementation_t oxi_aes_implementation_fastest_rt();
bool oxi_aes_implementation_is_available(oxi_aes_implementation_t implementation);

/* Engine. */

typedef struct oxi_aes_engine_t {
  void (*expand_key)(const uint8_t*, uint8_t*);
  void (*inverse_key)(uint8_t*);
  void (*encrypt1)(uint8_t*, const uint8_t*);
  void (*decrypt1)(uint8_t*, const uint8_t*);
} oxi_aes_engine_t;

oxi_aes_engine_t oxi_aes128_engine_new(oxi_aes_implementation_t implementation);
const oxi_aes_engine_t* oxi_aes128_engine_as_ref(oxi_aes_implementation_t implementation);

oxi_aes_engine_t oxi_aes192_engine_new(oxi_aes_implementation_t implementation);
const oxi_aes_engine_t* oxi_aes192_engine_as_ref(oxi_aes_implementation_t implementation);

oxi_aes_engine_t oxi_aes256_engine_new(oxi_aes_implementation_t implementation);
const oxi_aes_engine_t* oxi_aes256_engine_as_ref(oxi_aes_implementation_t implementation);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_AES_H_
