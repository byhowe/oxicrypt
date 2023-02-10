#ifndef OXICRYPT_CORE_AESNI_H_
#define OXICRYPT_CORE_AESNI_H_

#include <stdint.h>
#include <oxicrypt/oxicrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OXI_HAVE_X86
/* AES ENCRYPT */
void oxi_core_aesni_aes128_encrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_encrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_encrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_encrypt8(uint8_t* block, const uint8_t* key_schedule);

void oxi_core_aesni_aes192_encrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_encrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_encrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_encrypt8(uint8_t* block, const uint8_t* key_schedule);

void oxi_core_aesni_aes256_encrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_encrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_encrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_encrypt8(uint8_t* block, const uint8_t* key_schedule);

/* AES DECRYPT */
void oxi_core_aesni_aes128_decrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_decrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_decrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes128_decrypt8(uint8_t* block, const uint8_t* key_schedule);

void oxi_core_aesni_aes192_decrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_decrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_decrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes192_decrypt8(uint8_t* block, const uint8_t* key_schedule);

void oxi_core_aesni_aes256_decrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_decrypt2(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_decrypt4(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aesni_aes256_decrypt8(uint8_t* block, const uint8_t* key_schedule);

/* AES EXPAND KEY */
void oxi_core_aesni_aes128_expand_key(const uint8_t* key, uint8_t* key_schedule);
void oxi_core_aesni_aes192_expand_key(const uint8_t* key, uint8_t* key_schedule);
void oxi_core_aesni_aes256_expand_key(const uint8_t* key, uint8_t* key_schedule);

/* AES INVERSE KEY */
void oxi_core_aesni_aes128_inverse_key(uint8_t* key_schedule);
void oxi_core_aesni_aes192_inverse_key(uint8_t* key_schedule);
void oxi_core_aesni_aes256_inverse_key(uint8_t* key_schedule);
#endif

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_CORE_AESNI_H_
