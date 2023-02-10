#ifndef OXICRYPT_CORE_AES_LUT_H_
#define OXICRYPT_CORE_AES_LUT_H_

#include <stdint.h>
#include <oxicrypt/oxicrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AES ENCRYPT */
void oxi_core_aes_lut_aes128_encrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aes_lut_aes192_encrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aes_lut_aes256_encrypt1(uint8_t* block, const uint8_t* key_schedule);

/* AES DECRYPT */
void oxi_core_aes_lut_aes128_decrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aes_lut_aes192_decrypt1(uint8_t* block, const uint8_t* key_schedule);
void oxi_core_aes_lut_aes256_decrypt1(uint8_t* block, const uint8_t* key_schedule);

/* AES EXPAND KEY */
void oxi_core_aes_lut_aes128_expand_key(const uint8_t* key, uint8_t* key_schedule);
void oxi_core_aes_lut_aes192_expand_key(const uint8_t* key, uint8_t* key_schedule);
void oxi_core_aes_lut_aes256_expand_key(const uint8_t* key, uint8_t* key_schedule);

/* AES INVERSE KEY */
void oxi_core_aes_lut_aes128_inverse_key(uint8_t* key_schedule);
void oxi_core_aes_lut_aes192_inverse_key(uint8_t* key_schedule);
void oxi_core_aes_lut_aes256_inverse_key(uint8_t* key_schedule);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_CORE_AES_LUT_H_
