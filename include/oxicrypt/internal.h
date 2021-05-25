#ifndef _H_OXICRYPT_INTERNAL
#define _H_OXICRYPT_INTERNAL

#include <stdint.h>

void oxi_sha1_compress_generic(uint32_t *state, const uint8_t *block);
void oxi_sha256_compress_generic(uint32_t *state, const uint8_t *block);
void oxi_sha512_compress_generic(uint64_t *state, const uint8_t *block);

#endif // _H_OXICRYPT_INTERNAL
