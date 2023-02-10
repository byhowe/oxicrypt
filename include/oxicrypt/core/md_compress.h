#ifndef OXICRYPT_CORE_MD_COMPRESS_H_
#define OXICRYPT_CORE_MD_COMPRESS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void oxi_digest_compress_md5(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha1(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha256(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha512(uint64_t* state, const uint8_t* block);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_CORE_MD_COMPRESS_H_
