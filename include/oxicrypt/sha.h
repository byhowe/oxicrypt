#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#include <stddef.h>
#include <stdint.h>

#include "oxicrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Useful constants. */

const size_t OXI_SHA1_DIGEST_LEN = 20;
const size_t OXI_SHA1_BLOCK_LEN = 64;

const size_t OXI_SHA224_DIGEST_LEN = 28;
const size_t OXI_SHA224_BLOCK_LEN = 64;

const size_t OXI_SHA256_DIGEST_LEN = 32;
const size_t OXI_SHA256_BLOCK_LEN = 64;

const size_t OXI_SHA384_DIGEST_LEN = 48;
const size_t OXI_SHA384_BLOCK_LEN = 128;

const size_t OXI_SHA512_DIGEST_LEN = 64;
const size_t OXI_SHA512_BLOCK_LEN = 128;

const size_t OXI_SHA512_224_DIGEST_LEN = 28;
const size_t OXI_SHA512_224_BLOCK_LEN = 128;

const size_t OXI_SHA512_256_DIGEST_LEN = 32;
const size_t OXI_SHA512_256_BLOCK_LEN = 128;

/* Raw SHA functions. */

void oxi_sha1_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha256_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha512_compress_generic(uint64_t* state, const uint8_t* block);

/* SHA engines. */

typedef struct oxi_sha_engine1_t {
  uint32_t h[5];
  uint8_t block[64];
  size_t blocklen;
  uint64_t len;
} oxi_sha_engine1_t;

typedef struct oxi_sha_engine256_t {
  uint32_t h[8];
  uint8_t block[64];
  size_t blocklen;
  uint64_t len;
} oxi_sha_engine256_t;

typedef struct oxi_sha_engine512_t {
  uint64_t h[8];
  uint8_t block[128];
  size_t blocklen;
  __uint128_t len;
} oxi_sha_engine512_t;

/* SHA contexts. */

typedef oxi_sha_engine1_t oxi_sha1_t;
typedef oxi_sha_engine256_t oxi_sha224_t;
typedef oxi_sha_engine256_t oxi_sha256_t;
typedef oxi_sha_engine512_t oxi_sha384_t;
typedef oxi_sha_engine512_t oxi_sha512_t;
typedef oxi_sha_engine512_t oxi_sha512_224_t;
typedef oxi_sha_engine512_t oxi_sha512_256_t;

/* SHA functions. */

void oxi_sha1_reset(oxi_sha1_t* ctx);
void oxi_sha224_reset(oxi_sha224_t* ctx);
void oxi_sha256_reset(oxi_sha256_t* ctx);
void oxi_sha384_reset(oxi_sha384_t* ctx);
void oxi_sha512_reset(oxi_sha512_t* ctx);
void oxi_sha512_224_reset(oxi_sha512_224_t* ctx);
void oxi_sha512_256_reset(oxi_sha512_256_t* ctx);

void oxi_sha1_update(oxi_sha1_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha224_update(oxi_sha224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha256_update(oxi_sha256_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha384_update(oxi_sha384_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_update(oxi_sha512_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_224_update(oxi_sha512_224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_256_update(oxi_sha512_256_t* ctx, const uint8_t* data, size_t datalen);

void oxi_sha1_update_impl(oxi_sha1_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha224_update_impl(oxi_sha224_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha256_update_impl(oxi_sha256_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha384_update_impl(oxi_sha384_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha512_update_impl(oxi_sha512_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha512_224_update_impl(oxi_sha512_224_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha512_256_update_impl(oxi_sha512_256_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);

const uint8_t* oxi_sha1_finish_sliced(oxi_sha1_t* ctx);
const uint8_t* oxi_sha224_finish_sliced(oxi_sha224_t* ctx);
const uint8_t* oxi_sha256_finish_sliced(oxi_sha256_t* ctx);
const uint8_t* oxi_sha384_finish_sliced(oxi_sha384_t* ctx);
const uint8_t* oxi_sha512_finish_sliced(oxi_sha512_t* ctx);
const uint8_t* oxi_sha512_224_finish_sliced(oxi_sha512_224_t* ctx);
const uint8_t* oxi_sha512_256_finish_sliced(oxi_sha512_256_t* ctx);

const uint8_t* oxi_sha1_finish_sliced_impl(oxi_sha1_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha224_finish_sliced_impl(oxi_sha224_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha256_finish_sliced_impl(oxi_sha256_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha384_finish_sliced_impl(oxi_sha384_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha512_finish_sliced_impl(oxi_sha512_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha512_224_finish_sliced_impl(oxi_sha512_224_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_sha512_256_finish_sliced_impl(oxi_sha512_256_t* ctx, oxi_implementation_t implementation);

void oxi_sha1_finish_into(oxi_sha1_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha224_finish_into(oxi_sha224_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha256_finish_into(oxi_sha256_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha384_finish_into(oxi_sha384_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_finish_into(oxi_sha512_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_224_finish_into(oxi_sha512_224_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_256_finish_into(oxi_sha512_256_t* ctx, uint8_t* out, size_t outlen);

void oxi_sha1_finish_into_impl(oxi_sha1_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha224_finish_into_impl(oxi_sha224_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha256_finish_into_impl(oxi_sha256_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha384_finish_into_impl(oxi_sha384_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_finish_into_impl(oxi_sha512_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_224_finish_into_impl(oxi_sha512_224_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_256_finish_into_impl(oxi_sha512_256_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);

void oxi_sha1_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha224_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha256_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha384_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_224_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_256_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

void oxi_sha1_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha224_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha256_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha384_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_224_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_256_oneshot_impl(oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_SHA_H_
