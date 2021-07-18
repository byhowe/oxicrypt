#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Useful constants. */

#define OXI_SHA1_DIGEST_LEN 20
#define OXI_SHA1_BLOCK_LEN 64

#define OXI_SHA224_DIGEST_LEN 28
#define OXI_SHA224_BLOCK_LEN 64

#define OXI_SHA256_DIGEST_LEN 32
#define OXI_SHA256_BLOCK_LEN 64

#define OXI_SHA384_DIGEST_LEN 48
#define OXI_SHA384_BLOCK_LEN 128

#define OXI_SHA512_DIGEST_LEN 64
#define OXI_SHA512_BLOCK_LEN 128

#define OXI_SHA512_224_DIGEST_LEN 28
#define OXI_SHA512_224_BLOCK_LEN 128

#define OXI_SHA512_256_DIGEST_LEN 32
#define OXI_SHA512_256_BLOCK_LEN 128

/* Raw SHA functions. */

void oxi_sha1_compress_generic(uint8_t* state, const uint8_t* block);
void oxi_sha256_compress_generic(uint8_t* state, const uint8_t* block);
void oxi_sha512_compress_generic(uint8_t* state, const uint8_t* block);

/* Implementations. */

typedef enum oxi_sha_implementation_t {
  OXI_SHA_IMPL_GENERIC = 0,
} oxi_sha_implementation_t;

oxi_sha_implementation_t oxi_sha_implementation_fastest();
oxi_sha_implementation_t oxi_sha_implementation_fastest_rt();
bool oxi_sha_implementation_is_available(oxi_sha_implementation_t implementation);

/* Engine. */

typedef struct oxi_sha_engine_t {
  void (*compress)(uint8_t*, const uint8_t*);
} oxi_sha_engine_t;

oxi_sha_engine_t oxi_sha1_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha1_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha224_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha224_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha256_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha256_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha384_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha384_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha512_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha512_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha512_224_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha512_224_engine_as_ref(oxi_sha_implementation_t implementation);

oxi_sha_engine_t oxi_sha512_256_engine_new(oxi_sha_implementation_t implementation);
const oxi_sha_engine_t* oxi_sha512_256_engine_as_ref(oxi_sha_implementation_t implementation);

/* SHA contexts. */

typedef struct oxi_sha1_t {
  uint8_t h[20];
  uint8_t block[64];
  uint64_t len;
  size_t blocklen;
} oxi_sha1_t;

typedef struct oxi_sha256_t {
  uint8_t h[32];
  uint8_t block[64];
  uint64_t len;
  size_t blocklen;
} oxi_sha256_t;

typedef struct oxi_sha512_t {
  uint8_t h[64];
  uint8_t block[128];
  uint64_t len;
  size_t blocklen;
} oxi_sha512_t;

typedef oxi_sha256_t oxi_sha224_t;

typedef oxi_sha512_t oxi_sha384_t;

typedef oxi_sha512_t oxi_sha512_224_t;

typedef oxi_sha512_t oxi_sha512_256_t;

void oxi_sha1_reset(oxi_sha1_t* ctx);
void oxi_sha224_reset(oxi_sha224_t* ctx);
void oxi_sha256_reset(oxi_sha256_t* ctx);
void oxi_sha384_reset(oxi_sha384_t* ctx);
void oxi_sha512_reset(oxi_sha512_t* ctx);
void oxi_sha512_224_reset(oxi_sha512_224_t* ctx);
void oxi_sha512_256_reset(oxi_sha512_256_t* ctx);

void oxi_sha1_update(
    oxi_sha1_t* ctx, oxi_sha_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_sha224_update(oxi_sha224_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_sha256_update(oxi_sha256_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_sha384_update(oxi_sha384_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_sha512_update(oxi_sha512_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_sha512_224_update(oxi_sha512_224_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_sha512_256_update(oxi_sha512_256_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);

void oxi_sha1_finish(
    oxi_sha1_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha224_finish(
    oxi_sha224_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha256_finish(
    oxi_sha256_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha384_finish(
    oxi_sha384_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_finish(
    oxi_sha512_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_224_finish(
    oxi_sha512_224_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_sha512_256_finish(
    oxi_sha512_256_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);

const uint8_t* oxi_sha1_finish_sliced(oxi_sha1_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha224_finish_sliced(oxi_sha224_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha256_finish_sliced(oxi_sha256_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha384_finish_sliced(oxi_sha384_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha512_finish_sliced(oxi_sha512_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha512_224_finish_sliced(
    oxi_sha512_224_t* ctx, oxi_sha_implementation_t implementation);
const uint8_t* oxi_sha512_256_finish_sliced(
    oxi_sha512_256_t* ctx, oxi_sha_implementation_t implementation);

void oxi_sha1_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data, size_t datalen,
    uint8_t* out, size_t outlen);
void oxi_sha224_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha256_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha384_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_224_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_256_oneshot(oxi_sha_implementation_t implementation, const uint8_t* data,
    size_t datalen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_SHA_H_
