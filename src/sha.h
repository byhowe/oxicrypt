#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <endian.h>
#include <stdint.h>
#include <string.h>

/* Compress functions from Rust. */

void oxi_sha1_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha256_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha512_compress_generic(uint64_t* state, const uint8_t* block);

/* Type definitions. */

typedef struct oxi_sha1_ctx_t {
  uint32_t h[5];
  uint8_t block[64];
  uint64_t len;
  size_t blocklen;
} oxi_sha1_ctx_t;

typedef struct oxi_sha256_ctx_t {
  uint32_t h[8];
  uint8_t block[64];
  uint64_t len;
  size_t blocklen;
} oxi_sha256_ctx_t;

typedef oxi_sha256_ctx_t oxi_sha224_ctx_t;

typedef struct oxi_sha512_ctx_t {
  uint64_t h[8];
  uint8_t block[128];
  uint64_t len;
  size_t blocklen;
} oxi_sha512_ctx_t;

typedef oxi_sha512_ctx_t oxi_sha384_ctx_t;

typedef oxi_sha512_ctx_t oxi_sha512_224_ctx_t;

typedef oxi_sha512_ctx_t oxi_sha512_256_ctx_t;

/* Constants that could be useful while working with SHA algorithms. */

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

/* Init functions. */

void oxi_sha1_init(oxi_sha1_ctx_t* ctx);
void oxi_sha224_init(oxi_sha224_ctx_t* ctx);
void oxi_sha256_init(oxi_sha256_ctx_t* ctx);
void oxi_sha384_init(oxi_sha384_ctx_t* ctx);
void oxi_sha512_init(oxi_sha512_ctx_t* ctx);
void oxi_sha512_224_init(oxi_sha512_224_ctx_t* ctx);
void oxi_sha512_256_init(oxi_sha512_256_ctx_t* ctx);

/* Update functions. */

void oxi_sha1_update(oxi_sha1_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha224_update(oxi_sha224_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha256_update(oxi_sha256_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha384_update(oxi_sha384_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha512_update(oxi_sha512_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha512_224_update(oxi_sha512_224_ctx_t* ctx, const uint8_t* in, size_t inlen);
void oxi_sha512_256_update(oxi_sha512_256_ctx_t* ctx, const uint8_t* in, size_t inlen);

/* Finish functions. Note: unlike their Rust counterparts, these functions do not reinitialize the
 * context afterwards. */

void oxi_sha1_finish(oxi_sha1_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha224_finish(oxi_sha224_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha256_finish(oxi_sha256_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha384_finish(oxi_sha384_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_finish(oxi_sha512_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_224_finish(oxi_sha512_224_ctx_t* ctx, uint8_t* out, size_t outlen);
void oxi_sha512_256_finish(oxi_sha512_256_ctx_t* ctx, uint8_t* out, size_t outlen);

/* Convenience functions. */

void oxi_sha1_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha224_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha256_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha384_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha512_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha512_224_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);
void oxi_sha512_256_oneshot(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_SHA_H_
