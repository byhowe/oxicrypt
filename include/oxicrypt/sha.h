#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <string.h>

#include "internal.h"

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

static void oxi_sha1_init(oxi_sha1_ctx_t *ctx) {
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;

  memset(ctx->block, 0, OXI_SHA224_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha224_init(oxi_sha224_ctx_t *ctx) {
  ctx->h[0] = 0xc1059ed8;
  ctx->h[1] = 0x367cd507;
  ctx->h[2] = 0x3070dd17;
  ctx->h[3] = 0xf70e5939;
  ctx->h[4] = 0xffc00b31;
  ctx->h[5] = 0x68581511;
  ctx->h[6] = 0x64f98fa7;
  ctx->h[7] = 0xbefa4fa4;

  memset(ctx->block, 0, OXI_SHA224_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha256_init(oxi_sha256_ctx_t *ctx) {
  ctx->h[0] = 0x6a09e667;
  ctx->h[1] = 0xbb67ae85;
  ctx->h[2] = 0x3c6ef372;
  ctx->h[3] = 0xa54ff53a;
  ctx->h[4] = 0x510e527f;
  ctx->h[5] = 0x9b05688c;
  ctx->h[6] = 0x1f83d9ab;
  ctx->h[7] = 0x5be0cd19;

  memset(ctx->block, 0, OXI_SHA224_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha384_init(oxi_sha384_ctx_t *ctx) {
  ctx->h[0] = 0xcbbb9d5dc1059ed8;
  ctx->h[1] = 0x629a292a367cd507;
  ctx->h[2] = 0x9159015a3070dd17;
  ctx->h[3] = 0x152fecd8f70e5939;
  ctx->h[4] = 0x67332667ffc00b31;
  ctx->h[5] = 0x8eb44a8768581511;
  ctx->h[6] = 0xdb0c2e0d64f98fa7;
  ctx->h[7] = 0x47b5481dbefa4fa4;

  memset(ctx->block, 0, OXI_SHA384_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha512_init(oxi_sha512_ctx_t *ctx) {
  ctx->h[0] = 0x6a09e667f3bcc908;
  ctx->h[1] = 0xbb67ae8584caa73b;
  ctx->h[2] = 0x3c6ef372fe94f82b;
  ctx->h[3] = 0xa54ff53a5f1d36f1;
  ctx->h[4] = 0x510e527fade682d1;
  ctx->h[5] = 0x9b05688c2b3e6c1f;
  ctx->h[6] = 0x1f83d9abfb41bd6b;
  ctx->h[7] = 0x5be0cd19137e2179;

  memset(ctx->block, 0, OXI_SHA512_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha512_224_init(oxi_sha512_224_ctx_t *ctx) {
  ctx->h[0] = 0x8c3d37c819544da2;
  ctx->h[1] = 0x73e1996689dcd4d6;
  ctx->h[2] = 0x1dfab7ae32ff9c82;
  ctx->h[3] = 0x679dd514582f9fcf;
  ctx->h[4] = 0x0f6d2b697bd44da8;
  ctx->h[5] = 0x77e36f7304c48942;
  ctx->h[6] = 0x3f9d85a86a1d36c8;
  ctx->h[7] = 0x1112e6ad91d692a1;

  memset(ctx->block, 0, OXI_SHA512_224_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

static void oxi_sha512_256_init(oxi_sha512_256_ctx_t *ctx) {
  ctx->h[0] = 0x22312194fc2bf72c;
  ctx->h[1] = 0x9f555fa3c84c64c2;
  ctx->h[2] = 0x2393b86b6f53b151;
  ctx->h[3] = 0x963877195940eabd;
  ctx->h[4] = 0x96283ee2a88effe3;
  ctx->h[5] = 0xbe5e1e2553863992;
  ctx->h[6] = 0x2b0199fc2c85b8aa;
  ctx->h[7] = 0x0eb72ddc81c52ca2;

  memset(ctx->block, 0, OXI_SHA512_256_BLOCK_LEN);

  ctx->len = 0;
  ctx->blocklen = 0;
}

// TODO: Implement update and finish functions.

#define sha_update(maxblocklen, compress)                                      \
  while (inlen != 0) {                                                         \
    const size_t emptyspace = (maxblocklen)-ctx->blocklen;                     \
    if (emptyspace >= inlen) {                                                 \
      const size_t newblocklen = ctx->blocklen + inlen;                        \
      memcpy(ctx->block + ctx->blocklen, in, inlen);                           \
      ctx->blocklen = newblocklen;                                             \
      inlen = 0;                                                               \
    } else {                                                                   \
      memcpy(ctx->block + ctx->blocklen, in, emptyspace);                      \
      ctx->blocklen = (maxblocklen);                                           \
      in = in + emptyspace;                                                    \
    }                                                                          \
    if (ctx->blocklen == (maxblocklen)) {                                      \
      (compress)(ctx->h, ctx->block);                                          \
      ctx->blocklen = 0;                                                       \
      ctx->len += (maxblocklen);                                               \
    }                                                                          \
  }

static void oxi_sha1_update(oxi_sha1_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA1_BLOCK_LEN, oxi_sha1_compress_generic);
}

static void oxi_sha224_update(oxi_sha224_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA224_BLOCK_LEN, oxi_sha256_compress_generic);
}

static void oxi_sha256_update(oxi_sha256_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA256_BLOCK_LEN, oxi_sha256_compress_generic);
}

static void oxi_sha384_update(oxi_sha384_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA384_BLOCK_LEN, oxi_sha512_compress_generic);
}

static void oxi_sha512_update(oxi_sha512_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA512_BLOCK_LEN, oxi_sha512_compress_generic);
}

static void oxi_sha512_224_update(oxi_sha512_224_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA512_224_BLOCK_LEN, oxi_sha512_compress_generic);
}

static void oxi_sha512_256_update(oxi_sha512_256_ctx_t *ctx, const uint8_t *in, size_t inlen) {
  sha_update(OXI_SHA512_256_BLOCK_LEN, oxi_sha512_compress_generic);
}

#undef sha_update

void oxi_sha1_finish(oxi_sha1_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha224_finish(oxi_sha224_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha256_finish(oxi_sha256_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha384_finish(oxi_sha384_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha512_finish(oxi_sha512_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha512_224_finish(oxi_sha512_224_ctx_t *ctx, uint8_t *out, size_t outlen);

void oxi_sha512_256_finish(oxi_sha512_256_ctx_t *ctx, uint8_t *out, size_t outlen);


static void oxi_sha1_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha1_ctx_t ctx;
  oxi_sha1_init(&ctx);
  oxi_sha1_update(&ctx, in, inlen);
  oxi_sha1_finish(&ctx, out, outlen);
}

static void oxi_sha224_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha224_ctx_t ctx;
  oxi_sha224_init(&ctx);
  oxi_sha224_update(&ctx, in, inlen);
  oxi_sha224_finish(&ctx, out, outlen);
}

static void oxi_sha256_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha256_ctx_t ctx;
  oxi_sha256_init(&ctx);
  oxi_sha256_update(&ctx, in, inlen);
  oxi_sha256_finish(&ctx, out, outlen);
}

static void oxi_sha384_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha384_ctx_t ctx;
  oxi_sha384_init(&ctx);
  oxi_sha384_update(&ctx, in, inlen);
  oxi_sha384_finish(&ctx, out, outlen);
}

static void oxi_sha512_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha512_ctx_t ctx;
  oxi_sha512_init(&ctx);
  oxi_sha512_update(&ctx, in, inlen);
  oxi_sha512_finish(&ctx, out, outlen);
}

static void oxi_sha512_224_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha512_224_ctx_t ctx;
  oxi_sha512_224_init(&ctx);
  oxi_sha512_224_update(&ctx, in, inlen);
  oxi_sha512_224_finish(&ctx, out, outlen);
}

static void oxi_sha512_256_oneshot(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  oxi_sha512_256_ctx_t ctx;
  oxi_sha512_256_init(&ctx);
  oxi_sha512_256_update(&ctx, in, inlen);
  oxi_sha512_256_finish(&ctx, out, outlen);
}

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_SHA_H_
