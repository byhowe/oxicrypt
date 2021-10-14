#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Useful constants. */

static const char* OXI_SHA1_NAME = "SHA-1";
const size_t OXI_SHA1_DIGEST_LEN = 20;
const size_t OXI_SHA1_BLOCK_LEN = 64;

static const char* OXI_SHA224_NAME = "SHA-224";
const size_t OXI_SHA224_DIGEST_LEN = 28;
const size_t OXI_SHA224_BLOCK_LEN = 64;

static const char* OXI_SHA256_NAME = "SHA-256";
const size_t OXI_SHA256_DIGEST_LEN = 32;
const size_t OXI_SHA256_BLOCK_LEN = 64;

static const char* OXI_SHA384_NAME = "SHA-384";
const size_t OXI_SHA384_DIGEST_LEN = 48;
const size_t OXI_SHA384_BLOCK_LEN = 128;

static const char* OXI_SHA512_NAME = "SHA-512";
const size_t OXI_SHA512_DIGEST_LEN = 64;
const size_t OXI_SHA512_BLOCK_LEN = 128;

static const char* OXI_SHA512_224_NAME = "SHA-512/224";
const size_t OXI_SHA512_224_DIGEST_LEN = 28;
const size_t OXI_SHA512_224_BLOCK_LEN = 128;

static const char* OXI_SHA512_256_NAME = "SHA-512/256";
const size_t OXI_SHA512_256_DIGEST_LEN = 32;
const size_t OXI_SHA512_256_BLOCK_LEN = 128;

/* Raw SHA functions. */

void oxi_sha1_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha256_compress_generic(uint32_t* state, const uint8_t* block);
void oxi_sha512_compress_generic(uint64_t* state, const uint8_t* block);

/* SHA engines. */

typedef struct oxi_sha_context1 {
  uint32_t h[5];
  uint8_t block[64];
  size_t blocklen;
  uint64_t len;
} oxi_sha_context1_t;

typedef struct oxi_sha_context256 {
  uint32_t h[8];
  uint8_t block[64];
  size_t blocklen;
  uint64_t len;
} oxi_sha_context256_t;

typedef struct oxi_sha_context512 {
  uint64_t h[8];
  uint8_t block[128];
  size_t blocklen;
  __uint128_t len;
} oxi_sha_context512_t;

/* SHA contexts. */

typedef oxi_sha_context1_t oxi_sha1_t;
typedef oxi_sha_context256_t oxi_sha224_t;
typedef oxi_sha_context256_t oxi_sha256_t;
typedef oxi_sha_context512_t oxi_sha384_t;
typedef oxi_sha_context512_t oxi_sha512_t;
typedef oxi_sha_context512_t oxi_sha512_224_t;
typedef oxi_sha_context512_t oxi_sha512_256_t;

/* SHA functions. */

void oxi_sha1_reset(oxi_sha1_t* ctx);
void oxi_sha224_reset(oxi_sha224_t* ctx);
void oxi_sha256_reset(oxi_sha256_t* ctx);
void oxi_sha384_reset(oxi_sha384_t* ctx);
void oxi_sha512_reset(oxi_sha512_t* ctx);
void oxi_sha512_224_reset(oxi_sha512_224_t* ctx);
void oxi_sha512_256_reset(oxi_sha512_256_t* ctx);

void oxi_sha1_update_generic(oxi_sha1_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha224_update_generic(oxi_sha224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha256_update_generic(oxi_sha256_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha384_update_generic(oxi_sha384_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_update_generic(oxi_sha512_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_224_update_generic(oxi_sha512_224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_256_update_generic(oxi_sha512_256_t* ctx, const uint8_t* data, size_t datalen);

void oxi_sha1_finish_generic(oxi_sha1_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha224_finish_generic(oxi_sha224_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha256_finish_generic(oxi_sha256_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha384_finish_generic(oxi_sha384_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha512_finish_generic(oxi_sha512_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha512_224_finish_generic(oxi_sha512_224_t* ctx, uint8_t* buf, size_t buflen);
void oxi_sha512_256_finish_generic(oxi_sha512_256_t* ctx, uint8_t* buf, size_t buflen);

void oxi_sha1_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha224_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha256_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha384_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha512_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha512_224_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);
void oxi_sha512_256_oneshot_generic(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_SHA_H_
