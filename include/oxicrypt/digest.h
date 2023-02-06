#ifndef OXICRYPT_DIGEST_H_
#define OXICRYPT_DIGEST_H_

#include <cstdint>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const size_t OXI_DIGEST_MD5_LEN = 16;
const size_t OXI_DIGEST_SHA1_LEN = 20;
const size_t OXI_DIGEST_SHA224_LEN = 28;
const size_t OXI_DIGEST_SHA256_LEN = 32;
const size_t OXI_DIGEST_SHA384_LEN = 48;
const size_t OXI_DIGEST_SHA512_LEN = 64;
const size_t OXI_DIGEST_SHA512_224_LEN = 28;
const size_t OXI_DIGEST_SHA512_256_LEN = 32;

const size_t OXI_DIGEST_MD5_BLOCK_LEN = 64;
const size_t OXI_DIGEST_SHA1_BLOCK_LEN = 64;
const size_t OXI_DIGEST_SHA224_BLOCK_LEN = 64;
const size_t OXI_DIGEST_SHA256_BLOCK_LEN = 64;
const size_t OXI_DIGEST_SHA384_BLOCK_LEN = 128;
const size_t OXI_DIGEST_SHA512_BLOCK_LEN = 128;
const size_t OXI_DIGEST_SHA512_224_BLOCK_LEN = 128;
const size_t OXI_DIGEST_SHA512_256_BLOCK_LEN = 128;

typedef struct oxi_digest_md5* oxi_digest_md5_t;
typedef struct oxi_digest_sha1* oxi_digest_sha1_t;
typedef struct oxi_digest_sha224* oxi_digest_sha224_t;
typedef struct oxi_digest_sha256* oxi_digest_sha256_t;
typedef struct oxi_digest_sha384* oxi_digest_sha384_t;
typedef struct oxi_digest_sha512* oxi_digest_sha512_t;
typedef struct oxi_digest_sha512_224* oxi_digest_sha512_224_t;
typedef struct oxi_digest_sha512_256* oxi_digest_sha512_256_t;

oxi_digest_md5_t oxi_digest_md5_new();
oxi_digest_sha1_t oxi_digest_sha1_new();
oxi_digest_sha224_t oxi_digest_sha224_new();
oxi_digest_sha256_t oxi_digest_sha256_new();
oxi_digest_sha384_t oxi_digest_sha384_new();
oxi_digest_sha512_t oxi_digest_sha512_new();
oxi_digest_sha512_224_t oxi_digest_sha512_224_new();
oxi_digest_sha512_256_t oxi_digest_sha512_256_new();

void oxi_digest_md5_drop(oxi_digest_md5_t ctx);
void oxi_digest_sha1_drop(oxi_digest_sha1_t ctx);
void oxi_digest_sha224_drop(oxi_digest_sha224_t ctx);
void oxi_digest_sha256_drop(oxi_digest_sha256_t ctx);
void oxi_digest_sha384_drop(oxi_digest_sha384_t ctx);
void oxi_digest_sha512_drop(oxi_digest_sha512_t ctx);
void oxi_digest_sha512_224_drop(oxi_digest_sha512_224_t ctx);
void oxi_digest_sha512_256_drop(oxi_digest_sha512_256_t ctx);

void oxi_digest_md5_reset(oxi_digest_md5_t ctx);
void oxi_digest_sha1_reset(oxi_digest_sha1_t ctx);
void oxi_digest_sha224_reset(oxi_digest_sha224_t ctx);
void oxi_digest_sha256_reset(oxi_digest_sha256_t ctx);
void oxi_digest_sha384_reset(oxi_digest_sha384_t ctx);
void oxi_digest_sha512_reset(oxi_digest_sha512_t ctx);
void oxi_digest_sha512_224_reset(oxi_digest_sha512_224_t ctx);
void oxi_digest_sha512_256_reset(oxi_digest_sha512_256_t ctx);

void oxi_digest_md5_update(oxi_digest_md5_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha1_update(oxi_digest_sha1_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha224_update(oxi_digest_sha224_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha256_update(oxi_digest_sha256_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha384_update(oxi_digest_sha384_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha512_update(oxi_digest_sha512_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha512_224_update(oxi_digest_sha512_224_t ctx, const uint8_t* data, size_t len);
void oxi_digest_sha512_256_update(oxi_digest_sha512_256_t ctx, const uint8_t* data, size_t len);

const uint8_t* oxi_digest_md5_finish(oxi_digest_md5_t ctx);
const uint8_t* oxi_digest_sha1_finish(oxi_digest_sha1_t ctx);
const uint8_t* oxi_digest_sha224_finish(oxi_digest_sha224_t ctx);
const uint8_t* oxi_digest_sha256_finish(oxi_digest_sha256_t ctx);
const uint8_t* oxi_digest_sha384_finish(oxi_digest_sha384_t ctx);
const uint8_t* oxi_digest_sha512_finish(oxi_digest_sha512_t ctx);
const uint8_t* oxi_digest_sha512_224_finish(oxi_digest_sha512_224_t ctx);
const uint8_t* oxi_digest_sha512_256_finish(oxi_digest_sha512_256_t ctx);

void oxi_digest_md5_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha1_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha224_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha256_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha384_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha512_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha512_224_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);
void oxi_digest_sha512_256_oneshot(const uint8_t* data, size_t data_len, uint8_t* digest, size_t digest_len);

void oxi_digest_compress_md5(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha1(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha256(uint32_t* state, const uint8_t* block);
void oxi_digest_compress_sha512(uint64_t* state, const uint8_t* block);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_DIGEST_H_
