#ifndef OXICRYPT_HMAC_H_
#define OXICRYPT_HMAC_H_

#include <cstdint>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const size_t OXI_HMAC_MD5_LEN = 16;
const size_t OXI_HMAC_SHA1_LEN = 20;
const size_t OXI_HMAC_SHA224_LEN = 28;
const size_t OXI_HMAC_SHA256_LEN = 32;
const size_t OXI_HMAC_SHA384_LEN = 48;
const size_t OXI_HMAC_SHA512_LEN = 64;
const size_t OXI_HMAC_SHA512_224_LEN = 28;
const size_t OXI_HMAC_SHA512_256_LEN = 32;

typedef void oxi_hmac_md5_t;
typedef void oxi_hmac_sha1_t;
typedef void oxi_hmac_sha224_t;
typedef void oxi_hmac_sha256_t;
typedef void oxi_hmac_sha384_t;
typedef void oxi_hmac_sha512_t;
typedef void oxi_hmac_sha512_224_t;
typedef void oxi_hmac_sha512_256_t;

oxi_hmac_md5_t* oxi_hmac_md5_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha1_t* oxi_hmac_sha1_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha224_t* oxi_hmac_sha224_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha256_t* oxi_hmac_sha256_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha384_t* oxi_hmac_sha384_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha512_t* oxi_hmac_sha512_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha512_224_t* oxi_hmac_sha512_224_new(const uint8_t* key, size_t key_len);
oxi_hmac_sha512_256_t* oxi_hmac_sha512_256_new(const uint8_t* key, size_t key_len);

void oxi_hmac_md5_drop(oxi_hmac_md5_t* ctx);
void oxi_hmac_sha1_drop(oxi_hmac_sha1_t* ctx);
void oxi_hmac_sha224_drop(oxi_hmac_sha224_t* ctx);
void oxi_hmac_sha256_drop(oxi_hmac_sha256_t* ctx);
void oxi_hmac_sha384_drop(oxi_hmac_sha384_t* ctx);
void oxi_hmac_sha512_drop(oxi_hmac_sha512_t* ctx);
void oxi_hmac_sha512_224_drop(oxi_hmac_sha512_224_t* ctx);
void oxi_hmac_sha512_256_drop(oxi_hmac_sha512_256_t* ctx);

void oxi_hmac_md5_set_key(oxi_hmac_md5_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha1_set_key(oxi_hmac_sha1_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha224_set_key(oxi_hmac_sha224_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha256_set_key(oxi_hmac_sha256_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha384_set_key(oxi_hmac_sha384_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha512_set_key(oxi_hmac_sha512_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha512_224_set_key(oxi_hmac_sha512_224_t* ctx, const uint8_t* key, size_t key_len);
void oxi_hmac_sha512_256_set_key(oxi_hmac_sha512_256_t* ctx, const uint8_t* key, size_t key_len);

void oxi_hmac_md5_update(oxi_hmac_md5_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha1_update(oxi_hmac_sha1_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha224_update(oxi_hmac_sha224_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha256_update(oxi_hmac_sha256_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha384_update(oxi_hmac_sha384_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha512_update(oxi_hmac_sha512_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha512_224_update(oxi_hmac_sha512_224_t* ctx, const uint8_t* data, size_t len);
void oxi_hmac_sha512_256_update(oxi_hmac_sha512_256_t* ctx, const uint8_t* data, size_t len);

const uint8_t* oxi_hmac_md5_finish(oxi_hmac_md5_t* ctx);
const uint8_t* oxi_hmac_sha1_finish(oxi_hmac_sha1_t* ctx);
const uint8_t* oxi_hmac_sha224_finish(oxi_hmac_sha224_t* ctx);
const uint8_t* oxi_hmac_sha256_finish(oxi_hmac_sha256_t* ctx);
const uint8_t* oxi_hmac_sha384_finish(oxi_hmac_sha384_t* ctx);
const uint8_t* oxi_hmac_sha512_finish(oxi_hmac_sha512_t* ctx);
const uint8_t* oxi_hmac_sha512_224_finish(oxi_hmac_sha512_224_t* ctx);
const uint8_t* oxi_hmac_sha512_256_finish(oxi_hmac_sha512_256_t* ctx);

void oxi_hmac_md5_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha1_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha224_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha256_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha384_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha512_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha512_224_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);
void oxi_hmac_sha512_256_oneshot(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* hmac, size_t hmac_len);

#ifdef __cplusplus
}
#endif


#endif // OXICRYPT_HMAC_H_
