#ifndef OXICRYPT_HMAC_H_
#define OXICRYPT_HMAC_H_

#include <stddef.h>
#include <stdint.h>

#include "sha.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC contexts. */

typedef struct oxi_hmac_sha1_t {
  oxi_sha1_t hash;
  bool x5c;
  uint8_t key[OXI_SHA1_BLOCK_LEN];
} oxi_hmac_sha1_t;

typedef struct oxi_hmac_sha224_t {
  oxi_sha224_t hash;
  bool x5c;
  uint8_t key[OXI_SHA224_BLOCK_LEN];
} oxi_hmac_sha224_t;

typedef struct oxi_hmac_sha256_t {
  oxi_sha256_t hash;
  bool x5c;
  uint8_t key[OXI_SHA256_BLOCK_LEN];
} oxi_hmac_sha256_t;

typedef struct oxi_hmac_sha384_t {
  oxi_sha384_t hash;
  bool x5c;
  uint8_t key[OXI_SHA384_BLOCK_LEN];
} oxi_hmac_sha384_t;

typedef struct oxi_hmac_sha512_t {
  oxi_sha512_t hash;
  bool x5c;
  uint8_t key[OXI_SHA512_BLOCK_LEN];
} oxi_hmac_sha512_t;

typedef struct oxi_hmac_sha512_224_t {
  oxi_sha512_224_t hash;
  bool x5c;
  uint8_t key[OXI_SHA512_224_BLOCK_LEN];
} oxi_hmac_sha512_224_t;

typedef struct oxi_hmac_sha512_256_t {
  oxi_sha512_256_t hash;
  bool x5c;
  uint8_t key[OXI_SHA512_256_BLOCK_LEN];
} oxi_hmac_sha512_256_t;

void oxi_hmac_sha1_set_key(oxi_hmac_sha1_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* key, size_t keylen);
void oxi_hmac_sha224_set_key(oxi_hmac_sha224_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* key, size_t keylen);
void oxi_hmac_sha256_set_key(oxi_hmac_sha256_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* key, size_t keylen);
void oxi_hmac_sha384_set_key(oxi_hmac_sha384_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_set_key(oxi_hmac_sha512_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_224_set_key(oxi_hmac_sha512_224_t* ctx,
    oxi_sha_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_256_set_key(oxi_hmac_sha512_256_t* ctx,
    oxi_sha_implementation_t implementation, const uint8_t* key, size_t keylen);

void oxi_hmac_sha1_update(oxi_hmac_sha1_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha224_update(oxi_hmac_sha224_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha256_update(oxi_hmac_sha256_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha384_update(oxi_hmac_sha384_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_update(oxi_hmac_sha512_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_224_update(oxi_hmac_sha512_224_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_256_update(oxi_hmac_sha512_256_t* ctx, oxi_sha_implementation_t implementation,
    const uint8_t* data, size_t datalen);

void oxi_hmac_sha1_finish(
    oxi_hmac_sha1_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_finish(
    oxi_hmac_sha224_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_finish(
    oxi_hmac_sha256_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_finish(
    oxi_hmac_sha384_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_finish(
    oxi_hmac_sha512_t* ctx, oxi_sha_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_finish(oxi_hmac_sha512_224_t* ctx, oxi_sha_implementation_t implementation,
    uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_finish(oxi_hmac_sha512_256_t* ctx, oxi_sha_implementation_t implementation,
    uint8_t* out, size_t outlen);

void oxi_hmac_sha1_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_oneshot(oxi_sha_implementation_t implementation, const uint8_t* key,
    size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_HMAC_H_
