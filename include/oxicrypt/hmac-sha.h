#ifndef OXICRYPT_HMAC_H_
#define OXICRYPT_HMAC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oxicrypt.h"
#include "sha.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC contexts. */

typedef struct oxi_hmac_sha1_t {
  oxi_sha1_t digest;
  uint8_t key[64];
  bool x5c;
} oxi_hmac_sha1_t;

typedef struct oxi_hmac_sha224_t {
  oxi_sha224_t digest;
  uint8_t key[64];
  bool x5c;
} oxi_hmac_sha224_t;

typedef struct oxi_hmac_sha256_t {
  oxi_sha256_t digest;
  uint8_t key[64];
  bool x5c;
} oxi_hmac_sha256_t;

typedef struct oxi_hmac_sha384_t {
  oxi_sha384_t digest;
  uint8_t key[128];
  bool x5c;
} oxi_hmac_sha384_t;

typedef struct oxi_hmac_sha512_t {
  oxi_sha512_t digest;
  uint8_t key[128];
  bool x5c;
} oxi_hmac_sha512_t;

typedef struct oxi_hmac_sha512_224_t {
  oxi_sha512_224_t digest;
  uint8_t key[128];
  bool x5c;
} oxi_hmac_sha512_224_t;

typedef struct oxi_hmac_sha512_256_t {
  oxi_sha512_256_t digest;
  uint8_t key[128];
  bool x5c;
} oxi_hmac_sha512_256_t;

/* HMAC functions. */

void oxi_hmac_sha1_set_key(oxi_hmac_sha1_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha224_set_key(oxi_hmac_sha224_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha256_set_key(oxi_hmac_sha256_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha384_set_key(oxi_hmac_sha384_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_set_key(oxi_hmac_sha512_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_224_set_key(oxi_hmac_sha512_224_t* ctx, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_256_set_key(oxi_hmac_sha512_256_t* ctx, const uint8_t* key, size_t keylen);

void oxi_hmac_sha1_set_key_impl(oxi_hmac_sha1_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha224_set_key_impl(oxi_hmac_sha224_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha256_set_key_impl(oxi_hmac_sha256_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha384_set_key_impl(oxi_hmac_sha384_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_set_key_impl(oxi_hmac_sha512_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_224_set_key_impl(oxi_hmac_sha512_224_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);
void oxi_hmac_sha512_256_set_key_impl(oxi_hmac_sha512_256_t* ctx, oxi_implementation_t implementation, const uint8_t* key, size_t keylen);

void oxi_hmac_sha1_reset(oxi_hmac_sha1_t* ctx);
void oxi_hmac_sha224_reset(oxi_hmac_sha224_t* ctx);
void oxi_hmac_sha256_reset(oxi_hmac_sha256_t* ctx);
void oxi_hmac_sha384_reset(oxi_hmac_sha384_t* ctx);
void oxi_hmac_sha512_reset(oxi_hmac_sha512_t* ctx);
void oxi_hmac_sha512_224_reset(oxi_hmac_sha512_224_t* ctx);
void oxi_hmac_sha512_256_reset(oxi_hmac_sha512_256_t* ctx);

void oxi_hmac_sha1_reset_impl(oxi_hmac_sha1_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha224_reset_impl(oxi_hmac_sha224_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha256_reset_impl(oxi_hmac_sha256_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha384_reset_impl(oxi_hmac_sha384_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha512_reset_impl(oxi_hmac_sha512_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha512_224_reset_impl(oxi_hmac_sha512_224_t* ctx, oxi_implementation_t implementation);
void oxi_hmac_sha512_256_reset_impl(oxi_hmac_sha512_256_t* ctx, oxi_implementation_t implementation);

void oxi_hmac_sha1_update(oxi_hmac_sha1_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha224_update(oxi_hmac_sha224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha256_update(oxi_hmac_sha256_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha384_update(oxi_hmac_sha384_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_update(oxi_hmac_sha512_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_224_update(oxi_hmac_sha512_224_t* ctx, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_256_update(oxi_hmac_sha512_256_t* ctx, const uint8_t* data, size_t datalen);

void oxi_hmac_sha1_update_impl(oxi_hmac_sha1_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha224_update_impl(oxi_hmac_sha224_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha256_update_impl(oxi_hmac_sha256_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha384_update_impl(oxi_hmac_sha384_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_update_impl(oxi_hmac_sha512_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_224_update_impl(oxi_hmac_sha512_224_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);
void oxi_hmac_sha512_256_update_impl(oxi_hmac_sha512_256_t* ctx, oxi_implementation_t implementation, const uint8_t* data, size_t datalen);

const uint8_t* oxi_hmac_sha1_finish_sliced(oxi_hmac_sha1_t* ctx);
const uint8_t* oxi_hmac_sha224_finish_sliced(oxi_hmac_sha224_t* ctx);
const uint8_t* oxi_hmac_sha256_finish_sliced(oxi_hmac_sha256_t* ctx);
const uint8_t* oxi_hmac_sha384_finish_sliced(oxi_hmac_sha384_t* ctx);
const uint8_t* oxi_hmac_sha512_finish_sliced(oxi_hmac_sha512_t* ctx);
const uint8_t* oxi_hmac_sha512_224_finish_sliced(oxi_hmac_sha512_224_t* ctx);
const uint8_t* oxi_hmac_sha512_256_finish_sliced(oxi_hmac_sha512_256_t* ctx);

const uint8_t* oxi_hmac_sha1_finish_sliced_impl(oxi_hmac_sha1_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha224_finish_sliced_impl(oxi_hmac_sha224_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha256_finish_sliced_impl(oxi_hmac_sha256_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha384_finish_sliced_impl(oxi_hmac_sha384_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha512_finish_sliced_impl(oxi_hmac_sha512_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha512_224_finish_sliced_impl(oxi_hmac_sha512_224_t* ctx, oxi_implementation_t implementation);
const uint8_t* oxi_hmac_sha512_256_finish_sliced_impl(oxi_hmac_sha512_256_t* ctx, oxi_implementation_t implementation);

void oxi_hmac_sha1_finish(oxi_hmac_sha1_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_finish(oxi_hmac_sha224_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_finish(oxi_hmac_sha256_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_finish(oxi_hmac_sha384_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_finish(oxi_hmac_sha512_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_finish(oxi_hmac_sha512_224_t* ctx, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_finish(oxi_hmac_sha512_256_t* ctx, uint8_t* out, size_t outlen);

void oxi_hmac_sha1_finish_impl(oxi_hmac_sha1_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_finish_impl(oxi_hmac_sha224_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_finish_impl(oxi_hmac_sha256_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_finish_impl(oxi_hmac_sha384_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_finish_impl(oxi_hmac_sha512_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_finish_impl(oxi_hmac_sha512_224_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_finish_impl(oxi_hmac_sha512_256_t* ctx, oxi_implementation_t implementation, uint8_t* out, size_t outlen);

void oxi_hmac_sha1_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_oneshot(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

void oxi_hmac_sha1_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha224_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha256_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha384_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_224_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_hmac_sha512_256_oneshot_impl(const uint8_t* key, size_t keylen, oxi_implementation_t implementation, const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_HMAC_H_
