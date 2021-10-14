#ifndef OXICRYPT_DIGEST_H_
#define OXICRYPT_DIGEST_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Function signatures that are used with the digest interface. */

typedef void oxi_digest_reset_func(void* ctx);
typedef void oxi_digest_update_func(void* ctx, const uint8_t* data, size_t datalen);
typedef void oxi_digest_finish_func(void* ctx, uint8_t* buf, size_t buflen);
typedef void oxi_digest_oneshot_func(const uint8_t* data, size_t datalen, uint8_t* buf, size_t buflen);

/* Available digest algorithms. */
enum oxi_digest_algo {
  OXI_DIGEST_SHA1_ALGO = 0,
  OXI_DIGEST_SHA224_ALGO = 1,
  OXI_DIGEST_SHA256_ALGO = 2,
  OXI_DIGEST_SHA384_ALGO = 3,
  OXI_DIGEST_SHA512_ALGO = 4,
  OXI_DIGEST_SHA512_224_ALGO = 5,
  OXI_DIGEST_SHA512_256_ALGO = 6,
};

struct oxi_digest {
  /* Name of the algorithm. */
  const char* name;
  /* Algorithm id. */
  enum oxi_digest_algo algo;

  /* Total size needed to store the context. */
  size_t context_size;

  /* Digest length that the algorithm produces. */
  size_t digest_len;
  /* Inner block lengththat the algorithm uses. */
  size_t block_len;

  oxi_digest_reset_func* reset;
  oxi_digest_update_func* update;
  oxi_digest_finish_func* finish;
  oxi_digest_oneshot_func* oneshot;
};

const struct oxi_digest* oxi_digest_generic(enum oxi_digest_algo algo);
const struct oxi_digest* oxi_digest_cpu_optimized(enum oxi_digest_algo algo);

extern const struct oxi_digest oxi_digest_sha1_generic;
extern const struct oxi_digest oxi_digest_sha224_generic;
extern const struct oxi_digest oxi_digest_sha256_generic;
extern const struct oxi_digest oxi_digest_sha384_generic;
extern const struct oxi_digest oxi_digest_sha512_generic;
extern const struct oxi_digest oxi_digest_sha512_224_generic;
extern const struct oxi_digest oxi_digest_sha512_256_generic;

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_DIGEST_H_
