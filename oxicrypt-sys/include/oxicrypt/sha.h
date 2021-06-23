#ifndef OXICRYPT_SHA_H_
#define OXICRYPT_SHA_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct oxi_sha512_ctx_t {
  uint64_t h[8];
  uint8_t block[128];
  uint64_t len;
  size_t blocklen;
} oxi_sha512_ctx_t;

typedef oxi_sha256_ctx_t oxi_sha224_ctx_t;
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

void oxi_sha1_update(oxi_sha1_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha224_update(oxi_sha224_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha256_update(oxi_sha256_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha384_update(oxi_sha384_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_update(oxi_sha512_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_224_update(oxi_sha512_224_ctx_t* ctx, const uint8_t* data, size_t datalen);
void oxi_sha512_256_update(oxi_sha512_256_ctx_t* ctx, const uint8_t* data, size_t datalen);

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

void oxi_sha1_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha224_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha256_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha384_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_224_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);
void oxi_sha512_256_oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <array>
#include <vector>

namespace oxi {

#define impl_sha(variant)                                                                          \
  class Sha##variant {                                                                             \
private:                                                                                           \
    oxi_sha##variant##_ctx_t ctx;                                                                  \
                                                                                                   \
public:                                                                                            \
    inline static const size_t DIGEST_LEN = OXI_SHA##variant##_DIGEST_LEN;                         \
    inline static const size_t BLOCK_LEN = OXI_SHA##variant##_BLOCK_LEN;                           \
                                                                                                   \
    inline Sha##variant() noexcept { oxi_sha##variant##_init(&this->ctx); }                        \
                                                                                                   \
    inline void update(const uint8_t* data, size_t datalen) noexcept                               \
    {                                                                                              \
      oxi_sha##variant##_update(&this->ctx, data, datalen);                                        \
    }                                                                                              \
                                                                                                   \
    inline void update(const std::vector<uint8_t>& data) noexcept                                  \
    {                                                                                              \
      oxi_sha##variant##_update(&this->ctx, data.data(), data.size());                             \
    }                                                                                              \
                                                                                                   \
    template <size_t N> inline void update(const std::array<uint8_t, N>& data) noexcept            \
    {                                                                                              \
      oxi_sha##variant##_update(&this->ctx, data.data(), N);                                       \
    }                                                                                              \
                                                                                                   \
    inline void finish(uint8_t* out, size_t outlen) noexcept                                       \
    {                                                                                              \
      oxi_sha##variant##_finish(&this->ctx, out, outlen);                                          \
    }                                                                                              \
                                                                                                   \
    inline void finish(std::vector<uint8_t>& out) noexcept                                         \
    {                                                                                              \
      oxi_sha##variant##_finish(&this->ctx, out.data(), out.size());                               \
    }                                                                                              \
                                                                                                   \
    template <size_t N> inline void finish(std::array<uint8_t, N>& out) noexcept                   \
    {                                                                                              \
      oxi_sha##variant##_finish(&this->ctx, out.data(), N);                                        \
    }                                                                                              \
                                                                                                   \
    inline static void oneshot(                                                                    \
        const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen) noexcept                 \
    {                                                                                              \
      oxi_sha##variant##_oneshot(data, datalen, out, outlen);                                      \
    }                                                                                              \
  };

impl_sha(1);
impl_sha(224);
impl_sha(256);
impl_sha(384);
impl_sha(512);
impl_sha(512_224);
impl_sha(512_256);

#undef impl_sha

}
#endif

#endif // OXICRYPT_SHA_H_
