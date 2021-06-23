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
namespace oxi {

class Sha1 {
  private:
  oxi_sha1_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA1_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA1_BLOCK_LEN;

  Sha1()
  {
    oxi_sha1_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha1_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha1_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha1_oneshot(data, datalen, out, outlen);
  }
};

class Sha224 {
  private:
  oxi_sha224_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA224_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA224_BLOCK_LEN;

  Sha224()
  {
    oxi_sha224_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha224_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha224_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha224_oneshot(data, datalen, out, outlen);
  }
};

class Sha256 {
  private:
  oxi_sha256_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA256_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA256_BLOCK_LEN;

  Sha256()
  {
    oxi_sha256_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha256_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha256_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha256_oneshot(data, datalen, out, outlen);
  }
};

class Sha384 {
  private:
  oxi_sha384_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA384_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA384_BLOCK_LEN;

  Sha384()
  {
    oxi_sha384_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha384_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha384_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha384_oneshot(data, datalen, out, outlen);
  }
};

class Sha512 {
  private:
  oxi_sha512_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA512_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA512_BLOCK_LEN;

  Sha512()
  {
    oxi_sha512_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha512_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha512_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha512_oneshot(data, datalen, out, outlen);
  }
};

class Sha512_224 {
  private:
  oxi_sha512_224_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA512_224_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA512_224_BLOCK_LEN;

  Sha512_224()
  {
    oxi_sha512_224_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha512_224_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha512_224_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha512_224_oneshot(data, datalen, out, outlen);
  }
};

class Sha512_256 {
  private:
  oxi_sha512_256_ctx_t ctx;

  public:
  static const size_t DIGEST_LEN = OXI_SHA512_256_DIGEST_LEN;
  static const size_t BLOCK_LEN = OXI_SHA512_256_BLOCK_LEN;

  Sha512_256()
  {
    oxi_sha512_256_init(&this->ctx);
  }

  void update(const uint8_t* data, size_t datalen)
  {
    oxi_sha512_256_update(&this->ctx, data, datalen);
  }

  void finish(uint8_t* out, size_t outlen)
  {
    oxi_sha512_256_finish(&this->ctx, out, outlen);
  }

  static void oneshot(const uint8_t* data, size_t datalen, uint8_t* out, size_t outlen)
  {
    oxi_sha512_256_oneshot(data, datalen, out, outlen);
  }
};

}
#endif

#endif // OXICRYPT_SHA_H_
