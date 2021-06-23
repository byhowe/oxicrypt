#ifndef OXICRYPT_AES_H_
#define OXICRYPT_AES_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions. */

typedef struct oxi_aes128_ctx_t {
  const void* aes;
  uint8_t round_keys[176];
} oxi_aes128_ctx_t;

typedef struct oxi_aes192_ctx_t {
  const void* aes;
  uint8_t round_keys[208];
} oxi_aes192_ctx_t;

typedef struct oxi_aes256_ctx_t {
  const void* aes;
  uint8_t round_keys[240];
} oxi_aes256_ctx_t;

/* Constants that could be useful while working with AES. */

#define OXI_AES_BLOCK_LEN 16

#define OXI_AES128_KEY_LEN 16
#define OXI_AES192_KEY_LEN 24
#define OXI_AES256_KEY_LEN 32

#define OXI_AES128_KEY_SCHEDULE_LEN 176
#define OXI_AES192_KEY_SCHEDULE_LEN 208
#define OXI_AES256_KEY_SCHEDULE_LEN 240

/* Init functions. */

void oxi_aes128_init(oxi_aes128_ctx_t* ctx);
void oxi_aes192_init(oxi_aes192_ctx_t* ctx);
void oxi_aes256_init(oxi_aes256_ctx_t* ctx);

/* Set key functions. */

void oxi_aes128_set_encrypt_key(oxi_aes128_ctx_t* ctx, const uint8_t* key);
void oxi_aes192_set_encrypt_key(oxi_aes192_ctx_t* ctx, const uint8_t* key);
void oxi_aes256_set_encrypt_key(oxi_aes256_ctx_t* ctx, const uint8_t* key);
void oxi_aes128_set_decrypt_key(oxi_aes128_ctx_t* ctx, const uint8_t* key);
void oxi_aes192_set_decrypt_key(oxi_aes192_ctx_t* ctx, const uint8_t* key);
void oxi_aes256_set_decrypt_key(oxi_aes256_ctx_t* ctx, const uint8_t* key);

/* Inverse key functions. */

void oxi_aes128_inverse_key(oxi_aes128_ctx_t* ctx);
void oxi_aes192_inverse_key(oxi_aes192_ctx_t* ctx);
void oxi_aes256_inverse_key(oxi_aes256_ctx_t* ctx);

/* Encrypt functions. */

void oxi_aes128_encrypt(oxi_aes128_ctx_t* ctx, uint8_t* block);
void oxi_aes192_encrypt(oxi_aes192_ctx_t* ctx, uint8_t* block);
void oxi_aes256_encrypt(oxi_aes256_ctx_t* ctx, uint8_t* block);

/* Decrypt functions. */

void oxi_aes128_decrypt(oxi_aes128_ctx_t* ctx, uint8_t* block);
void oxi_aes192_decrypt(oxi_aes192_ctx_t* ctx, uint8_t* block);
void oxi_aes256_decrypt(oxi_aes256_ctx_t* ctx, uint8_t* block);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace oxi {

class Aes128 {
  private:
  oxi_aes128_ctx_t ctx;

  public:
  static const size_t BLOCK_LEN = OXI_AES_BLOCK_LEN;
  static const size_t KEY_LEN = OXI_AES128_KEY_LEN;
  static const size_t KEY_SCHEDULE_LEN = OXI_AES128_KEY_SCHEDULE_LEN;

  Aes128()
  {
    oxi_aes128_init(&this->ctx);
  }

  Aes128(const uint8_t* key)
  {
    oxi_aes128_init(&this->ctx);
    oxi_aes128_set_encrypt_key(&this->ctx, key);
  }

  void set_encrypt_key(const uint8_t* key)
  {
    oxi_aes128_set_encrypt_key(&this->ctx, key);
  }

  void set_decrypt_key(const uint8_t* key)
  {
    oxi_aes128_set_decrypt_key(&this->ctx, key);
  }

  void inverse_key()
  {
    oxi_aes128_inverse_key(&this->ctx);
  }

  void encrypt_single(uint8_t* block)
  {
    oxi_aes128_encrypt(&this->ctx, block);
  }

  void decrypt_single(uint8_t* block)
  {
    oxi_aes128_decrypt(&this->ctx, block);
  }
};

class Aes192 {
  private:
  oxi_aes192_ctx_t ctx;

  public:
  static const size_t BLOCK_LEN = OXI_AES_BLOCK_LEN;
  static const size_t KEY_LEN = OXI_AES192_KEY_LEN;
  static const size_t KEY_SCHEDULE_LEN = OXI_AES192_KEY_SCHEDULE_LEN;

  Aes192()
  {
    oxi_aes192_init(&this->ctx);
  }

  Aes192(const uint8_t* key)
  {
    oxi_aes192_init(&this->ctx);
    oxi_aes192_set_encrypt_key(&this->ctx, key);
  }

  void set_encrypt_key(const uint8_t* key)
  {
    oxi_aes192_set_encrypt_key(&this->ctx, key);
  }

  void set_decrypt_key(const uint8_t* key)
  {
    oxi_aes192_set_decrypt_key(&this->ctx, key);
  }

  void inverse_key()
  {
    oxi_aes192_inverse_key(&this->ctx);
  }

  void encrypt_single(uint8_t* block)
  {
    oxi_aes192_encrypt(&this->ctx, block);
  }

  void decrypt_single(uint8_t* block)
  {
    oxi_aes192_decrypt(&this->ctx, block);
  }
};

class Aes256 {
  private:
  oxi_aes256_ctx_t ctx;

  public:
  static const size_t BLOCK_LEN = OXI_AES_BLOCK_LEN;
  static const size_t KEY_LEN = OXI_AES256_KEY_LEN;
  static const size_t KEY_SCHEDULE_LEN = OXI_AES256_KEY_SCHEDULE_LEN;

  Aes256()
  {
    oxi_aes256_init(&this->ctx);
  }

  Aes256(const uint8_t* key)
  {
    oxi_aes256_init(&this->ctx);
    oxi_aes256_set_encrypt_key(&this->ctx, key);
  }

  void set_encrypt_key(const uint8_t* key)
  {
    oxi_aes256_set_encrypt_key(&this->ctx, key);
  }

  void set_decrypt_key(const uint8_t* key)
  {
    oxi_aes256_set_decrypt_key(&this->ctx, key);
  }

  void inverse_key()
  {
    oxi_aes256_inverse_key(&this->ctx);
  }

  void encrypt_single(uint8_t* block)
  {
    oxi_aes256_encrypt(&this->ctx, block);
  }

  void decrypt_single(uint8_t* block)
  {
    oxi_aes256_decrypt(&this->ctx, block);
  }
};

}
#endif

#endif // OXICRYPT_AES_H_
