#ifndef _AESNI_INTEL
#define _AESNI_INTEL

#if !defined(ALIGN16)
#if defined(__GNUC__)
#define ALIGN16 __attribute__((aligned(16)))
#else
#define ALIGN16 __declspec(align(16))
#endif
#endif
typedef struct KEY_SCHEDULE {
  ALIGN16 unsigned char KEY[16 * 15];
  unsigned int nr;
} AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
                     unsigned char *out,   // pointer to the CIPHERTEXT buffer
                     unsigned long length, // text length in bytes
                     const char *key, // pointer to the expanded key schedule
                     int number_of_rounds); // number of AES rounds 10,12 or 14
void AES_ECB_decrypt(const unsigned char *in, // pointer to the CIPHERTEXT
                     unsigned char *out, // pointer to the DECRYPTED TEXT buffer
                     unsigned long length, // text length in bytes
                     const char *key, // pointer to the expanded key schedule
                     int number_of_rounds); // number of AES rounds 10,12 or 14

#endif // _AESNI_INTEL
