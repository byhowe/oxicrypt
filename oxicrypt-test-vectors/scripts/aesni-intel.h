#ifndef _AESNI_INTEL
#define _AESNI_INTEL

void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key);
void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key);
void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key);

#endif // _AESNI_INTEL
